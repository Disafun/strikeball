#!/usr/bin/env python3
"""Одноразовый перенос данных из СТАРОЙ локальной базы (strikeball.db) в Supabase.

Что делает: создаёт учётные записи Auth для старых игроков (с временными паролями),
переносит профили, мероприятия, записи, альбомы и фото (файлы -> Supabase Storage).
Повторный запуск безопасен: уже перенесённое пропускается (файл migration_state.json).

Нужен service_role-ключ (Project Settings -> API). Передавайте его ТОЛЬКО через окружение
терминала на время запуска и нигде не сохраняйте:
    Linux/macOS:  MIGRATION_SERVICE_ROLE_KEY=... python migrate_from_sqlite.py --dry-run
    Windows PS:   $env:MIGRATION_SERVICE_ROLE_KEY="..."; python migrate_from_sqlite.py --dry-run
Сначала запустите с --dry-run (ничего не отправляет), затем без него.
"""
import argparse
import csv
import json
import mimetypes
import os
import secrets
import sqlite3
import sys
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import requests

TZ = ZoneInfo(os.environ.get("APP_TZ", "Asia/Almaty"))
STATE_FILE = "migration_state.json"


def load_dotenv(path=".env"):
    if os.path.exists(path):
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def iso(local):
    """'2030-05-01T10:00' (местное время) -> ISO с часовым поясом."""
    return datetime.strptime(local[:16], "%Y-%m-%dT%H:%M").replace(tzinfo=TZ).isoformat()


class Cloud:
    def __init__(self, url, key):
        self.url = url.rstrip("/")
        self.h = {"apikey": key, "Authorization": f"Bearer {key}"}

    def call(self, method, path, **kw):
        headers = {**self.h, **kw.pop("headers", {})}
        r = requests.request(method, self.url + path, headers=headers, timeout=30, **kw)
        if r.status_code >= 400:
            raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:200]}")
        return r.json() if r.content else None

    def auth_user(self, email, password):
        try:
            u = self.call("POST", "/auth/v1/admin/users",
                          json={"email": email, "password": password, "email_confirm": True})
            return u["id"], True
        except RuntimeError as e:
            if "422" not in str(e):
                raise
        page = 1
        while True:                                  # пользователь уже существует — ищем id
            data = self.call("GET", "/auth/v1/admin/users", params={"page": page, "per_page": 200})
            users = data.get("users", [])
            for u in users:
                if (u.get("email") or "").lower() == email.lower():
                    return u["id"], False
            if len(users) < 200:
                raise RuntimeError(f"не найден существующий пользователь {email}")
            page += 1

    def insert(self, table, row):
        return self.call("POST", f"/rest/v1/{table}", json=row,
                         headers={"Prefer": "return=representation"})[0]

    def upload(self, folder, local_path):
        ext = os.path.splitext(local_path)[1].lower() or ".jpg"
        path = f"{folder}/{uuid.uuid4().hex}{ext}"
        mime = mimetypes.guess_type(local_path)[0] or "image/jpeg"
        with open(local_path, "rb") as f:
            self.call("POST", f"/storage/v1/object/photos/{path}", data=f.read(),
                      headers={"Content-Type": mime, "x-upsert": "false"})
        return path


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--db", default="strikeball.db", help="старая SQLite-база")
    ap.add_argument("--uploads", default="old_data/uploads", help="папка со старыми фото")
    ap.add_argument("--dry-run", action="store_true", help="только показать, что будет перенесено")
    args = ap.parse_args()
    load_dotenv()

    if not os.path.exists(args.db):
        sys.exit(f"Не найдена база {args.db}. Укажите путь через --db.")
    db = sqlite3.connect(args.db)
    db.row_factory = sqlite3.Row
    users = db.execute("SELECT * FROM users ORDER BY id").fetchall()
    events = db.execute("SELECT * FROM events ORDER BY id").fetchall()
    regs = db.execute("SELECT * FROM registrations ORDER BY id").fetchall()
    albums = db.execute("SELECT * FROM albums ORDER BY id").fetchall()
    photos = db.execute("SELECT * FROM photos ORDER BY id").fetchall()
    print(f"В старой базе: игроков {len(users)}, мероприятий {len(events)}, записей {len(regs)}, "
          f"альбомов {len(albums)}, фото {len(photos)}")
    if args.dry_run:
        for u in users:
            print(f"  игрок: {u['full_name']} <{u['email']}>")
        for e in events:
            print(f"  мероприятие: {e['title']} ({e['event_date']})")
        print("Dry-run: ничего не отправлено.")
        return

    url, key = os.environ.get("SUPABASE_URL", ""), os.environ.get("MIGRATION_SERVICE_ROLE_KEY", "")
    if not url or not key:
        sys.exit("Нужны SUPABASE_URL и MIGRATION_SERVICE_ROLE_KEY (см. описание в начале файла).")
    cloud = Cloud(url, key)
    st = json.load(open(STATE_FILE)) if os.path.exists(STATE_FILE) else {}
    for k in ("users", "events", "albums", "photos", "regs"):
        st.setdefault(k, {})
    save = lambda: json.dump(st, open(STATE_FILE, "w"))
    failed, creds = [], []

    def local_file(name):
        p = os.path.join(args.uploads, name) if name else None
        return p if p and os.path.exists(p) else None

    for u in users:
        if str(u["id"]) in st["users"]:
            continue
        try:
            pw = secrets.token_urlsafe(9)
            uid, created = cloud.auth_user(u["email"], pw)
            photo = None
            if local_file(u["photo"]):
                photo = cloud.upload(uid, local_file(u["photo"]))
            try:
                cloud.insert("profiles", {"id": uid, "full_name": u["full_name"], "age": u["age"],
                                          "phone": u["phone"], "email": u["email"], "photo": photo})
            except RuntimeError as e:
                if "23505" not in str(e):             # профиль уже есть — не ошибка
                    raise
            st["users"][str(u["id"])] = uid
            if created:
                creds.append((u["email"], pw))
            print(f"игрок перенесён: {u['email']}")
        except Exception as e:                        # noqa: BLE001
            failed.append(f"игрок {u['email']}: {e}")
        save()

    for e in events:
        if str(e["id"]) in st["events"]:
            continue
        try:
            photo = cloud.upload("legacy", local_file(e["photo"])) if local_file(e["photo"]) else None
            row = cloud.insert("events", {
                "title": e["title"], "description": e["description"], "location": e["location"],
                "photo": photo, "event_date": iso(e["event_date"]), "max_players": e["max_players"]})
            st["events"][str(e["id"])] = row["id"]
            print(f"мероприятие перенесено: {e['title']}")
        except Exception as ex:                       # noqa: BLE001
            failed.append(f"мероприятие {e['title']}: {ex}")
        save()

    for r in regs:
        eid, uid = st["events"].get(str(r["event_id"])), st["users"].get(str(r["user_id"]))
        if not eid or not uid or str(r["id"]) in st["regs"]:
            continue
        try:
            cloud.insert("registrations", {"event_id": eid, "user_id": uid})
        except Exception as ex:                       # noqa: BLE001
            if "23505" not in str(ex):
                failed.append(f"запись {r['id']}: {ex}")
                continue
        st["regs"][str(r["id"])] = True
    save()

    for a in albums:
        if str(a["id"]) in st["albums"]:
            continue
        try:
            st["albums"][str(a["id"])] = cloud.insert("albums", {"title": a["title"]})["id"]
            print(f"альбом перенесён: {a['title']}")
        except Exception as ex:                       # noqa: BLE001
            failed.append(f"альбом {a['title']}: {ex}")
        save()

    for p in photos:
        aid, f = st["albums"].get(str(p["album_id"])), local_file(p["filename"])
        if not aid or str(p["id"]) in st["photos"]:
            continue
        if not f:
            failed.append(f"фото {p['id']}: файл {p['filename']} не найден в {args.uploads}")
            continue
        uid = st["users"].get(str(p["user_id"]))
        try:
            path = cloud.upload(uid or "legacy", f)
            cloud.insert("photos", {"album_id": aid, "user_id": uid, "path": path})
            st["photos"][str(p["id"])] = True
        except Exception as ex:                       # noqa: BLE001
            failed.append(f"фото {p['id']}: {ex}")
        save()

    if creds:
        with open("migrated_users_temp_passwords.csv", "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["email", "temporary_password"])
            w.writerows(creds)
        print(f"\nВременные пароли: migrated_users_temp_passwords.csv ({len(creds)} шт.). "
              "Передайте игрокам и УДАЛИТЕ файл; пароль можно сменить в профиле.")
    print(f"\nГотово. Ошибок: {len(failed)}")
    for line in failed:
        print("  !", line)


if __name__ == "__main__":
    main()
