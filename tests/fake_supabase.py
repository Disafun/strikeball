"""Эмулятор REST-API Supabase (Auth + PostgREST + Storage) для тестов приложения.

ВАЖНО: это НЕ настоящий Supabase. Эмулятор повторяет правила из supabase/migrations/001_init.sql
(RLS, права на колонки, триггер вместимости) для проверки Python-кода приложения.
Сам SQL он не проверяет.
"""
import json as jsonlib
import re
import time
import uuid
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests


class Resp:
    def __init__(self, status, body=None):
        self.status_code = status
        self._body = body
        self.content = b"" if body is None else jsonlib.dumps(body).encode()
        self.text = self.content.decode()

    def json(self):
        if self._body is None:
            raise ValueError
        return self._body


def ts(v):
    d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


class FakeSupabase:
    ANON = "anon-key"
    BASE = "https://fake.supabase.test"

    def __init__(self, confirm_email=False):
        self.confirm_email = confirm_email
        self.users, self.tokens, self.refresh = {}, {}, {}
        self.t = {k: [] for k in ("profiles", "events", "registrations", "albums", "photos")}
        self.seq = {k: 0 for k in self.t}
        self.storage = {}
        self.down = False
        self.expires_in = 3600
        self.calls = []

    # ---- утилиты ----
    def add_user(self, email, password, role=None, profile=None):
        uid = str(uuid.uuid4())
        self.users[uid] = {"id": uid, "email": email, "password": password}
        if role:
            self.t["profiles"].append({"id": uid, "full_name": profile or "Администратор", "age": 30,
                                       "phone": "00000", "email": email, "photo": None, "role": role,
                                       "created_at": "2026-01-01T00:00:00+00:00"})
        return uid

    def session(self, uid):
        n = len(self.tokens)
        at, rt = f"at{n}_{uid}", f"rt{n}_{uid}"
        self.tokens[at], self.refresh[rt] = uid, uid
        return {"access_token": at, "refresh_token": rt, "expires_in": self.expires_in,
                "expires_at": int(time.time()) + self.expires_in,
                "user": {"id": uid, "email": self.users[uid]["email"]}}

    def role(self, uid):
        for p in self.t["profiles"]:
            if p["id"] == uid:
                return p["role"]
        return "player"

    def _err(self, status, code, msg):
        return Resp(status, {"code": code, "message": msg})

    # ---- вход в эмулятор ----
    def request(self, method, url, headers=None, params=None, json=None, data=None, timeout=None):
        if self.down:
            raise requests.ConnectionError("network down")
        headers = headers or {}
        assert headers.get("apikey") == self.ANON, "нет apikey"
        auth = headers.get("Authorization", "").replace("Bearer ", "")
        assert "service_role" not in auth
        uid = self.tokens.get(auth)
        path = urlparse(url).path
        self.calls.append((method, path))
        params = params or {}
        if path.startswith("/auth/v1/"):
            return self.auth(method, path[9:], params, json, uid)
        if path.startswith("/rest/v1/"):
            return self.rest(method, path[9:], params, json, uid, headers)
        if path.startswith("/storage/v1/object/photos/"):
            return self.store(method, path[len("/storage/v1/object/photos/"):], uid, headers, data)
        return Resp(404, {"message": "not found"})

    # ---- Auth ----
    def auth(self, method, path, params, body, uid):
        if path == "signup":
            if any(u["email"] == body["email"] for u in self.users.values()):
                return Resp(422, {"error_code": "user_already_exists", "msg": "User already registered"})
            if len(body["password"]) < 6:
                return Resp(422, {"error_code": "weak_password", "msg": "Password should be at least 6 characters"})
            new = self.add_user(body["email"], body["password"])
            if self.confirm_email:
                return Resp(200, {"id": new, "email": body["email"]})
            return Resp(200, self.session(new))
        if path == "token" and params.get("grant_type") == "password":
            for u in self.users.values():
                if u["email"] == body["email"] and u["password"] == body["password"]:
                    return Resp(200, self.session(u["id"]))
            return Resp(400, {"error_code": "invalid_credentials", "msg": "Invalid login credentials"})
        if path == "token" and params.get("grant_type") == "refresh_token":
            u = self.refresh.get(body["refresh_token"])
            return Resp(200, self.session(u)) if u else Resp(400, {"error_code": "refresh_token_not_found", "msg": "bad"})
        if path == "user" and method == "PUT":
            if not uid:
                return Resp(401, {"msg": "no auth"})
            self.users[uid]["password"] = body["password"]
            return Resp(200, {"id": uid})
        if path == "logout":
            return Resp(204)
        return Resp(404, {"message": "x"})

    # ---- PostgREST ----
    def match(self, row, params):
        for k, v in params.items():
            if k in ("select", "order", "limit"):
                continue
            op, _, val = v.partition(".")
            cur = row.get(k)
            if op == "eq" and str(cur) != val:
                return False
            if op == "in" and str(cur) not in val.strip("()").split(","):
                return False
            if op == "gte" and not (ts(cur) >= ts(val)):
                return False
        return True

    def rest(self, method, table, params, body, uid, headers):
        if not uid:
            return self._err(401, "PGRST301", "JWT expired or invalid")
        admin = self.role(uid) == "admin"
        # представления
        if table == "public_profiles":
            rows = [{k: p[k] for k in ("id", "full_name", "age", "photo")} for p in self.t["profiles"]]
            return Resp(200, [r for r in rows if self.match(r, params)])
        if table == "event_stats":
            return Resp(200, [{"event_id": e["id"], "cnt": sum(1 for r in self.t["registrations"] if r["event_id"] == e["id"])}
                              for e in self.t["events"]])
        if table == "album_stats":
            out = []
            for a in self.t["albums"]:
                ph = [p for p in self.t["photos"] if p["album_id"] == a["id"]]
                out.append({"album_id": a["id"], "cnt": len(ph), "cover": ph[-1]["path"] if ph else None})
            return Resp(200, out)
        rows = self.t[table]
        denied = lambda: self._err(403, "42501", f"new row violates row-level security policy for table \"{table}\"")
        if method == "GET":
            vis = rows
            if table == "profiles" and not admin:
                vis = [r for r in rows if r["id"] == uid]
            out = [dict(r) for r in vis if self.match(r, params)]
            key, _, d = params.get("order", "").partition(".")
            if key:
                out.sort(key=lambda r: r[key], reverse=(d == "desc"))
            if "limit" in params:
                out = out[: int(params["limit"])]
            return Resp(200, out)
        if method == "POST":
            items = body if isinstance(body, list) else [body]
            created = []
            for it in items:
                r = self.insert(table, dict(it), uid, admin)
                if isinstance(r, Resp):
                    return r
                created.append(r)
            return Resp(201, created)
        # PATCH / DELETE: строки, не прошедшие RLS, молча не затрагиваются
        targets = [r for r in rows if self.match(r, params)]
        if method == "PATCH":
            allowed = {"profiles": {"full_name", "age", "phone", "photo"},
                       "events": {"title", "description", "location", "photo", "event_date", "max_players", "status"},
                       "albums": {"title"}}.get(table, set())
            if not set(body) <= allowed:
                return self._err(403, "42501", f"permission denied for table {table}")
            ok = lambda r: (r["id"] == uid or admin) if table == "profiles" else admin
            hit = [r for r in targets if ok(r)]
            if "event_date" in body:
                body = {**body, "event_date": ts(body["event_date"]).astimezone(timezone.utc).isoformat()}
            for r in hit:
                r.update(body)
            return Resp(200, [dict(r) for r in hit])
        if method == "DELETE":
            if table == "profiles":
                return self._err(403, "42501", "permission denied")
            ok = {"events": lambda r: admin, "albums": lambda r: admin,
                  "registrations": lambda r: r["user_id"] == uid or admin,
                  "photos": lambda r: r["user_id"] == uid or admin}[table]
            hit = [r for r in targets if ok(r)]
            for r in hit:
                rows.remove(r)
            if table == "events":
                self.t["registrations"] = [x for x in self.t["registrations"] if x["event_id"] != hit[0]["id"]] if hit else self.t["registrations"]
            if table == "albums" and hit:
                self.t["photos"] = [x for x in self.t["photos"] if x["album_id"] != hit[0]["id"]]
            return Resp(200, [dict(r) for r in hit])

    def insert(self, table, it, uid, admin):
        cols = {"profiles": {"id", "full_name", "age", "phone", "photo"},
                "events": {"title", "description", "location", "photo", "event_date", "max_players", "status"},
                "registrations": {"event_id", "user_id"}, "albums": {"title"},
                "photos": {"album_id", "user_id", "path"}}[table]
        if not set(it) <= cols:
            return self._err(403, "42501", f"permission denied for table {table}")
        if table in ("events", "albums") and not admin:
            return self._err(403, "42501", f"new row violates row-level security policy for table \"{table}\"")
        if table == "profiles":
            if it["id"] != uid:
                return self._err(403, "42501", "new row violates row-level security policy")
            if any(p["id"] == uid for p in self.t["profiles"]):
                return self._err(409, "23505", "duplicate key")
            it.update(role="player", email=self.users[uid]["email"], created_at="now")
        elif table in ("registrations", "photos"):
            it.setdefault("user_id", uid)
            if it["user_id"] != uid:
                return self._err(403, "42501", "new row violates row-level security policy")
        if table == "registrations":
            ev = next((e for e in self.t["events"] if e["id"] == it["event_id"]), None)
            if not ev:
                return self._err(400, "P0001", "event_not_found")
            if ev["status"] != "open":
                return self._err(400, "P0001", "event_closed")
            if ts(ev["event_date"]) < datetime.now(timezone.utc):
                return self._err(400, "P0001", "event_past")
            cnt = sum(1 for r in self.t["registrations"] if r["event_id"] == ev["id"])
            if ev["max_players"] is not None and cnt >= ev["max_players"]:
                return self._err(400, "P0001", "event_full")
            if any(r["event_id"] == ev["id"] and r["user_id"] == uid for r in self.t["registrations"]):
                return self._err(409, "23505", "duplicate key value violates unique constraint")
        if table == "events":
            it.setdefault("status", "open"); it.setdefault("description", None)
            it.setdefault("location", None); it.setdefault("photo", None); it.setdefault("max_players", None)
            it["organizer_id"] = uid
        if table in ("events", "registrations", "albums", "photos"):
            self.seq[table] += 1
            it["id"] = self.seq[table]
            it["created_at"] = f"2026-01-01T00:00:{self.seq[table]:02d}+00:00"
        if table == "events":
            it["event_date"] = ts(it["event_date"]).astimezone(timezone.utc).isoformat()
        self.t[table].append(it)
        return it

    # ---- Storage ----
    def store(self, method, path, uid, headers, data):
        if not uid:
            return Resp(401, {"message": "no auth"})
        folder_ok = path.split("/")[0] == uid
        if method == "POST":
            if not folder_ok:
                return Resp(403, {"message": "new row violates row-level security policy", "statusCode": "403"})
            if headers.get("Content-Type") not in ("image/png", "image/jpeg", "image/gif", "image/webp"):
                return Resp(415, {"message": "mime type not supported"})
            self.storage[path] = data
            return Resp(200, {"Key": path})
        if method == "DELETE":
            if folder_ok or self.role(uid) == "admin":
                self.storage.pop(path, None)
                return Resp(200, {"message": "Successfully deleted"})
            return Resp(400, {"message": "not allowed"})
        return Resp(404, {"message": "x"})
