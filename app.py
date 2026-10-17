"""Страйкбол-клуб: набор команды на игры. Общие данные хранятся в Supabase.

Профили, мероприятия, записи, альбомы и фото лежат в облачной базе (PostgreSQL +
Storage). Локально хранится только подписанная cookie с сессией входа.
Запуск: см. README.md
"""
import hmac
import os
import re
import secrets
import time
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timezone
from functools import wraps
from zoneinfo import ZoneInfo

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)

import supa
from supa import NetworkError, SupaError


# ---------- конфигурация ----------
def load_dotenv(path):
    """Минимальный загрузчик .env (без внешних зависимостей)."""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join(BASE_DIR, ".env"))

TZ = ZoneInfo(os.environ.get("APP_TZ", "Asia/Almaty"))
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "webp"}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or secrets.token_hex(32)
if not os.environ.get("SECRET_KEY"):
    print("ВНИМАНИЕ: SECRET_KEY не задан; сессии сбросятся при перезапуске сервера.")
app.config.update(
    MAX_CONTENT_LENGTH=12 * 1024 * 1024,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SESSION_COOKIE_SECURE", "0") == "1",
    PERMANENT_SESSION_LIFETIME=60 * 60 * 24 * 30,
)
if os.environ.get("TRUST_PROXY", "0") == "1":      # за reverse proxy (Render и т.п.)
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)


# ---------- время ----------
def parse_ts(value):
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def to_local_input(value):
    return parse_ts(value).astimezone(TZ).strftime("%Y-%m-%dT%H:%M")


def from_local_input(value):
    """'2030-05-01T10:00' (местное время) -> ISO с часовым поясом для timestamptz."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M").replace(tzinfo=TZ).isoformat()


@app.template_filter("dt")
def fmt_dt(value):
    try:
        return parse_ts(value).astimezone(TZ).strftime("%d.%m.%Y %H:%M")
    except (TypeError, ValueError, AttributeError):
        return value or ""


# ---------- ошибки Supabase -> понятные сообщения ----------
def friendly(e):
    if isinstance(e, NetworkError):
        return "Нет связи с облачной базой данных. Изменения НЕ сохранены — попробуйте ещё раз."
    msg, code = e.message.lower(), e.code.lower()
    known = [
        ("event_full", "Все места заняты."),
        ("event_closed", "Запись на это мероприятие закрыта."),
        ("event_past", "Это мероприятие уже прошло."),
        ("event_not_found", "Мероприятие не найдено."),
    ]
    for key, text in known:
        if key in msg:
            return text
    if code in ("invalid_credentials",) or "invalid login credentials" in msg:
        return "Неверная почта или пароль."
    if code == "email_not_confirmed" or "email not confirmed" in msg:
        return "Почта не подтверждена. Перейдите по ссылке из письма."
    if code in ("user_already_exists", "email_exists") or "already registered" in msg:
        return "Эта почта уже зарегистрирована — войдите."
    if code == "weak_password" or "password should be" in msg:
        return "Слишком простой пароль (минимум 6 символов)."
    if e.status == 429 or "rate limit" in msg:
        return "Слишком много попыток. Подождите немного и повторите."
    if e.status == 403 or code == "42501" or "row-level security" in msg:
        return "Недостаточно прав для этого действия."
    if e.status in (502, 503, 504):
        return "Облачная база временно недоступна. Попробуйте позже."
    return f"Ошибка облачной базы данных ({e.status}). Изменения не сохранены."


@app.errorhandler(NetworkError)
@app.errorhandler(SupaError)
def backend_error(e):
    if isinstance(e, SupaError) and e.status == 401:
        session.clear()
        flash("Сессия истекла, войдите заново.", "error")
        return redirect(url_for("login"))
    msg = friendly(e)
    if request.method == "POST":
        flash(msg, "error")
        return redirect(request.referrer or url_for("index"))
    return render_template("error.html", message=msg), 503


@app.errorhandler(403)
def err403(_e):
    return render_template("error.html", message="Недостаточно прав для этого действия."), 403


@app.errorhandler(404)
def err404(_e):
    return render_template("error.html", message="Страница не найдена."), 404


@app.errorhandler(413)
def err413(_e):
    return render_template("error.html", message="Файл слишком большой (максимум 12 МБ)."), 413


# ---------- сессия и авторизация ----------
def store_session(data):
    session.permanent = True
    session["at"] = data["access_token"]
    session["rt"] = data["refresh_token"]
    session["exp"] = data.get("expires_at") or time.time() + data.get("expires_in", 3600)
    session["uid"] = data["user"]["id"]


def fetch_profile(token, uid):
    rows = supa.rest("GET", "profiles", token, {"id": f"eq.{uid}", "select": "*", "limit": 1})
    return rows[0] if rows else None


@app.before_request
def load_auth():
    g.token, g.me, g.is_admin = None, None, False
    if request.endpoint in (None, "static"):
        return None
    if not supa.configured():
        return render_template("config_error.html"), 503
    if not session.get("at") or request.endpoint == "logout":
        return None
    if session.get("exp", 0) - time.time() < 60:
        try:
            store_session(supa.refresh(session["rt"]))
        except SupaError:
            session.clear()
            return None
    g.token = session["at"]
    g.me = fetch_profile(g.token, session["uid"])
    g.is_admin = bool(g.me and g.me.get("role") == "admin")
    return None


@app.context_processor
def inject_globals():
    return {"authed": bool(g.get("token")), "is_admin": g.get("is_admin", False),
            "me": g.get("me"), "photo_url": supa.public_url}


def auth_only(f):
    @wraps(f)
    def wrapper(*a, **kw):
        if not g.token:
            return redirect(url_for("login"))
        return f(*a, **kw)
    return wrapper


def login_required(f):
    @wraps(f)
    @auth_only
    def wrapper(*a, **kw):
        if g.me is None:
            return redirect(url_for("complete_profile"))
        return f(*a, **kw)
    return wrapper


def admin_required(f):
    @wraps(f)
    @login_required
    def wrapper(*a, **kw):
        if not g.is_admin:
            abort(403)
        return f(*a, **kw)
    return wrapper


# ---------- изображения (Supabase Storage) ----------
def sniff_image(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png", "image/png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg", "image/jpeg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif", "image/gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp", "image/webp"
    return None


def upload_image(file_storage):
    """Загружает картинку в Storage (папка = id пользователя). Возвращает путь или None."""
    if not file_storage or not file_storage.filename:
        return None
    data = file_storage.read()
    kind = sniff_image(data)
    if not kind:
        flash("Допустимы только изображения: png, jpg, gif, webp.", "error")
        return None
    ext, mime = kind
    path = f"{session['uid']}/{uuid.uuid4().hex}.{ext}"
    supa.upload(g.token, path, data, mime)
    return path


# ---------- вход / регистрация ----------
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_admin_fails = defaultdict(list)          # ip -> метки времени неудачных попыток
ADMIN_MAX_FAILS, ADMIN_WINDOW = 5, 600


@app.route("/login")
def login():
    if g.token and g.me:
        return redirect(url_for("index"))
    return render_template("login.html")


@app.post("/login/user")
def login_user():
    email = request.form.get("email", "").strip().lower()
    password = request.form.get("password", "")
    if not EMAIL_RE.match(email) or not password:
        flash("Введите почту и пароль.", "error")
        return redirect(url_for("login"))
    try:
        data = supa.sign_in(email, password)
    except SupaError as e:
        flash(friendly(e), "error")
        return redirect(url_for("login"))
    session.clear()
    store_session(data)
    if fetch_profile(data["access_token"], data["user"]["id"]) is None:
        flash("Заполните профиль, чтобы продолжить.", "info")
        return redirect(url_for("complete_profile"))
    return redirect(url_for("index"))


@app.post("/login/admin")
def login_admin():
    ip = request.remote_addr or "?"
    now = time.time()
    _admin_fails[ip] = [t for t in _admin_fails[ip] if now - t < ADMIN_WINDOW]
    if len(_admin_fails[ip]) >= ADMIN_MAX_FAILS:
        flash("Слишком много неверных попыток. Подождите 10 минут.", "error")
        return redirect(url_for("login"))
    expected = os.environ.get("ADMIN_PASSWORD", "")
    given = request.form.get("password", "")
    if not expected or not hmac.compare_digest(given.encode(), expected.encode()):
        _admin_fails[ip].append(now)
        flash("Неверный пароль администратора.", "error")
        return redirect(url_for("login"))
    email = os.environ.get("ADMIN_ACCOUNT_EMAIL", "")
    acc_pw = os.environ.get("ADMIN_ACCOUNT_PASSWORD", "")
    if not email or not acc_pw:
        flash("Админ-аккаунт не настроен (ADMIN_ACCOUNT_EMAIL / ADMIN_ACCOUNT_PASSWORD).", "error")
        return redirect(url_for("login"))
    try:
        data = supa.sign_in(email, acc_pw)
        profile = fetch_profile(data["access_token"], data["user"]["id"])
    except SupaError as e:
        flash(f"Не удалось войти в админ-аккаунт Supabase: {friendly(e)}", "error")
        return redirect(url_for("login"))
    if not profile or profile.get("role") != "admin":
        flash("Этот аккаунт не имеет роли admin в базе (см. supabase/seed_admin.sql).", "error")
        return redirect(url_for("login"))
    session.clear()
    store_session(data)
    return redirect(url_for("index"))


def read_profile_form():
    name = request.form.get("full_name", "").strip()
    phone = request.form.get("phone", "").strip()
    try:
        age = int(request.form.get("age", ""))
    except ValueError:
        age = 0
    errors = []
    if len(name.split()) < 2:
        errors.append("Укажите ФИО полностью.")
    if not 10 <= age <= 99:
        errors.append("Возраст должен быть от 10 до 99.")
    if len(re.sub(r"\D", "", phone)) < 10 or len(phone) > 30:
        errors.append("Введите корректный номер телефона.")
    return {"full_name": name, "age": age, "phone": phone}, errors


def create_profile(fields):
    """Создаёт профиль для вошедшего пользователя (RLS: id = auth.uid())."""
    photo = upload_image(request.files.get("photo"))
    payload = {"id": session["uid"], **fields, "photo": photo}
    try:
        supa.rest("POST", "profiles", g.token, json=payload)
    except (SupaError, NetworkError):
        supa.remove_object(g.token, photo)
        raise


@app.route("/register", methods=["GET", "POST"])
def register():
    if g.token:
        return redirect(url_for("index") if g.me else url_for("complete_profile"))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        fields, errors = read_profile_form()
        if not EMAIL_RE.match(email):
            errors.append("Введите корректную почту.")
        if len(password) < 6:
            errors.append("Пароль — минимум 6 символов.")
        for msg in errors:
            flash(msg, "error")
        if not errors:
            try:
                data = supa.sign_up(email, password)
            except SupaError as e:
                flash(friendly(e), "error")
                return render_template("profile.html", mode="register", user=None, email=email)
            if not data.get("access_token"):
                flash("Аккаунт создан. Подтвердите почту по письму и войдите — "
                      "затем мы попросим заполнить профиль.", "info")
                return redirect(url_for("login"))
            session.clear()
            store_session(data)
            g.token = data["access_token"]
            create_profile(fields)
            flash("Профиль создан. Добро пожаловать!", "success")
            return redirect(url_for("index"))
        return render_template("profile.html", mode="register", user=None, email=email)
    return render_template("profile.html", mode="register", user=None, email="")


@app.route("/profile/complete", methods=["GET", "POST"])
@auth_only
def complete_profile():
    """Для вошедших пользователей, у которых ещё нет профиля."""
    if g.me:
        return redirect(url_for("index"))
    if request.method == "POST":
        fields, errors = read_profile_form()
        for msg in errors:
            flash(msg, "error")
        if not errors:
            create_profile(fields)
            flash("Профиль создан. Добро пожаловать!", "success")
            return redirect(url_for("index"))
    return render_template("profile.html", mode="complete", user=None, email="")


@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    if g.is_admin:
        flash("У администратора нет профиля игрока.", "info")
        return redirect(url_for("index"))
    user = g.me
    if request.method == "POST":
        fields, errors = read_profile_form()
        for msg in errors:
            flash(msg, "error")
        if not errors:
            new_photo = upload_image(request.files.get("photo"))
            payload = dict(fields)
            if new_photo:
                payload["photo"] = new_photo
            try:
                rows = supa.rest("PATCH", "profiles", g.token,
                                 params={"id": f"eq.{user['id']}"}, json=payload)
            except (SupaError, NetworkError):
                supa.remove_object(g.token, new_photo)
                raise
            if not rows:
                flash("Не удалось сохранить профиль.", "error")
            else:
                if new_photo:
                    supa.remove_object(g.token, user.get("photo"))
                flash("Профиль обновлён.", "success")
            return redirect(url_for("profile"))
    return render_template("profile.html", mode="edit", user=user, email=user["email"])


@app.post("/profile/password")
@login_required
def change_password():
    pw = request.form.get("password", "")
    if len(pw) < 6:
        flash("Пароль — минимум 6 символов.", "error")
    else:
        supa.update_password(g.token, pw)
        flash("Пароль изменён.", "success")
    return redirect(url_for("profile"))


@app.route("/logout")
def logout():
    token = session.get("at")
    if token:
        try:
            supa.sign_out(token)
        except (SupaError, NetworkError):
            pass
    session.clear()
    return redirect(url_for("login"))


# ---------- мероприятия ----------
@app.route("/")
@login_required
def index():
    events = supa.rest("GET", "events", g.token, {"select": "*", "order": "event_date.asc"})
    stats = {r["event_id"]: r["cnt"] for r in
             supa.rest("GET", "event_stats", g.token, {"select": "*"})}
    joined = set()
    if not g.is_admin:
        joined = {r["event_id"] for r in supa.rest(
            "GET", "registrations", g.token,
            {"select": "event_id", "user_id": f"eq.{session['uid']}"})}
    now = datetime.now(timezone.utc)
    for e in events:
        e["cnt"] = stats.get(e["id"], 0)
    upcoming = [e for e in events if parse_ts(e["event_date"]) >= now]
    past = [e for e in events if parse_ts(e["event_date"]) < now][::-1]
    return render_template("index.html", upcoming=upcoming, past_events=past, joined=joined)


def read_event_form():
    title = request.form.get("title", "").strip()
    date = request.form.get("event_date", "").strip()
    errors, iso = [], None
    if not title:
        errors.append("Введите название мероприятия.")
    try:
        iso = from_local_input(date)
    except ValueError:
        errors.append("Укажите дату и время.")
    mp = request.form.get("max_players", "").strip()
    return {
        "title": title,
        "event_date": iso,
        "max_players": int(mp) if mp.isdigit() and int(mp) > 0 else None,
        "description": request.form.get("description", "").strip() or None,
        "location": request.form.get("location", "").strip() or None,
        "status": "cancelled" if request.form.get("cancelled") else "open",
    }, errors


def get_event(event_id):
    rows = supa.rest("GET", "events", g.token, {"id": f"eq.{event_id}", "select": "*", "limit": 1})
    if not rows:
        abort(404)
    return rows[0]


@app.route("/event/new", methods=["GET", "POST"])
@admin_required
def event_new():
    if request.method == "POST":
        data, errors = read_event_form()
        for msg in errors:
            flash(msg, "error")
        if not errors:
            data["photo"] = upload_image(request.files.get("photo"))
            try:
                supa.rest("POST", "events", g.token, json=data)
            except (SupaError, NetworkError):
                supa.remove_object(g.token, data["photo"])
                raise
            flash("Мероприятие создано.", "success")
            return redirect(url_for("index"))
    return render_template("event_form.html", event=None, date_value="")


@app.route("/event/<int:event_id>/edit", methods=["GET", "POST"])
@admin_required
def event_edit(event_id):
    event = get_event(event_id)
    if request.method == "POST":
        data, errors = read_event_form()
        for msg in errors:
            flash(msg, "error")
        if not errors:
            new_photo = upload_image(request.files.get("photo"))
            if new_photo:
                data["photo"] = new_photo
            try:
                rows = supa.rest("PATCH", "events", g.token,
                                 params={"id": f"eq.{event_id}"}, json=data)
            except (SupaError, NetworkError):
                supa.remove_object(g.token, new_photo)
                raise
            if not rows:
                flash("Не удалось сохранить изменения.", "error")
            else:
                if new_photo:
                    supa.remove_object(g.token, event.get("photo"))
                flash("Изменения сохранены.", "success")
                return redirect(url_for("index"))
    return render_template("event_form.html", event=event,
                           date_value=to_local_input(event["event_date"]))


@app.post("/event/<int:event_id>/delete")
@admin_required
def event_delete(event_id):
    event = get_event(event_id)
    rows = supa.rest("DELETE", "events", g.token, params={"id": f"eq.{event_id}"})
    if rows:
        supa.remove_object(g.token, event.get("photo"))
        flash("Мероприятие удалено.", "info")
    return redirect(url_for("index"))


@app.post("/event/<int:event_id>/join")
@login_required
def event_join(event_id):
    if g.is_admin:
        flash("Администратор не записывается на игры.", "info")
        return redirect(url_for("index"))
    uid = session["uid"]
    already = supa.rest("GET", "registrations", g.token,
                        {"event_id": f"eq.{event_id}", "user_id": f"eq.{uid}", "select": "id"})
    if already:                                       # повторный запрос не создаёт дубль
        flash("Вы уже записаны на это мероприятие.", "info")
        return redirect(request.referrer or url_for("index"))
    event = get_event(event_id)
    try:
        supa.rest("POST", "registrations", g.token, json={"event_id": event_id, "user_id": uid})
    except SupaError as e:
        if e.code == "23505":                         # гонка двух одинаковых запросов
            flash("Вы уже записаны на это мероприятие.", "info")
            return redirect(request.referrer or url_for("index"))
        raise
    flash(f"Вы записаны на «{event['title']}».", "success")
    return redirect(request.referrer or url_for("index"))


@app.post("/event/<int:event_id>/leave")
@login_required
def event_leave(event_id):
    if not g.is_admin:
        supa.rest("DELETE", "registrations", g.token,
                  params={"event_id": f"eq.{event_id}", "user_id": f"eq.{session['uid']}"})
        flash("Запись отменена.", "info")
    return redirect(request.referrer or url_for("index"))


@app.post("/event/<int:event_id>/kick/<uuid:user_id>")
@admin_required
def event_kick(event_id, user_id):
    supa.rest("DELETE", "registrations", g.token,
              params={"event_id": f"eq.{event_id}", "user_id": f"eq.{user_id}"})
    flash("Игрок убран из списка.", "info")
    return redirect(url_for("team", event_id=event_id))


# ---------- статус команды ----------
@app.route("/team")
@login_required
def team():
    now_iso = datetime.now(timezone.utc).isoformat()
    events = supa.rest("GET", "events", g.token, {
        "select": "*", "event_date": f"gte.{now_iso}", "order": "event_date.asc"})
    selected = request.args.get("event_id", type=int)
    event = next((e for e in events if e["id"] == selected), events[0] if events else None)
    players = []
    if event:
        regs = supa.rest("GET", "registrations", g.token, {
            "select": "user_id,created_at", "event_id": f"eq.{event['id']}",
            "order": "created_at.asc"})
        if regs:
            ids = ",".join(r["user_id"] for r in regs)
            # админ видит полные профили (телефон, почта), игроки — только публичную часть
            table = "profiles" if g.is_admin else "public_profiles"
            people = {p["id"]: p for p in supa.rest(
                "GET", table, g.token, {"select": "*", "id": f"in.({ids})"})}
            for r in regs:
                p = people.get(r["user_id"])
                if p:
                    players.append({**p, "joined_at": r["created_at"]})
    return render_template("team.html", events=events, event=event, players=players)


# ---------- галерея ----------
@app.route("/gallery")
@login_required
def gallery():
    albums = supa.rest("GET", "albums", g.token, {"select": "*", "order": "id.desc"})
    stats = {r["album_id"]: r for r in supa.rest("GET", "album_stats", g.token, {"select": "*"})}
    for a in albums:
        s = stats.get(a["id"], {})
        a["cnt"], a["cover"] = s.get("cnt", 0), s.get("cover")
    return render_template("gallery.html", albums=albums)


@app.post("/gallery/album/new")
@admin_required
def album_new():
    title = request.form.get("title", "").strip()
    if title:
        supa.rest("POST", "albums", g.token, json={"title": title})
        flash("Альбом создан.", "success")
    else:
        flash("Введите название альбома.", "error")
    return redirect(url_for("gallery"))


def get_album(album_id):
    rows = supa.rest("GET", "albums", g.token, {"id": f"eq.{album_id}", "select": "*", "limit": 1})
    if not rows:
        abort(404)
    return rows[0]


@app.route("/gallery/album/<int:album_id>")
@login_required
def album(album_id):
    alb = get_album(album_id)
    photos = supa.rest("GET", "photos", g.token,
                       {"album_id": f"eq.{album_id}", "select": "*", "order": "id.desc"})
    ids = {p["user_id"] for p in photos if p["user_id"]}
    names = {}
    if ids:
        names = {p["id"]: p["full_name"] for p in supa.rest(
            "GET", "public_profiles", g.token,
            {"select": "id,full_name", "id": f"in.({','.join(ids)})"})}
    for p in photos:
        p["full_name"] = names.get(p["user_id"])
    return render_template("album.html", album=alb, photos=photos)


@app.post("/gallery/album/<int:album_id>/upload")
@login_required
def photo_upload(album_id):
    get_album(album_id)
    paths, bad = [], False
    try:
        for f in request.files.getlist("photos"):
            if not f or not f.filename:
                continue
            p = upload_image(f)
            if p:
                paths.append(p)
            else:
                bad = True
        if paths:
            supa.rest("POST", "photos", g.token, json=[
                {"album_id": album_id, "user_id": session["uid"], "path": p} for p in paths])
    except (SupaError, NetworkError):
        for p in paths:
            supa.remove_object(g.token, p)
        raise
    if paths:
        flash(f"Загружено фото: {len(paths)}.", "success")
    elif not bad:
        flash("Выберите файл для загрузки.", "error")
    return redirect(url_for("album", album_id=album_id))


@app.post("/gallery/photo/<int:photo_id>/delete")
@login_required
def photo_delete(photo_id):
    rows = supa.rest("GET", "photos", g.token, {"id": f"eq.{photo_id}", "select": "*", "limit": 1})
    if not rows:
        abort(404)
    ph = rows[0]
    if not g.is_admin and ph["user_id"] != session["uid"]:
        abort(403)
    if supa.rest("DELETE", "photos", g.token, params={"id": f"eq.{photo_id}"}):
        supa.remove_object(g.token, ph["path"])
    return redirect(url_for("album", album_id=ph["album_id"]))


@app.post("/gallery/album/<int:album_id>/delete")
@admin_required
def album_delete(album_id):
    photos = supa.rest("GET", "photos", g.token, {"album_id": f"eq.{album_id}", "select": "path"})
    if supa.rest("DELETE", "albums", g.token, params={"id": f"eq.{album_id}"}):
        for p in photos:
            supa.remove_object(g.token, p["path"])
        flash("Альбом удалён.", "info")
    return redirect(url_for("gallery"))


if __name__ == "__main__":
    # host="0.0.0.0" — чтобы заходить с телефонов в той же Wi-Fi сети
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
