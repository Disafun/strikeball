"""Тонкий клиент Supabase поверх REST (GoTrue + PostgREST + Storage).

Все запросы идут с токеном ВОШЕДШЕГО пользователя и публичным (anon/publishable)
ключом, поэтому правила RLS из базы действуют на каждый запрос. Секретного
service_role-ключа в приложении нет.
"""
import os

import requests

TIMEOUT = 15
BUCKET = "photos"


class NetworkError(Exception):
    """Нет связи с Supabase (таймаут, DNS, обрыв)."""


class SupaError(Exception):
    """Supabase ответил ошибкой."""

    def __init__(self, status, message, code=None):
        super().__init__(message)
        self.status = status
        self.message = message or ""
        self.code = code or ""


def base_url():
    return os.environ.get("SUPABASE_URL", "").strip().rstrip("/")


def anon_key():
    return os.environ.get("SUPABASE_ANON_KEY", "").strip()


def configured():
    url = base_url()
    return url.startswith("http") and bool(anon_key()) and "YOUR-PROJECT" not in url


def _headers(token=None, extra=None):
    h = {"apikey": anon_key(), "Authorization": f"Bearer {token or anon_key()}"}
    if extra:
        h.update(extra)
    return h


def _call(method, url, **kw):
    try:
        r = requests.request(method, url, timeout=TIMEOUT, **kw)
    except requests.RequestException as e:
        raise NetworkError(str(e)) from e
    if r.status_code >= 400:
        try:
            body = r.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        msg = body.get("message") or body.get("msg") or body.get("error_description") \
            or body.get("error") or r.text[:200]
        code = body.get("code") or body.get("error_code") or ""
        raise SupaError(r.status_code, str(msg), str(code))
    if r.status_code == 204 or not r.content:
        return None
    try:
        return r.json()
    except ValueError:
        return None


# ---------- Auth (GoTrue) ----------
def sign_up(email, password):
    return _call("POST", f"{base_url()}/auth/v1/signup", headers=_headers(),
                 json={"email": email, "password": password})


def sign_in(email, password):
    return _call("POST", f"{base_url()}/auth/v1/token", headers=_headers(),
                 params={"grant_type": "password"},
                 json={"email": email, "password": password})


def refresh(refresh_token):
    return _call("POST", f"{base_url()}/auth/v1/token", headers=_headers(),
                 params={"grant_type": "refresh_token"},
                 json={"refresh_token": refresh_token})


def update_password(token, new_password):
    return _call("PUT", f"{base_url()}/auth/v1/user", headers=_headers(token),
                 json={"password": new_password})


def sign_out(token):
    return _call("POST", f"{base_url()}/auth/v1/logout", headers=_headers(token))


# ---------- База данных (PostgREST) ----------
def rest(method, table, token, params=None, json=None):
    """GET/POST/PATCH/DELETE по таблице или представлению. Возвращает список строк."""
    extra = {}
    if method in ("POST", "PATCH", "DELETE"):
        extra["Prefer"] = "return=representation"
    return _call(method, f"{base_url()}/rest/v1/{table}",
                 headers=_headers(token, extra), params=params, json=json)


# ---------- Storage ----------
def upload(token, path, data, mime):
    _call("POST", f"{base_url()}/storage/v1/object/{BUCKET}/{path}",
          headers=_headers(token, {"Content-Type": mime, "x-upsert": "false"}), data=data)


def remove_object(token, path):
    """Удаление файла; ошибки не критичны (файл мог быть удалён ранее)."""
    if not path:
        return
    try:
        _call("DELETE", f"{base_url()}/storage/v1/object/{BUCKET}/{path}",
              headers=_headers(token))
    except (SupaError, NetworkError):
        pass


def public_url(path):
    return f"{base_url()}/storage/v1/object/public/{BUCKET}/{path}" if path else ""
