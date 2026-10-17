"""Тесты приложения на эмуляторе Supabase (см. fake_supabase.py).
Запуск из корня проекта:  python -m unittest discover -s tests -v
"""
import io
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fake_supabase import FakeSupabase  # noqa: E402

os.environ.update(SUPABASE_URL=FakeSupabase.BASE, SUPABASE_ANON_KEY=FakeSupabase.ANON,
                  SECRET_KEY="test-secret", ADMIN_PASSWORD="5376",
                  ADMIN_ACCOUNT_EMAIL="admin@club.test", ADMIN_ACCOUNT_PASSWORD="long-admin-pass-1")
import app as A  # noqa: E402
import supa  # noqa: E402

PNG = b"\x89PNG\r\n\x1a\n" + b"0" * 32
FUT = "2030-05-01T10:00"


class Base(unittest.TestCase):
    def setUp(self):
        self.cloud = FakeSupabase()
        self.cloud.add_user("admin@club.test", "long-admin-pass-1", role="admin")
        p = mock.patch("requests.request", self.cloud.request)
        p.start()
        self.addCleanup(p.stop)
        A._admin_fails.clear()
        A.app.config["TESTING"] = True

    def client(self):
        return A.app.test_client()

    def register(self, c, email, name="Иванов Иван", phone="+7 700 123 45 67", photo=True):
        data = {"email": email, "password": "secret1", "full_name": name, "age": "25", "phone": phone}
        if photo:
            data["photo"] = (io.BytesIO(PNG), "me.png")
        return c.post("/register", data=data, content_type="multipart/form-data")

    def admin(self):
        c = self.client()
        r = c.post("/login/admin", data={"password": "5376"})
        self.assertEqual(r.status_code, 302)
        return c

    def make_event(self, admin, title="Игра", max_players="", date=FUT):
        data = {"title": title, "event_date": date, "location": "Лес", "description": "Описание",
                "max_players": max_players, "photo": (io.BytesIO(PNG), "e.png")}
        r = admin.post("/event/new", data=data, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        return self.cloud.t["events"][-1]["id"]


class TestAuthProfile(Base):
    def test_unconfigured_shows_setup_page(self):
        with mock.patch.dict(os.environ, {"SUPABASE_URL": ""}):
            r = self.client().get("/login")
        self.assertEqual(r.status_code, 503)
        self.assertIn("не настроено".encode(), r.data)

    def test_register_creates_cloud_profile_and_photo(self):
        c = self.client()
        r = self.register(c, "a@x.com")
        self.assertEqual(r.status_code, 302)
        prof = [p for p in self.cloud.t["profiles"] if p["email"] == "a@x.com"][0]
        self.assertEqual(prof["role"], "player")
        self.assertTrue(prof["photo"].startswith(prof["id"] + "/"))
        self.assertIn(prof["photo"], self.cloud.storage)
        self.assertEqual(c.get("/").status_code, 200)

    def test_login_from_other_device_and_after_logout(self):
        c1 = self.client()
        self.register(c1, "a@x.com")
        c1.get("/logout")
        self.assertEqual(c1.get("/").status_code, 302)        # вышли
        c2 = self.client()                                      # "другое устройство"
        r = c2.post("/login/user", data={"email": "a@x.com", "password": "secret1"})
        self.assertTrue(r.location.endswith("/"))
        self.assertIn("Иванов Иван".encode(), c2.get("/profile").data)

    def test_wrong_password_and_duplicate_email(self):
        c = self.client()
        self.register(c, "a@x.com")
        r = self.client().post("/login/user", data={"email": "a@x.com", "password": "bad"}, follow_redirects=True)
        self.assertIn("Неверная почта или пароль".encode(), r.data)
        r = self.register(self.client(), "a@x.com")
        self.assertIn("уже зарегистрирована".encode(), r.data)

    def test_profile_edit_persists_and_password_change(self):
        c = self.client()
        self.register(c, "a@x.com")
        r = c.post("/profile", data={"full_name": "Петров Пётр", "age": "30", "phone": "+7 701 000 00 00"},
                   content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        self.assertEqual([p for p in self.cloud.t["profiles"] if p["email"] == "a@x.com"][0]["full_name"], "Петров Пётр")
        c.post("/profile/password", data={"password": "newpass1"})
        c2 = self.client()
        r = c2.post("/login/user", data={"email": "a@x.com", "password": "newpass1"})
        self.assertTrue(r.location.endswith("/"))

    def test_email_confirmation_flow_asks_profile_after_login(self):
        self.cloud.confirm_email = True
        c = self.client()
        r = self.register(c, "b@x.com")
        self.assertTrue(r.location.endswith("/login"))
        self.assertEqual([p for p in self.cloud.t["profiles"] if p["email"] == "b@x.com"], [])
        r = c.post("/login/user", data={"email": "b@x.com", "password": "secret1"})
        self.assertTrue(r.location.endswith("/profile/complete"))
        self.assertEqual(c.get("/").location.endswith("/profile/complete"), True)
        r = c.post("/profile/complete", data={"full_name": "Сидоров Сидор", "age": "22", "phone": "+7 702 111 22 33"},
                   content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(c.get("/").status_code, 200)

    def test_admin_login_wrong_password_and_throttle(self):
        for _ in range(5):
            r = self.client().post("/login/admin", data={"password": "0000"}, follow_redirects=True)
            self.assertIn("Неверный пароль".encode(), r.data)
        r = self.client().post("/login/admin", data={"password": "5376"}, follow_redirects=True)
        self.assertIn("Слишком много".encode(), r.data)

    def test_admin_account_without_admin_role_is_rejected(self):
        self.cloud.t["profiles"][0]["role"] = "player"
        r = self.client().post("/login/admin", data={"password": "5376"}, follow_redirects=True)
        self.assertIn("не имеет роли admin".encode(), r.data)

    def test_token_refresh(self):
        c = self.client()
        self.register(c, "a@x.com")
        with c.session_transaction() as s:
            s["exp"] = time.time() - 10
            old = s["at"]
        self.assertEqual(c.get("/").status_code, 200)
        with c.session_transaction() as s:
            self.assertNotEqual(s["at"], old)


class TestEventsRegistration(Base):
    def test_admin_creates_event_visible_to_player_and_edit(self):
        adm, pl = self.admin(), self.client()
        self.register(pl, "a@x.com")
        eid = self.make_event(adm, "Операция «Лес»")
        self.assertIn("Операция «Лес»".encode(), pl.get("/").data)
        self.assertIn("01.05.2030 10:00".encode(), pl.get("/").data)       # время показывается в APP_TZ
        self.assertTrue(self.cloud.t["events"][0]["event_date"].startswith("2030-05-01T05:00"))   # в БД хранится UTC
        r = adm.post(f"/event/{eid}/edit", data={"title": "Новое имя", "event_date": FUT}, content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        self.assertIn("Новое имя".encode(), pl.get("/").data)
        self.assertIn(FUT.encode(), adm.get(f"/event/{eid}/edit").data)

    def test_join_visible_to_admin_duplicate_and_leave(self):
        adm, pl = self.admin(), self.client()
        self.register(pl, "a@x.com", phone="+7 700 555 66 77")
        eid = self.make_event(adm)
        pl.post(f"/event/{eid}/join")
        pl.post(f"/event/{eid}/join")                                       # повтор: дубля нет
        self.assertEqual(len(self.cloud.t["registrations"]), 1)
        team = adm.get("/team").data.decode()
        self.assertIn("Иванов Иван", team)
        self.assertIn("+7 700 555 66 77", team)                             # админ видит телефон
        self.assertIn("a@x.com", team)
        pl.post(f"/event/{eid}/leave")
        self.assertEqual(self.cloud.t["registrations"], [])

    def test_player_sees_roster_without_contacts(self):
        adm, p1, p2 = self.admin(), self.client(), self.client()
        self.register(p1, "a@x.com", phone="+7 700 555 66 77")
        self.register(p2, "b@x.com", name="Петров Пётр", phone="+7 701 999 88 77")
        eid = self.make_event(adm)
        p1.post(f"/event/{eid}/join")
        t = p2.get("/team").data.decode()
        self.assertIn("Иванов Иван", t)
        self.assertNotIn("+7 700 555 66 77", t)
        self.assertNotIn("a@x.com", t)

    def test_capacity_enforced_by_backend_and_message(self):
        adm, p1, p2 = self.admin(), self.client(), self.client()
        self.register(p1, "a@x.com")
        self.register(p2, "b@x.com", name="Петров Пётр")
        eid = self.make_event(adm, max_players="1")
        p1.post(f"/event/{eid}/join")
        r = p2.post(f"/event/{eid}/join", follow_redirects=True)
        self.assertIn("Все места заняты".encode(), r.data)
        self.assertEqual(len(self.cloud.t["registrations"]), 1)

    def test_past_and_cancelled_events_closed(self):
        adm, pl = self.admin(), self.client()
        self.register(pl, "a@x.com")
        past = self.make_event(adm, "Старая", date="2020-01-01T10:00")
        r = pl.post(f"/event/{past}/join", follow_redirects=True)
        self.assertIn("уже прошло".encode(), r.data)
        eid = self.make_event(adm, "Отмена")
        adm.post(f"/event/{eid}/edit", data={"title": "Отмена", "event_date": FUT, "cancelled": "1"},
                 content_type="multipart/form-data")
        r = pl.post(f"/event/{eid}/join", follow_redirects=True)
        self.assertIn("закрыта".encode(), r.data)

    def test_admin_removes_player_and_deletes_event(self):
        adm, pl = self.admin(), self.client()
        self.register(pl, "a@x.com")
        eid = self.make_event(adm)
        pl.post(f"/event/{eid}/join")
        uid = self.cloud.t["registrations"][0]["user_id"]
        adm.post(f"/event/{eid}/kick/{uid}")
        self.assertEqual(self.cloud.t["registrations"], [])
        adm.post(f"/event/{eid}/delete")
        self.assertEqual(self.cloud.t["events"], [])


class TestSecurity(Base):
    def test_player_cannot_use_admin_routes(self):
        adm, pl = self.admin(), self.client()
        self.register(pl, "a@x.com")
        eid = self.make_event(adm)
        self.assertEqual(pl.get("/event/new").status_code, 403)
        self.assertEqual(pl.post("/event/new", data={"title": "x", "event_date": FUT}).status_code, 403)
        self.assertEqual(pl.post(f"/event/{eid}/delete").status_code, 403)
        self.assertEqual(pl.post("/gallery/album/new", data={"title": "x"}).status_code, 403)
        self.assertEqual(len(self.cloud.t["events"]), 1)

    def test_forged_requests_are_rejected_by_database_rules(self):
        """Клиентский код обходится: запросы идут напрямую в API с токеном игрока."""
        pl = self.client()
        self.register(pl, "a@x.com")
        with pl.session_transaction() as s:
            tok, uid = s["at"], s["uid"]
        other = self.cloud.add_user("c@x.com", "secret1", role="player", profile="Другой Игрок")
        eid = self.make_event(self.admin())
        with self.assertRaises(supa.SupaError):                              # стать админом
            supa.rest("PATCH", "profiles", tok, {"id": f"eq.{uid}"}, {"role": "admin"})
        with self.assertRaises(supa.SupaError):                              # создать профиль-админа
            supa.rest("POST", "profiles", tok, json={"id": other, "full_name": "A B C", "age": 20, "phone": "12345678901"})
        with self.assertRaises(supa.SupaError):                              # заявка от чужого имени
            supa.rest("POST", "registrations", tok, json={"event_id": eid, "user_id": other})
        with self.assertRaises(supa.SupaError):                              # создать мероприятие
            supa.rest("POST", "events", tok, json={"title": "x", "event_date": "2031-01-01T00:00:00+00:00"})
        self.assertEqual(supa.rest("PATCH", "events", tok, {"id": f"eq.{eid}"}, {"title": "hack"}), [])
        self.assertEqual(self.cloud.t["events"][0]["title"], "Игра")
        with self.assertRaises(supa.SupaError):                              # загрузка в чужую папку Storage
            supa.upload(tok, f"{other}/x.png", PNG, "image/png")
        self.assertEqual([p["id"] for p in supa.rest("GET", "profiles", tok, {"select": "*"})], [uid])

    def test_no_session_is_rejected(self):
        r = self.client().get("/")
        self.assertTrue(r.location.endswith("/login"))
        with self.assertRaises(supa.SupaError):
            supa.rest("GET", "events", None)

    def test_service_role_not_used(self):
        self.register(self.client(), "a@x.com")
        with open(A.__file__, encoding="utf-8") as f:
            self.assertNotIn("service_role", f.read().lower())


class TestErrors(Base):
    def test_network_down_does_not_pretend_success(self):
        adm, pl = self.admin(), self.client()
        self.register(pl, "a@x.com")
        eid = self.make_event(adm)
        self.cloud.down = True
        r = pl.post(f"/event/{eid}/join", follow_redirects=True)
        self.assertIn("Нет связи".encode(), r.data)
        self.assertNotIn("Вы записаны".encode(), r.data)
        self.cloud.down = False
        self.assertEqual(self.cloud.t["registrations"], [])
        pl.post(f"/event/{eid}/join")                                       # после восстановления связи работает
        self.assertEqual(len(self.cloud.t["registrations"]), 1)

    def test_network_down_on_page_load(self):
        pl = self.client()
        self.register(pl, "a@x.com")
        self.cloud.down = True
        r = pl.get("/")
        self.assertEqual(r.status_code, 503)
        self.assertIn("Нет связи".encode(), r.data)


class TestGallery(Base):
    def test_album_upload_and_permissions(self):
        adm, p1, p2 = self.admin(), self.client(), self.client()
        self.register(p1, "a@x.com")
        self.register(p2, "b@x.com", name="Петров Пётр")
        adm.post("/gallery/album/new", data={"title": "Игра 1"})
        self.assertIn("Игра 1".encode(), p1.get("/gallery").data)
        r = p1.post("/gallery/album/1/upload", data={"photos": [(io.BytesIO(PNG), "1.png"), (io.BytesIO(PNG), "2.png")]},
                    content_type="multipart/form-data")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(len(self.cloud.t["photos"]), 2)
        self.assertIn("Иванов Иван".encode(), p2.get("/gallery/album/1").data)
        pid = self.cloud.t["photos"][0]["id"]
        self.assertEqual(p2.post(f"/gallery/photo/{pid}/delete").status_code, 403)
        p1.post(f"/gallery/photo/{pid}/delete")
        self.assertEqual(len(self.cloud.t["photos"]), 1)
        adm.post(f"/gallery/photo/{self.cloud.t['photos'][0]['id']}/delete")
        self.assertEqual(self.cloud.t["photos"], [])
        adm.post("/gallery/album/1/delete")
        self.assertEqual(self.cloud.t["albums"], [])

    def test_non_image_rejected(self):
        adm, pl = self.admin(), self.client()
        self.register(pl, "a@x.com")
        adm.post("/gallery/album/new", data={"title": "A"})
        r = pl.post("/gallery/album/1/upload", data={"photos": (io.BytesIO(b"<script>alert(1)</script>"), "x.png")},
                    content_type="multipart/form-data", follow_redirects=True)
        self.assertIn("Допустимы только изображения".encode(), r.data)
        self.assertEqual(self.cloud.t["photos"], [])


if __name__ == "__main__":
    unittest.main()
