import os
import tempfile
import unittest
from pathlib import Path

import app as app_module


class AuthApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "test.db")
        app_module.DB_PATH = self.db_path
        with app_module.app.app_context():
            app_module.init_db()
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def register_user(self, email="user@example.com", password="Pass1234"):
        return self.client.post(
            "/register",
            json={
                "first_name": "Ivan",
                "last_name": "Petrov",
                "middle_name": "Ivanovich",
                "email": email,
                "password": password,
                "password_repeat": password,
            },
        )

    def login_user(self, email="user@example.com", password="Pass1234"):
        return self.client.post(
            "/login",
            json={"email": email, "password": password},
        )

    def test_register_login_and_get_profile(self):
        register_resp = self.register_user()
        self.assertEqual(register_resp.status_code, 201)

        login_resp = self.login_user()
        self.assertEqual(login_resp.status_code, 200)
        token = login_resp.get_json()["access_token"]

        me_resp = self.client.get(
            "/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(me_resp.status_code, 200)
        self.assertEqual(me_resp.get_json()["email"], "user@example.com")

    def test_logout_revokes_token(self):
        self.register_user()
        login_resp = self.login_user()
        token = login_resp.get_json()["access_token"]

        logout_resp = self.client.post(
            "/logout",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(logout_resp.status_code, 200)

        me_resp = self.client.get(
            "/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(me_resp.status_code, 401)

    def test_soft_delete_blocks_next_login(self):
        self.register_user()
        login_resp = self.login_user()
        token = login_resp.get_json()["access_token"]

        delete_resp = self.client.delete(
            "/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(delete_resp.status_code, 200)

        relogin_resp = self.login_user()
        self.assertEqual(relogin_resp.status_code, 401)

    def test_forbidden_and_granted_resources(self):
        self.register_user()
        login_resp = self.login_user()
        token = login_resp.get_json()["access_token"]

        reports_resp = self.client.get(
            "/resource/reports",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(reports_resp.status_code, 200)

        admin_resource_resp = self.client.get(
            "/resource/users-admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(admin_resource_resp.status_code, 403)

    def test_validation_rules_for_registration(self):
        bad_resp = self.client.post(
            "/register",
            json={
                "first_name": "I",
                "last_name": "Petrov",
                "middle_name": "Ivanovich",
                "email": "not-an-email",
                "password": "12345678",
                "password_repeat": "12345678",
            },
        )
        self.assertEqual(bad_resp.status_code, 400)


if __name__ == "__main__":
    unittest.main()
