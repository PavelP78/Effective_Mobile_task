import sqlite3
import tempfile
import unittest
from pathlib import Path

import app as app_module


class AdminAccessTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "admin_test.db")
        app_module.DB_PATH = self.db_path
        with app_module.app.app_context():
            app_module.init_db()
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_admin_can_access_admin_resource(self):
        register_resp = self.client.post(
            "/register",
            json={
                "first_name": "Admin",
                "last_name": "User",
                "middle_name": "Root",
                "email": "admin@example.com",
                "password": "Admin1234",
                "password_repeat": "Admin1234",
            },
        )
        self.assertEqual(register_resp.status_code, 201)
        user_id = register_resp.get_json()["user_id"]

        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        admin_role = conn.execute("SELECT id FROM roles WHERE name = 'admin'").fetchone()
        conn.execute(
            "INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES (?, ?)",
            (user_id, admin_role["id"]),
        )
        conn.commit()
        conn.close()

        login_resp = self.client.post(
            "/login",
            json={"email": "admin@example.com", "password": "Admin1234"},
        )
        self.assertEqual(login_resp.status_code, 200)
        token = login_resp.get_json()["access_token"]

        admin_resource_resp = self.client.get(
            "/resource/users-admin",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(admin_resource_resp.status_code, 200)


if __name__ == "__main__":
    unittest.main()
