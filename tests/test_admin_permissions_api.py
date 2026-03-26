import sqlite3
import tempfile
import unittest
from pathlib import Path

import app as app_module


class AdminPermissionsApiTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "admin_permissions_test.db")
        app_module.DB_PATH = self.db_path
        with app_module.app.app_context():
            app_module.init_db()
        self.client = app_module.app.test_client()

    def tearDown(self):
        self.temp_dir.cleanup()

    def _register(self, email: str, password: str = "Pass1234"):
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

    def _login(self, email: str, password: str = "Pass1234"):
        resp = self.client.post("/login", json={"email": email, "password": password})
        self.assertEqual(resp.status_code, 200)
        return resp.get_json()["access_token"]

    def _promote_to_admin(self, user_id: int):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        admin_role = conn.execute("SELECT id FROM roles WHERE name = 'admin'").fetchone()
        conn.execute(
            "INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES (?, ?)",
            (user_id, admin_role["id"]),
        )
        conn.commit()
        conn.close()

    def test_non_admin_cannot_use_admin_endpoints(self):
        self._register("user@example.com")
        token = self._login("user@example.com")

        resp = self.client.get(
            "/admin/roles",
            headers={"Authorization": f"Bearer {token}"},
        )
        self.assertEqual(resp.status_code, 403)

    def test_admin_can_read_and_update_role_permissions(self):
        reg = self._register("admin@example.com")
        admin_user_id = reg.get_json()["user_id"]
        self._promote_to_admin(admin_user_id)
        admin_token = self._login("admin@example.com")

        list_resp = self.client.get(
            "/admin/roles",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(list_resp.status_code, 200)

        get_perms_resp = self.client.get(
            "/admin/roles/user/permissions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(get_perms_resp.status_code, 200)
        self.assertIn("profile.read", get_perms_resp.get_json()["permissions"])

        update_resp = self.client.patch(
            "/admin/roles/user/permissions",
            json={"permissions": ["profile.read"]},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(update_resp.status_code, 200)
        self.assertEqual(update_resp.get_json()["permissions"], ["profile.read"])

        get_updated_resp = self.client.get(
            "/admin/roles/user/permissions",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(get_updated_resp.status_code, 200)
        self.assertEqual(get_updated_resp.get_json()["permissions"], ["profile.read"])

    def test_admin_can_assign_user_roles(self):
        admin_reg = self._register("admin2@example.com")
        admin_user_id = admin_reg.get_json()["user_id"]
        self._promote_to_admin(admin_user_id)
        admin_token = self._login("admin2@example.com")

        user_reg = self._register("target@example.com")
        target_user_id = user_reg.get_json()["user_id"]

        assign_resp = self.client.post(
            f"/admin/users/{target_user_id}/roles",
            json={"roles": ["admin", "user"]},
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(assign_resp.status_code, 200)

        get_roles_resp = self.client.get(
            f"/admin/users/{target_user_id}/roles",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        self.assertEqual(get_roles_resp.status_code, 200)
        self.assertEqual(get_roles_resp.get_json()["roles"], ["admin", "user"])


if __name__ == "__main__":
    unittest.main()
