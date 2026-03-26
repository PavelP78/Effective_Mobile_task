import os
import re
import sqlite3
import uuid
from datetime import UTC, datetime, timedelta
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash


DB_PATH = os.getenv("DB_PATH", "app.db")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")
JWT_ALGORITHM = "HS256"
JWT_EXPIRES_HOURS = int(os.getenv("JWT_EXPIRES_HOURS", "8"))
DEV_ADMIN_KEY = os.getenv("DEV_ADMIN_KEY", "dev-admin-key")
ENABLE_DEV_ENDPOINTS = os.getenv("ENABLE_DEV_ENDPOINTS", "1") == "1"
NAME_MIN_LEN = 2
NAME_MAX_LEN = 50
PASSWORD_MIN_LEN = 8
PASSWORD_MAX_LEN = 128
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


app = Flask(__name__)

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PATCH, DELETE, OPTIONS"
    return response


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def validate_name(value: str, field_name: str) -> str | None:
    if not isinstance(value, str):
        return f"{field_name} must be a string"
    cleaned = value.strip()
    if len(cleaned) < NAME_MIN_LEN or len(cleaned) > NAME_MAX_LEN:
        return f"{field_name} length must be between {NAME_MIN_LEN} and {NAME_MAX_LEN}"
    if not re.fullmatch(r"[A-Za-zА-Яа-яЁё -]+", cleaned):
        return f"{field_name} contains invalid characters"
    return None


def validate_email(email: str) -> str | None:
    if not isinstance(email, str):
        return "email must be a string"
    cleaned = email.strip().lower()
    if len(cleaned) > 254:
        return "email is too long"
    if not EMAIL_RE.fullmatch(cleaned):
        return "email format is invalid"
    return None


def validate_password(password: str) -> str | None:
    if not isinstance(password, str):
        return "password must be a string"
    if len(password) < PASSWORD_MIN_LEN or len(password) > PASSWORD_MAX_LEN:
        return f"password length must be between {PASSWORD_MIN_LEN} and {PASSWORD_MAX_LEN}"
    if not re.search(r"[A-Za-z]", password):
        return "password must contain at least one letter"
    if not re.search(r"\d", password):
        return "password must contain at least one digit"
    return None


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            first_name TEXT NOT NULL,
            last_name TEXT NOT NULL,
            middle_name TEXT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1,
            deleted_at TEXT DEFAULT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS roles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE
        );

        CREATE TABLE IF NOT EXISTS permissions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            description TEXT
        );

        CREATE TABLE IF NOT EXISTS role_permissions (
            role_id INTEGER NOT NULL,
            permission_id INTEGER NOT NULL,
            PRIMARY KEY(role_id, permission_id),
            FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
            FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS user_roles (
            user_id INTEGER NOT NULL,
            role_id INTEGER NOT NULL,
            PRIMARY KEY(user_id, role_id),
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS resources (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            required_permission TEXT NOT NULL,
            FOREIGN KEY(required_permission) REFERENCES permissions(code)
        );

        CREATE TABLE IF NOT EXISTS revoked_tokens (
            jti TEXT PRIMARY KEY,
            revoked_at TEXT NOT NULL
        );
        """
    )
    db.commit()
    seed_defaults(db)


def seed_defaults(db: sqlite3.Connection):
    roles = ["admin", "user"]
    permissions = [
        ("profile.read", "Read own profile"),
        ("profile.update", "Update own profile"),
        ("account.delete", "Soft-delete own account"),
        ("resource.reports.read", "Read reports resource"),
        ("admin.panel.access", "Access admin management API"),
    ]
    resources = [
        ("reports", "resource.reports.read"),
        ("users-admin", "admin.panel.access"),
    ]

    for role in roles:
        db.execute("INSERT OR IGNORE INTO roles(name) VALUES (?)", (role,))
    for code, description in permissions:
        db.execute(
            "INSERT OR IGNORE INTO permissions(code, description) VALUES (?, ?)",
            (code, description),
        )
    for resource_name, perm_code in resources:
        db.execute(
            """
            INSERT INTO resources(name, required_permission)
            VALUES (?, ?)
            ON CONFLICT(name) DO UPDATE SET required_permission = excluded.required_permission
            """,
            (resource_name, perm_code),
        )

    role_map = {
        row["name"]: row["id"] for row in db.execute("SELECT id, name FROM roles").fetchall()
    }
    perm_map = {
        row["code"]: row["id"]
        for row in db.execute("SELECT id, code FROM permissions").fetchall()
    }

    admin_perms = [code for code, _ in permissions]
    user_perms = ["profile.read", "profile.update", "account.delete", "resource.reports.read"]

    for code in admin_perms:
        db.execute(
            "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES (?, ?)",
            (role_map["admin"], perm_map[code]),
        )
    for code in user_perms:
        db.execute(
            "INSERT OR IGNORE INTO role_permissions(role_id, permission_id) VALUES (?, ?)",
            (role_map["user"], perm_map[code]),
        )
    db.commit()


def create_token(user_id: int, email: str) -> str:
    jti = str(uuid.uuid4())
    payload = {
        "sub": str(user_id),
        "email": email,
        "jti": jti,
        "iat": datetime.now(UTC),
        "exp": datetime.now(UTC) + timedelta(hours=JWT_EXPIRES_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def parse_bearer_token() -> str | None:
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    return auth_header.replace("Bearer ", "", 1).strip()


def is_token_revoked(jti: str) -> bool:
    db = get_db()
    row = db.execute("SELECT jti FROM revoked_tokens WHERE jti = ?", (jti,)).fetchone()
    return row is not None


def get_user_permissions(user_id: int) -> set[str]:
    db = get_db()
    rows = db.execute(
        """
        SELECT DISTINCT p.code
        FROM user_roles ur
        JOIN role_permissions rp ON rp.role_id = ur.role_id
        JOIN permissions p ON p.id = rp.permission_id
        WHERE ur.user_id = ?
        """,
        (user_id,),
    ).fetchall()
    return {row["code"] for row in rows}


def auth_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        token = parse_bearer_token()
        if not token:
            return jsonify({"error": "Unauthorized", "message": "Token is missing"}), 401
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        except jwt.PyJWTError:
            return jsonify({"error": "Unauthorized", "message": "Token is invalid"}), 401

        if is_token_revoked(payload["jti"]):
            return jsonify({"error": "Unauthorized", "message": "Token is revoked"}), 401

        db = get_db()
        user = db.execute(
            """
            SELECT id, first_name, last_name, middle_name, email, is_active
            FROM users WHERE id = ? AND deleted_at IS NULL
            """,
            (int(payload["sub"]),),
        ).fetchone()
        if user is None or user["is_active"] != 1:
            return jsonify({"error": "Unauthorized", "message": "User is inactive"}), 401

        g.current_user = user
        g.current_token_jti = payload["jti"]
        g.current_permissions = get_user_permissions(user["id"])
        return fn(*args, **kwargs)

    return wrapper


def permission_required(permission_code: str):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if permission_code not in g.current_permissions:
                return (
                    jsonify(
                        {
                            "error": "Forbidden",
                            "message": f"Permission '{permission_code}' is required",
                        }
                    ),
                    403,
                )
            return fn(*args, **kwargs)

        return wrapper

    return decorator


@app.post("/register")
def register():
    payload = request.get_json(silent=True) or {}
    required_fields = [
        "first_name",
        "last_name",
        "email",
        "password",
        "password_repeat",
    ]
    for field in required_fields:
        if not payload.get(field):
            return jsonify({"error": "ValidationError", "message": f"Missing {field}"}), 400
    first_name = payload["first_name"].strip()
    last_name = payload["last_name"].strip()
    middle_name_raw = (payload.get("middle_name") or "").strip()
    email = payload["email"].strip().lower()
    password = payload["password"]

    for field_name, field_value in (
        ("first_name", first_name),
        ("last_name", last_name),
    ):
        error = validate_name(field_value, field_name)
        if error:
            return jsonify({"error": "ValidationError", "message": error}), 400
    if middle_name_raw:
        middle_name_error = validate_name(middle_name_raw, "middle_name")
        if middle_name_error:
            return jsonify({"error": "ValidationError", "message": middle_name_error}), 400

    email_error = validate_email(email)
    if email_error:
        return jsonify({"error": "ValidationError", "message": email_error}), 400

    password_error = validate_password(password)
    if password_error:
        return jsonify({"error": "ValidationError", "message": password_error}), 400

    if payload["password"] != payload["password_repeat"]:
        return jsonify({"error": "ValidationError", "message": "Passwords do not match"}), 400

    db = get_db()
    existing = db.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,),
    ).fetchone()
    if existing:
        return jsonify({"error": "Conflict", "message": "Email already exists"}), 409

    created_at = now_iso()
    db.execute(
        """
        INSERT INTO users(first_name, last_name, middle_name, email, password_hash, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            first_name,
            last_name,
            middle_name_raw or None,
            email,
            generate_password_hash(password),
            created_at,
            created_at,
        ),
    )
    user_id = db.execute("SELECT last_insert_rowid() AS id").fetchone()["id"]
    user_role = db.execute("SELECT id FROM roles WHERE name = 'user'").fetchone()
    db.execute(
        "INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES (?, ?)",
        (user_id, user_role["id"]),
    )
    db.commit()
    return jsonify({"message": "User registered", "user_id": user_id}), 201


@app.post("/login")
def login():
    payload = request.get_json(silent=True) or {}
    email = (payload.get("email") or "").strip().lower()
    password = payload.get("password") or ""

    if not email or not password:
        return jsonify({"error": "ValidationError", "message": "Email and password are required"}), 400
    email_error = validate_email(email)
    if email_error:
        return jsonify({"error": "ValidationError", "message": email_error}), 400

    db = get_db()
    user = db.execute(
        """
        SELECT id, email, password_hash, is_active
        FROM users WHERE email = ? AND deleted_at IS NULL
        """,
        (email,),
    ).fetchone()

    if user is None or user["is_active"] != 1:
        return jsonify({"error": "Unauthorized", "message": "Invalid credentials"}), 401
    if not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Unauthorized", "message": "Invalid credentials"}), 401

    token = create_token(user["id"], user["email"])
    return jsonify({"access_token": token, "token_type": "Bearer"}), 200


@app.post("/logout")
@auth_required
def logout():
    db = get_db()
    db.execute(
        "INSERT OR IGNORE INTO revoked_tokens(jti, revoked_at) VALUES (?, ?)",
        (g.current_token_jti, now_iso()),
    )
    db.commit()
    return jsonify({"message": "Logged out"}), 200


@app.get("/me")
@auth_required
@permission_required("profile.read")
def me():
    user = g.current_user
    return (
        jsonify(
            {
                "id": user["id"],
                "first_name": user["first_name"],
                "last_name": user["last_name"],
                "middle_name": user["middle_name"],
                "email": user["email"],
            }
        ),
        200,
    )


@app.patch("/me")
@auth_required
@permission_required("profile.update")
def update_me():
    payload = request.get_json(silent=True) or {}
    allowed = {"first_name", "last_name", "middle_name"}
    raw_update_data = {
        k: v.strip() for k, v in payload.items() if k in allowed and isinstance(v, str)
    }
    update_data: dict[str, str | None] = {}

    if not raw_update_data:
        return jsonify({"error": "ValidationError", "message": "No valid fields to update"}), 400

    for key, value in raw_update_data.items():
        if key == "middle_name" and value == "":
            update_data[key] = None
            continue
        error = validate_name(value, key)
        if error:
            return jsonify({"error": "ValidationError", "message": error}), 400
        update_data[key] = value

    updates = ", ".join([f"{key} = ?" for key in update_data.keys()] + ["updated_at = ?"])
    values = list(update_data.values()) + [now_iso(), g.current_user["id"]]

    db = get_db()
    db.execute(f"UPDATE users SET {updates} WHERE id = ?", values)
    db.commit()
    return jsonify({"message": "Profile updated"}), 200


@app.delete("/me")
@auth_required
@permission_required("account.delete")
def soft_delete_me():
    db = get_db()
    db.execute(
        "UPDATE users SET is_active = 0, deleted_at = ?, updated_at = ? WHERE id = ?",
        (now_iso(), now_iso(), g.current_user["id"]),
    )
    db.execute(
        "INSERT OR IGNORE INTO revoked_tokens(jti, revoked_at) VALUES (?, ?)",
        (g.current_token_jti, now_iso()),
    )
    db.commit()
    return jsonify({"message": "Account soft-deleted"}), 200


@app.get("/resource/<resource_name>")
@auth_required
def get_resource(resource_name: str):
    db = get_db()
    resource = db.execute(
        "SELECT name, required_permission FROM resources WHERE name = ?",
        (resource_name,),
    ).fetchone()
    if resource is None:
        return jsonify({"error": "NotFound", "message": "Resource not found"}), 404

    required_permission = resource["required_permission"]
    if required_permission not in g.current_permissions:
        return (
            jsonify(
                {
                    "error": "Forbidden",
                    "message": f"Access denied to resource '{resource_name}'",
                }
            ),
            403,
        )
    return jsonify({"resource": resource_name, "status": "granted"}), 200


@app.get("/admin/roles")
@auth_required
@permission_required("admin.panel.access")
def admin_list_roles():
    db = get_db()
    roles = [
        {"id": row["id"], "name": row["name"]}
        for row in db.execute("SELECT id, name FROM roles ORDER BY id").fetchall()
    ]
    return jsonify({"roles": roles}), 200


@app.get("/admin/roles/<role_name>/permissions")
@auth_required
@permission_required("admin.panel.access")
def admin_get_role_permissions(role_name: str):
    db = get_db()
    role = db.execute("SELECT id, name FROM roles WHERE name = ?", (role_name,)).fetchone()
    if role is None:
        return jsonify({"error": "NotFound", "message": "Role not found"}), 404

    permissions = [
        row["code"]
        for row in db.execute(
            """
            SELECT p.code
            FROM role_permissions rp
            JOIN permissions p ON p.id = rp.permission_id
            WHERE rp.role_id = ?
            ORDER BY p.code
            """,
            (role["id"],),
        ).fetchall()
    ]
    return jsonify({"role": role["name"], "permissions": permissions}), 200


@app.patch("/admin/roles/<role_name>/permissions")
@auth_required
@permission_required("admin.panel.access")
def admin_update_role_permissions(role_name: str):
    payload = request.get_json(silent=True) or {}
    requested_permissions = payload.get("permissions")
    if not isinstance(requested_permissions, list):
        return (
            jsonify(
                {
                    "error": "ValidationError",
                    "message": "Field 'permissions' must be a list of permission codes",
                }
            ),
            400,
        )
    if any(not isinstance(code, str) or not code.strip() for code in requested_permissions):
        return jsonify({"error": "ValidationError", "message": "All permission codes must be non-empty strings"}), 400

    unique_permissions = sorted({code.strip() for code in requested_permissions})
    db = get_db()
    role = db.execute("SELECT id, name FROM roles WHERE name = ?", (role_name,)).fetchone()
    if role is None:
        return jsonify({"error": "NotFound", "message": "Role not found"}), 404

    if unique_permissions:
        placeholders = ",".join("?" for _ in unique_permissions)
        rows = db.execute(
            f"SELECT id, code FROM permissions WHERE code IN ({placeholders})",
            unique_permissions,
        ).fetchall()
    else:
        rows = []
    found_codes = {row["code"] for row in rows}
    missing_codes = [code for code in unique_permissions if code not in found_codes]
    if missing_codes:
        return (
            jsonify(
                {
                    "error": "ValidationError",
                    "message": "Some permissions do not exist",
                    "missing_permissions": missing_codes,
                }
            ),
            400,
        )

    db.execute("DELETE FROM role_permissions WHERE role_id = ?", (role["id"],))
    for row in rows:
        db.execute(
            "INSERT INTO role_permissions(role_id, permission_id) VALUES (?, ?)",
            (role["id"], row["id"]),
        )
    db.commit()
    return jsonify({"message": "Role permissions updated", "role": role["name"], "permissions": unique_permissions}), 200


@app.get("/admin/users/<int:user_id>/roles")
@auth_required
@permission_required("admin.panel.access")
def admin_get_user_roles(user_id: int):
    db = get_db()
    user = db.execute(
        "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL",
        (user_id,),
    ).fetchone()
    if user is None:
        return jsonify({"error": "NotFound", "message": "User not found"}), 404

    roles = [
        row["name"]
        for row in db.execute(
            """
            SELECT r.name
            FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = ?
            ORDER BY r.name
            """,
            (user_id,),
        ).fetchall()
    ]
    return jsonify({"user_id": user_id, "roles": roles}), 200


@app.post("/admin/users/<int:user_id>/roles")
@auth_required
@permission_required("admin.panel.access")
def admin_update_user_roles(user_id: int):
    payload = request.get_json(silent=True) or {}
    requested_roles = payload.get("roles")
    if not isinstance(requested_roles, list) or len(requested_roles) == 0:
        return (
            jsonify(
                {
                    "error": "ValidationError",
                    "message": "Field 'roles' must be a non-empty list of role names",
                }
            ),
            400,
        )
    if any(not isinstance(name, str) or not name.strip() for name in requested_roles):
        return jsonify({"error": "ValidationError", "message": "All role names must be non-empty strings"}), 400

    unique_roles = sorted({name.strip() for name in requested_roles})
    db = get_db()
    user = db.execute(
        "SELECT id FROM users WHERE id = ? AND deleted_at IS NULL",
        (user_id,),
    ).fetchone()
    if user is None:
        return jsonify({"error": "NotFound", "message": "User not found"}), 404

    placeholders = ",".join("?" for _ in unique_roles)
    role_rows = db.execute(
        f"SELECT id, name FROM roles WHERE name IN ({placeholders})",
        unique_roles,
    ).fetchall()
    found_roles = {row["name"] for row in role_rows}
    missing_roles = [name for name in unique_roles if name not in found_roles]
    if missing_roles:
        return (
            jsonify(
                {
                    "error": "ValidationError",
                    "message": "Some roles do not exist",
                    "missing_roles": missing_roles,
                }
            ),
            400,
        )

    db.execute("DELETE FROM user_roles WHERE user_id = ?", (user_id,))
    for role_row in role_rows:
        db.execute(
            "INSERT INTO user_roles(user_id, role_id) VALUES (?, ?)",
            (user_id, role_row["id"]),
        )
    db.commit()
    return jsonify({"message": "User roles updated", "user_id": user_id, "roles": unique_roles}), 200


@app.post("/dev/make-admin")
def dev_make_admin():
    if not ENABLE_DEV_ENDPOINTS:
        return jsonify({"error": "Forbidden", "message": "Dev endpoints are disabled"}), 403

    payload = request.get_json(silent=True) or {}
    dev_key = payload.get("dev_key")
    email = (payload.get("email") or "").strip().lower()
    if dev_key != DEV_ADMIN_KEY:
        return jsonify({"error": "Forbidden", "message": "Invalid dev key"}), 403
    if not email:
        return jsonify({"error": "ValidationError", "message": "email is required"}), 400

    db = get_db()
    user = db.execute("SELECT id FROM users WHERE email = ? AND deleted_at IS NULL", (email,)).fetchone()
    if user is None:
        return jsonify({"error": "NotFound", "message": "User not found"}), 404
    admin_role = db.execute("SELECT id FROM roles WHERE name = 'admin'").fetchone()
    db.execute(
        "INSERT OR IGNORE INTO user_roles(user_id, role_id) VALUES (?, ?)",
        (user["id"], admin_role["id"]),
    )
    db.commit()
    return jsonify({"message": "Admin role granted", "email": email}), 200


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


with app.app_context():
    init_db()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8000, debug=True)
