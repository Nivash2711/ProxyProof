# ProxyProof

import os
import io
import csv
import time
import json
import hmac
import hashlib
import secrets
import sqlite3
import base64
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, Depends, Header, HTTPException, Response
from pydantic import BaseModel, Field

DB = os.getenv("DATABASE_PATH", "proxyproof.db")
SECRET = os.getenv("PROXYPROOF_SECRET", "change-this-secret-before-deployment")
TOKEN_TTL = 30

app = FastAPI(title="ProxyProof Bluetooth Attendance API")


def connect():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def now():
    return int(time.time())


def iso(ts):
    return datetime.fromtimestamp(
        ts, timezone.utc
    ).isoformat()


def password_hash(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 180000
    ).hex()
    return salt + "$" + digest


def password_ok(password, stored):
    try:
        salt, expected = stored.split("$", 1)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), salt.encode(), 180000
        ).hex()
        return hmac.compare_digest(actual, expected)
    except Exception:
        return False


def seed_user(c, uid, name, email, password, role):
    if not c.execute(
        "SELECT id FROM users WHERE email=?", (email,)
    ).fetchone():
        c.execute(
            """INSERT INTO users
            (id,name,email,password_hash,role,created_at)
            VALUES(?,?,?,?,?,?)""",
            (uid, name, email, password_hash(password), role, now())
        )


def init_db():
    with connect() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            device_id TEXT,
            created_at INTEGER NOT NULL
        );

        CREATE TABLE IF NOT EXISTS sessions(
            id TEXT PRIMARY KEY,
            code TEXT UNIQUE NOT NULL,
            organiser_id TEXT NOT NULL,
            title TEXT NOT NULL,
            starts_at INTEGER NOT NULL,
            ends_at INTEGER NOT NULL,
            closed INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(organiser_id) REFERENCES users(id)
        );

        CREATE TABLE IF NOT EXISTS attendance(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT NOT NULL,
            student_id TEXT NOT NULL,
            marked_at INTEGER NOT NULL,
            source TEXT NOT NULL,
            UNIQUE(session_id, student_id),
            FOREIGN KEY(session_id) REFERENCES sessions(id),
            FOREIGN KEY(student_id) REFERENCES users(id)
        );
        """)
        seed_user(c, "demo-organiser", "Demo Organiser",
                  "organiser@proxyproof.local", "organiser123", "organiser")
        seed_user(c, "demo-student", "Demo Student",
                  "student@proxyproof.local", "student123", "student")
        seed_user(c, "demo-admin", "Demo Admin",
                  "admin@proxyproof.local", "admin12345", "admin")


@app.on_event("startup")
def startup():
    init_db()


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def make_token(user):
    payload = {
        "sub": user["id"],
        "role": user["role"],
        "exp": now() + 43200
    }
    body = b64(json.dumps(payload, separators=(",", ":")).encode())
    signature = b64(hmac.new(
        SECRET.encode(), body.encode(), hashlib.sha256
    ).digest())
    return body + "." + signature


def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Sign in first")

    try:
        body, signature = authorization[7:].split(".", 1)
        expected = b64(hmac.new(
            SECRET.encode(), body.encode(), hashlib.sha256
        ).digest())

        if not hmac.compare_digest(signature, expected):
            raise ValueError()

        raw = base64.urlsafe_b64decode(
            body + "=" * (-len(body) % 4)
        )
        payload = json.loads(raw)

        if payload["exp"] < now():
            raise ValueError()

        with connect() as c:
            user = c.execute(
                "SELECT id,name,email,role,device_id FROM users WHERE id=?",
                (payload["sub"],)
            ).fetchone()

        if not user:
            raise ValueError()

        return dict(user)
    except Exception:
        raise HTTPException(401, "Invalid or expired login token")


def roles(*allowed):
    def check(user=Depends(current_user)):
        if user["role"] not in allowed:
            raise HTTPException(403, "Permission denied")
        return user
    return check


class Register(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    email: str
    password: str = Field(min_length=8, max_length=128)
    role: str


class Login(BaseModel):
    email: str
    password: str
    device_id: str = Field(min_length=8, max_length=128)


class NewSession(BaseModel):
    title: str = Field(min_length=2, max_length=120)
    duration_seconds: int = Field(default=300, ge=60, le=1800)


class MarkAttendance(BaseModel):
    session_code: str
    token: str
    device_id: str
    rssi: int = Field(ge=-127, le=0)


class ManualAttendance(BaseModel):
    student_id: str


class ApproveDevice(BaseModel):
    student_id: str
    device_id: str


def beacon_token(code, slot):
    message = f"{code}:{slot}".encode()
    return hmac.new(
        SECRET.encode(), message, hashlib.sha256
    ).hexdigest()[:12].upper()


@app.get("/")
def home():
    return {
        "project": "ProxyProof",
        "status": "running",
        "docs": "/docs"
    }


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/auth/register")
def register(body: Register):
    role = body.role.lower()
    if role not in ("student", "organiser"):
        raise HTTPException(400, "Role must be student or organiser")

    uid = "u_" + secrets.token_hex(8)
    try:
        with connect() as c:
            c.execute(
                """INSERT INTO users
                (id,name,email,password_hash,role,created_at)
                VALUES(?,?,?,?,?,?)""",
                (uid, body.name.strip(), body.email.lower().strip(),
                 password_hash(body.password), role, now())
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Email already registered")

    return {"id": uid, "role": role, "message": "Account created"}


@app.post("/auth/login")
def login(body: Login):
    with connect() as c:
        user = c.execute(
            "SELECT * FROM users WHERE email=?",
            (body.email.lower().strip(),)
        ).fetchone()

        if not user or not password_ok(
            body.password, user["password_hash"]
        ):
            raise HTTPException(401, "Incorrect email or password")

        if user["role"] == "student":
            if user["device_id"] is None:
                c.execute(
                    "UPDATE users SET device_id=? WHERE id=?",
                    (body.device_id, user["id"])
                )
                user = c.execute(
                    "SELECT * FROM users WHERE id=?", (user["id"],)
                ).fetchone()
            elif user["device_id"] != body.device_id:
                raise HTTPException(
                    403, "Device changed. Contact an administrator."
                )

        return {
            "access_token": make_token(user),
            "token_type": "bearer",
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "role": user["role"],
                "device_id": user["device_id"]
            }
        }


@app.get("/me")
def me(user=Depends(current_user)):
    return user


@app.post("/sessions")
def create_session(
    body: NewSession,
    user=Depends(roles("organiser", "admin"))
):
    sid = "s_" + secrets.token_hex(8)
    code = secrets.token_hex(4).upper()
    start = now()
    end = start + body.duration_seconds

    with connect() as c:
        c.execute(
            """INSERT INTO sessions
            (id,code,organiser_id,title,starts_at,ends_at)
            VALUES(?,?,?,?,?,?)""",
            (sid, code, user["id"], body.title, start, end)
        )

    return {
        "id": sid,
        "session_code": code,
        "title": body.title,
        "starts_at": iso(start),
        "ends_at": iso(end),
        "duration_seconds": body.duration_seconds
    }


@app.get("/sessions")
def list_sessions(user=Depends(current_user)):
    with connect() as c:
        if user["role"] == "student":
            rows = c.execute("""
                SELECT s.*,
                EXISTS(SELECT 1 FROM attendance a
                    WHERE a.session_id=s.id AND a.student_id=?) AS present
                FROM sessions s ORDER BY s.starts_at DESC
            """, (user["id"],)).fetchall()
        elif user["role"] == "admin":
            rows = c.execute(
                "SELECT * FROM sessions ORDER BY starts_at DESC"
            ).fetchall()
        else:
            rows = c.execute(
                "SELECT * FROM sessions WHERE organiser_id=? ORDER BY starts_at DESC",
                (user["id"],)
            ).fetchall()

    return [dict(r, starts_at=iso(r["starts_at"]),
                 ends_at=iso(r["ends_at"])) for r in rows]


@app.get("/sessions/{session_id}/beacon")
def get_beacon(
    session_id: str,
    user=Depends(roles("organiser", "admin"))
):
    with connect() as c:
        s = c.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()

    if not s:
        raise HTTPException(404, "Session not found")
    if user["role"] != "admin" and s["organiser_id"] != user["id"]:
        raise HTTPException(403, "Not your session")
    if s["closed"] or now() > s["ends_at"]:
        raise HTTPException(400, "Session is closed or expired")

    slot = now() // TOKEN_TTL
    return {
        "session_code": s["code"],
        "token": beacon_token(s["code"], slot),
        "expires_in": TOKEN_TTL - (now() % TOKEN_TTL),
        "service_uuid": "0000FFE0-0000-1000-8000-00805F9B34FB"
    }


@app.post("/attendance/ble")
def mark_ble(body: MarkAttendance, user=Depends(roles("student"))):
    if not user["device_id"] or user["device_id"] != body.device_id:
        raise HTTPException(403, "Unregistered device")
    if body.rssi < -85:
        raise HTTPException(403, "Signal too weak")

    with connect() as c:
        s = c.execute(
            "SELECT * FROM sessions WHERE code=?",
            (body.session_code.upper(),)
        ).fetchone()

        if not s:
            raise HTTPException(404, "Unknown session")
        if s["closed"] or now() < s["starts_at"] or now() > s["ends_at"]:
            raise HTTPException(400, "Session inactive")

        slot = now() // TOKEN_TTL
        valid = any(
            hmac.compare_digest(
                body.token.upper(), beacon_token(s["code"], old_slot)
            )
            for old_slot in (slot, slot - 1)
        )
        if not valid:
            raise HTTPException(403, "Invalid or expired token")

        try:
            c.execute(
                """INSERT INTO attendance
                (session_id,student_id,marked_at,source)
                VALUES(?,?,?,'ble')""",
                (s["id"], user["id"], now())
            )
        except sqlite3.IntegrityError:
            return {"marked": True, "already_marked": True}

    return {"marked": True, "already_marked": False}


@app.get("/sessions/{session_id}")
def session_details(session_id: str, user=Depends(current_user)):
    with connect() as c:
        s = c.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        if not s:
            raise HTTPException(404, "Session not found")
        if user["role"] == "organiser" and s["organiser_id"] != user["id"]:
            raise HTTPException(403, "Not your session")

        attendance = c.execute("""
            SELECT a.student_id,u.name,u.email,a.marked_at,a.source
            FROM attendance a JOIN users u ON u.id=a.student_id
            WHERE a.session_id=? ORDER BY a.marked_at
        """, (session_id,)).fetchall()

    return {
        "id": s["id"],
        "title": s["title"],
        "session_code": s["code"],
        "closed": bool(s["closed"]),
        "starts_at": iso(s["starts_at"]),
        "ends_at": iso(s["ends_at"]),
        "attendance": [
            dict(a, marked_at=iso(a["marked_at"])) for a in attendance
        ]
    }


@app.post("/sessions/{session_id}/attendance")
def manual_add(
    session_id: str,
    body: ManualAttendance,
    user=Depends(roles("organiser", "admin"))
):
    with connect() as c:
        s = c.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        student = c.execute(
            "SELECT id FROM users WHERE id=? AND role='student'",
            (body.student_id,)
        ).fetchone()

        if not s or not student:
            raise HTTPException(404, "Session or student not found")
        if user["role"] != "admin" and s["organiser_id"] != user["id"]:
            raise HTTPException(403, "Not your session")

        try:
            c.execute(
                """INSERT INTO attendance
                (session_id,student_id,marked_at,source)
                VALUES(?,?,?,'manual')""",
                (session_id, body.student_id, now())
            )
        except sqlite3.IntegrityError:
            raise HTTPException(409, "Already marked")

    return {"added": True}


@app.delete("/sessions/{session_id}/attendance/{student_id}")
def remove_attendance(
    session_id: str,
    student_id: str,
    user=Depends(roles("organiser", "admin"))
):
    with connect() as c:
        s = c.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        if not s:
            raise HTTPException(404, "Session not found")
        if user["role"] != "admin" and s["organiser_id"] != user["id"]:
            raise HTTPException(403, "Not your session")
        c.execute(
            "DELETE FROM attendance WHERE session_id=? AND student_id=?",
            (session_id, student_id)
        )
    return {"removed": True}


@app.post("/sessions/{session_id}/close")
def close_session(
    session_id: str,
    user=Depends(roles("organiser", "admin"))
):
    with connect() as c:
        s = c.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        if not s:
            raise HTTPException(404, "Session not found")
        if user["role"] != "admin" and s["organiser_id"] != user["id"]:
            raise HTTPException(403, "Not your session")
        c.execute("UPDATE sessions SET closed=1 WHERE id=?", (session_id,))
    return {"closed": True}


@app.get("/students/me/attendance")
def student_history(user=Depends(roles("student"))):
    with connect() as c:
        rows = c.execute("""
            SELECT s.id session_id,s.title,s.starts_at,
            CASE WHEN a.student_id IS NULL THEN 0 ELSE 1 END present,
            a.marked_at
            FROM sessions s LEFT JOIN attendance a
            ON a.session_id=s.id AND a.student_id=?
            ORDER BY s.starts_at DESC
        """, (user["id"],)).fetchall()

    total = len(rows)
    attended = sum(r["present"] for r in rows)
    return {
        "total_sessions": total,
        "attended": attended,
        "percentage": round(100 * attended / total, 1) if total else 0,
        "history": [
            dict(r, starts_at=iso(r["starts_at"]),
                 marked_at=iso(r["marked_at"]) if r["marked_at"] else None)
            for r in rows
        ]
    }


@app.get("/sessions/{session_id}/export.csv")
def export_csv(
    session_id: str,
    user=Depends(roles("organiser", "admin"))
):
    with connect() as c:
        s = c.execute(
            "SELECT * FROM sessions WHERE id=?", (session_id,)
        ).fetchone()
        if not s:
            raise HTTPException(404, "Session not found")
        if user["role"] != "admin" and s["organiser_id"] != user["id"]:
            raise HTTPException(403, "Not your session")

        rows = c.execute("""
            SELECT u.id,u.name,u.email,a.marked_at,a.source
            FROM users u LEFT JOIN attendance a
            ON a.student_id=u.id AND a.session_id=?
            WHERE u.role='student' ORDER BY u.name
        """, (session_id,)).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["student_id", "name", "email", "status", "marked_at_utc", "source"])
    for r in rows:
        writer.writerow([
            r["id"], r["name"], r["email"],
            "present" if r["marked_at"] else "absent",
            iso(r["marked_at"]) if r["marked_at"] else "",
            r["source"] or ""
        ])

    return Response(
        output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="proxyproof.csv"'}
    )


@app.get("/admin/students")
def admin_students(user=Depends(roles("admin"))):
    with connect() as c:
        rows = c.execute("""
            SELECT id,name,email,device_id FROM users
            WHERE role='student' ORDER BY name
        """).fetchall()
    return [dict(r) for r in rows]


@app.post("/admin/device-approval")
def approve_device(
    body: ApproveDevice,
    user=Depends(roles("admin"))
):
    with connect() as c:
        result = c.execute(
            "UPDATE users SET device_id=? WHERE id=? AND role='student'",
            (body.device_id, body.student_id)
        )
        if result.rowcount == 0:
            raise HTTPException(404, "Student not found")
    return {"approved": True}
