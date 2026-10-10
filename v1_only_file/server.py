#!/usr/bin/env python3
"""A dependency-free LAN file relay for Python 3.10+."""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import json
import mimetypes
import os
import re
import secrets
import shutil
import socket
import sqlite3
import sys
import threading
import time
import unicodedata
import urllib.parse
import uuid
from dataclasses import dataclass
from email.utils import formatdate
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


APP_DIR = Path(__file__).resolve().parent
STATIC_DIR = APP_DIR / "static"
COOKIE_NAME = "relay_session"
SESSION_SECONDS = 7 * 24 * 60 * 60
PBKDF2_ROUNDS = 310_000
DEFAULT_LARGE_THRESHOLD = 128 * 1024 * 1024
DEFAULT_CHUNK_SIZE = 8 * 1024 * 1024
MAX_JSON = 128 * 1024
USERNAME_RE = re.compile(r"^[^\x00-\x1f\x7f/\\]{1,32}$")


def now() -> int:
    return int(time.time())


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def safe_name(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("文件名无效")
    name = unicodedata.normalize("NFC", value).strip()
    if not name or name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError("文件名无效")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in name):
        raise ValueError("文件名含控制字符")
    if len(name.encode("utf-8")) > 240:
        raise ValueError("文件名过长")
    return name


def normalize_username(value: Any) -> tuple[str, str]:
    if not isinstance(value, str):
        raise ValueError("用户名无效")
    shown = unicodedata.normalize("NFKC", value).strip()
    if not USERNAME_RE.fullmatch(shown):
        raise ValueError("用户名应为 1–32 个字符，不能包含路径符号")
    return shown, shown.casefold()


def parse_checksum(value: str | None) -> str:
    value = (value or "").lower()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError("校验值无效")
    return value


@dataclass
class Config:
    data_dir: Path
    listen: str
    port: int
    large_threshold: int
    chunk_size: int
    max_storage_bytes: int
    users_file: Path | None = None


class Store:
    def __init__(self, config: Config):
        self.config = config
        self.root = config.data_dir
        self.files_dir = self.root / "files"
        self.parts_dir = self.root / "parts"
        self.db_path = self.root / "relay.sqlite3"
        self.secret_path = self.root / ".session-key"
        self.lock = threading.RLock()
        self.whitelist_lock = threading.RLock()
        self.whitelist_stamp: tuple[int, int] | None = None
        self.whitelist: dict[str, tuple[str, str]] = {}
        self.upload_locks: dict[str, threading.Lock] = {}
        self.root.mkdir(parents=True, exist_ok=True)
        self.files_dir.mkdir(exist_ok=True)
        self.parts_dir.mkdir(exist_ok=True)
        self.secret = self._load_secret()
        self._init_db()
        if self.config.users_file:
            self.load_whitelist(force=True)
        self._cleanup_stale_uploads()

    def load_whitelist(self, force: bool = False) -> dict[str, tuple[str, str]]:
        path = self.config.users_file
        if not path:
            return {}
        try:
            stat = path.stat()
        except OSError as exc:
            raise ValueError(f"无法读取用户白名单：{path}") from exc
        stamp = (stat.st_mtime_ns, stat.st_size)
        with self.whitelist_lock:
            if not force and stamp == self.whitelist_stamp:
                return self.whitelist
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError) as exc:
                raise ValueError(f"无法读取 UTF-8 用户白名单：{path}") from exc
            parsed: dict[str, tuple[str, str]] = {}
            for number, line in enumerate(lines, 1):
                if not line.strip() or line.lstrip().startswith("#"):
                    continue
                if ":" not in line:
                    raise ValueError(f"用户白名单第 {number} 行缺少冒号")
                username, password = line.split(":", 1)
                shown, normalized = normalize_username(username.strip())
                if not 6 <= len(password) <= 256:
                    raise ValueError(f"用户白名单第 {number} 行的密码应为 6–256 个字符")
                if normalized in parsed:
                    raise ValueError(f"用户白名单第 {number} 行的用户名重复")
                parsed[normalized] = (shown, password)
            self.whitelist = parsed
            self.whitelist_stamp = stamp
            return parsed

    def _load_secret(self) -> bytes:
        if self.secret_path.exists():
            return self.secret_path.read_bytes()
        secret = secrets.token_bytes(32)
        fd = os.open(self.secret_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(secret)
        return secret

    @contextlib.contextmanager
    def db(self):
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA journal_mode = WAL")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_db(self) -> None:
        with self.db() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    username TEXT NOT NULL,
                    username_norm TEXT NOT NULL UNIQUE,
                    salt BLOB NOT NULL,
                    password_hash BLOB NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS files (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    disk_name TEXT NOT NULL UNIQUE,
                    size INTEGER NOT NULL,
                    checksum TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS files_owner_time ON files(user_id, created_at DESC);
                CREATE TABLE IF NOT EXISTS uploads (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    file_key TEXT NOT NULL,
                    name TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    chunk_size INTEGER NOT NULL,
                    total_chunks INTEGER NOT NULL,
                    part_name TEXT NOT NULL UNIQUE,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    UNIQUE(user_id, file_key)
                );
                CREATE TABLE IF NOT EXISTS upload_chunks (
                    upload_id TEXT NOT NULL REFERENCES uploads(id) ON DELETE CASCADE,
                    chunk_index INTEGER NOT NULL,
                    size INTEGER NOT NULL,
                    checksum TEXT NOT NULL,
                    PRIMARY KEY(upload_id, chunk_index)
                );
                """
            )

    def _cleanup_stale_uploads(self) -> None:
        cutoff = now() - 7 * 24 * 60 * 60
        with self.db() as db:
            rows = db.execute("SELECT id, part_name FROM uploads WHERE updated_at < ?", (cutoff,)).fetchall()
            for row in rows:
                with contextlib.suppress(FileNotFoundError):
                    (self.parts_dir / row["part_name"]).unlink()
                db.execute("DELETE FROM uploads WHERE id = ?", (row["id"],))
        for temp in self.parts_dir.glob("*.chunk"):
            with contextlib.suppress(OSError):
                if temp.stat().st_mtime < cutoff:
                    temp.unlink()

    def password_digest(self, password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)

    def authenticate(self, username: Any, password: Any) -> tuple[sqlite3.Row, bool]:
        shown, normalized = normalize_username(username)
        if not isinstance(password, str) or not (6 <= len(password) <= 256):
            raise ValueError("密码应为 6–256 个字符")
        if self.config.users_file:
            allowed = self.load_whitelist().get(normalized)
            if not allowed or not hmac.compare_digest(password, allowed[1]):
                raise PermissionError("用户名或密码错误")
            shown = allowed[0]
        with self.lock, self.db() as db:
            row = db.execute("SELECT * FROM users WHERE username_norm = ?", (normalized,)).fetchone()
            if row:
                test = self.password_digest(password, row["salt"])
                if not self.config.users_file and not hmac.compare_digest(test, row["password_hash"]):
                    raise PermissionError("用户名或密码错误")
                if self.config.users_file and not hmac.compare_digest(test, row["password_hash"]):
                    salt = secrets.token_bytes(16)
                    digest = self.password_digest(password, salt)
                    db.execute(
                        "UPDATE users SET username = ?, salt = ?, password_hash = ? WHERE id = ?",
                        (shown, salt, digest, row["id"]),
                    )
                    row = db.execute("SELECT * FROM users WHERE id = ?", (row["id"],)).fetchone()
                return row, False
            salt = secrets.token_bytes(16)
            digest = self.password_digest(password, salt)
            cursor = db.execute(
                "INSERT INTO users(username, username_norm, salt, password_hash, created_at) VALUES(?,?,?,?,?)",
                (shown, normalized, salt, digest, now()),
            )
            row = db.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
            return row, True

    def make_session(self, user_id: int) -> str:
        payload = f"{user_id}.{now() + SESSION_SECONDS}.{b64(secrets.token_bytes(12))}".encode()
        return b64(payload) + "." + b64(hmac.new(self.secret, payload, hashlib.sha256).digest())

    def verify_session(self, token: str | None) -> sqlite3.Row | None:
        try:
            encoded, signature = (token or "").split(".", 1)
            payload = unb64(encoded)
            expected = hmac.new(self.secret, payload, hashlib.sha256).digest()
            if not hmac.compare_digest(expected, unb64(signature)):
                return None
            user_id, expires, _nonce = payload.decode().split(".", 2)
            if int(expires) < now():
                return None
            with self.db() as db:
                row = db.execute(
                    "SELECT id, username, username_norm FROM users WHERE id = ?", (int(user_id),)
                ).fetchone()
            if row and self.config.users_file and row["username_norm"] not in self.load_whitelist():
                return None
            return row
        except (ValueError, UnicodeError, sqlite3.Error):
            return None

    def list_files(self, user_id: int) -> list[dict[str, Any]]:
        with self.db() as db:
            rows = db.execute(
                "SELECT id, name, size, checksum, created_at FROM files WHERE user_id = ? ORDER BY created_at DESC, rowid DESC",
                (user_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def storage_used(self, user_id: int) -> int:
        with self.db() as db:
            row = db.execute("SELECT COALESCE(SUM(size), 0) AS used FROM files WHERE user_id = ?", (user_id,)).fetchone()
            active = db.execute("SELECT COALESCE(SUM(size), 0) AS used FROM uploads WHERE user_id = ?", (user_id,)).fetchone()
        return int(row["used"]) + int(active["used"])

    def ensure_space(self, user_id: int, size: int) -> None:
        if size < 0:
            raise ValueError("文件大小无效")
        if self.config.max_storage_bytes and self.storage_used(user_id) + size > self.config.max_storage_bytes:
            raise OSError("用户暂存区空间不足")
        free = shutil.disk_usage(self.root).free
        if free < size + 64 * 1024 * 1024:
            raise OSError("磁盘剩余空间不足")

    def add_file(self, user_id: int, name: str, temp_path: Path, size: int, checksum: str) -> dict[str, Any]:
        file_id = uuid.uuid4().hex
        disk_name = uuid.uuid4().hex
        destination = self.files_dir / disk_name
        os.replace(temp_path, destination)
        created = now()
        try:
            with self.db() as db:
                db.execute(
                    "INSERT INTO files(id,user_id,name,disk_name,size,checksum,created_at) VALUES(?,?,?,?,?,?,?)",
                    (file_id, user_id, name, disk_name, size, checksum, created),
                )
        except Exception:
            with contextlib.suppress(FileNotFoundError):
                destination.unlink()
            raise
        return {"id": file_id, "name": name, "size": size, "checksum": checksum, "created_at": created}

    def init_upload(self, user_id: int, data: dict[str, Any]) -> dict[str, Any]:
        name = safe_name(data.get("name"))
        size = int(data.get("size", -1))
        file_key = parse_checksum(data.get("file_key"))
        if size < self.config.large_threshold:
            raise ValueError("该文件应使用普通上传")
        with self.lock, self.db() as db:
            existing = db.execute(
                "SELECT * FROM uploads WHERE user_id = ? AND file_key = ?", (user_id, file_key)
            ).fetchone()
            if existing and (existing["name"] != name or existing["size"] != size):
                raise ValueError("续传信息与文件不匹配")
            if not existing:
                self.ensure_space(user_id, size)
                upload_id = uuid.uuid4().hex
                part_name = upload_id + ".part"
                total = (size + self.config.chunk_size - 1) // self.config.chunk_size
                db.execute(
                    "INSERT INTO uploads VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (upload_id, user_id, file_key, name, size, self.config.chunk_size, total, part_name, now(), now()),
                )
                with open(self.parts_dir / part_name, "wb") as handle:
                    handle.truncate(size)
                existing = db.execute("SELECT * FROM uploads WHERE id = ?", (upload_id,)).fetchone()
            chunks = db.execute(
                "SELECT chunk_index AS 'index', size, checksum FROM upload_chunks WHERE upload_id = ? ORDER BY chunk_index",
                (existing["id"],),
            ).fetchall()
        return {
            "id": existing["id"], "name": existing["name"], "size": existing["size"],
            "chunk_size": existing["chunk_size"], "total_chunks": existing["total_chunks"],
            "received": [dict(row) for row in chunks],
        }

    def get_upload(self, upload_id: str, user_id: int) -> sqlite3.Row | None:
        with self.db() as db:
            return db.execute("SELECT * FROM uploads WHERE id = ? AND user_id = ?", (upload_id, user_id)).fetchone()

    def upload_lock(self, upload_id: str) -> threading.Lock:
        with self.lock:
            return self.upload_locks.setdefault(upload_id, threading.Lock())

    def save_chunk(self, upload: sqlite3.Row, index: int, source, length: int, expected_hash: str) -> dict[str, Any]:
        if not 0 <= index < upload["total_chunks"]:
            raise ValueError("分块编号无效")
        expected_size = min(upload["chunk_size"], upload["size"] - index * upload["chunk_size"])
        if length != expected_size:
            raise ValueError("分块大小不匹配")
        temporary = self.parts_dir / f"{upload['id']}.{index}.{secrets.token_hex(4)}.chunk"
        digest = hashlib.sha256()
        remaining = length
        try:
            with open(temporary, "wb") as out:
                while remaining:
                    block = source.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ConnectionError("上传中断")
                    out.write(block)
                    digest.update(block)
                    remaining -= len(block)
                out.flush()
                os.fsync(out.fileno())
            actual = digest.hexdigest()
            if not hmac.compare_digest(actual, expected_hash):
                raise ValueError("分块校验失败")
            with self.upload_lock(upload["id"]):
                latest = self.get_upload(upload["id"], upload["user_id"])
                if not latest:
                    raise FileNotFoundError("续传任务不存在")
                with open(temporary, "rb") as incoming, open(self.parts_dir / upload["part_name"], "r+b") as target:
                    target.seek(index * upload["chunk_size"])
                    shutil.copyfileobj(incoming, target, 1024 * 1024)
                    target.flush()
                    os.fsync(target.fileno())
                with self.db() as db:
                    db.execute(
                        "INSERT OR REPLACE INTO upload_chunks(upload_id,chunk_index,size,checksum) VALUES(?,?,?,?)",
                        (upload["id"], index, length, actual),
                    )
                    db.execute("UPDATE uploads SET updated_at = ? WHERE id = ?", (now(), upload["id"]))
            return {"index": index, "size": length, "checksum": actual}
        finally:
            with contextlib.suppress(FileNotFoundError):
                temporary.unlink()

    def complete_upload(self, upload: sqlite3.Row, manifest_hash: str) -> dict[str, Any]:
        with self.upload_lock(upload["id"]), self.db() as db:
            chunks = db.execute(
                "SELECT * FROM upload_chunks WHERE upload_id = ? ORDER BY chunk_index", (upload["id"],)
            ).fetchall()
            if len(chunks) != upload["total_chunks"] or any(row["chunk_index"] != i for i, row in enumerate(chunks)):
                raise ValueError("仍有分块未上传")
            manifest = hashlib.sha256(b"".join(bytes.fromhex(row["checksum"]) for row in chunks)).hexdigest()
            if not hmac.compare_digest(manifest, manifest_hash):
                raise ValueError("整体校验失败")
            part = self.parts_dir / upload["part_name"]
            digest = hashlib.sha256()
            total = 0
            with open(part, "rb") as handle:
                while block := handle.read(4 * 1024 * 1024):
                    total += len(block)
                    digest.update(block)
            if total != upload["size"]:
                raise ValueError("文件大小校验失败")
            result = self.add_file(upload["user_id"], upload["name"], part, total, digest.hexdigest())
            db.execute("DELETE FROM uploads WHERE id = ?", (upload["id"],))
        with self.lock:
            self.upload_locks.pop(upload["id"], None)
        return result

    def cancel_upload(self, upload: sqlite3.Row) -> None:
        with self.upload_lock(upload["id"]):
            with contextlib.suppress(FileNotFoundError):
                (self.parts_dir / upload["part_name"]).unlink()
            with self.db() as db:
                db.execute("DELETE FROM uploads WHERE id = ? AND user_id = ?", (upload["id"], upload["user_id"]))
        with self.lock:
            self.upload_locks.pop(upload["id"], None)

    def get_file(self, user_id: int, file_id: str) -> sqlite3.Row | None:
        with self.db() as db:
            return db.execute("SELECT * FROM files WHERE id = ? AND user_id = ?", (file_id, user_id)).fetchone()

    def delete_file(self, user_id: int, file_id: str) -> bool:
        with self.lock, self.db() as db:
            row = db.execute("SELECT * FROM files WHERE id = ? AND user_id = ?", (file_id, user_id)).fetchone()
            if not row:
                return False
            with contextlib.suppress(FileNotFoundError):
                (self.files_dir / row["disk_name"]).unlink()
            db.execute("DELETE FROM files WHERE id = ? AND user_id = ?", (file_id, user_id))
            return True


class RelayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, handler, store: Store):
        super().__init__(address, handler)
        self.store = store


class Handler(BaseHTTPRequestHandler):
    server: RelayServer
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        sys.stderr.write(f"[{self.log_date_time_string()}] {self.address_string()} {fmt % args}\n")

    @property
    def store(self) -> Store:
        return self.server.store

    def send_common(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")

    def json_response(self, status: int, payload: Any, cookie: str | None = None) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_common()
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def error_json(self, status: int, message: str) -> None:
        self.json_response(status, {"error": message})

    def read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("请求长度无效")
        if length <= 0 or length > MAX_JSON:
            raise ValueError("请求内容无效")
        try:
            value = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("JSON 无效")
        if not isinstance(value, dict):
            raise ValueError("请求内容无效")
        return value

    def cookie_token(self) -> str | None:
        cookie = SimpleCookie()
        with contextlib.suppress(Exception):
            cookie.load(self.headers.get("Cookie", ""))
            item = cookie.get(COOKIE_NAME)
            return item.value if item else None
        return None

    def user(self) -> sqlite3.Row | None:
        return self.store.verify_session(self.cookie_token())

    def require_user(self) -> sqlite3.Row | None:
        user = self.user()
        if not user:
            self.error_json(HTTPStatus.UNAUTHORIZED, "请先登录")
        return user

    def same_origin(self) -> bool:
        fetch_site = self.headers.get("Sec-Fetch-Site", "")
        if fetch_site == "cross-site":
            return False
        origin = self.headers.get("Origin")
        if not origin:
            return True
        try:
            return urllib.parse.urlsplit(origin).netloc == self.headers.get("Host")
        except ValueError:
            return False

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/session":
            user = self.user()
            if not user:
                return self.json_response(200, {"authenticated": False})
            return self.json_response(200, {
                "authenticated": True, "username": user["username"],
                "large_threshold": self.store.config.large_threshold,
                "chunk_size": self.store.config.chunk_size,
            })
        if path == "/api/files":
            user = self.require_user()
            if user:
                return self.json_response(200, {"files": self.store.list_files(user["id"])})
            return
        match = re.fullmatch(r"/api/files/([0-9a-f]{32})/download", path)
        if match:
            user = self.require_user()
            if user:
                return self.download(user["id"], match.group(1), head=False)
            return
        return self.static(path, head=False)

    def do_HEAD(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        match = re.fullmatch(r"/api/files/([0-9a-f]{32})/download", path)
        if match:
            user = self.require_user()
            if user:
                return self.download(user["id"], match.group(1), head=True)
            return
        return self.static(path, head=True)

    def do_POST(self) -> None:
        if not self.same_origin():
            return self.error_json(HTTPStatus.FORBIDDEN, "请求来源无效")
        path = urllib.parse.urlsplit(self.path).path
        try:
            if path == "/api/login":
                data = self.read_json()
                user, created = self.store.authenticate(data.get("username"), data.get("password"))
                token = self.store.make_session(user["id"])
                cookie = f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={SESSION_SECONDS}"
                return self.json_response(200, {"username": user["username"], "created": created}, cookie)
            if path == "/api/logout":
                cookie = f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
                return self.json_response(200, {"ok": True}, cookie)
            user = self.require_user()
            if not user:
                return
            if path == "/api/files/small":
                return self.small_upload(user["id"])
            if path == "/api/uploads/init":
                return self.json_response(200, self.store.init_upload(user["id"], self.read_json()))
            match = re.fullmatch(r"/api/uploads/([0-9a-f]{32})/complete", path)
            if match:
                upload = self.store.get_upload(match.group(1), user["id"])
                if not upload:
                    return self.error_json(404, "续传任务不存在")
                manifest = parse_checksum(self.read_json().get("manifest_checksum"))
                return self.json_response(201, {"file": self.store.complete_upload(upload, manifest)})
            return self.error_json(404, "未找到")
        except PermissionError as exc:
            return self.error_json(HTTPStatus.UNAUTHORIZED, str(exc))
        except (ValueError, OSError, ConnectionError) as exc:
            return self.error_json(HTTPStatus.BAD_REQUEST, str(exc))
        except Exception as exc:
            self.log_error("Unhandled POST error: %r", exc)
            return self.error_json(500, "服务器处理失败")

    def do_PUT(self) -> None:
        if not self.same_origin():
            return self.error_json(403, "请求来源无效")
        path = urllib.parse.urlsplit(self.path).path
        user = self.require_user()
        if not user:
            return
        match = re.fullmatch(r"/api/uploads/([0-9a-f]{32})/chunks/(\d+)", path)
        if not match:
            return self.error_json(404, "未找到")
        upload = self.store.get_upload(match.group(1), user["id"])
        if not upload:
            return self.error_json(404, "续传任务不存在")
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            checksum = parse_checksum(self.headers.get("X-Chunk-Sha256"))
            result = self.store.save_chunk(upload, int(match.group(2)), self.rfile, length, checksum)
            return self.json_response(200, result)
        except (ValueError, OSError, ConnectionError, FileNotFoundError) as exc:
            return self.error_json(400, str(exc))

    def do_DELETE(self) -> None:
        if not self.same_origin():
            return self.error_json(403, "请求来源无效")
        path = urllib.parse.urlsplit(self.path).path
        user = self.require_user()
        if not user:
            return
        match = re.fullmatch(r"/api/files/([0-9a-f]{32})", path)
        if match:
            if not self.store.delete_file(user["id"], match.group(1)):
                return self.error_json(404, "文件不存在")
            return self.json_response(200, {"ok": True})
        match = re.fullmatch(r"/api/uploads/([0-9a-f]{32})", path)
        if match:
            upload = self.store.get_upload(match.group(1), user["id"])
            if not upload:
                return self.error_json(404, "续传任务不存在")
            self.store.cancel_upload(upload)
            return self.json_response(200, {"ok": True})
        return self.error_json(404, "未找到")

    def small_upload(self, user_id: int) -> None:
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            name = safe_name(urllib.parse.unquote(self.headers.get("X-File-Name", "")))
            expected = parse_checksum(self.headers.get("X-File-Sha256"))
            if length < 0 or length >= self.store.config.large_threshold:
                raise ValueError("文件大小不属于普通上传范围")
            self.store.ensure_space(user_id, length)
            temporary = self.store.parts_dir / (uuid.uuid4().hex + ".small")
            digest = hashlib.sha256()
            remaining = length
            try:
                with open(temporary, "wb") as out:
                    while remaining:
                        block = self.rfile.read(min(1024 * 1024, remaining))
                        if not block:
                            raise ConnectionError("上传中断")
                        out.write(block)
                        digest.update(block)
                        remaining -= len(block)
                    out.flush()
                    os.fsync(out.fileno())
                actual = digest.hexdigest()
                if not hmac.compare_digest(actual, expected):
                    raise ValueError("文件校验失败")
                result = self.store.add_file(user_id, name, temporary, length, actual)
                return self.json_response(201, {"file": result})
            finally:
                with contextlib.suppress(FileNotFoundError):
                    temporary.unlink()
        except (ValueError, OSError, ConnectionError) as exc:
            return self.error_json(400, str(exc))

    def download(self, user_id: int, file_id: str, head: bool) -> None:
        row = self.store.get_file(user_id, file_id)
        if not row:
            return self.error_json(404, "文件不存在")
        source = self.store.files_dir / row["disk_name"]
        if not source.is_file():
            return self.error_json(404, "文件不存在")
        size = row["size"]
        start, end, status = 0, size - 1, 200
        range_header = self.headers.get("Range")
        if range_header:
            match = re.fullmatch(r"bytes=(\d*)-(\d*)", range_header.strip())
            if not match:
                return self.range_error(size)
            left, right = match.groups()
            if not left and not right:
                return self.range_error(size)
            if not left:
                suffix = int(right)
                if suffix <= 0:
                    return self.range_error(size)
                start = max(0, size - suffix)
            else:
                start = int(left)
                end = min(size - 1, int(right)) if right else size - 1
            if start >= size or start > end:
                return self.range_error(size)
            status = 206
        length = max(0, end - start + 1)
        self.send_response(status)
        self.send_common()
        self.send_header("Accept-Ranges", "bytes")
        self.send_header("Content-Length", str(length))
        self.send_header("Content-Type", mimetypes.guess_type(row["name"])[0] or "application/octet-stream")
        self.send_header("Last-Modified", formatdate(source.stat().st_mtime, usegmt=True))
        self.send_header("ETag", f'"sha256-{row["checksum"]}"')
        fallback = re.sub(r"[^A-Za-z0-9._-]", "_", row["name"]) or "download"
        quoted = urllib.parse.quote(row["name"], safe="")
        self.send_header("Content-Disposition", f"attachment; filename=\"{fallback}\"; filename*=UTF-8''{quoted}")
        if status == 206:
            self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
        self.end_headers()
        if head:
            return
        try:
            with open(source, "rb") as handle:
                handle.seek(start)
                remaining = length
                while remaining:
                    block = handle.read(min(1024 * 1024, remaining))
                    if not block:
                        break
                    self.wfile.write(block)
                    remaining -= len(block)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def range_error(self, size: int) -> None:
        self.send_response(416)
        self.send_common()
        self.send_header("Content-Range", f"bytes */{size}")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def static(self, path: str, head: bool) -> None:
        mapping = {"/": "index.html", "/app.css": "app.css", "/app.js": "app.js"}
        name = mapping.get(path)
        if not name:
            return self.error_json(404, "未找到")
        source = STATIC_DIR / name
        try:
            raw = source.read_bytes()
        except OSError:
            return self.error_json(500, "静态文件缺失")
        mime = {"html": "text/html; charset=utf-8", "css": "text/css; charset=utf-8", "js": "text/javascript; charset=utf-8"}[name.rsplit(".", 1)[1]]
        self.send_response(200)
        self.send_common()
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        if not head:
            self.wfile.write(raw)


def local_addresses(port: int) -> list[str]:
    found = {"127.0.0.1"}
    with contextlib.suppress(OSError):
        for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            address = item[4][0]
            if not address.startswith("127."):
                found.add(address)
    return [f"http://{address}:{port}" for address in sorted(found, key=lambda x: x.startswith("127."), reverse=True)]


def parse_args() -> Config:
    parser = argparse.ArgumentParser(description="局域网文件中转站")
    parser.add_argument("--listen", default="0.0.0.0", help="监听地址，默认 0.0.0.0")
    parser.add_argument("--port", type=int, default=8080, help="端口，默认 8080")
    parser.add_argument("--data", type=Path, default=APP_DIR / "data", help="数据目录")
    parser.add_argument("--large-threshold-mb", type=int, default=128, help="分片上传阈值，默认 128MB")
    parser.add_argument("--chunk-mb", type=int, default=8, help="分片大小，默认 8MB")
    parser.add_argument("--max-storage-gb", type=float, default=0, help="每用户空间上限，0 为不限")
    parser.add_argument("--users", type=Path, help="UTF-8 用户白名单文件，每行 用户名:密码")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or not 1 <= args.chunk_mb <= 64 or args.large_threshold_mb < args.chunk_mb:
        parser.error("端口或分片参数无效")
    return Config(
        data_dir=args.data.expanduser().resolve(), listen=args.listen, port=args.port,
        large_threshold=args.large_threshold_mb * 1024 * 1024,
        chunk_size=args.chunk_mb * 1024 * 1024,
        max_storage_bytes=max(0, int(args.max_storage_gb * 1024**3)),
        users_file=args.users.expanduser().resolve() if args.users else None,
    )


def main() -> None:
    config = parse_args()
    if not all((STATIC_DIR / name).is_file() for name in ("index.html", "app.css", "app.js")):
        raise SystemExit(f"静态文件不完整：{STATIC_DIR}")
    store = Store(config)
    server = RelayServer((config.listen, config.port), Handler, store)
    print("\n".join(local_addresses(config.port)), flush=True)
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        print("\n已停止", file=sys.stderr)
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
