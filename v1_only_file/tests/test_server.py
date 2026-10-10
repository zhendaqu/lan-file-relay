import hashlib
import http.client
import json
import tempfile
import threading
import unittest
from pathlib import Path

import server


class RelayHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        config = server.Config(
            data_dir=Path(self.temp.name), listen="127.0.0.1", port=0,
            large_threshold=10, chunk_size=4, max_storage_bytes=0,
        )
        self.store = server.Store(config)
        self.httpd = server.RelayServer(("127.0.0.1", 0), server.Handler, self.store)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()
        self.port = self.httpd.server_address[1]

    def tearDown(self):
        self.httpd.shutdown()
        self.httpd.server_close()
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None, cookie=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=5)
        headers = dict(headers or {})
        if cookie:
            headers["Cookie"] = cookie
        if isinstance(body, dict):
            body = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read()
        result_headers = dict(response.getheaders())
        conn.close()
        try:
            parsed = json.loads(raw) if raw else None
        except json.JSONDecodeError:
            parsed = raw
        return response.status, result_headers, parsed

    def login(self, username):
        status, headers, body = self.request("POST", "/api/login", {"username": username, "password": "secret1"})
        self.assertEqual(status, 200, body)
        return headers["Set-Cookie"].split(";", 1)[0]

    def login_with_password(self, username, password):
        status, headers, body = self.request("POST", "/api/login", {"username": username, "password": password})
        self.assertEqual(status, 200, body)
        return headers["Set-Cookie"].split(";", 1)[0]

    def test_user_isolation_small_upload_range_and_delete(self):
        alice = self.login("alice")
        bob = self.login("bob")
        payload = b"small"
        checksum = hashlib.sha256(payload).hexdigest()
        status, _, body = self.request(
            "POST", "/api/files/small", payload,
            {"X-File-Name": "note.txt", "X-File-Sha256": checksum}, alice,
        )
        self.assertEqual(status, 201, body)
        file_id = body["file"]["id"]
        self.assertEqual(self.request("GET", "/api/files", cookie=bob)[2]["files"], [])
        status, headers, ranged = self.request(
            "GET", f"/api/files/{file_id}/download", headers={"Range": "bytes=1-3"}, cookie=alice
        )
        self.assertEqual((status, ranged), (206, b"mal"))
        self.assertEqual(headers["Content-Range"], "bytes 1-3/5")
        self.assertEqual(self.request("GET", f"/api/files/{file_id}/download", cookie=bob)[0], 404)
        self.assertEqual(self.request("DELETE", f"/api/files/{file_id}", cookie=alice)[0], 200)

    def test_large_upload_resume_and_manifest(self):
        cookie = self.login("large-user")
        payload = b"abcdefghijklmnopq"
        file_key = hashlib.sha256(b"fixture").hexdigest()
        status, _, upload = self.request(
            "POST", "/api/uploads/init",
            {"name": "large.bin", "size": len(payload), "file_key": file_key}, cookie=cookie,
        )
        self.assertEqual(status, 200, upload)
        hashes = []
        for index in range(upload["total_chunks"]):
            chunk = payload[index * 4:(index + 1) * 4]
            digest = hashlib.sha256(chunk).hexdigest()
            hashes.append(digest)
            if index == 0:
                rejected = self.request(
                    "PUT", f"/api/uploads/{upload['id']}/chunks/{index}", chunk,
                    {"X-Chunk-Sha256": "0" * 64}, cookie,
                )
                self.assertEqual(rejected[0], 400)
            status, _, body = self.request(
                "PUT", f"/api/uploads/{upload['id']}/chunks/{index}", chunk,
                {"X-Chunk-Sha256": digest}, cookie,
            )
            self.assertEqual(status, 200, body)
            if index == 1:
                resumed = self.request(
                    "POST", "/api/uploads/init",
                    {"name": "large.bin", "size": len(payload), "file_key": file_key}, cookie=cookie,
                )[2]
                self.assertEqual([x["index"] for x in resumed["received"]], [0, 1])
        manifest = hashlib.sha256(b"".join(bytes.fromhex(x) for x in hashes)).hexdigest()
        status, _, result = self.request(
            "POST", f"/api/uploads/{upload['id']}/complete",
            {"manifest_checksum": manifest}, cookie=cookie,
        )
        self.assertEqual(status, 201, result)
        file_id = result["file"]["id"]
        self.assertEqual(result["file"]["checksum"], hashlib.sha256(payload).hexdigest())
        self.assertEqual(self.request("GET", f"/api/files/{file_id}/download", cookie=cookie)[2], payload)

    def test_whitelist_file_reloads_and_revokes_session(self):
        users_file = Path(self.temp.name) / "users.txt"
        users_file.write_text("alice:file-password\n", encoding="utf-8")
        self.store.config.users_file = users_file
        self.store.load_whitelist(force=True)

        denied = self.request("POST", "/api/login", {"username": "bob", "password": "file-password"})
        self.assertEqual(denied[0], 401)
        cookie = self.login_with_password("alice", "file-password")
        self.assertTrue(self.request("GET", "/api/session", cookie=cookie)[2]["authenticated"])

        users_file.write_text("# alice removed\n", encoding="utf-8")
        self.assertFalse(self.request("GET", "/api/session", cookie=cookie)[2]["authenticated"])


if __name__ == "__main__":
    unittest.main()
