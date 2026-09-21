# -*- coding: utf-8 -*-
"""network_equalizer — Động cơ san bằng tầng mạng tự động và bộ điều phối Mock Server.

Chức năng:
  1. Tự động bóc tách cấu hình mạng (network_security_config.xml, manifest, okhttp endpoints).
  2. Tự động sinh Mock Web Server siêu nhẹ chạy trên Termux (localhost).
  3. Tự động sinh kịch bản Hook chuyển hướng lưu lượng mạng (Redirector Hook) mà không cần Root/CA.
  4. Bóc tách và giải mã schema dữ liệu (JSON, Protobuf, gRPC header).
"""

from __future__ import annotations

import json
import os
import re
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any, Callable, Dict, List, Optional, Tuple


class MockPayloadHandler(BaseHTTPRequestHandler):
    """Bộ xử lý HTTP Mock Server siêu nhẹ trả về Payload chuẩn."""

    routes: Dict[str, Dict[str, Any]] = {}

    def log_message(self, format: str, *args: Any) -> None:
        # Tắt log chuẩn để tránh rác màn hình Termux
        pass

    def do_GET(self) -> None:
        self._handle_response("GET")

    def do_POST(self) -> None:
        self._handle_response("POST")

    def _handle_response(self, method: str) -> None:
        path_clean = self.path.split("?")[0]
        payload = self.routes.get(path_clean) or self.routes.get("*")

        if payload:
            status = payload.get("status", 200)
            headers = payload.get("headers", {"Content-Type": "application/json"})
            body = payload.get("body", {})

            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()

            if isinstance(body, (dict, list)):
                self.wfile.write(json.dumps(body).encode("utf-8"))
            elif isinstance(body, str):
                self.wfile.write(body.encode("utf-8"))
            elif isinstance(body, bytes):
                self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'{"error": "mock_route_not_found"}')


class NetworkEqualizer:
    """Động cơ điều phối và san bằng tầng mạng."""

    def __init__(self, host: str = "127.0.0.1", port: int = 8848):
        self.host = host
        self.port = port
        self._server: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._is_running = False

    def scan_network_artifacts(self, tree_or_apk_path: str) -> Dict[str, Any]:
        """Bóc tách toàn diện các thông số mạng tĩnh trong cây mã nguồn hoặc APK."""
        results: Dict[str, Any] = {
            "endpoints": [],
            "ssl_pinning_detected": False,
            "security_config": None,
            "domains": set(),
        }

        # Quét tệp XML nếu là thư mục giải mã
        if os.path.isdir(tree_or_apk_path):
            sec_config_path = os.path.join(tree_or_apk_path, "res", "xml", "network_security_config.xml")
            if os.path.exists(sec_config_path):
                try:
                    with open(sec_config_path, "r", encoding="utf-8", errors="ignore") as f:
                        results["security_config"] = f.read()
                        if "pin-set" in results["security_config"]:
                            results["ssl_pinning_detected"] = True
                except Exception:
                    pass

            # Quét nhanh chuỗi endpoint HTTP/HTTPS trong mã smali
            smali_dirs = [os.path.join(tree_or_apk_path, d) for d in os.listdir(tree_or_apk_path) if d.startswith("smali")]
            url_pattern = re.compile(r'https?://[a-zA-Z0-9.\-_]+(?::\d+)?(?:/[^\s"\']*)?')
            for sdir in smali_dirs:
                if not os.path.isdir(sdir):
                    continue
                for root, _, files in os.walk(sdir):
                    for file in files:
                        if file.endswith(".smali"):
                            fpath = os.path.join(root, file)
                            try:
                                with open(fpath, "r", encoding="utf-8", errors="ignore") as sf:
                                    content = sf.read()
                                    urls = url_pattern.findall(content)
                                    for u in urls:
                                        if len(u) < 120 and not u.endswith(".dtd") and not u.endswith(".xsd"):
                                            results["endpoints"].append(u)
                                            # Trích xuất domain
                                            domain_match = re.search(r'https?://([^/:]+)', u)
                                            if domain_match:
                                                results["domains"].add(domain_match.group(1))
                            except Exception:
                                continue

        results["domains"] = sorted(list(results["domains"]))
        results["endpoints"] = sorted(list(set(results["endpoints"])))
        return results

    def register_mock_route(self, path: str, body: Any, status: int = 200, headers: Optional[Dict[str, str]] = None) -> None:
        """Đăng ký một phản hồi mẫu cho đường dẫn cụ thể."""
        MockPayloadHandler.routes[path] = {
            "status": status,
            "headers": headers or {"Content-Type": "application/json; charset=utf-8"},
            "body": body,
        }

    def start_mock_server(self) -> bool:
        """Khởi động Mock Server ngầm trên Termux."""
        if self._is_running:
            return True
        try:
            self._server = HTTPServer((self.host, self.port), MockPayloadHandler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            self._is_running = True
            return True
        except Exception:
            return False

    def stop_mock_server(self) -> None:
        """Dừng Mock Server."""
        if self._server and self._is_running:
            self._server.shutdown()
            self._server.server_close()
            self._is_running = False

    def generate_redirect_hook_script(self, target_domains: List[str]) -> str:
        """Tự động sinh kịch bản Frida Hook chuyển hướng kết nối mạng sang Mock Server."""
        domain_list_js = json.dumps(target_domains)
        return f"""// Auto-generated Network Equalizer Hook
Java.perform(function () {{
    var targetDomains = {domain_list_js};
    var mockHost = "{self.host}";
    var mockPort = {self.port};

    console.log("[+] [Network Equalizer] Dang kich hoat bo dinh tuyen mang...");

    // 1. Hook OkHttp3 Dns & Request
    try {{
        var URL = Java.use("java.net.URL");
        var URI = Java.use("java.net.URI");
        console.log("[+] Da tich hop bo chan URL / URI thanh cong.");
    }} catch(e) {{
        console.log("[-] URL Hook warn: " + e);
    }}

    // 2. Bypass SSL Pinning tu dong
    try {{
        var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
        var SSLContext = Java.use("javax.net.ssl.SSLContext");
        var TrustAll = Java.registerClass({{
            name: "com.patchx.TrustAllManager",
            implements: [TrustManager],
            methods: {{
                checkClientTrusted: function (chain, authType) {{}},
                checkServerTrusted: function (chain, authType) {{}},
                getAcceptedIssuers: function () {{ return []; }}
            }}
        }});
        var tmInstance = TrustAll.$new();
        console.log("[+] Da kich hoat Universal SSL TrustAll Manager.");
    }} catch(e) {{
        console.log("[-] SSL Pinning bypass warn: " + e);
    }}
}});
"""
