# -*- coding: utf-8 -*-
"""network_breakthrough — Đột phá tầng mạng toàn diện cho Toolkit patchx.

Kết hợp 3 trụ cột can thiệp tầng mạng thế hệ mới:
1. AxmlNetworkEnabler:
   - Mở khóa toàn diện lưu lượng văn bản thuần (Cleartext Traffic) và ép tin tưởng chứng chỉ
     người dùng (User CA) thông qua Network Security Config trực tiếp trên APK/AXML/XML.
2. UniversalSslPinningNullifier:
   - Ma trận vô hiệu hóa SSL/TLS Pinning đa tầng (Java OkHttp, Conscrypt, Trustkit, Cronet,
     BoringSSL native và Flutter libflutter.so) thông qua Frida Script tự sinh.
3. PacketForgeBridge:
   - Cầu nối tích hợp tự động với PacketProxy của packet_security, tự động làm giả phản hồi API
     (API Entitlement Forging) theo thời gian thực (JSON VIP, gói thuê bao, mã trạng thái).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional


class AxmlNetworkEnabler:
    """Mở khóa cấu hình an ninh mạng trong AndroidManifest và tệp tài nguyên XML."""

    NSC_CONTENT = """<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <base-config cleartextTrafficPermitted="true">
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </base-config>
    <debug-overrides>
        <trust-anchors>
            <certificates src="system" />
            <certificates src="user" />
        </trust-anchors>
    </debug-overrides>
</network-security-config>
"""

    @classmethod
    def enable_on_tree(cls, tree_dir: str | Path) -> Dict[str, Any]:
        """Kích hoạt cấu hình an ninh mạng trên cây thư mục APK đã giải mã."""
        tree = Path(tree_dir)
        manifest_path = tree / "AndroidManifest.xml"
        res_dir = tree / "res" / "xml"
        nsc_path = res_dir / "network_security_config.xml"

        result = {
            "success": False,
            "manifest_patched": False,
            "nsc_created": False,
            "details": [],
        }

        if not manifest_path.is_file():
            result["details"].append("Không tìm thấy AndroidManifest.xml trong cây")
            return result

        # 1. Tạo tệp network_security_config.xml
        try:
            res_dir.mkdir(parents=True, exist_ok=True)
            nsc_path.write_text(cls.NSC_CONTENT, encoding="utf-8")
            result["nsc_created"] = True
            result["details"].append(f"Đã tạo: {nsc_path.relative_to(tree)}")
        except Exception as e:
            result["details"].append(f"Lỗi tạo tệp NSC: {e}")

        # 2. Sửa AndroidManifest.xml để thêm thuộc tính
        try:
            content = manifest_path.read_text(encoding="utf-8", errors="replace")
            app_match = re.search(r"<application\b([^>]*)>", content)
            if app_match:
                attrs = app_match.group(1)
                new_attrs = attrs
                if "android:usesCleartextTraffic" not in attrs:
                    new_attrs += ' android:usesCleartextTraffic="true"'
                if "android:networkSecurityConfig" not in attrs:
                    new_attrs += ' android:networkSecurityConfig="@xml/network_security_config"'

                if new_attrs != attrs:
                    content = content[:app_match.start(1)] + new_attrs + content[app_match.end(1):]
                    manifest_path.write_text(content, encoding="utf-8")
                    result["manifest_patched"] = True
                    result["details"].append("Đã thêm usesCleartextTraffic và networkSecurityConfig vào <application>")
                else:
                    result["manifest_patched"] = True
                    result["details"].append("Cấu hình mạng trong manifest đã có sẵn")
        except Exception as e:
            result["details"].append(f"Lỗi sửa AndroidManifest.xml: {e}")

        result["success"] = result["nsc_created"] and result["manifest_patched"]
        return result

    @classmethod
    def enable_on_apk_fast(cls, apk_path: str | Path, output_apk: Optional[str | Path] = None) -> Dict[str, Any]:
        """Áp dụng nhanh trực tiếp trên tệp APK không cần giải mã apktool."""
        from .axml_editor import bypass_network_security_config
        apk = Path(apk_path)
        out = Path(output_apk) if output_apk else apk

        res = bypass_network_security_config(str(apk))
        return {
            "success": res.get("status") == "success" or res.get("has_network_security_config", False),
            "original_apk": str(apk),
            "output_apk": str(out),
            "axml_result": res,
        }


class UniversalSslPinningNullifier:
    """Bộ sinh mã Frida Script vô hiệu hóa SSL Pinning đa tầng toàn năng."""

    @staticmethod
    def generate_script(output_file: Optional[str | Path] = None) -> str:
        """Sinh mã JavaScript Frida vượt qua mọi cơ chế kiểm tra chứng chỉ và ghim khóa."""
        js_code = r"""// ==============================================================================
// UNIVERSAL MULTI-LAYER SSL/TLS PINNING NULLIFIER & TRAFFIC ENABLER
// Hỗ trợ: Java TrustManager, OkHttp 3/4/5, Conscrypt, Trustkit, Cronet,
//         Native OpenSSL/BoringSSL và Flutter libflutter.so.
// ==============================================================================

Java.perform(function () {
    console.log('[+] Đang kích hoạt Universal SSL Pinning Nullifier...');

    // 1. Vô hiệu hóa X509TrustManager phổ quát
    try {
        var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
        var SSLContext = Java.use('javax.net.ssl.SSLContext');
        var TrustManager = Java.registerClass({
            name: 'com.patchx.universal.TrustAllManager',
            implements: [X509TrustManager],
            methods: {
                checkClientTrusted: function (chain, authType) {},
                checkServerTrusted: function (chain, authType) {},
                getAcceptedIssuers: function () { return []; }
            }
        });
        var trustManagers = [TrustManager.$new()];
        var SSLContext_init = SSLContext.init.overload(
            '[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom'
        );
        SSLContext_init.implementation = function (km, tm, sr) {
            SSLContext_init.call(this, km, trustManagers, sr);
        };
        console.log('  [+] Đã vô hiệu hóa javax.net.ssl.SSLContext & X509TrustManager');
    } catch (e) {
        console.log('  [-] Lưu ý X509TrustManager: ' + e);
    }

    // 2. Vô hiệu hóa OkHttp3 / OkHttp4 / OkHttp5 CertificatePinner
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function (hostname, peerCertificates) {
            // Không ném SSLPeerUnverifiedException
            return;
        };
        try {
            CertificatePinner.check.overload('java.lang.String', '[Ljava.security.cert.Certificate;').implementation = function (hostname, peerCertificates) {
                return;
            };
        } catch (e2) {}
        try {
            CertificatePinner['check$okhttp'].implementation = function (hostname, cleanedPeerCertificatesFn) {
                return;
            };
        } catch (e3) {}
        console.log('  [+] Đã vô hiệu hóa okhttp3.CertificatePinner');
    } catch (e) {
        console.log('  [-] Lưu ý OkHttp CertificatePinner: ' + e);
    }

    // 3. Vô hiệu hóa Conscrypt TrustManagerImpl
    try {
        var ConscryptTrustManager = Java.use('org.conscrypt.TrustManagerImpl');
        ConscryptTrustManager.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            return untrustedChain;
        };
        console.log('  [+] Đã vô hiệu hóa Conscrypt TrustManagerImpl');
    } catch (e) {}

    // 4. Vô hiệu hóa TrustKit OkHostnameVerifier
    try {
        var TrustKitVerifier = Java.use('com.datatheorem.android.trustkit.pinning.OkHostnameVerifier');
        TrustKitVerifier.verify.overload('java.lang.String', 'javax.net.ssl.SSLSession').implementation = function (h, s) {
            return true;
        };
        console.log('  [+] Đã vô hiệu hóa TrustKit OkHostnameVerifier');
    } catch (e) {}

    // 5. Vô hiệu hóa HostnameVerifier mặc định
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        var NullVerifier = Java.registerClass({
            name: 'com.patchx.universal.NullHostnameVerifier',
            implements: [HostnameVerifier],
            methods: {
                verify: function (hostname, session) { return true; }
            }
        });
        HttpsURLConnection.setDefaultHostnameVerifier(NullVerifier.$new());
        console.log('  [+] Đã thiết lập DefaultHostnameVerifier -> Always True');
    } catch (e) {}
});

// ==============================================================================
// NATIVE SSL / BORINGSSL / FLUTTER BYPASS
// ==============================================================================
try {
    // A. Hook BoringSSL trong libflutter.so (nếu ứng dụng Flutter)
    var flutterModule = Process.findModuleByName('libflutter.so');
    if (flutterModule) {
        console.log('[+] Tìm thấy libflutter.so tại ' + flutterModule.base);
        // Quét mẫu bytecode hàm session_verify_cert_chain trong BoringSSL của Flutter
        // ARM64 pattern: 0xf? 0x0f 0x1d 0xaa ...
        Memory.scan(flutterModule.base, flutterModule.size, 'ff 83 01 d1 fd 7b 02 a9 fc 6f 03 a9', {
            onMatch: function (address, size) {
                console.log('  [+] Đã tìm thấy điểm neo xác thực chứng chỉ Flutter tại: ' + address);
                Interceptor.attach(address, {
                    onLeave: function (retval) {
                        // Ép hàm trả về 1 (thành công)
                        retval.replace(ptr(1));
                    }
                });
            },
            onError: function (reason) {},
            onComplete: function () {}
        });
    }

    // B. Hook các hàm kiểm tra chứng chỉ Native C chuẩn
    var ssl_set_verify = Module.findExportByName(null, 'SSL_set_verify');
    if (ssl_set_verify) {
        Interceptor.attach(ssl_set_verify, {
            onEnter: function (args) {
                // args[1] = mode -> đặt về SSL_VERIFY_NONE (0)
                args[1] = ptr(0);
            }
        });
        console.log('[+] Đã hook native SSL_set_verify -> SSL_VERIFY_NONE');
    }

    var ssl_ctx_set_custom_verify = Module.findExportByName(null, 'SSL_CTX_set_custom_verify');
    if (ssl_ctx_set_custom_verify) {
        Interceptor.attach(ssl_ctx_set_custom_verify, {
            onEnter: function (args) {
                // args[1] = mode -> 0
                args[1] = ptr(0);
            }
        });
        console.log('[+] Đã hook native SSL_CTX_set_custom_verify');
    }
} catch (nativeErr) {
    console.log('[-] Lưu ý Native SSL Hook: ' + nativeErr);
}
"""
        if output_file:
            p = Path(output_file)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(js_code, encoding="utf-8")
        return js_code


class PacketForgeBridge:
    """Cầu nối làm giả phản hồi mạng theo quy tắc tự động hóa."""

    DEFAULT_RULES = [
        {"pattern": r'"is_vip"\s*:\s*false', "replacement": '"is_vip":true'},
        {"pattern": r'"is_premium"\s*:\s*false', "replacement": '"is_premium":true'},
        {"pattern": r'"subscribed"\s*:\s*false', "replacement": '"subscribed":true'},
        {"pattern": r'"status"\s*:\s*"expired"', "replacement": '"status":"active"'},
        {"pattern": r'"code"\s*:\s*403', "replacement": '"code":200'},
        {"pattern": r'"has_license"\s*:\s*false', "replacement": '"has_license":true'},
    ]

    def __init__(self, rules: Optional[List[Dict[str, str]]] = None):
        self.rules = rules or list(self.DEFAULT_RULES)

    def forge_payload(self, data: bytes) -> bytes:
        """Duyệt và thay thế nội dung phản hồi gói tin nếu là dữ liệu văn bản/JSON."""
        try:
            text = data.decode("utf-8")
            modified = text
            for rule in self.rules:
                pat = rule["pattern"]
                rep = rule["replacement"]
                modified = re.sub(pat, rep, modified)
            if modified != text:
                return modified.encode("utf-8")
        except UnicodeDecodeError:
            pass
        return data


def apply_network_bypass(
    target_path: str | Path,
    output_dir: Optional[str | Path] = None,
    enable_cleartext: bool = True,
    gen_ssl_script: bool = True,
) -> Dict[str, Any]:
    """Hàm điều phối toàn diện cho đột phá tầng mạng."""
    target = Path(target_path)
    out_dir = Path(output_dir or "outputs/network_bypass")
    out_dir.mkdir(parents=True, exist_ok=True)

    report: Dict[str, Any] = {
        "target": str(target),
        "is_tree": target.is_dir(),
        "is_apk": target.is_file() and target.suffix.lower() == ".apk",
        "nsc_enabler": None,
        "ssl_script_path": None,
        "forge_rules_count": len(PacketForgeBridge.DEFAULT_RULES),
    }

    # 1. Kích hoạt NSC & Cleartext
    if enable_cleartext:
        if target.is_dir():
            report["nsc_enabler"] = AxmlNetworkEnabler.enable_on_tree(target)
        elif report["is_apk"]:
            report["nsc_enabler"] = AxmlNetworkEnabler.enable_on_apk_fast(target)

    # 2. Sinh tập lệnh SSL Pinning Nullifier
    if gen_ssl_script:
        script_file = out_dir / "universal_ssl_nullifier.js"
        UniversalSslPinningNullifier.generate_script(script_file)
        report["ssl_script_path"] = str(script_file)

    report["success"] = True
    return report
