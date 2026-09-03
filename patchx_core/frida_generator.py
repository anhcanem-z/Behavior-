from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, List

try:
    from .crypto_interceptor import CryptoInterceptorGenerator
except ImportError:
    from crypto_interceptor import CryptoInterceptorGenerator


class FridaScriptGenerator:
    """Bien dich Script Frida ket hop giua Hook tu dong, Generic SSL Bypass, Crypto Interceptor va Frida RPC Control."""

    def __init__(self):
        self.hooks: List[str] = []

    def generate(self, targets: List[Any], output_file: str | Path = "generated_hook.js") -> str:
        self.hooks.clear()

        header = (
            "// Dynamic Frida Agent - Controlled via RPC\n"
            "var GLOBAL_VIP_OVERRIDE = true;\n"
            "var GLOBAL_SSL_BYPASS = true;\n"
            "var GLOBAL_FAKE_LOGGED_IN = true;\n"
            "var GLOBAL_LOGIN_BYPASS = true;\n"
            "var GLOBAL_SKIP_LOGIN_GATE = true;\n"
            "var MOCK_API_RESPONSE = null;\n\n"
            "Java.perform(function () {\n"
            "    console.log('[+] Dynamic Frida RPC Engine Initialized');\n"
        )

        crypto_code = CryptoInterceptorGenerator.generate_crypto_hooks()

        ssl_generic_bypass = (
            "    // --- Generic SSL Pinning Bypass ---\n"
            "    try {\n"
            "        var array_list = Java.use('java.util.ArrayList');\n"
            "        var TrustManager = Java.use('javax.net.ssl.X509TrustManager');\n"
            "        var SSLContext = Java.use('javax.net.ssl.SSLContext');\n"
            "        var TrustManagerImpl = Java.registerClass({\n"
            "            name: 'com.bypass.TrustManager',\n"
            "            implements: [TrustManager],\n"
            "            methods: {\n"
            "                checkClientTrusted: function (chain, authType) {},\n"
            "                checkServerTrusted: function (chain, authType) {},\n"
            "                getAcceptedIssuers: function () { return []; }\n"
            "            }\n"
            "        });\n"
            "        var TrustManagers = [TrustManagerImpl.$new()];\n"
            "        var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');\n"
            "        SSLContext_init.implementation = function (keyManager, trustManager, secureRandom) {\n"
            "            SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);\n"
            "        };\n"
            "        console.log('[+] Generic SSL Pinning Bypassed');\n"
            "    } catch (err) { console.log('[-] SSL Bypass Notice: ' + err); }\n"
        )
        okhttp_interceptor = (
            "    // --- KN 1: Dynamic OkHttp Interceptor Injection ---\n"
            "    try {\n"
            "        var Interceptor = Java.use('okhttp3.Interceptor');\n"
            "        var ResponseBody = Java.use('okhttp3.ResponseBody');\n"
            "        var OkHttpInterceptor = Java.registerClass({\n"
            "            name: 'com.patchx.runtime.NetworkInterceptor',\n"
            "            implements: [Interceptor],\n"
            "            methods: {\n"
            "                intercept: function (chain) {\n"
            "                    var request = chain.request();\n"
            "                    var newReq = request.newBuilder()\n"
            "                        .header('X-App-Env', 'staging')\n"
            "                        .header('X-Client-Group', 'beta_pro')\n"
            "                        .build();\n"
            "                    var response = chain.proceed(newReq);\n"
            "                    var body = response.body();\n"
            "                    var mediaType = body ? body.contentType() : null;\n"
            "                    if (mediaType && mediaType.toString().indexOf('application/json') !== -1) {\n"
            "                        var source = body.source();\n"
            "                        source.request(1048576);\n"
            "                        var json = source.buffer().clone().readUtf8();\n"
            "                        var modified = json.replace(/\"(is_vip|is_premium|is_subscribed|has_active_entitlement)\":\\s*false/g, '\"$1\":true');\n"
            "                        return response.newBuilder().body(ResponseBody.create(mediaType, modified)).build();\n"
            "                    }\n"
            "                    return response;\n"
            "                }\n"
            "            }\n"
            "        });\n"
            "        Java.use('okhttp3.OkHttpClient$Builder').build.implementation = function () {\n"
            "            this.addInterceptor(OkHttpInterceptor.$new());\n"
            "            return this.build();\n"
            "        };\n"
            "        console.log('[+] OkHttp Network Interceptor Injected');\n"
            "    } catch (err) { console.log('[-] OkHttp Interceptor Notice: ' + err); }\n"
        )

        device_spoof = (
            "    // --- KN 7: Device Identity Rotation (Android ID) ---\n"
            "    try {\n"
            "        var SettingsSecure = Java.use('android.provider.Settings$Secure');\n"
            "        SettingsSecure.getString.overload('android.content.ContentResolver', 'java.lang.String').implementation = function (resolver, name) {\n"
            "            if (name === 'android_id') {\n"
            "                return '35' + Math.floor(10000000000000 + Math.random() * 90000000000000);\n"
            "            }\n"
            "            return this.getString(resolver, name);\n"
            "        };\n"
            "        console.log('[+] Device ID Rotator Hooked');\n"
            "    } catch (err) { console.log('[-] Device ID Rotator Notice: ' + err); }\n"
        )

        rasp_bypass = (
            "    // --- KN 6: RASP Anti-Debug & ptrace Bypass ---\n"
            "    try {\n"
            "        var ptrace = Module.findExportByName(null, 'ptrace');\n"
            "        if (ptrace) {\n"
            "            Interceptor.attach(ptrace, {\n"
            "                onLeave: function (retval) { retval.replace(0); }\n"
            "            });\n"
            "            console.log('[+] RASP ptrace & Anti-Debug Bypassed');\n"
            "        }\n"
            "    } catch (err) { console.log('[-] RASP Bypass Notice: ' + err); }\n"
        )

        for target in targets:
            if hasattr(target, "to_frida_hook_config"):
                hook = target.to_frida_hook_config()
                target_info = hook.get("target", {})
                frida_code = hook.get("frida_script")
                if not target_info.get("class") or not target_info.get("method"):
                    continue
            else:
                target_dict = target.to_dict() if hasattr(target, "to_dict") else (target if isinstance(target, dict) else {})
                target_info = target_dict.get("target", {})
                strategy = target_dict.get("suggested_actions", {}).get("auto_strategy", {}) if isinstance(target_dict, dict) else {}
                frida_code = target_dict.get("frida_script") or strategy.get("frida_hook_script")
                if not target_info.get("class") or not target_info.get("method"):
                    continue

            if frida_code and frida_code not in self.hooks:
                self.hooks.append(frida_code)

        body = "\n\n".join(f"    // Hook Entry {i+1}\n    {code}" for i, code in enumerate(self.hooks))

        rpc_exports = """
// =====================================================
// RPC CONTROL INTERFACE (DIEU KHIEN HANH VI TU XA)
// =====================================================
rpc.exports = {
    set_vip_status: function (enable) {
        GLOBAL_VIP_OVERRIDE = enable;
        console.log('[RPC] Command Received: Set VIP = ' + enable);
        return 'SUCCESS_VIP_' + enable;
    },
    override_api_response: function (jsonStr) {
        MOCK_API_RESPONSE = jsonStr;
        console.log('[RPC] Command Received: Mock API Response Loaded');
        return 'SUCCESS_MOCK_LOADED';
    },
    toggle_ssl_bypass: function (enable) {
        GLOBAL_SSL_BYPASS = enable;
        console.log('[RPC] Command Received: Toggle SSL Bypass = ' + enable);
        return 'SUCCESS_SSL_' + enable;
    },
    set_fake_logged_in: function (enable) {
        GLOBAL_FAKE_LOGGED_IN = enable;
        console.log('[RPC] Command Received: Fake Logged In = ' + enable);
        return 'SUCCESS_FAKE_LOGGED_IN_' + enable;
    },
    set_login_bypass: function (enable) {
        GLOBAL_LOGIN_BYPASS = enable;
        console.log('[RPC] Command Received: Login Bypass = ' + enable);
        return 'SUCCESS_LOGIN_BYPASS_' + enable;
    },
    set_skip_login_gate: function (enable) {
        GLOBAL_SKIP_LOGIN_GATE = enable;
        console.log('[RPC] Command Received: Skip Login Gate = ' + enable);
        return 'SUCCESS_SKIP_LOGIN_GATE_' + enable;
    }
};
"""

        footer = "\n});\n"
        full_script = f"{header}\n{crypto_code}\n{ssl_generic_bypass}\n{okhttp_interceptor}\n{device_spoof}\n{rasp_bypass}\n{body}{footer}\n{rpc_exports}"

        if output_file:
            Path(output_file).write_text(full_script, encoding="utf-8")

        return full_script


def frida_main(input_file: str | Path | None = None, output_file: str | Path = "generated_hook.js", *args, **kwargs):
    """Ham thuc thi ho tro ca truyen tham so truc tiep tu cli.py va qua argparse."""
    if input_file is None:
        parser = argparse.ArgumentParser(description="Bo sinh script Frida PatchX")
        parser.add_argument("-i", "--input", required=True, help="Duong dan tệp dau vao")
        parser.add_argument("-o", "--output", default="generated_hook.js", help="Duong dan tệp JS xuat ra")

        args_parsed = parser.parse_args()
        input_path = Path(args_parsed.input)
        out_file = args_parsed.output
    else:
        input_path = Path(input_file)
        out_file = output_file

    if not input_path.exists():
        print(f"[-] Loi: Khong tim thay tệp dau vao: {input_path}")
        sys.exit(1)

    targets = []
    try:
        with open(input_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                targets = data
            elif isinstance(data, dict):
                targets = data.get("targets", data.get("patches", [data]))
    except json.JSONDecodeError:
        print(f"[!] Tep {input_path} khong phai dang JSON, se tao Frida Script co ban (Crypto + SSL Bypass).")

    generator = FridaScriptGenerator()
    generator.generate(targets, output_file=out_file)
    print(f"[+] Da tao Frida Agent thanh cong: {out_file}")


main = frida_main

if __name__ == "__main__":
    frida_main()
