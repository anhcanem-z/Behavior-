from __future__ import annotations

import re
from pathlib import Path

# Behavior stack dependencies: CFG -> evidence model -> ontology.
from .cfg import CFGBuilder, build_cfg
from .model import Behavior, Evidence
from .ontology import BEHAVIORS


class BehaviorDetector:

    SENSITIVE_PATTERNS = (
        "isDebuggerConnected",
        "waitingForDebugger",
        "isDebuggerAttached",
        "TracerPid",
        "ptrace",
        "GET_SIGNATURES",
        "GET_SIGNING_CERTIFICATES",
        "getPackageInfo",
        "getApplicationInfo",
        "PackageManager",
        "Signature",
        "MessageDigest",
        "checkSelfPermission",
        "requestPermissions",
        "RequestPermission",
        "RequestMultiplePermissions",
        "LocationManager",
        "FusedLocationProviderClient",
        # Pro / Premium
        "isPro",
        "isPremium",
        "isVip",
        "isPurchased",
        "isSubscribed",
        "isUnlocked",
        "hasPremium",
        "hasVip",
        "hasAccess",
        "entitlement",
        "entitled",
        "unlocked",
        "paywall",
        "featureEnabled",
        "featureUnlocked",
        "noAds",
        "adFree",
        "trial",
        "subscription",
        "premium",
        # Google Play Billing
        "BillingClient",
        "PurchasesUpdatedListener",
        "onPurchasesUpdated",
        "queryPurchasesAsync",
        "getPurchaseState",
        "BillingResult",
        "querySkuDetailsAsync",
        "acknowledgePurchase",
        "launchBillingFlow",
        "consumePurchase",
        # SSL Pinning & TrustManager
        "checkServerTrusted",
        "CertificatePinner",
        "X509TrustManager",
        "HostnameVerifier",
        "SSLContext",
        "SSLSocketFactory",
        "TrustManager",
        "checkValidity",
        "CertPathValidator",
        "networkSecurityConfig",
        # Dependency / Environment
        "isGooglePlayServicesAvailable",
        "isRooted",
        "checkSuBinary",
        "RootBeer",
        "Magisk",
        "Superuser",
        "test-keys",
        "ro.debuggable",
        "ro.secure",
        # Login / Authentication / Session
        "isLoggedIn",
        "isAuthenticated",
        "isSignedIn",
        "hasSession",
        "signIn",
        "signOut",
        "FirebaseAuth",
        "getCurrentUser",
        "access_token",
        "refresh_token",
        "id_token",
        "Authorization",
        "X-Api-Key",
        "X-API-Key",
        "api_key",
        "apikey",
        "auth_token",
        "session_id",
        "client_secret",
        "Bearer",
        "oauth",
        "jwt",
    )

    DEBUG_APIS = (
        "isDebuggerConnected",
        "waitingForDebugger",
        "debugger",
        "isdebuggerattached",
        "tracerpid",
        "ptrace",
        "waitfordebugger",
    )

    INTEGRITY_APIS = (
        "GET_SIGNATURES",
        "GET_SIGNING_CERTIFICATES",
        "getPackageInfo",
        "getApplicationInfo",
        "Signature",
        "MessageDigest",
        "signingInfo",
        "getSigningCertificateHistory",
        "getApkContentsSigners",
        "CRC32",
        "checksum",
        "sourceDir",
        "publicSourceDir",
        "codePath",
        "lastUpdateTime",
        "firstInstallTime",
        "test-keys",
        "release-keys",
        "signingInfo",
        "getSigningCertificateHistory",
        "getApkContentsSigners",
        "getSignatures",
        "PackageInfo",
        "ApplicationInfo",
        "FLAG_DEBUGGABLE",
        "DEBUGGABLE",
        "CRC32",
        "checksum",
        "sourceDir",
        "publicSourceDir",
        "codePath",
        "lastUpdateTime",
        "firstInstallTime",
    )

    PRO_APIS = (
        "isPro",
        "isPremium",
        "isVip",
        "isSubscribed",
        "isPurchased",
        "isUnlocked",
        "hasPremium",
        "hasVip",
        "hasAccess",
        "is_premium",
        "is_vip",
        "is_pro",
        "entitlement",
        "entitled",
        "unlocked",
        "paywall",
        "subscription",
        "subscribed",
        "premium",
        "no_ads",
        "noads",
        "adfree",
        "has_subscription",
        "is_subscribed",
        "is_unlocked",
        "has_active_subscription",
        "subscription_active",
        "membership",
        "access_level",
    )

    BILLING_APIS = (
        "onPurchasesUpdated",
        "queryPurchasesAsync",
        "getPurchaseState",
        "BillingClient",
        "billingclient",
        "billingresult",
        "purchasesresult",
        "purchasehistoryrecord",
        "consumepurchase",
        "acknowledgepurchase",
        "launchbillingflow",
        "querypurchases",
        "queryskudetailsasync",
        "getskudetails",
        "isfeaturesupported",
        "productdetails",
        "subscriptionofferdetails",
        "billingflowparams",
    )

    SSL_APIS = (
        "checkServerTrusted",
        "checkClientTrusted",
        "CertificatePinner",
        "verify",
        "sslcontext",
        "sslsocketfactory",
        "x509trustmanager",
        "hostnameverifier",
        "checkvalidity",
        "certpathvalidator",
        "trustanchors",
        "cleartext",
        "networksecurityconfig",
        "setsslcontext",
        "initsslcontext",
        "configuretls",
        "checkpins",
        "pinning",
    )

    DEPENDENCY_APIS = (
        "isGooglePlayServicesAvailable",
        "isRooted",
        "checkSuBinary",
        "rootbeer",
        "magisk",
        "superuser",
        "ro.debuggable",
        "ro.secure",
        "ro.build.tags",
        "test-keys",
        "whichsu",
        "/system/xbin/su",
        "/sbin/su",
    )

    LOGIN_APIS = (
        "firebaseauth",
        "signinwithemailandpassword",
        "signinwithcredential",
        "createuserwithemailandpassword",
        "getcurrentuser",
        "isloggedin",
        "isauthenticated",
        "issignedin",
        "hassession",
        "islogin",
        "checksession",
        "validatesession",
        "accesstoken",
        "refreshtoken",
        "idtoken",
        "authorization",
        "x-api-key",
        "x-apikey",
        "x-access-token",
        "x-auth-token",
        "api_key",
        "apikey",
        "auth_token",
        "authtoken",
        "session_id",
        "sessionid",
        "client_secret",
        "client_id",
        "oauth",
        "bearer",
        "jwt",
        "openid",
        "open_id",
        "token_type",
        "expires_in",
        "grant_type",
        "client_credentials",
        "x-client-id",
        "x-device-id",
        "x-session-token",
    )

    API_APIS = (
        "https://",
        "http://",
        "ws://",
        "wss://",
        "x-api-key",
        "x-apikey",
        "apikey",
        "api_key",
        "endpoint",
        "base_url",
        "retrofit",
        "okhttpclient",
        "httpurlconnection",
        "volley",
        "graphql",
        "grpc",
        "@get",
        "@post",
        "@put",
        "@delete",
        "@patch",
    )

    CRYPTO_APIS = (
        "javax/crypto/cipher",
        "secretskeyspec",
        "ivparameterspec",
        "messagedigest",
        "android/util/base64",
        "aes",
        "des",
        "rsa",
        "cipher",
    )

    LOGIN_PREFILTER_PATTERNS = (
        "login",
        "signin",
        "sign_in",
        "authenticate",
        "session",
        "token",
        "auth",
        "credential",
        "firebase",
        "jwt",
        "oauth",
        "bearer",
        "isloggedin",
        "issignedin",
        "isauthenticated",
        "hassession",
    )

    SSL_PREFILTER_PATTERNS = (
        "checkservertrusted",
        "checkclienttrusted",
        "x509trustmanager",
        "certificatepinner",
        "hostnameverifier",
        "sslcontext",
        "sslsocketfactory",
        "trustmanager",
        "checkvalidity",
        "certpathvalidator",
        "networksecurityconfig",
        "cleartext",
        "pinning",
        "tls",
        "certificate",
    )

    MIN_EVIDENCE_WEIGHT = 0.50
    MAX_EVIDENCE_PER_SOURCE = 20
    MAX_EVIDENCE_PER_BEHAVIOR = 300

    FEATURE_UNLOCK_NAMES = (
        "ispro",
        "isvip",
        "ispremium",
        "haspremium",
        "hasvip",
        "canaccess",
        "hasaccess",
        "isunlocked",
        "unlockfeature",
        "featureunlocked",
        "isenabled",
        "featureenabled",
        "checkentitlement",
        "hasentitlement",
        "ispremiumuser",
        "isproaccount",
        "ispaiduser",
        "issubscriber",
        "issubscribed",
        "haspurchased",
        "ispremiumfeature",
        "ispremiumsubscriber",
        "isadfree",
        "isnoads",
        "haspremiumaccess",
        "hasactivesubscription",
        "issubscriptionactive",
        "hasactiveplan",
        "getsubscriptiontier",
        "getmembershiptier",
        "ismember",
        "islifetime",
        "haslifetimeaccess",
        "istrialactive",
        "istrialexpired",
        "iseligible",
        "isentitled",
        "getentitlement",
        "getaccesslevel",
        "getusertier",
        "getplantype",
        "ispremiumcontent",
        "canplay",
        "candownload",
        "iscontentlocked",
        "isfeaturelocked",
        "ispaywallvisible",
        "shouldshowpaywall",
    )

    FEATURE_UNLOCK_BODY_PATTERNS = (
        "is_vip",
        "isvip",
        "is_premium",
        "ispremium",
        "is_pro",
        "ispro",
        "premium",
        "entitlement",
        "entitled",
        "unlocked",
        "unlock",
        "feature_flag",
        "featureflag",
        "feature_enabled",
        "featureenabled",
        "paywall",
        "subscription",
        "subscribed",
        "purchase",
        "trial",
        "no_ads",
        "noads",
        "ad_free",
        "adfree",
        "gold",
        "plus",
        "entitlements",
        "subscription_status",
        "subscription_active",
        "membership",
        "access_level",
        "tier",
        "plan_type",
        "is_active",
        "expires_at",
        "trial_ends_at",
        "unlocked_features",
        "premium_features",
        "lifetime",
    )

    API_TOKEN_BODY_PATTERNS = (
        "authorization",
        "x-api-key",
        "x-apikey",
        "x-access-token",
        "x-auth-token",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
        "id_token",
        "session_id",
        "sessionid",
        "auth_token",
        "authtoken",
        "client_secret",
        "client_id",
        "oauth",
        "bearer",
        "jwt",
        "openid",
        "open_id",
        "token_type",
        "expires_in",
        "grant_type",
        "client_credentials",
        "x-client-id",
        "x-device-id",
        "x-session-token",
    )

    OBFUSCATED_NAME_RE = re.compile(r"^[a-zA-Z]{1,3}$|^[a-zA-Z]\d{0,2}$")

    def __init__(self, root):
        self.root = Path(root)

        self.stats = {
            "files": 0,
            "smali": 0,
            "sensitive_files": 0,
            "methods": 0,
            "cfg_methods": 0,
            "targets": 0,
            "evidence_raw": 0,
            "evidence_kept": 0,
            "evidence_pruned": 0,
            "errors": 0,
        }

    # =====================================================
    # PUBLIC
    # =====================================================

    def scan(self):
        results = {}

        files = list(self._iter_files())

        if not files:
            return []

        if len(files) <= 10:
            for path in files:
                self.stats["files"] += 1

                try:
                    text = path.read_text(
                        encoding="utf-8",
                        errors="ignore",
                    )
                except Exception:
                    self.stats["errors"] += 1
                    continue

                try:
                    self._scan_file(
                        path,
                        text,
                        results,
                    )
                except Exception:
                    self.stats["errors"] += 1
        else:
            from patchx_core.pool import run_parallel, get_cpu_cores

            workers = get_cpu_cores()
            chunk_sz = max(10, min(100, len(files) // (workers * 4) or 10))

            def _scan_chunk(chunk_paths):
                local_results = {}
                local_stats = {
                    "files": 0,
                    "smali": 0,
                    "sensitive_files": 0,
                    "methods": 0,
                    "cfg_methods": 0,
                    "targets": 0,
                    "errors": 0,
                }
                worker_det = BehaviorDetector(self.root)
                worker_det.stats = local_stats
                for p in chunk_paths:
                    local_stats["files"] += 1
                    try:
                        t = p.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        local_stats["errors"] += 1
                        continue
                    try:
                        worker_det._scan_file(p, t, local_results)
                    except Exception:
                        local_stats["errors"] += 1
                return local_results, local_stats

            chunk_outputs = run_parallel(
                _scan_chunk, files, max_workers=workers, chunk_size=chunk_sz
            )

            for local_results, local_stats in chunk_outputs:
                for k, v in local_stats.items():
                    self.stats[k] = self.stats.get(k, 0) + v
                for name, behavior in local_results.items():
                    if name not in results:
                        results[name] = behavior
                    else:
                        results[name].evidence.extend(behavior.evidence)
                        results[name].suggestions.extend(behavior.suggestions)

        for name, behavior in results.items():
            if name in BEHAVIORS and "suggestions" in BEHAVIORS[name]:
                behavior.add_suggestions(BEHAVIORS[name]["suggestions"])

        self._prune_evidence(results)
        return list(results.values())

    def _prune_evidence(self, results):
        """Chi giu evidence co trong so cao, khong trung lap va gioi han moi nguon."""
        for behavior in results.values():
            raw_count = len(behavior.evidence)
            self.stats["evidence_raw"] += raw_count

            unique: dict[tuple, Any] = {}
            for evidence in behavior.evidence:
                if evidence.weight < self.MIN_EVIDENCE_WEIGHT:
                    continue

                key = (evidence.kind, evidence.value, evidence.source)
                current = unique.get(key)
                if current is None or evidence.weight > current.weight:
                    unique[key] = evidence

            by_source: dict[str, list[Any]] = {}
            kept = []
            for evidence in sorted(
                unique.values(),
                key=lambda item: (-item.weight, item.source, item.value),
            ):
                source = evidence.source or ""
                if len(by_source.get(source, [])) >= self.MAX_EVIDENCE_PER_SOURCE:
                    continue
                by_source.setdefault(source, []).append(evidence)
                kept.append(evidence)

            behavior.evidence = kept[: self.MAX_EVIDENCE_PER_BEHAVIOR]
            self.stats["evidence_kept"] += len(behavior.evidence)
            self.stats["evidence_pruned"] += raw_count - len(behavior.evidence)

    # =====================================================
    # FILE ITERATOR
    # =====================================================

    def _iter_files(self):
        allowed = {
            ".smali",
            ".xml",
            ".txt",
            ".json",
        }

        for path in self.root.rglob("*"):
            if not path.is_file():
                continue
            if path.suffix.lower() not in allowed:
                continue
            yield path

    # =====================================================
    # COMMON
    # =====================================================

    def _get(self, results, name):
        if name not in results:
            results[name] = Behavior(name)

        return results[name]

    @staticmethod
    def _line_number(
        text: str,
        position: int,
    ) -> int:
        return text.count("\n", 0, position) + 1

    # =====================================================
    # FILE SCAN
    # =====================================================

    def _scan_file(
        self,
        path: Path,
        text: str,
        results: dict,
    ):
        suffix = path.suffix.lower()
        lower = text.lower()

        feature_hit = any(
            pattern in lower
            for pattern in self.FEATURE_UNLOCK_BODY_PATTERNS
        )
        token_hit = any(
            pattern in lower
            for pattern in self.API_TOKEN_BODY_PATTERNS
        )
        login_hit = token_hit or any(
            pattern in lower
            for pattern in self.LOGIN_PREFILTER_PATTERNS
        )
        ssl_hit = any(
            pattern in lower
            for pattern in self.SSL_PREFILTER_PATTERNS
        )
        billing_hit = any(
            pattern.lower() in lower
            for pattern in self.BILLING_APIS
        )
        integrity_hit = any(
            pattern.lower() in lower
            for pattern in self.INTEGRITY_APIS
        ) or any(
            pattern in lower
            for pattern in (
                "checkintegrity",
                "verifyintegrity",
                "integritycheck",
                "istampered",
                "tampercheck",
                "getsignature",
                "verifysignature",
                "checksignature",
            )
        )
        api_hit = any(
            pattern.lower() in lower
            for pattern in self.API_APIS
        ) or any(
            pattern in lower
            for pattern in (
                "getapi",
                "apicall",
                "sendrequest",
                "getresponse",
                "fetchdata",
                "callapi",
                "executeapi",
                "buildrequest",
                "parsejson",
                "getjson",
            )
        )
        crypto_hit = any(
            pattern.lower() in lower
            for pattern in self.CRYPTO_APIS
        )

        if suffix == ".smali":
            self.stats["smali"] += 1

            if (
                any(
                    x.lower() in lower
                    for x in self.SENSITIVE_PATTERNS
                )
                or feature_hit
                or token_hit
                or ssl_hit
                or billing_hit
                or integrity_hit
                or api_hit
                or crypto_hit
            ):
                self.stats["sensitive_files"] += 1

                self._scan_smali_cfg(
                    path,
                    text,
                    results,
                )

            if integrity_hit:
                self._scan_integrity_flow(path, text, results)
            if ssl_hit:
                self._scan_ssl_pinning(path, text, results)
            if billing_hit:
                self._scan_google_billing(path, text, results)
            if login_hit:
                self._scan_login_flow(path, text, results)
            if feature_hit:
                self._scan_pro_patterns(path, text, results)
            if api_hit:
                self._scan_api_flow(path, text, results)
            if crypto_hit or feature_hit or token_hit:
                self._scan_obfuscation_flow(path, text, results)
            self._scan_log_flow(path, text, results)
            self._scan_native_bridge(path, text, results)
        elif suffix == ".xml":
            if feature_hit:
                self._scan_pro_patterns(path, text, results)
            if ssl_hit:
                self._scan_ssl_pinning(path, text, results)
            if billing_hit:
                self._scan_google_billing(path, text, results)
            if integrity_hit:
                self._scan_integrity_flow(path, text, results)
            if api_hit:
                self._scan_api_flow(path, text, results)
        else:
            if feature_hit:
                self._scan_pro_patterns(path, text, results)
            if ssl_hit:
                self._scan_ssl_pinning(path, text, results)
            if billing_hit:
                self._scan_google_billing(path, text, results)
            if integrity_hit:
                self._scan_integrity_flow(path, text, results)
            if api_hit:
                self._scan_api_flow(path, text, results)

        if any(
            pattern in lower
            for pattern in (
                "debugger",
                "ptrace",
                "tracerpid",
                "waitingfordebugger",
                "isdebuggerconnected",
                "isdebuggerattached",
            )
        ):
            self._scan_debug_patterns(path, text, results)

        if any(
            pattern in lower
            for pattern in (
                "httpurlconnection",
                "urlconnection",
                "okhttpclient",
                "retrofit",
                "volley",
                "ktor",
                "graphql",
                "grpc",
                "websocket",
                "execute(",
                "enqueue(",
            )
        ):
            self._scan_network(path, text, results)

        if any(
            pattern in lower
            for pattern in (
                "locationmanager",
                "fusedlocationproviderclient",
                "access_fine_location",
                "access_coarse_location",
            )
        ):
            self._scan_location(path, text, results)

        if any(
            pattern in lower
            for pattern in (
                "isgoogleplayservicesavailable",
                "googleapi",
                "isrooted",
                "checksubinary",
                "rootbeer",
                "xposedbridge",
                "frida-server",
                "magisk",
                "superuser",
                "test-keys",
                "/system/xbin/su",
                "/sbin/su",
            )
        ):
            self._scan_dependency_patterns(path, text, results)

    # =====================================================
    # SSL PINNING & CERTIFICATE CHECK
    # =====================================================

    def _scan_ssl_pinning(self, path, text, results):
        if path.suffix.lower() != ".smali":
            patterns = (
                r"checkServerTrusted",
                r"checkClientTrusted",
                r"X509TrustManager",
                r"CertificatePinner",
                r"HostnameVerifier",
                r"SSLContext",
                r"SSLSocketFactory",
                r"TrustManager",
                r"networkSecurityConfig",
                r"usesCleartextTraffic",
                r"cleartextTrafficPermitted",
            )
            for pattern in patterns:
                for match in re.finditer(pattern, text, re.I):
                    behavior = self._get(results, "ssl_pinning")
                    behavior.add_evidence(
                        Evidence(
                            kind="ssl-pattern",
                            value=match.group(0),
                            source=str(path),
                            weight=0.70,
                            details={
                                "line": self._line_number(text, match.start()),
                                "pattern": pattern,
                            },
                        )
                    )
            return

        class_match = re.search(
            r"(?m)^\.class\s+[^\n]*?\s(L[^;]+;)",
            text,
        )
        class_name = class_match.group(1) if class_match else ""
        method_pattern = re.compile(
            r"(?ms)^(\.method[^\n]*)\n(.*?)^\.end\s+method"
        )

        name_patterns = (
            "checkservertrusted",
            "checkclienttrusted",
            "x509trustmanager",
            "certificatepinner",
            "hostnameverifier",
            "sslcontext",
            "sslsocketfactory",
            "sethostnameverifier",
            "checkpins",
            "trustmanager",
            "checkvalidity",
            "certpathvalidator",
            "initsslcontext",
            "configuretls",
            "verify",
        )
        body_patterns = (
            "checkservertrusted",
            "checkclienttrusted",
            "x509trustmanager",
            "certificatepinner",
            "hostnameverifier",
            "sslcontext",
            "sslsocketfactory",
            "sha256",
            "sha-256",
            "certificate",
            "pinning",
            "trustanchors",
            "trustmanager",
            "cleartext",
            "networksecurityconfig",
            "tls",
        )

        for match in method_pattern.finditer(text):
            method_head = match.group(1).strip()
            body = match.group(2)
            method_match = re.search(
                r"\s([A-Za-z_$][\w$]*)\s*\(",
                method_head,
            )
            if not method_match:
                continue

            method_name = method_match.group(1)
            name_lower = method_name.lower()
            body_lower = (method_head + "\n" + body).lower()
            obfuscated_name = bool(self.OBFUSCATED_NAME_RE.match(method_name))
            name_hit = any(
                pattern in name_lower
                for pattern in name_patterns
            )
            body_hit = any(
                pattern in body_lower
                for pattern in body_patterns
            )

            if not (name_hit or (obfuscated_name and body_hit)):
                continue

            return_match = re.search(
                r"\)\s*([^\s]+)",
                method_head,
            )
            return_type = return_match.group(1) if return_match else ""

            behavior = self._get(results, "ssl_pinning")
            behavior.add_evidence(
                Evidence(
                    kind="ssl-pinning-method" if name_hit else "obfuscated-ssl-pinning",
                    value=method_name,
                    source=str(path),
                    weight=0.88 if name_hit else 0.58,
                    details={
                        "class": class_name,
                        "method": method_name,
                        "method_head": method_head,
                        "return_type": return_type,
                        "line": self._line_number(text, match.start()),
                        "obfuscated": obfuscated_name,
                    },
                )
            )

    # =====================================================
    # GOOGLE PLAY BILLING
    # =====================================================

    def _scan_google_billing(self, path, text, results):
        if path.suffix.lower() != ".smali":
            patterns = (
                r"com/android/billingclient",
                r"BillingClient",
                r"PurchasesUpdatedListener",
                r"onPurchasesUpdated",
                r"queryPurchasesAsync",
                r"getPurchaseState",
                r"BillingResult",
            )
            for pattern in patterns:
                for match in re.finditer(pattern, text, re.I):
                    behavior = self._get(results, "google_billing")
                    behavior.add_evidence(
                        Evidence(
                            kind="google-billing-pattern",
                            value=match.group(0),
                            source=str(path),
                            weight=0.80,
                            details={
                                "line": self._line_number(text, match.start()),
                                "pattern": pattern,
                            },
                        )
                    )
            return

        class_match = re.search(
            r"(?m)^\.class\s+[^\n]*?\s(L[^;]+;)",
            text,
        )
        class_name = class_match.group(1) if class_match else ""
        method_pattern = re.compile(
            r"(?ms)^(\.method[^\n]*)\n(.*?)^\.end\s+method"
        )

        name_patterns = (
            "onpurchasesupdated",
            "querypurchasesasync",
            "getpurchasestate",
            "billingclient",
            "billingresult",
            "purchasesresult",
            "purchasehistoryrecord",
            "consumepurchase",
            "acknowledgepurchase",
            "launchbillingflow",
            "querypurchases",
            "queryskudetailsasync",
            "getskudetails",
            "isfeaturesupported",
        )
        body_patterns = (
            "com/android/billingclient",
            "billingclient",
            "onpurchasesupdated",
            "querypurchasesasync",
            "getpurchasestate",
            "billingresult",
            "purchasesresult",
            "purchasehistoryrecord",
            "consumepurchase",
            "acknowledgepurchase",
            "launchbillingflow",
            "productdetails",
            "subscriptionofferdetails",
            "billingflowparams",
        )

        for match in method_pattern.finditer(text):
            method_head = match.group(1).strip()
            body = match.group(2)
            method_match = re.search(
                r"\s([A-Za-z_$][\w$]*)\s*\(",
                method_head,
            )
            if not method_match:
                continue

            method_name = method_match.group(1)
            name_lower = method_name.lower()
            body_lower = (method_head + "\n" + body).lower()
            obfuscated_name = bool(self.OBFUSCATED_NAME_RE.match(method_name))
            name_hit = any(
                pattern in name_lower
                for pattern in name_patterns
            )
            body_hit = any(
                pattern in body_lower
                for pattern in body_patterns
            )

            if not (name_hit or (obfuscated_name and body_hit)):
                continue

            return_match = re.search(
                r"\)\s*([^\s]+)",
                method_head,
            )
            return_type = return_match.group(1) if return_match else ""

            behavior = self._get(results, "google_billing")
            behavior.add_evidence(
                Evidence(
                    kind="google-billing-method" if name_hit else "obfuscated-billing-flow",
                    value=method_name,
                    source=str(path),
                    weight=0.88 if name_hit else 0.58,
                    details={
                        "class": class_name,
                        "method": method_name,
                        "method_head": method_head,
                        "return_type": return_type,
                        "line": self._line_number(text, match.start()),
                        "obfuscated": obfuscated_name,
                    },
                )
            )

    # =====================================================
    # LOGIN / AUTHENTICATION / SESSION
    # =====================================================

    def _scan_login_flow(self, path, text, results):
        class_match = re.search(
            r"(?m)^\.class\s+[^\n]*?\s(L[^;]+;)",
            text,
        )
        class_name = class_match.group(1) if class_match else ""

        session_patterns = (
            "isloggedin",
            "islogin",
            "issignedin",
            "isauthenticated",
            "hassession",
            "isvalidsession",
            "isuserloggedin",
            "checksession",
            "validatesession",
            "issessionactive",
            "istokenvalid",
            "isvalidtoken",
            "hasaccesstoken",
            "hasrefreshtoken",
            "hastoken",
            "checksessionvalid",
        )
        gate_patterns = (
            "requirelogin",
            "showlogin",
            "openlogin",
            "gotologin",
            "redirecttologin",
            "ensureloggedin",
            "onloginrequired",
            "needlogin",
            "requireauth",
            "requiresession",
            "checkloginrequired",
            "ensureauthenticated",
        )
        execute_patterns = (
            "login",
            "signin",
            "sign_in",
            "dologin",
            "authenticate",
            "verifylogin",
            "performlogin",
            "loginuser",
            "verifycredentials",
            "checkcredentials",
            "validatecredentials",
            "getaccesstoken",
            "refreshtoken",
            "getauthtoken",
            "settoken",
            "savetoken",
            "loadtoken",
            "gettokendata",
            "parsejwt",
            "decodejwt",
            "validatejwt",
            "getapikey",
            "setapikey",
            "getauthorization",
            "authorizationheader",
            "getauthheader",
        )
        auth_api_patterns = (
            "firebaseauth",
            "signinwithemailandpassword",
            "signinwithcredential",
            "createuserwithemailandpassword",
            "getcurrentuser",
            "accountmanager",
            "authtoken",
            "oauth",
            "jwt",
            "bearer",
            "access_token",
            "refresh_token",
            "id_token",
            "authorization",
            "x-api-key",
            "x-apikey",
            "x-access-token",
            "x-auth-token",
            "api_key",
            "apikey",
            "auth_token",
            "authtoken",
            "session_id",
            "sessionid",
            "client_secret",
            "client_id",
            "oauth",
            "bearer",
            "jwt",
        )

        method_pattern = re.compile(
            r"(?ms)^(\.method[^\n]*)\n(.*?)^\.end\s+method"
        )

        for match in method_pattern.finditer(text):
            method_head = match.group(1).strip()
            body = match.group(2)
            method_match = re.search(
                r"\s([A-Za-z_$][\w$]*)\s*\(",
                method_head,
            )
            if not method_match:
                continue

            method_name = method_match.group(1)
            name_lower = method_name.lower()
            body_lower = (method_head + "\n" + body).lower()
            obfuscated_name = bool(self.OBFUSCATED_NAME_RE.match(method_name))

            if any(pattern in name_lower for pattern in session_patterns):
                method_kind = "session-state-check"
                weight = 0.92
            elif any(pattern in name_lower for pattern in gate_patterns):
                method_kind = "login-gate"
                weight = 0.72
            elif obfuscated_name and any(
                pattern in body_lower for pattern in session_patterns
            ):
                method_kind = "session-state-check"
                weight = 0.68
            elif obfuscated_name and any(
                pattern in body_lower for pattern in gate_patterns
            ):
                method_kind = "login-gate"
                weight = 0.58
            elif (
                any(pattern in name_lower for pattern in execute_patterns)
                or any(pattern in body_lower for pattern in auth_api_patterns)
            ):
                method_kind = "login-execute"
                weight = 0.86
            elif obfuscated_name and any(
                pattern in body_lower for pattern in auth_api_patterns
            ):
                method_kind = "login-execute"
                weight = 0.64
            else:
                continue

            return_match = re.search(
                r"\)\s*([^\s]+)",
                method_head,
            )
            return_type = return_match.group(1) if return_match else ""

            behavior = self._get(results, "login_authentication")
            behavior.add_evidence(
                Evidence(
                    kind=f"login-{method_kind.replace('-', '_')}",
                    value=method_name,
                    source=str(path),
                    weight=weight,
                    details={
                        "class": class_name,
                        "method": method_name,
                        "method_head": method_head,
                        "method_kind": method_kind,
                        "return_type": return_type,
                        "line": self._line_number(text, match.start()),
                    },
                )
            )

    # =====================================================
    # DEBUG
    # =====================================================

    def _scan_debug_patterns(self, path, text, results):
        patterns = (
            r"\bdebugger\b",
            r"isDebuggerConnected",
            r"isDebuggerAttached",
            r"waitingForDebugger",
            r"Debug;->isDebuggerConnected",
            r"Debug;->waitingForDebugger",
            r"Debug;->isDebuggerAttached",
            r"/proc/self/status",
            r"TracerPid",
            r"\bptrace\b",
        )

        for pattern in patterns:
            if not re.search(pattern, text, re.I):
                continue

            behavior = self._get(results, "debug_detection")
            behavior.add_evidence(
                Evidence(
                    kind="api/pattern",
                    value=pattern,
                    source=str(path),
                    weight=0.70,
                )
            )

    # =====================================================
    # NETWORK
    # =====================================================

    def _scan_network(self, path, text, results):
        patterns = (
            r"HttpURLConnection",
            r"URLConnection",
            r"OkHttpClient",
            r"Retrofit",
            r"Volley",
            r"Ktor",
            r"GraphQL",
            r"gRPC",
            r"WebSocket",
            r"execute\(",
            r"enqueue\(",
        )

        for pattern in patterns:
            if not re.search(pattern, text, re.I):
                continue

            behavior = self._get(results, "remote_configuration")
            behavior.add_evidence(
                Evidence(
                    kind="network-pattern",
                    value=pattern,
                    source=str(path),
                    weight=0.30,
                )
            )

    # =====================================================
    # API SERVER FLOW / ENDPOINT / HEADER
    # =====================================================

    def _scan_api_flow(self, path, text, results):
        endpoint_patterns = (
            r"https?://[^\s\"'<>]+",
            r"wss?://[^\s\"'<>]+",
            r"@(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s*\(",
            r"@Headers\s*\(",
            r"@Path\s*\(",
            r"@Query\s*\(",
            r"@Field\s*\(",
            r"@Body\s*\(",
            r"Retrofit",
            r"OkHttpClient",
            r"HttpURLConnection",
            r"Volley",
            r"GraphQL",
            r"gRPC",
            r"/api/",
            r"/v[0-9]+/",
            r"api\.json",
            r"endpoint",
            r"base_url",
            r"BASE_URL",
        )

        if path.suffix.lower() != ".smali":
            for pattern in endpoint_patterns:
                for match in re.finditer(pattern, text, re.I):
                    behavior = self._get(results, "api_server_flow")
                    behavior.add_evidence(
                        Evidence(
                            kind="api-endpoint-pattern",
                            value=match.group(0),
                            source=str(path),
                            weight=0.55,
                            details={
                                "line": self._line_number(text, match.start()),
                                "pattern": pattern,
                            },
                        )
                    )
            return

        class_match = re.search(
            r"(?m)^\.class\s+[^\n]*?\s(L[^;]+;)",
            text,
        )
        class_name = class_match.group(1) if class_match else ""
        method_pattern = re.compile(
            r"(?ms)^(\.method[^\n]*)\n(.*?)^\.end\s+method"
        )

        name_patterns = (
            "getapi",
            "apicall",
            "sendrequest",
            "getresponse",
            "fetchdata",
            "request",
            "callapi",
            "executeapi",
            "buildrequest",
            "parsejson",
            "getjson",
        )
        body_patterns = (
            "x-api-key",
            "x-apikey",
            "apikey",
            "api_key",
            "authorization",
            "base_url",
            "endpoint",
            "https://",
            "http://",
            "@get",
            "@post",
            "@put",
            "@delete",
        )

        for match in method_pattern.finditer(text):
            method_head = match.group(1).strip()
            body = match.group(2)
            method_match = re.search(
                r"\s([A-Za-z_$][\w$]*)\s*\(",
                method_head,
            )
            if not method_match:
                continue

            method_name = method_match.group(1)
            name_lower = method_name.lower()
            body_lower = (method_head + "\n" + body).lower()
            obfuscated_name = bool(self.OBFUSCATED_NAME_RE.match(method_name))
            name_hit = any(
                pattern in name_lower
                for pattern in name_patterns
            )
            body_hit = any(
                pattern in body_lower
                for pattern in body_patterns
            )

            if not (name_hit or (obfuscated_name and body_hit)):
                continue

            return_match = re.search(
                r"\)\s*([^\s]+)",
                method_head,
            )
            return_type = return_match.group(1) if return_match else ""

            behavior = self._get(results, "api_server_flow")
            behavior.add_evidence(
                Evidence(
                    kind="api-server-method" if name_hit else "obfuscated-api-flow",
                    value=method_name,
                    source=str(path),
                    weight=0.72 if name_hit else 0.55,
                    details={
                        "class": class_name,
                        "method": method_name,
                        "method_head": method_head,
                        "return_type": return_type,
                        "line": self._line_number(text, match.start()),
                        "obfuscated": obfuscated_name,
                    },
                )
            )

    # =====================================================
    # LOCATION
    # =====================================================

    def _scan_location(self, path, text, results):
        patterns = (
            r"LocationManager",
            r"FusedLocationProviderClient",
            r"ACCESS_FINE_LOCATION",
            r"ACCESS_COARSE_LOCATION",
        )

        for pattern in patterns:
            if not re.search(pattern, text, re.I):
                continue

            behavior = self._get(results, "location_usage")
            behavior.add_evidence(
                Evidence(
                    kind="location-pattern",
                    value=pattern,
                    source=str(path),
                    weight=0.70,
                )
            )

    # =====================================================
    # PRO / PREMIUM
    # =====================================================

    def _scan_pro_patterns(self, path, text, results):
        if path.suffix.lower() != ".smali":
            for pattern in self.FEATURE_UNLOCK_BODY_PATTERNS:
                for match in re.finditer(re.escape(pattern), text, re.I):
                    behavior = self._get(results, "pro_premium_check")
                    behavior.add_evidence(
                        Evidence(
                            kind="feature-unlock-pattern",
                            value=match.group(0),
                            source=str(path),
                            weight=0.55,
                            details={
                                "line": self._line_number(text, match.start()),
                                "pattern": pattern,
                            },
                        )
                    )
            return

        class_match = re.search(
            r"(?m)^\.class\s+[^\n]*?\s(L[^;]+;)",
            text,
        )
        class_name = class_match.group(1) if class_match else ""
        method_pattern = re.compile(
            r"(?ms)^(\.method[^\n]*)\n(.*?)^\.end\s+method"
        )

        for match in method_pattern.finditer(text):
            method_head = match.group(1).strip()
            body = match.group(2)
            method_match = re.search(
                r"\s([A-Za-z_$][\w$]*)\s*\(",
                method_head,
            )
            if not method_match:
                continue

            method_name = method_match.group(1)
            name_lower = method_name.lower()
            body_lower = (method_head + "\n" + body).lower()
            obfuscated_name = bool(self.OBFUSCATED_NAME_RE.match(method_name))
            name_hit = any(
                pattern in name_lower
                for pattern in self.FEATURE_UNLOCK_NAMES
            )
            body_hits = [
                pattern
                for pattern in self.FEATURE_UNLOCK_BODY_PATTERNS
                if pattern in body_lower
            ]

            if not (name_hit or (obfuscated_name and body_hits)):
                continue

            return_match = re.search(
                r"\)\s*([^\s]+)",
                method_head,
            )
            return_type = return_match.group(1) if return_match else ""

            matched_value = method_name if name_hit else (body_hits[0] if body_hits else method_name)
            weight = 0.82 if name_hit else 0.58
            kind = "feature-unlock-method" if name_hit else "obfuscated-feature-unlock"

            behavior = self._get(results, "pro_premium_check")
            behavior.add_evidence(
                Evidence(
                    kind=kind,
                    value=matched_value,
                    source=str(path),
                    weight=weight,
                    details={
                        "class": class_name,
                        "method": method_name,
                        "method_head": method_head,
                        "return_type": return_type,
                        "line": self._line_number(text, match.start()),
                        "obfuscated": obfuscated_name,
                        "matched_value": matched_value,
                    },
                )
            )

    # =====================================================
    # R8 / D8 OBFUSCATION & ENCODED CONSTANTS
    # =====================================================

    def _scan_obfuscation_flow(self, path, text, results):
        if path.suffix.lower() != ".smali":
            return

        crypto_patterns = (
            r"Ljavax/crypto/Cipher;",
            r"Ljavax/crypto/spec/SecretKeySpec;",
            r"Ljavax/crypto/spec/IvParameterSpec;",
            r"Ljava/security/MessageDigest;",
            r"Landroid/util/Base64;",
            r"\bAES\b",
            r"\bDES\b",
            r"\bRSA\b",
        )

        for pattern in crypto_patterns:
            for match in re.finditer(pattern, text, re.I):
                behavior = self._get(results, "cryptographic_operations")
                behavior.add_evidence(
                    Evidence(
                        kind="obfuscated-crypto-api",
                        value=match.group(0),
                        source=str(path),
                        weight=0.45,
                        details={
                            "line": self._line_number(text, match.start()),
                            "pattern": pattern,
                        },
                    )
                )

        encoded_constants = (
            re.compile(r'"[A-Za-z0-9+/]{40,}={0,2}"'),
            re.compile(r'"[0-9A-Fa-f]{32,}"'),
        )

        for pattern in encoded_constants:
            for match in pattern.finditer(text):
                value = match.group(0)
                behavior = self._get(results, "cryptographic_operations")
                behavior.add_evidence(
                    Evidence(
                        kind="encoded-constant",
                        value=value[:48] + ("..." if len(value) > 48 else ""),
                        source=str(path),
                        weight=0.28,
                        details={
                            "line": self._line_number(text, match.start()),
                            "length": len(value),
                        },
                    )
                )

    # =====================================================
    # DEPENDENCY & ENVIRONMENT
    # =====================================================

    def _scan_dependency_patterns(self, path, text, results):
        patterns = (
            r"isGooglePlayServicesAvailable",
            r"GoogleApiAvailability",
            r"isRooted",
            r"checkSuBinary",
            r"RootBeer",
            r"XposedBridge",
            r"frida-server",
            r"magisk",
            r"Magisk",
            r"Superuser",
            r"test-keys",
            r"ro\.debuggable",
            r"ro\.secure",
            r"ro\.build\.tags",
            r"/system/xbin/su",
            r"/sbin/su",
            r"which\s+su",
        )

        for pattern in patterns:
            if not re.search(pattern, text, re.I):
                continue

            behavior = self._get(results, "dependency_check")
            behavior.add_evidence(
                Evidence(
                    kind="dependency-pattern",
                    value=pattern,
                    source=str(path),
                    weight=0.70,
                )
            )

    # =====================================================
    # PERMISSION
    # =====================================================

    def _scan_permission_flow(self, path, text, results):
        permission_pattern = re.compile(
            r'android:name\s*=\s*"([^"]+)"',
            re.I,
        )

        for match in permission_pattern.finditer(text):
            permission = match.group(1)

            if not permission.startswith("android.permission."):
                continue

            behavior = self._get(results, "permission_usage")
            behavior.add_evidence(
                Evidence(
                    kind="permission-declaration",
                    value=permission,
                    source=str(path),
                    weight=0.35,
                    details={
                        "permission": permission,
                        "action": "declaration",
                        "line": self._line_number(text, match.start()),
                    },
                )
            )

        patterns = (
            (r"checkSelfPermission", "permission-check", 0.55, "check"),
            (r"requestPermissions", "permission-request", 0.75, "request"),
            (r"RequestPermission", "permission-request", 0.75, "request"),
            (r"RequestMultiplePermissions", "permission-request", 0.75, "request"),
        )

        for pattern, kind, weight, action in patterns:
            for match in re.finditer(pattern, text, re.I):
                behavior = self._get(results, "permission_usage")
                behavior.add_evidence(
                    Evidence(
                        kind=kind,
                        value=match.group(0),
                        source=str(path),
                        weight=weight,
                        details={
                            "action": action,
                            "line": self._line_number(text, match.start()),
                        },
                    )
                )

    # =====================================================
    # LOG
    # =====================================================

    def _scan_log_flow(self, path, text, results):
        pattern = re.compile(
            r"Landroid/util/Log;->(v|d|i|w|e|wtf)\s*\(",
            re.I,
        )

        for match in pattern.finditer(text):
            level = match.group(1)

            behavior = self._get(results, "logging_usage")
            behavior.add_evidence(
                Evidence(
                    kind="android-log",
                    value=f"Log.{level}()",
                    source=str(path),
                    weight=0.45,
                    details={
                        "level": level,
                        "line": self._line_number(text, match.start()),
                    },
                )
            )

    # =====================================================
    # INTEGRITY
    # =====================================================

    def _scan_integrity_flow(self, path, text, results):
        indicators = {
            "package-manager": (
                r"PackageManager",
                r"getPackageInfo",
                r"getApplicationInfo",
                r"getPackageInfo",
                r"getApplicationInfo",
            ),
            "signature": (
                r"GET_SIGNATURES",
                r"GET_SIGNING_CERTIFICATES",
                r"signingInfo",
                r"Signature",
                r"getSigningCertificateHistory",
                r"getApkContentsSigners",
                r"getSignatures",
            ),
            "digest": (
                r"MessageDigest",
                r"SHA-256",
                r"SHA-1",
                r"MD5",
                r"CRC32",
                r"digest",
                r"checksum",
            ),
        }

        if path.suffix.lower() != ".smali":
            for category, patterns in indicators.items():
                for pattern in patterns:
                    for match in re.finditer(pattern, text, re.I):
                        behavior = self._get(results, "integrity_check")
                        behavior.add_evidence(
                            Evidence(
                                kind=f"integrity-{category}",
                                value=match.group(0),
                                source=str(path),
                                weight=0.40,
                                details={
                                    "category": category,
                                    "line": self._line_number(text, match.start()),
                                },
                            )
                        )
            return

        class_match = re.search(
            r"(?m)^\.class\s+[^\n]*?\s(L[^;]+;)",
            text,
        )
        class_name = class_match.group(1) if class_match else ""
        method_pattern = re.compile(
            r"(?ms)^(\.method[^\n]*)\n(.*?)^\.end\s+method"
        )

        name_patterns = (
            "getsignature",
            "verifysignature",
            "checksignature",
            "integritycheck",
            "checkintegrity",
            "verifyintegrity",
            "istampered",
            "tampercheck",
            "checkpackage",
            "getpackageinfo",
            "verifysign",
            "checksum",
            "getcrc",
            "checkcrc",
            "validatesignature",
            "getsigningcertificates",
        )
        body_patterns = (
            "gets_signatures",
            "gets_signing_certificates",
            "signinginfo",
            "messagedigest",
            "sha-256",
            "sha256",
            "sha-1",
            "sha1",
            "md5",
            "crc32",
            "checksum",
            "sourcedir",
            "publicsourcedir",
            "codepath",
            "lastupdatetime",
            "firstinstalltime",
            "test-keys",
            "release-keys",
            "certificate",
        )

        for match in method_pattern.finditer(text):
            method_head = match.group(1).strip()
            body = match.group(2)
            method_match = re.search(
                r"\s([A-Za-z_$][\w$]*)\s*\(",
                method_head,
            )
            if not method_match:
                continue

            method_name = method_match.group(1)
            name_lower = method_name.lower()
            body_lower = (method_head + "\n" + body).lower()
            obfuscated_name = bool(self.OBFUSCATED_NAME_RE.match(method_name))
            name_hit = any(
                pattern in name_lower
                for pattern in name_patterns
            )
            body_hit = any(
                pattern in body_lower
                for pattern in body_patterns
            )

            if not (name_hit or (obfuscated_name and body_hit)):
                continue

            return_match = re.search(
                r"\)\s*([^\s]+)",
                method_head,
            )
            return_type = return_match.group(1) if return_match else ""

            behavior = self._get(results, "integrity_check")
            behavior.add_evidence(
                Evidence(
                    kind="integrity-method" if name_hit else "obfuscated-integrity-flow",
                    value=method_name,
                    source=str(path),
                    weight=0.82 if name_hit else 0.58,
                    details={
                        "class": class_name,
                        "method": method_name,
                        "method_head": method_head,
                        "return_type": return_type,
                        "line": self._line_number(text, match.start()),
                        "obfuscated": obfuscated_name,
                    },
                )
            )

    def _scan_native_bridge(self, path, text, results):
        """Quét cầu nối JNI Smali -> Native (.so) và khai báo phương thức native."""
        if path.suffix.lower() != ".smali":
            return

        # 1. Tìm System.loadLibrary("xxx")
        load_matches = re.finditer(
            r'const-string\s+[vp]\d+,\s*"([^"]+)"[\s\r\n]+invoke-static\s+\{[^\}]+\},\s*Ljava/lang/System;->loadLibrary\(Ljava/lang/String;\)V',
            text
        )
        loaded_lib = None
        for m in load_matches:
            loaded_lib = m.group(1)
            behavior = self._get(results, "integrity_check")
            behavior.add_evidence(
                Evidence(
                    kind="jni-native-library",
                    value=f"System.loadLibrary(\"{loaded_lib}\")",
                    source=str(path),
                    weight=0.85,
                    details={"library": loaded_lib, "line": self._line_number(text, m.start())},
                )
            )

        # 2. Tìm khai báo .method ... native
        native_matches = re.finditer(
            r'\.method\s+(?:[a-z]+\s+)*native\s+([a-zA-Z0-9_$]+)\(([^\)]*)\)([^\s]+)',
            text
        )
        for nm in native_matches:
            method_name = nm.group(1)
            params = nm.group(2)
            ret = nm.group(3)
            sig = f"{method_name}({params}){ret}"
            behavior = self._get(results, "integrity_check")
            behavior.add_evidence(
                Evidence(
                    kind="jni-native-method",
                    value=f"native {sig}" + (f" -> [lib{loaded_lib}.so]" if loaded_lib else ""),
                    source=str(path),
                    weight=0.80,
                    details={"method": method_name, "signature": sig, "library": loaded_lib, "line": self._line_number(text, nm.start())},
                )
            )

    # =====================================================
    # CFG
    # =====================================================

    def _scan_smali_cfg(self, path, text, results):
        method_pattern = re.compile(
            r"(?ms)^(\.method[^\n]*)\n(.*?)" r"^\.end\s+method"
        )

        for match in method_pattern.finditer(text):
            method_head = match.group(1).strip()
            smali_code = match.group(2)

            self.stats["methods"] += 1

            if not smali_code.strip():
                continue

            lower_method = smali_code.lower()

            if not any(p.lower() in lower_method for p in self.SENSITIVE_PATTERNS):
                continue

            try:
                cfg = build_cfg(smali_code, method=method_head)
            except Exception:
                self.stats["errors"] += 1
                continue

            self.stats["cfg_methods"] += 1

            self._analyze_cfg_method(
                path,
                text,
                match,
                method_head,
                smali_code,
                cfg,
                results,
            )

    # =====================================================
    # CFG ANALYSIS
    # =====================================================

    def _analyze_cfg_method(
        self,
        path,
        full_text,
        method_match,
        method_head,
        smali_code,
        cfg,
        results,
    ):
        sensitive = []

        for block in cfg.blocks.values():
            for ins in block.instructions:
                value = ins.text.lower()

                if any(api.lower() in value for api in self.DEBUG_APIS):
                    sensitive.append(("debug_detection", ins))

                elif any(api.lower() in value for api in self.INTEGRITY_APIS):
                    sensitive.append(("integrity_check", ins))

                elif any(api.lower() in value for api in self.PRO_APIS):
                    sensitive.append(("pro_premium_check", ins))

                elif any(api.lower() in value for api in self.BILLING_APIS):
                    sensitive.append(("google_billing", ins))

                elif any(api.lower() in value for api in self.SSL_APIS):
                    sensitive.append(("ssl_pinning", ins))

                elif any(api.lower() in value for api in self.CRYPTO_APIS):
                    sensitive.append(("cryptographic_operations", ins))

                elif any(api.lower() in value for api in self.LOGIN_APIS):
                    sensitive.append(("login_authentication", ins))

                elif any(api.lower() in value for api in self.API_APIS):
                    sensitive.append(("api_server_flow", ins))

                elif any(api.lower() in value for api in self.DEPENDENCY_APIS):
                    sensitive.append(("dependency_check", ins))

        for behavior_type, api_instruction in sensitive:
            api_block = self._find_block(cfg, api_instruction.index)

            if api_block is None:
                continue

            branches = self._find_branches(cfg, api_block, api_instruction)

            for branch in branches:
                method_start_line = self._line_number(full_text, method_match.start())
                api_line = method_start_line + api_instruction.line_number
                branch_line = method_start_line + branch.line_number

                behavior = self._get(results, behavior_type)
                behavior.add_evidence(
                    Evidence(
                        kind="cfg-branch-analysis",
                        value=f"{method_head}: {api_instruction.opcode} → {branch.opcode}",
                        source=str(path),
                        weight=0.85,
                        details={
                            "method": method_head,
                            "api": api_instruction.text,
                            "api_line": api_line,
                            "branch": branch.text,
                            "branch_line": branch_line,
                            "block_id": api_block.id,
                            "successors": sorted(api_block.successors),
                            "target_type": behavior_type,
                        },
                    )
                )

                self.stats["targets"] += 1

    # =====================================================
    # BLOCK
    # =====================================================

    @staticmethod
    def _find_block(cfg, instruction_index):
        for block in cfg.blocks.values():
            for ins in block.instructions:
                if ins.index == instruction_index:
                    return block

        return None

    # =====================================================
    # BRANCH
    # =====================================================

    @staticmethod
    def _find_branches(cfg, block, api_instruction):
        branches = []

        for ins in block.instructions:
            if ins.index < api_instruction.index:
                continue

            if ins.opcode in CFGBuilder.CONDITIONAL_BRANCHES:
                branches.append(ins)

        if branches:
            return branches

        for successor_id in block.successors:
            successor = cfg.blocks.get(successor_id)

            if not successor:
                continue

            for ins in successor.instructions:
                if ins.opcode in CFGBuilder.CONDITIONAL_BRANCHES:
                    branches.append(ins)

        return branches

    # =====================================================
    # STATS
    # =====================================================

    def get_stats(self):
        return dict(self.stats)
