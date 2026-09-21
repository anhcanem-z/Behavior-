# -*- coding: utf-8 -*-
"""Phan tich ngu nghia smali (truc T1 — tu khớp chuoi sang hieu code).

Gom: parser method-level, coverage theo method, nhan dien packer, phat hien
nghi ma hoa chuoi, va call-graph tu entry (launcher/application) de xep hang
target that su duoc goi.
"""

import os
import re
import hashlib
import json
from collections import defaultdict, deque


def extract_methods(smali_text):
    """Tach cac khối `.method ... .end method` trong mot file smali.

    Tra list dict: name, signature, body, line (so dong bat dau).
    """
    methods = []
    lines = smali_text.splitlines()
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        if line.lstrip().startswith(".method"):
            start = i
            sig = line.strip()
            j = i + 1
            while j < n and not lines[j].lstrip().startswith(".end method"):
                j += 1
            body = "\n".join(lines[i + 1:j])
            name = ""
            m = re.search(r"\.method(?:\s+\w+)*\s+([^\s(]+)", sig)
            if m:
                name = m.group(1)
            methods.append({"name": name, "signature": sig, "body": body,
                            "line": start + 1})
            i = j + 1
        else:
            i += 1
    return methods


def find_method_matches(smali_text, pattern, is_regex):
    """Tim method nao chua pattern — tra list dict {method, lần}.

    pattern la chuoi (literal hoac regex) nhu trong khối MATCH_*.
    """
    if not pattern:
        return []
    if is_regex:
        try:
            rx = re.compile(pattern)
        except re.error:
            rx = None
    out = []
    for meth in extract_methods(smali_text):
        if is_regex:
            if rx is None:
                continue
            hits = len(rx.findall(meth["body"]))
        else:
            hits = meth["body"].count(pattern)
        if hits:
            out.append({"method": meth["name"], "signature": meth["signature"],
                        "line": meth["line"], "lần": hits})
    return out


PACKER_LIBS = [
    ("libjiagu.so", "jiagu/360"),
    ("libDexHelper.so", "jiagu/360 (DexHelper)"),
    ("libshell*.so", "bangcle"),
    ("libprotect*.so", "bangcle"),
    ("libtprt.so", "têncent"),
    ("libnesec.so", "têncent"),
    ("libmobisec*.so", "têncent"),
    ("libexec*.so", "têncent"),
    ("libnqshield.so", "netqin"),
    ("libsecexe.so", "ali"),
    ("libsgmain.so", "ali"),
    ("libaliprotect.so", "ali"),
    ("libtosprotection.so", "bytedance"),
    ("libmsaoaidsec.so", "baidu"),
    ("libbaiduprotect.so", "baidu"),
    ("libegis.so", "netease/egis"),
    ("libnesec*.so", "têncent/nesec"),
]

PACKER_SMALI_HINTS = [
    ("Lcom/qihoo/util/", "360 jiagu"),
    ("Lcom/qihoo360/", "360 jiagu"),
    ("Lcom/secneo/", "secneo/360"),
    ("Lcom/têncent/stub/", "têncent stub"),
    ("Lcom/têncent/mobisec/", "têncent mobisec"),
    ("Lcom/bangcle/", "bangcle"),
    ("Lcom/baidu/protect/", "baidu protect"),
    ("Lcom/aliyun/security/", "ali yun security"),
    ("Lcom/sijla/", "sijla/jiagu"),
]


def detect_packers(tree):
    """Quet lib/*.so va smali tim dau hieu packer — tra list dict."""
    found = []
    lib_dir = os.path.join(tree, "lib")
    if os.path.isdir(lib_dir):
        for root, _dirs, files in os.walk(lib_dir):
            for fname in files:
                if not fname.endswith(".so"):
                    continue
                for pat, name in PACKER_LIBS:
                    if re.fullmatch(pat.replace("*", ".*"), fname):
                        found.append({"loại": "lib", "tệp": fname,
                                      "nghi_ngờ": name,
                                      "đường_dẫn": os.path.relpath(
                                          os.path.join(root, fname), tree)})
    smali_dirs = [os.path.join(tree, "smali")]
    if not os.path.isdir(smali_dirs[0]):
        smali_dirs = []
    for d in list(smali_dirs):
        if not os.path.isdir(d):
            smali_dirs.remove(d)
    if smali_dirs:
        for root, _dirs, files in os.walk(smali_dirs[0]):
            for fname in files:
                if not fname.endswith(".smali"):
                    continue
                path = os.path.join(root, fname)
                try:
                    text = open(path, encoding="utf-8",
                                errors="replace").read()
                except OSError:
                    continue
                for hint, name in PACKER_SMALI_HINTS:
                    if hint in text:
                        found.append({"loại": "smali", "tệp": fname,
                                      "nghi_ngờ": name,
                                      "đường_dẫn": os.path.relpath(
                                          path, tree)})
    # Gop trung theo (loại, tệp, nghi_ngờ)
    seen = set()
    uniq = []
    for f in found:
        key = (f["loại"], f["tệp"], f["nghi_ngờ"])
        if key not in seen:
            seen.add(key)
            uniq.append(f)
    return uniq


def detect_string_encryption(tree, limit=10):
    """Heuristic phat hien nghi ma hoa chuoi trong smali.

    Dau hieu: chuoi base64 dai / chuoi \\uXXXX don dap; lỗi goi method tên
    goi y giai ma (decrypt/decode/aes/rc4/base64/...). Tra list dict.
    """
    suspects = []
    base64_re = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
    unicode_run_re = re.compile(r"(?:\\u[0-9a-fA-F]{4}){4,}")
    crypt_names = re.compile(
        r"(?i)\b(decrypt|encode|decode|aes|rc4|des|base64|unpack|"
        r"deobfuscate|getstring|frombytes)\b")
    smali_dir = os.path.join(tree, "smali")
    if not os.path.isdir(smali_dir):
        return []
    counted = 0
    for root, _dirs, files in os.walk(smali_dir):
        for fname in files:
            if not fname.endswith(".smali"):
                continue
            path = os.path.join(root, fname)
            try:
                text = open(path, encoding="utf-8",
                            errors="replace").read()
            except OSError:
                continue
            b64 = len(base64_re.findall(text))
            unir = len(unicode_run_re.findall(text))
            crypt = len(crypt_names.findall(text))
            score = b64 * 2 + unir * 2 + (1 if crypt else 0)
            if score >= 3:
                suspects.append({
                    "tệp": os.path.relpath(path, tree),
                    "điểm": score, "chuoi_base64_dai": b64,
                    "chuoi_unicode_don": unir, "lỗi_goi_giai_ma": crypt})
                counted += 1
                if counted >= limit:
                    break
        if counted >= limit:
            break
    suspects.sort(key=lambda x: -x["điểm"])
    return suspects


def _resolve_class(name, package):
    """Ten class trong manifest co the dang `.Main` → package.Main."""
    name = (name or "").strip()
    if not name:
        return ""
    if name.startswith("."):
        return (package + name).lstrip(".")
    if "." not in name:
        return (package + "." + name).lstrip(".")
    return name


def entry_classes(tree):
    """Doc AndroidManifest.xml (da decode text) — tra (application, launchers)."""
    man_path = os.path.join(tree, "AndroidManifest.xml")
    if not os.path.isfile(man_path):
        return "", []
    try:
        text = open(man_path, encoding="utf-8", errors="replace").read()
    except OSError:
        return "", []
    pkg = ""
    m = re.search(r'package="([^"]+)"', text)
    if m:
        pkg = m.group(1)
    app = ""
    m = re.search(r"<application[^>]*\bname=\"([^\"]+)\"", text)
    if m:
        app = _resolve_class(m.group(1), pkg)
    launchers = []
    # Khối activity + intent-filter MAIN/LAUNCHER
    for block in re.finditer(
            r"<activity\b([^>]*?)(?:/>|>.*?</activity>)", text, re.S):
        body = block.group(0)
        if ("android.intent.action.MAIN" in body
                and "android.intent.category.LAUNCHER" in body):
            m = re.search(r'<activity\b[^>]*\bname="([^"]+)"', body)
            if m:
                launchers.append(_resolve_class(m.group(1), pkg))
    return app, launchers


INVOKE_RE = re.compile(
    r"\binvoke-(?:virtual|super|direct|static|interface|range|"
    r"virtual/range|super/range|direct/range|static/range|"
    r"interface/range)\s*\{[^}]*\},\s*(L[^;]+;)->")

# Giu du chu ky lỗi goi de mo hinh khong phai suy luan tu tên tệp.  Bieu thuc
# nay co y khong dung tên method de tao dau van tay: R8/ProGuard thuong chi
# doi tên, con kieu, cau truc lệnh va quan he goi van la bang chung huu ich.
INVOKE_FULL_RE = re.compile(
    r"\binvoke-[^\s]+\s*\{(?P<registers>[^}]*)\},\s*"
    r"(?P<target>L[^;]+;->[^\s(]+\([^)]*\)[^\s]+)")
_CLASS_RE = re.compile(r"^\.class\s+(?:.+?\s+)?(L[^;]+;)", re.M)
_FIELD_READ_RE = re.compile(r"\b(?:sget|iget)(?:-[\w/]+)?\s+[^,]+(?:,\s*[^,]+)?,\s*(L[^;]+;->[^\s]+)")
_FIELD_WRITE_RE = re.compile(r"\b(?:sput|iput)(?:-[\w/]+)?\s+[^,]+(?:,\s*[^,]+)?,\s*(L[^;]+;->[^\s]+)")
_STRING_RE = re.compile(r'\bconst-string(?:/jumbo)?\s+[^,]+,\s+"((?:\\.|[^"\\])*)"')


def _method_types(signature):
    """Tra kieu tham so va kieu tra ve tu dong .method.

    Day la parser DEX nho, du cho descriptor smali; no khong phu thuoc tên
    method nen an toan khi code bi obfuscate.
    """
    m = re.search(r"\(([^)]*)\)(\S+)", signature)
    if not m:
        return [], ""
    raw = m.group(1)
    params = []
    i = 0
    while i < len(raw):
        start = i
        while i < len(raw) and raw[i] == '[':
            i += 1
        if i < len(raw) and raw[i] == 'L':
            end = raw.find(';', i)
            i = len(raw) if end < 0 else end + 1
        else:
            i += 1
        params.append(raw[start:i])
    return params, m.group(2)


def method_fingerprint(method):
    """Dau van tay hanh vi on dinh trước viec doi tên lop/phuong thuc.

    No khong khang dinh hai method cung y nghia; no cung cap bang chung cau
    truc de tang nhan dien xep hang va bat buoc preflight xac minh them.
    """
    params, ret = _method_types(method["signature"])
    ops = []
    for raw in method["body"].splitlines():
        line = raw.strip()
        if not line or line.startswith((".", ":", "#")):
            continue
        # invoke-* va const-* duoc chuan hoa theo ho lệnh, khong chua tên.
        op = line.split(None, 1)[0]
        ops.append(op.split("/", 1)[0])
    calls = [x.group("target").split("->", 1)[1]
             for x in INVOKE_FULL_RE.finditer(method["body"])]
    payload = {
        "params": params, "return": ret, "ops": ops,
        "branches": sum(1 for op in ops if op.startswith("if-")),
        "calls": sorted(calls),
        "strings": sorted(_STRING_RE.findall(method["body"])),
    }
    canonical = repr(payload).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()[:24]


def build_app_model(tree, include_bodies=False):
    """Xay mo hinh trung gian cua APK tu tat ca thu mức smali.

    Mo hinh tach nhan dien khối thay doi: moi method co cau truc, dau van tay,
    canh goi, nguon/dich du lieu so bo va điểm quyet dinh. Khong co thao tac
    ghi nao len cây APK.
    """
    methods = []
    callers = defaultdict(list)
    for root in _smali_roots(tree):
        for base, _dirs, files in os.walk(root):
            for fname in sorted(files):
                if not fname.endswith(".smali"):
                    continue
                path = os.path.join(base, fname)
                try:
                    text = open(path, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                cm = _CLASS_RE.search(text)
                cls = cm.group(1) if cm else ""
                rel = os.path.relpath(path, tree)
                for meth in extract_methods(text):
                    params, ret = _method_types(meth["signature"])
                    calls = [m.group("target") for m in INVOKE_FULL_RE.finditer(meth["body"])]
                    reads = _FIELD_READ_RE.findall(meth["body"])
                    writes = _FIELD_WRITE_RE.findall(meth["body"])
                    branches = sum(1 for line in meth["body"].splitlines()
                                   if line.strip().startswith("if-"))
                    key = "%s->%s" % (cls, re.search(r"([^\s(]+\([^)]*\)\S+)", meth["signature"]).group(1)) if cls and re.search(r"([^\s(]+\([^)]*\)\S+)", meth["signature"]) else "%s:%d" % (rel, meth["line"])
                    record = {
                        "id": key, "class": cls, "file": rel,
                        "line": meth["line"], "signature": meth["signature"],
                        "parameters": params, "return_type": ret,
                        "fingerprint": method_fingerprint(meth),
                        "calls": calls, "field_reads": reads,
                        "field_writes": writes, "strings": _STRING_RE.findall(meth["body"]),
                        "branch_count": branches,
                        "decision_point": ret == "Z" or branches > 0,
                    }
                    if include_bodies:
                        record["body"] = meth["body"]
                    methods.append(record)
                    for target in calls:
                        callers[target].append(key)
    for method in methods:
        method["called_by"] = sorted(callers.get(method["id"], []))
        # Luồng dữ liệu mức bao thu: nguon va sink duoc ghi rieng, khong tu
        # suy dien def-use lien method khi chua co chung cu register day du.
        method["data_flow"] = {
            "sources": ([{"type": "field_read", "value": x} for x in method["field_reads"]] +
                        [{"type": "constant_string", "value": x} for x in method["strings"]]),
            "sinks": [{"type": "invoke", "value": x} for x in method["calls"]],
        }
    edges = [{"from": m["id"], "to": target}
             for m in methods for target in m["calls"]]
    return {
        "schema": "patchx.app-model/v1", "tree": os.path.abspath(tree),
        "smali_roots": [os.path.relpath(p, tree) for p in _smali_roots(tree)],
        "methods": methods, "call_edges": edges,
        "summary": {"methods": len(methods), "call_edges": len(edges),
                    "decision_points": sum(1 for m in methods if m["decision_point"]),
                    "data_sources": sum(len(m["data_flow"]["sources"]) for m in methods)},
    }


def _normalized_method_body(body):
    """Chuan hoa than method cho identity exact co the tai lap.

    Bo metadata/debug va khoang trang khong mang ngu nghia; giu nguyen operand
    de identity nay chi dung nhan dien thay doi chinh xac, khong dung ghep APK
    da obfuscate.
    """
    lines = []
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ".line", ".local", ".param",
                                        ".prologue", ".epilogue")):
            continue
        lines.append(" ".join(line.split()))
    return "\n".join(lines)


def _sha24(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:24]


def _descriptor_types(descriptor):
    """Tach tham so/return tu descriptor goi method, khong lay tên method."""
    m = re.search(r"\(([^)]*)\)(\S+)$", descriptor or "")
    if not m:
        return [], ""
    return _method_types("(" + m.group(1) + ")" + m.group(2))


def _invoke_shape(target):
    """Dac trung lỗi goi chiu duoc doi tên class/method noi bo.

    API nen tang Android/Java duoc giu class de tang bang chung ngu nghia;
    lỗi goi app noi bo chi giu prototype. Day la dac trung xep hang, khong phai
    bang chung doc lap de thuc thi thay doi.
    """
    cls, _, member = (target or "").partition("->")
    params, ret = _descriptor_types(member)
    prefix = cls if cls.startswith(("Landroid/", "Ljava/", "Lkotlin/")) else "Lapp;"
    return "%s(%s)%s" % (prefix, "".join(params), ret)


def _opcode_histogram(body):
    hist = defaultdict(int)
    for raw in body.splitlines():
        line = raw.strip()
        if not line or line.startswith((".", ":", "#")):
            continue
        op = line.split(None, 1)[0]
        hist[op.split("/", 1)[0]] += 1
    return dict(sorted(hist.items()))


def build_app_model_v2(tree, include_bodies=False):
    """Xay ``patchx.app-model/v2`` chi-doc, song song model V1.

    V2 bo sung ba identity (exact/structural/semantic), quan he caller/callee
    va khoang cach ngan nhat tu Application/launcher. Tối ưu hóa bằng bộ nhớ đệm
    thông minh và xử lý song song trên 8 nhân CPU.
    """
    cache_dir = os.path.join(tree, ".patchx", "cache")
    if not os.path.exists(cache_dir):
        try:
            os.makedirs(cache_dir, exist_ok=True)
        except OSError:
            cache_dir = os.path.join(os.getcwd(), "outputs", "cache")
            os.makedirs(cache_dir, exist_ok=True)

    smali_paths = []
    for root in _smali_roots(tree):
        for base, _dirs, files in os.walk(root):
            for fname in files:
                if fname.endswith(".smali"):
                    smali_paths.append(os.path.join(base, fname))

    if not smali_paths:
        return {
            "schema": "patchx.app-model/v2", "tree": os.path.abspath(tree),
            "smali_roots": [], "entry_classes": [], "methods": [], "call_edges": [],
            "summary": {"methods": 0, "call_edges": 0, "reachable_from_entry": 0, "decision_points": 0},
        }

    # Tính khóa bộ nhớ đệm dựa trên số tệp, mtime lớn nhất và tổng kích thước
    max_mtime = 0
    total_size = 0
    for p in smali_paths:
        try:
            st = os.stat(p)
            if st.st_mtime_ns > max_mtime:
                max_mtime = st.st_mtime_ns
            total_size += st.st_size
        except OSError:
            pass

    cache_key = f"{len(smali_paths)}_{max_mtime}_{total_size}_{include_bodies}"
    cache_hash = hashlib.md5(cache_key.encode()).hexdigest()[:16]
    cache_path = os.path.join(cache_dir, f"model_v2_{cache_hash}.json")

    if os.path.isfile(cache_path):
        try:
            with open(cache_path, "r", encoding="utf-8") as fh:
                cached_data = json.load(fh)
                if cached_data.get("cache_key") == cache_key:
                    return cached_data["model"]
        except Exception:
            pass

    methods = []
    by_id = {}

    def _process_file(path):
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            return []
        cm = _CLASS_RE.search(text)
        cls = cm.group(1) if cm else ""
        rel = os.path.relpath(path, tree)
        file_methods = []
        for meth in extract_methods(text):
            sig_match = re.search(r"([^\s(]+\([^)]*\)\S+)", meth["signature"])
            method_sig = sig_match.group(1) if sig_match else ""
            method_id = "%s->%s" % (cls, method_sig) if cls and method_sig else "%s:%d" % (rel, meth["line"])
            params, ret = _method_types(meth["signature"])
            calls = [m.group("target") for m in INVOKE_FULL_RE.finditer(meth["body"])]
            reads = _FIELD_READ_RE.findall(meth["body"])
            writes = _FIELD_WRITE_RE.findall(meth["body"])
            strings = _STRING_RE.findall(meth["body"])
            ops = _opcode_histogram(meth["body"])
            branches = sum(v for op, v in ops.items() if op.startswith("if-"))
            structural = {
                "parameters": params, "return_type": ret,
                "opcode_histogram": ops, "branch_count": branches,
                "invoke_shapes": sorted(_invoke_shape(x) for x in calls),
            }
            semantic = {
                "parameters": params, "return_type": ret,
                "platform_calls": sorted(_invoke_shape(x) for x in calls
                                         if x.startswith(("Landroid/", "Ljava/", "Lkotlin/"))),
                "strings": sorted(strings),
                "field_read_types": sorted(x.rsplit(":", 1)[-1] for x in reads),
            }
            record = {
                "id": method_id, "class": cls, "file": rel,
                "line": meth["line"], "signature": meth["signature"],
                "features": {"return_type": ret, "parameters": params,
                             "opcode_histogram": ops, "branch_count": branches,
                             "strings": strings, "calls": calls,
                             "field_reads": reads, "field_writes": writes},
                "identity": {
                    "exact": _sha24(_normalized_method_body(meth["body"])),
                    "structural": _sha24(repr(structural)),
                    "semantic": _sha24(repr(semantic)),
                },
                "relations": {"callers": [], "callees": calls,
                              "entry_distance": None},
                "evidence": {"source_file": rel, "line": meth["line"],
                             "extractor_version": "model/v2"},
            }
            if include_bodies:
                record["body"] = meth["body"]
            file_methods.append(record)
        return file_methods

    from .pool import run_parallel, get_cpu_cores
    workers = get_cpu_cores()
    parallel_results = run_parallel(_process_file, smali_paths, max_workers=workers)

    for item in parallel_results:
        if isinstance(item, list):
            for m in item:
                methods.append(m)
                by_id[m["id"]] = m
        elif item:
            methods.append(item)
            by_id[item["id"]] = item

    callers = defaultdict(list)
    edges = []
    for method in methods:
        for target in method["relations"]["callees"]:
            callers[target].append(method["id"])
            edges.append({"from": method["id"], "to": target})
    for method in methods:
        method["relations"]["callers"] = sorted(callers.get(method["id"], []))

    app, launchers = entry_classes(tree)
    entry_classes_desc = set()
    for name in [app] + launchers:
        if name:
            entry_classes_desc.add("L%s;" % name.replace(".", "/"))
    queue = deque((m["id"], 0) for m in methods if m["class"] in entry_classes_desc)
    visited = set()
    while queue:
        method_id, distance = queue.popleft()
        if method_id in visited:
            continue
        visited.add(method_id)
        method = by_id.get(method_id)
        if not method:
            continue
        method["relations"]["entry_distance"] = distance
        for target in method["relations"]["callees"]:
            if target in by_id and target not in visited:
                queue.append((target, distance + 1))

    model_res = {
        "schema": "patchx.app-model/v2", "tree": os.path.abspath(tree),
        "smali_roots": [os.path.relpath(p, tree) for p in _smali_roots(tree)],
        "entry_classes": sorted(entry_classes_desc), "methods": methods,
        "call_edges": edges,
        "summary": {
            "methods": len(methods), "call_edges": len(edges),
            "reachable_from_entry": sum(1 for m in methods
                                        if m["relations"]["entry_distance"] is not None),
            "decision_points": sum(1 for m in methods
                                   if m["features"]["return_type"] == "Z"
                                   or m["features"]["branch_count"] > 0),
        },
    }

    try:
        with open(cache_path, "w", encoding="utf-8") as fh:
            json.dump({"cache_key": cache_key, "model": model_res}, fh, ensure_ascii=False)
    except Exception:
        pass

    return model_res


def call_graph_rank(tree, entries, depth=3, top=15):
    """Dung call-graph tu cac class entry — xep hang target duoc goi.

    entries: list class descriptor dang `Lcom/foo/Bar;`. Tra list dict
    {class, lần, do_sau} cua cac class trong cây duoc goi tu entry.
    """
    def to_path(desc):
        return desc.strip("L;").replace("/", os.sep) + ".smali"

    entry_descs = []
    for e in entries:
        e = (e or "").strip()
        if not e:
            continue
        if e.startswith("L") and e.endswith(";"):
            entry_descs.append(e)
        else:
            entry_descs.append("L%s;" % e.replace(".", "/"))
    rank = defaultdict(int)
    queue = deque((d, 0) for d in entry_descs)
    visited = set()
    smali_dir = os.path.join(tree, "smali")
    file_cache = {}
    while queue:
        desc, d = queue.popleft()
        if d > depth or desc in visited:
            continue
        visited.add(desc)
        path = os.path.join(smali_dir, to_path(desc))
        if not os.path.isfile(path):
            # thu tim duoi .smali o bat ky vi tri nao (cây smali_*)
            path = None
            for base in _smali_roots(tree):
                cand = os.path.join(base, to_path(desc))
                if os.path.isfile(cand):
                    path = cand
                    break
            if not path:
                continue
        if path not in file_cache:
            try:
                file_cache[path] = open(path, encoding="utf-8",
                                        errors="replace").read()
            except OSError:
                file_cache[path] = ""
        text = file_cache[path]
        for m in INVOKE_RE.finditer(text):
            target = m.group(1)
            if target in entry_descs or target in visited:
                continue
            rank[target] += 1
            queue.append((target, d + 1))
    ranked = [{"class": c, "lần": n}
              for c, n in sorted(rank.items(), key=lambda x: -x[1])]
    return ranked[:top]


def _smali_roots(tree):
    """Cac thu mức chua smali trong cây apktool (smali, smali_classes2, ...)."""
    roots = []
    try:
        for name in sorted(os.listdir(tree)):
            full = os.path.join(tree, name)
            if os.path.isdir(full) and (name == "smali"
                                        or name.startswith("smali_")):
                roots.append(full)
    except OSError:
        pass
    return roots


def method_coverage_for_file(smali_text, pattern, is_regex):
    """Bao quat theo method cho mot pattern tren mot file — tien cho CLI."""
    return find_method_matches(smali_text, pattern, is_regex)


def build_semantic_report(tree, top=15):
    """Bao cao ngu nghia tổng hop cho mot cây APK da giai ma (kem Security Gates khong can workkey)."""
    app, launchers = entry_classes(tree)
    entries = [e for e in [app] + launchers if e]
    graph = call_graph_rank(tree, entries, depth=3, top=top)
    packers = detect_packers(tree)
    enc = detect_string_encryption(tree)
    gates = detect_security_gates(tree, max_gates=top)
    return {
        "application": app,
        "launchers": launchers,
        "call_graph_top": graph,
        "packers": packers,
        "string_encryption_suspects": enc,
        "security_gates": gates,
        "gợi_ý_điểm_chèn": (
            "Co packer — patch can chen trước khi pack (vd INIT/HOOK_SCRIPT "
            "vao Application#attachBaseContext) hoac dung hook tang thap." if
            packers else "Khong phat hien packer — chen smali thong thuong "
            "ap dung duoc."),
    }


SENSITIVE_API_PATTERNS = [
    (re.compile(r"->(?:getPackageInfo|signatures|signingInfo|getInstallerPackageName|getSignature)"), "signature_integrity", 40),
    (re.compile(r"Ljava/lang/reflect/Method;->invoke"), "reflection_dynamic", 35),
    (re.compile(r"->(?:getSharedPreferences|getBoolean|getString|getInt)\b"), "preferences_state", 30),
    (re.compile(r"->(?:checkSelfPermission|checkCallingOrSelfPermission)\b"), "permission_gate", 35),
    (re.compile(r"->(?:isBillingSupported|queryPurchases|getPurchaseState|getResponseCode)\b"), "billing_license", 45),
    (re.compile(r"->(?:getActiveNetworkInfo|getNetworkCapabilities|isConnected)\b"), "network_connectivity", 25),
    (re.compile(r"Ljava/io/File;->(?:exists|canExecute)\b"), "root_file_tamper", 35),
    (re.compile(r"Ljava/lang/Runtime;->exec\b"), "shell_execution", 35),
]

THIRD_PARTY_PREFIXES = (
    "Landroid/", "Landroidx/", "Lcom/google/", "Lkotlin/", "Lkotlinx/",
    "Lokhttp3/", "Lokio/", "Lcom/facebook/", "Lio/reactivex/", "Lorg/apache/",
    "Lcom/android/", "Lorg/chromium/", "Lcom/tencent/mmkv/"
)


def _invert_branch(branch_inst):
    """Dao nguoc lenh re nhanh smali."""
    inversions = {
        "if-eqz": "if-nez",
        "if-nez": "if-eqz",
        "if-eq": "if-ne",
        "if-ne": "if-eq",
        "if-ltz": "if-gez",
        "if-gez": "if-ltz",
        "if-gtz": "if-lez",
        "if-lez": "if-gtz",
    }
    for orig, inv in inversions.items():
        if branch_inst.startswith(orig):
            return branch_inst.replace(orig, inv, 1)
    return branch_inst


def detect_security_gates(tree, max_gates=25):
    """Truy vet Taint Flow & Security Gates trong smali khong can tu khoa (Zero-Workkey).
    
    Quet cac method thuc te (da loc bo thu vien ben thu 3 nhu AndroidX/Google),
    lan theo chuoi thanh ghi (Def-Use Chain) tu loi goi API nhay cam den cac lenh
    re nhanh if-* hoac return boolean.
    """
    gates = []
    roots = _smali_roots(tree)
    if not roots:
        return []

    for root in roots:
        for base, _dirs, files in os.walk(root):
            for fname in sorted(files):
                if not fname.endswith(".smali"):
                    continue
                path = os.path.join(base, fname)
                try:
                    text = open(path, encoding="utf-8", errors="replace").read()
                except OSError:
                    continue
                cm = _CLASS_RE.search(text)
                cls = cm.group(1) if cm else ""
                if not cls:
                    cand_rel = os.path.relpath(path, root)
                    if cand_rel.endswith(".smali"):
                        cls = "L" + cand_rel[:-6].replace(os.sep, "/") + ";"
                if cls.startswith(THIRD_PARTY_PREFIXES):
                    continue  # Cat tia thu vien ben thu 3

                rel = os.path.relpath(path, tree)
                for meth in extract_methods(text):
                    params, ret = _method_types(meth["signature"])
                    lines = [l.strip() for l in meth["body"].splitlines() if l.strip()]
                    n_lines = len(lines)
                    for idx, line in enumerate(lines):
                        for pat, cat, base_score in SENSITIVE_API_PATTERNS:
                            if pat.search(line):
                                reg = None
                                if idx + 1 < n_lines:
                                    m_res = re.match(r"^move-result(?:-object|-boolean)?\s+([vp]\d+)", lines[idx + 1])
                                    if m_res:
                                        reg = m_res.group(1)
                                
                                if not reg:
                                    continue

                                for fwd_idx in range(idx + 2, min(idx + 22, n_lines)):
                                    fwd_line = lines[fwd_idx]
                                    branch_m = re.match(r"^(if-[a-z]+(?:z)?)\s+([vp]\d+)(?:,\s*([vp]\d+))?,\s*(:\S+)", fwd_line)
                                    if branch_m and reg in (branch_m.group(2), branch_m.group(3)):
                                        score = base_score + 35
                                        if ret == "Z":
                                            score += 15
                                        gates.append({
                                            "class": cls,
                                            "method": meth["name"],
                                            "signature": meth["signature"],
                                            "file": rel,
                                            "line": meth["line"] + fwd_idx,
                                            "return_type": ret,
                                            "category": cat,
                                            "taint_source": line,
                                            "taint_register": reg,
                                            "decision_branch": fwd_line,
                                            "confidence": min(100.0, float(score)),
                                            "suggested_patch": {
                                                "type": "RETURN_CONSTANT" if ret == "Z" else "INVERT_BRANCH",
                                                "value": "0x1" if ret == "Z" else None,
                                                "target_branch": fwd_line,
                                                "inverted_branch": _invert_branch(fwd_line),
                                            },
                                            "zero_workkey": True,
                                        })
                                        break

                                    if fwd_line.startswith("return") and reg in fwd_line:
                                        score = base_score + 30
                                        if ret == "Z":
                                            score += 20
                                        gates.append({
                                            "class": cls,
                                            "method": meth["name"],
                                            "signature": meth["signature"],
                                            "file": rel,
                                            "line": meth["line"] + fwd_idx,
                                            "return_type": ret,
                                            "category": cat,
                                            "taint_source": line,
                                            "taint_register": reg,
                                            "decision_branch": fwd_line,
                                            "confidence": min(100.0, float(score)),
                                            "suggested_patch": {
                                                "type": "RETURN_CONSTANT",
                                                "value": "0x1" if ret == "Z" else "0x0",
                                                "target_instruction": fwd_line,
                                            },
                                            "zero_workkey": True,
                                        })
                                        break

    gates.sort(key=lambda x: -x["confidence"])
    return gates[:max_gates]

