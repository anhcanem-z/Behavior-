# -*- coding: utf-8 -*-
"""Co van thong minh: tim nhanh/tim sau, bao quat chuoi, de xuat cai tien,
va xay lo trinh mod (roadmap) cho cây APK thuc te.

Nguyen tac: moi de xuat deu dua tren bang chung do duoc tu du lieu that
(so lần khớp, bien the chuoi, tệp bi anh huong) — khong doan mo.
"""

import glob
import hashlib
import json
import os
import re
import shutil
import subprocess
import time
import warnings

from .engine import Engine, _literal_hint
from .audit import audit_patch
from .optimizer import cluster_tag

TEXT_EXTS = (".smali", ".xml", ".txt", ".properties", ".json", ".js")
REGEX_SPECIAL = set(".^$*+?{}[]\\|()")
_TOOLKIT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RG_AVAILABLE = None
_RE_COMPILED = {}
_SAMPLE_LIMIT = 300
_SCAN_MODES = ("FAST", "NORMAL", "FULL", "RELEASE")
HINT_GENERIC_MIN = 1000
_COUNT_CAP = 100000
_LARGE_TEXT = 262144
_DANGEROUS_RE = re.compile(r"\\[1-9]|\([^()]*[.+*][^()]*\)[+*{]")


def iter_text_files(tree_root):
    """Duyet moi tệp van ban trong cây APK (smali/xml/...)."""
    for root, _dirs, files in os.walk(tree_root):
        if ".patchx" in root.split(os.sep):
            continue
        for f in files:
            if f.lower().endswith(TEXT_EXTS):
                yield os.path.relpath(os.path.join(root, f), tree_root)


def _rg_available():
    """rg co trong PATH khong (ket qua nho lai mot lần)."""
    global _RG_AVAILABLE
    if _RG_AVAILABLE is None:
        _RG_AVAILABLE = shutil.which("rg") is not None
    return _RG_AVAILABLE


def _tree_text_inventory(tree_root):
    """(relpath, size, mtime_ns) cua moi tệp text — fingerprint cây APK.

    Dung os.scandir de quy (DirEntry.stat nap mot lần) — nhanh hon os.walk
    + os.stat rieng le, dac biet tren luu tru FUSE cua Android.
    """
    items = []
    stack = [tree_root]
    while stack:
        root = stack.pop()
        if ".patchx" in root.split(os.sep):
            continue
        try:
            entries = os.scandir(root)
        except OSError:
            continue
        with entries as it:
            for entry in it:
                try:
                    if entry.is_dir(follow_symlinks=False):
                        stack.append(entry.path)
                    elif entry.is_file(follow_symlinks=False):
                        if not entry.name.lower().endswith(TEXT_EXTS):
                            continue
                        st = entry.stat(follow_symlinks=False)
                        items.append((os.path.relpath(entry.path, tree_root),
                                      st.st_size, st.st_mtime_ns))
                except OSError:
                    continue
    return items


def _inventory_key(items):
    """Khoa fingerprint theo (tên, kich thuoc, mtime) — cache theo hash APK."""
    h = hashlib.sha256()
    for rel, size, mtime in sorted(items):
        h.update(rel.encode("utf-8", "replace"))
        h.update(b"|%d|%d;" % (size, mtime))
    return h.hexdigest()[:16]


def _safe_relpath(tree_root, path):
    """Duong dan tuong doi an toan; None neu ngoai cây hoac khong phai text."""
    rel = os.path.relpath(path, tree_root)
    if rel.startswith("..") or not rel.lower().endswith(TEXT_EXTS):
        return None
    if ".patchx" in rel.split(os.sep):
        return None
    return rel


def _rg_batch(tree_root, patterns):
    """Mot luot rg (mau literal) cho nhieu pattern — tra {pattern: set(tệp)}."""
    result = {p: set() for p in patterns}
    if not _rg_available() or not patterns:
        return result
    cmd = ["rg", "-F", "-a", "--json", "--no-config", "--no-ignore", "-uu",
           "--color", "never"]
    for p in patterns:
        cmd += ["-e", p]
    cmd.append(tree_root)
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True, timeout=600)
    except (OSError, subprocess.TimeoutExpired):
        return result
    if proc.returncode not in (0, 1):
        return result
    for line in (proc.stdout or "").splitlines():
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("type") != "match":
            continue
        data = obj.get("data") or {}
        rel = _safe_relpath(tree_root,
                            (data.get("path") or {}).get("text", ""))
        if rel is None:
            continue
        for sub in data.get("submatches", []):
            text = (sub.get("match") or {}).get("text", "")
            for p in patterns:
                if p in text:
                    result[p].add(rel)
    return result


def _default_scan_cache_dir():
    """Thu mức cache quet (theo fingerprint cây APK)."""
    return os.path.join(_TOOLKIT_ROOT, "outputs", "cache")


DEGENERATE_MATCH = {".", ".+", ".*", "(.+)"}


def _is_degenerate_match(pattern):
    """Mau regex suy bien — khớp gan nhu moi thu, vo nghia cho coverage
    (vd 6.400 rule MATCH_ASSIGN '.' trong RES-ID). Chi dung de loại khối
    PHEP DO, khong doi noi dung patch."""
    return (pattern or "").strip() in DEGENERATE_MATCH


SCAN_CACHE_MIN_FILES = 40
SCAN_CACHE_MIN_BYTES = 5 * 1024 * 1024


class ScanCache:
    """Cache quet theo fingerprint cây APK — tang loc ung vien nhanh.

    Mot luot `rg` cho nhieu mau literal (thay vi regex Python tren toan bo
    text), ket qua luu theo hash cây APK de lần chay sau khong quet lai.
    Noi dung tệp chi duoc doc khi that can (tệp dich/ung vien) — khong nap
    toan bo cây vao RAM.
    """

    def __init__(self, tree_root, cache_dir=None, auto_save=True,
                 min_files=None, min_bytes=None):
        self.tree_root = os.path.abspath(tree_root)
        self.auto_save = auto_save
        self.min_files = SCAN_CACHE_MIN_FILES if min_files is None else min_files
        self.min_bytes = SCAN_CACHE_MIN_BYTES if min_bytes is None else min_bytes
        self.map = {}
        self._dirty = set()
        self._texts = {}
        self._text_cap = 5000
        self._count_memo = {}
        self.hint_counts = {}
        self.hint_files = {}
        self.generic_hints = set()
        self.absent_hints = set()
        self.hints_prepared = False
        items = _tree_text_inventory(self.tree_root)
        self.inventory = [rel for rel, _s, _m in items]
        self.total_bytes = sum(s for _r, s, _m in items)
        self.key = _inventory_key(items)
        self.cache_dir = cache_dir or _default_scan_cache_dir()
        self.cache_path = (os.path.join(self.cache_dir, "scan_%s.json"
                                        % self.key) if self.cache_dir else None)
        self._load()

    def _load(self):
        if not self.cache_path or not os.path.isfile(self.cache_path):
            return
        try:
            with open(self.cache_path, encoding="utf-8") as fh:
                data = json.load(fh)
            if data.get("key") == self.key:
                self.map = {p: set(files)
                            for p, files in data.get("map", {}).items()}
                self.hint_counts = dict(data.get("hint_counts", {}))
                self.hint_files = {
                    p: set(files)
                    for p, files in data.get("hint_files", {}).items()}
                self.generic_hints = set(data.get("generic_hints", []))
                self.absent_hints = set(data.get("absent_hints", []))
                if ("hint_counts" in data or "hint_files" in data
                        or "generic_hints" in data):
                    self.hints_prepared = True
        except (OSError, ValueError):
            self.map = {}

    def _should_cache(self):
        return (len(self.inventory) >= self.min_files
                or self.total_bytes >= self.min_bytes)

    def _save(self):
        if (not self.auto_save or not self.cache_path or not self._dirty
                or not self._should_cache()):
            return
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            data = {"key": self.key,
                    "map": {p: sorted(files)
                            for p, files in self.map.items()}}
            if self.hints_prepared:
                data["hint_counts"] = self.hint_counts
                data["hint_files"] = {p: sorted(files)
                                      for p, files in self.hint_files.items()}
                data["generic_hints"] = sorted(self.generic_hints)
                data["absent_hints"] = sorted(self.absent_hints)
            tmp = self.cache_path + ".tmp"
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(data, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.cache_path)
            self._dirty = set()
        except OSError:
            pass

    def prepare_hints(self, hints):
        """Phan loại literal hint va lap chi mức hint -> tệp bang rg.

        - Luot A: `rg -F -o` (stream, khong nap het RAM) dem so lần xuat hien
          tung hint → hint vang mat (0 lần) / chung chung (qua pho bien,
          khong loc duoc) / dac thu (loc tot).
        - Luot B: `rg -F --json` (stream) chi voi hint dac thu → map
          hint -> tap tệp. Ket qua luu theo hash cây APK, lần sau nap lai.
        """
        if self.hints_prepared or not _rg_available():
            return
        hints = [h for h in hints
                 if h and "\n" not in h and "\t" not in h and "\r" not in h]
        if not hints:
            self.hints_prepared = True
            return
        counts = {}
        try:
            proc = subprocess.Popen(
                ["rg", "-F", "-o", "-a", "--no-config", "--no-ignore", "-uu",
                 "--color", "never", "--no-filename"]
                + [x for h in hints for x in ("-e", h)]
                + [self.tree_root],
                stdout=subprocess.PIPE, text=True, bufsize=1)
            if proc.stdout:
                for line in proc.stdout:
                    s = line.rstrip("\n")
                    if s:
                        counts[s] = counts.get(s, 0) + 1
                proc.stdout.close()
            proc.wait(timeout=1800)
        except (OSError, subprocess.TimeoutExpired):
            self.hints_prepared = True
            return
        threshold = max(HINT_GENERIC_MIN, len(self.inventory) // 10)
        specific = []
        for h in hints:
            c = counts.get(h, 0)
            if c == 0:
                self.absent_hints.add(h)
            elif c >= threshold:
                self.generic_hints.add(h)
            else:
                specific.append(h)
        if specific:
            # hint hiem trước — neu phai cat giua chung, hint gia tri van xong
            specific.sort(key=lambda h: counts.get(h, 0))
            specific_set = set(specific)
            hint_file_cap = min(threshold, 2000)
            event_budget = 300000
            dropped = set()
            events = 0
            try:
                proc = subprocess.Popen(
                    ["rg", "-F", "--json", "-a", "--no-config", "--no-ignore",
                     "-uu", "--color", "never"]
                    + [x for h in specific for x in ("-e", h)]
                    + [self.tree_root],
                    stdout=subprocess.PIPE, text=True, bufsize=1)
                if proc.stdout:
                    for line in proc.stdout:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            obj = json.loads(line)
                        except ValueError:
                            continue
                        if obj.get("type") != "match":
                            continue
                        events += 1
                        if events > event_budget:
                            proc.kill()
                            break
                        data = obj.get("data") or {}
                        rel = _safe_relpath(
                            self.tree_root,
                            (data.get("path") or {}).get("text", ""))
                        if rel is None:
                            continue
                        for sub in data.get("submatches", []):
                            txt = (sub.get("match") or {}).get("text", "")
                            if txt in specific_set and txt not in dropped:
                                files = self.hint_files.setdefault(txt, set())
                                files.add(rel)
                                if len(files) >= hint_file_cap:
                                    dropped.add(txt)
                    proc.stdout.close()
                proc.wait(timeout=1800)
            except (OSError, subprocess.TimeoutExpired):
                self.hint_files = {}
            for h in dropped:
                self.hint_files.pop(h, None)
                self.generic_hints.add(h)
        self.hint_counts = {h: counts.get(h, 0) for h in hints}
        self.hints_prepared = True
        self._dirty.add("__hints__")
        self._save()

    def regex_candidates(self, pattern):
        """Tep ung vien cho rule regex qua literal hint; None neu khong loc.

        - hint vang mat trong cây → tap rong (regex chac chan khong khớp).
        - hint chung chung / khong trich duoc → None (can quet truc tiep).
        - hint dac thu → tap tệp chua hint.
        """
        if not self.hints_prepared or not _rg_available():
            return None
        hint = _literal_hint(pattern)
        if not hint or "\n" in hint or "\t" in hint or "\r" in hint:
            return None
        if hint in self.absent_hints:
            return set()
        if hint in self.generic_hints:
            return None
        return self.hint_files.get(hint)

    def ensure(self, patterns):
        """Bao dam map chua moi mau literal — quet rg batch phan thieu."""
        missing = [p for p in patterns
                   if p and "\n" not in p and p not in self.map]
        if not missing:
            return
        hits = _rg_batch(self.tree_root, missing)
        for p in missing:
            self.map[p] = hits.get(p, set())
            self._dirty.add(p)
        if self._dirty:
            self._save()

    def candidates(self, pattern):
        """Tep chua mau literal; None neu khong loc duoc bang rg."""
        if not pattern or "\n" in pattern or not _rg_available():
            return None
        self.ensure([pattern])
        return self.map.get(pattern, set())

    def text(self, rel):
        """Noi dung tệp (cache doc theo yeu cau, gioi han dung luong)."""
        if rel in self._texts:
            return self._texts[rel]
        path = os.path.join(self.tree_root, rel)
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            return None
        if len(self._texts) >= self._text_cap:
            self._texts.clear()
        self._texts[rel] = text
        return text

    def count_in(self, rel, pattern, is_regex):
        """Dem so lần khớp cua pattern trong tệp rel (nho lai ket qua).

        Rule auto-sinh thuong lap lai cung pattern tren cung tệp (vd hang
        nghin rule MATCH_ASSIGN '.' tren public.xml) — nho lai tranh tinh
        lai. Regex nguy hiem (backtracking bung no) duoc dem bang rg -P.
        """
        key = (rel, pattern, is_regex)
        if key in self._count_memo:
            return self._count_memo[key]
        text = self.text(rel)
        if text is None:
            self._count_memo[key] = 0
            return 0
        if is_regex and len(text) >= 65536 and _is_dangerous_regex(pattern):
            n = _rg_pcre_count(os.path.join(self.tree_root, rel), pattern)
            if n is not None:
                if len(self._count_memo) >= 60000:
                    self._count_memo.clear()
                self._count_memo[key] = n
                return n
        n = count_matches(text, pattern, is_regex)
        if len(self._count_memo) >= 60000:
            self._count_memo.clear()
        self._count_memo[key] = n
        return n


def collect_literal_patterns(patch_list):
    """Moi mau MATCH literal (REGEX false) can loc bang rg."""
    patterns = set()
    for p in patch_list:
        for sec in p.sections:
            if sec.type not in ("MATCH_REPLACE", "MATCH_ASSIGN", "MATCH_GOTO"):
                continue
            if sec.get("REGEX", "").strip().lower() in ("true", "1"):
                continue
            m = (sec.get("MATCH") or "").strip()
            if m and "\n" not in m:
                patterns.add(m)
    return patterns


def collect_regex_hints(patch_list):
    """Literal hint (engine._literal_hint) cua moi rule MATCH regex.

    Hint la chuoi literal chac chan phai xuat hien neu regex khớp — dung de
    loc file ung vien bang rg trước khi chay regex Python. Tra rong neu khong
    trich duoc hint chac chan (regex nhieu nhanh cap cao, toan meta...).
    """
    hints = set()
    for p in patch_list:
        for sec in p.sections:
            if sec.type not in ("MATCH_REPLACE", "MATCH_ASSIGN", "MATCH_GOTO"):
                continue
            if sec.get("REGEX", "").strip().lower() not in ("true", "1"):
                continue
            m = (sec.get("MATCH") or "").strip()
            if not m:
                continue
            h = _literal_hint(m)
            if h and "\n" not in h and "\t" not in h and "\r" not in h:
                hints.add(h)
    return hints


def count_matches(text, pattern, is_regex, flags=0):
    """Dem so lần khớp cua mau trong van ban."""
    if not pattern:
        return 0
    if is_regex:
        rx = _compile_regex(pattern, flags)
        if rx is None:
            return 0
        return _count_with_cap(text, rx)
    return text.count(pattern)


def _count_with_cap(text, rx, cap=_COUNT_CAP):
    """Dem match; cat o cap de tranh pattern khớp gan nhu moi ky tu
    (vd pattern '.' tren file lon tao hang trieu match)."""
    if len(text) < _LARGE_TEXT:
        return len(rx.findall(text))
    n = 0
    for _ in rx.finditer(text):
        n += 1
        if n >= cap:
            return cap
    return n


def _is_dangerous_regex(pattern):
    """Regex de backtracking bung no (backreference / nhóm co `.+*` duoc
    dinh luong lai) — nen dem bang rg -P thay vi re de tranh treo."""
    return bool(_DANGEROUS_RE.search(pattern))


def _rg_pcre_count(path, pattern, timeout=20):
    """Dem match bang rg -P (PCRE2, co backtracking limit) — chong treo."""
    if not _rg_available():
        return None
    cmd = ["rg", "-a", "-U", "-P", "-o", "--count-matches", "--no-config",
           "--no-ignore", "-uu", "--color", "never", "-e", pattern, path]
    try:
        proc = subprocess.run(cmd, text=True, capture_output=True,
                              timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode not in (0, 1):
        return None
    out = (proc.stdout or "").strip()
    if not out:
        return 0
    try:
        return int(out.splitlines()[-1])
    except ValueError:
        return None


def _compile_regex(pattern, flags=0):
    """Bien dich regex mot lần, nho lai theo (pattern, flags)."""
    key = (pattern, flags)
    rx = _RE_COMPILED.get(key)
    if rx is None:
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", FutureWarning)
                rx = re.compile(pattern, flags)
        except re.error:
            rx = None
        _RE_COMPILED[key] = rx
    return rx


def scan_variants(text, pattern, is_regex):
    """Tim bien the chuoi gan khớp de de xuat mo rong pham vi."""
    suggestions = []
    if not pattern or not text:
        return suggestions
    if len(text) > 524288:
        return suggestions
    if is_regex:
        base = count_matches(text, pattern, True)
        if base >= 1000:
            return suggestions
        if _is_dangerous_regex(pattern):
            return suggestions
        ci = count_matches(text, pattern, True, re.IGNORECASE)
        if ci > base:
            suggestions.append(
                "Co %d khớp nua neu bo phan biet hoa thuong — can nhac "
                "them co (?i) hoac mo rong chuoi" % (ci - base))
        # Bien the khoang trang: nen nhieu khoang trang thanh mot
        ws_pattern = re.sub(r"\\s", r"[\\t ]", pattern)
        try:
            ws_norm = re.compile(r"[ \t]+").sub(" ", text)
            ws_count = count_matches(ws_norm, ws_pattern, True)
            if ws_count > base:
                suggestions.append(
                    "Chuan hoa khoang trang cho them %d khớp — dung \\s+ "
                    "thay vi khoang trang cung" % (ws_count - base))
        except re.error:
            pass
    else:
        if pattern.lower() in text.lower():
            ci_count = text.lower().count(pattern.lower())
            if ci_count > text.count(pattern):
                suggestions.append(
                    "Chuoi khớp them %d lần neu bo phan biet hoa thuong"
                    % (ci_count - text.count(pattern)))
    return suggestions


def _read_all_texts(tree_root):
    """Doc moi tệp van ban mot lần (cache) — tang toc tim sau."""
    cache = {}
    for rel in iter_text_files(tree_root):
        try:
            with open(os.path.join(tree_root, rel), "r", encoding="utf-8",
                      errors="replace") as fh:
                cache[rel] = fh.read()
        except OSError:
            continue
    return cache


def coverage_patch_cached(patch, tree_root, texts=None, eng=None, fast=True,
                          cache=None, mode="FAST"):
    """Do do bao phu; cho phep dung cache text/engine dung chung.

    - mode (P16, 4 che do):
      FAST    — mac dinh, mau ≤ _SAMPLE_LIMIT tệp (danh dau `uoc_luong`);
      NORMAL  — quet du moi tệp trong target, khong uoc luong;
      FULL    — nhu NORMAL + tim sau chuoi khớp ngoai target;
      RELEASE — nhu FULL, bao cao day du nhat (dung khi nghiem thu).
    - fast=True (mac dinh): mau literal duoc loc ung vien bang rg (mot luot
      cho nhieu pattern, cache theo hash cây APK) — khong quet regex Python
      tren toan bo text.
    - Mau regex: neu ScanCache da `prepare_hints`, loc file ung vien bang
      literal hint (rg) roi moi chay regex Python tren ung vien; rule khong
      trich duoc hint chac chan tren target rong thi quet mau (≤ _SAMPLE_LIMIT
      tệp) va danh dau `uoc_luong`.
    - Khi khong co rg / chua prepare_hints: giu duong quet Python cu.
    """
    if mode not in _SCAN_MODES:
        raise ValueError("mode phai ∈ %s (nhan %r)" % (_SCAN_MODES, mode))
    no_sample = mode in ("NORMAL", "FULL", "RELEASE")
    deep_outside = mode in ("FULL", "RELEASE")
    eng = eng or Engine(tree_root, quiet=True, no_dex=True)
    texts = texts if texts is not None else {}
    sc = cache if cache is not None else ScanCache(tree_root)
    tcache = getattr(eng, "_patchx_target_cache", None)
    if not isinstance(tcache, dict):
        tcache = {}
        eng._patchx_target_cache = tcache
    full_texts = None
    results = []
    total_rules = 0
    matched_rules = 0
    skipped_rules = 0
    for sec in patch.sections:
        if sec.type not in ("MATCH_REPLACE", "MATCH_ASSIGN", "MATCH_GOTO"):
            continue
        pattern = (sec.get("MATCH") or "").strip()
        if _is_degenerate_match(pattern):
            skipped_rules += 1
            continue
        total_rules += 1
        is_regex = sec.get("REGEX", "").strip().lower() in ("true", "1")
        tkey = sec.get("TARGET").strip()
        if tkey not in tcache:
            tcache[tkey] = eng._resolve_targets(tkey)
        targets = tcache[tkey]
        target_set = set(targets)
        use_fast = (fast and not is_regex and pattern
                    and "\n" not in pattern and _rg_available()
                    and not texts)
        use_fast_regex = (fast and is_regex and pattern
                          and "\n" not in pattern and _rg_available()
                          and not texts and sc.hints_prepared)
        cands = sc.candidates(pattern) if use_fast else None
        if use_fast_regex:
            cands = sc.regex_candidates(pattern)
        if (not use_fast and not use_fast_regex and pattern
                and full_texts is None and not texts):
            full_texts = _read_all_texts(tree_root)
        occurrences = 0
        hit_files = []
        miss_files = []
        variants = []
        miss_cap = 20
        small_targets = len(targets) <= 100
        uoc_luong = False
        scanned = 0
        for rel_idx, rel in enumerate(targets):
            if use_fast and rel not in cands:
                if len(miss_files) < miss_cap:
                    miss_files.append(rel)
                continue
            if use_fast_regex and cands is not None and rel not in cands:
                if len(miss_files) < miss_cap:
                    miss_files.append(rel)
                continue
            if (use_fast or use_fast_regex) and not small_targets \
                    and not no_sample:
                if use_fast_regex and cands is None \
                        and rel_idx >= _SAMPLE_LIMIT:
                    uoc_luong = True
                    continue
                if scanned >= _SAMPLE_LIMIT:
                    uoc_luong = True
                    break
            if rel in texts:
                text = texts[rel]
            elif use_fast or use_fast_regex:
                text = sc.text(rel)
            elif full_texts is not None:
                text = full_texts.get(rel)
            else:
                text = None
            if text is None:
                miss_files.append(rel + " (thieu)")
                continue
            scanned += 1
            if use_fast or use_fast_regex:
                n = sc.count_in(rel, pattern, is_regex)
            else:
                n = count_matches(text, pattern, is_regex)
            occurrences += n
            if n:
                hit_files.append(rel)
                if len(variants) < 8:
                    variants.extend(scan_variants(text, pattern, is_regex))
            elif (not use_fast and not use_fast_regex) \
                    or len(miss_files) < miss_cap:
                miss_files.append(rel)
        # Tim sau: chuoi xuat hien ngoai pham vi target
        outside = []
        if pattern and occurrences:
            if deep_outside:
                if full_texts is None:
                    full_texts = _read_all_texts(tree_root)
                for rel, text in full_texts.items():
                    if rel in target_set:
                        continue
                    n = count_matches(text, pattern, is_regex)
                    if n:
                        outside.append((rel, n))
                outside = sorted(outside, key=lambda x: (-x[1], x[0]))
            elif (use_fast or use_fast_regex) and cands is not None:
                cand_out = sorted(rel for rel in cands
                                  if rel not in target_set)
                for rel in cand_out[:10]:
                    text = texts.get(rel) or sc.text(rel)
                    if text is None:
                        continue
                    n = sc.count_in(rel, pattern, is_regex)
                    if n:
                        outside.append((rel, n))
                outside = sorted(outside, key=lambda x: (-x[1], x[0]))
            elif full_texts is not None:
                for rel, text in full_texts.items():
                    if rel in target_set:
                        continue
                    n = count_matches(text, pattern, is_regex)
                    if n:
                        outside.append((rel, n))
                outside = sorted(outside, key=lambda x: (-x[1], x[0]))
            elif texts:
                for rel, text in texts.items():
                    if rel in target_set:
                        continue
                    n = count_matches(text, pattern, is_regex)
                    if n:
                        outside.append((rel, n))
                outside = sorted(outside, key=lambda x: (-x[1], x[0]))
        if occurrences:
            matched_rules += 1
        results.append({
            "khối": sec.order, "loại": sec.type,
            "target": sec.get("TARGET").strip(),
            "khớp": occurrences, "tệp_trúng": hit_files,
            "tệp_trượt": miss_files, "biến_thể": variants,
            "ngoai_target": sorted(outside)[:10],
            "uoc_luong": uoc_luong,
            "mode": mode,
            "loc_hint": (use_fast or use_fast_regex) and cands is not None,
        })
    return {
        "patch": patch.name,
        "quy_tắc": total_rules,
        "quy_tắc_khớp": matched_rules,
        "tỷ_lệ": (matched_rules / total_rules) if total_rules else 0.0,
        "mẫu_bỏ_qua": skipped_rules,
        "mode": mode,
        "chi_tiết": results,
    }


def coverage_patch(patch, tree_root, mode="FAST"):
    """Do do bao phu cua tung khối MATCH_* tren cây APK that."""
    return coverage_patch_cached(patch, tree_root, mode=mode)


def suggest_patch(patch, tree_root=None):
    """Tu de xuat cai tien dua tren kiem tra kien truc + do bao phu."""
    suggestions = []
    findings = audit_patch(patch)
    for f in findings:
        if f.fixable:
            suggestions.append({"mức": "sua-tu-dong", "nội_dung": f.message,
                                "lý_do": "Loi kien truc co the sua an toan"})
        elif f.level in ("cảnh-báo", "lỗi"):
            suggestions.append({"mức": "can-xem-xet", "nội_dung": f.message,
                                "lý_do": "Rui ro kien truc"})

    if tree_root:
        cov = coverage_patch(patch, tree_root)
        if cov["quy_tắc"]:
            if cov["tỷ_lệ"] == 0:
                suggestions.append({
                    "mức": "can-xem-xet",
                    "nội_dung": "Khong mau nao khớp tren cây APK nay — "
                                "patch co the khong ap dung cho app nay",
                    "lý_do": "Ty le bao phu 0%%"})
            elif cov["tỷ_lệ"] < 0.5:
                suggestions.append({
                    "mức": "can-xem-xet",
                    "nội_dung": "Chi %d/%d quy tac khớp — kiem tra target "
                                "va mau regex" % (cov["quy_tắc_khớp"],
                                                  cov["quy_tắc"]),
                    "lý_do": "Bao phu thap"})
            for d in cov["chi_tiết"]:
                for v in d["biến_thể"][:3]:
                    suggestions.append({"mức": "mo-rong-chuoi",
                                        "nội_dung": "[khối %d] %s"
                                                    % (d["khối"], v),
                                        "lý_do": "Bao quat them bien the"})
                if d["ngoai_target"]:
                    suggestions.append({
                        "mức": "mo-rong-target",
                        "nội_dung": "[khối %d] chuoi con xuat hien ngoai "
                                    "target (vd: %s) — can nhac mo rong "
                                    "TARGET" % (d["khối"],
                                                d["ngoai_target"][0][0]),
                        "lý_do": "Tim sau thay tệp khac"})
    return suggestions


def build_roadmap(collection_root, tree_root):
    """Lo trinh mod: xep hang patch theo mức ap dung duoc len APK that."""
    from .parser import parse_patch_file
    from .risk import risk_findings
    parsed = []
    for z in sorted(glob.glob(os.path.join(collection_root, "*.zip"))):
        try:
            parsed.append(parse_patch_file(z))
        except Exception:
            continue
    cache = ScanCache(tree_root)
    cache.ensure(sorted(collect_literal_patterns(parsed)))
    cache.prepare_hints(collect_regex_hints(parsed))
    eng = Engine(tree_root, quiet=True, no_dex=True)
    eng._file_index = list(cache.inventory)
    from .pool import run_parallel

    def _eval_patch_worker(p):
        cov = coverage_patch_cached(p, tree_root, eng=eng, cache=cache)
        risk = []
        for sec in p.sections:
            if sec.type == "EXECUTE_DEX":
                risk.append("can --dex-runner")
            if sec.type == "MERGE":
                risk.append("MERGE can public.xml de tai cau truc ID")
            if sec.type == "REMOVE_FILES":
                risk.append("xoa tệp (co sao luu)")
        for rf in risk_findings(p):
            risk.append("⚠ %s: %s" % (rf["loại"], rf["nội_dung"]))
        return {
            "patch": p.name, "nhóm": cluster_tag(p.name),
            "tỷ_lệ": cov["tỷ_lệ"], "quy_tắc_khớp": cov["quy_tắc_khớp"],
            "quy_tắc": cov["quy_tắc"], "lần_khớp": sum(
                d["khớp"] for d in cov["chi_tiết"]),
            "rui_ro": risk,
            "chi_tiết": cov["chi_tiết"],
        }

    items = run_parallel(_eval_patch_worker, parsed, max_workers=8)
    items.sort(key=lambda x: (-x["tỷ_lệ"], x["nhóm"]))
    return items


def render_roadmap(items):
    """Ket xuat lo trinh mod dang Markdown."""
    lines = ["# Lo trinh mod (roadmap)", "",
             "- Thời gian: %s" % time.strftime("%Y-%m-%d %H:%M:%S"), ""]
    for it in items:
        status = ("Ap dung duoc" if it["tỷ_lệ"] >= 0.5 else
                  "Mot phan" if it["tỷ_lệ"] > 0 else "Khong khớp")
        lines.append("## %s [%s] — %s" % (it["patch"], it["nhóm"], status))
        lines.append("- Bao phu: %d/%d quy tac, %d lần khớp" % (
            it["quy_tắc_khớp"], it["quy_tắc"], it["lần_khớp"]))
        if it["rui_ro"]:
            lines.append("- Rui ro: " + ", ".join(it["rui_ro"]))
        for d in it["chi_tiết"]:
            lines.append("  - khối %d (%s) target=%s: %d khớp" % (
                d["khối"], d["loại"], d["target"] or "<rỗng>", d["khớp"]))
        lines.append("")
    return "\n".join(lines)
