#!/usr/bin/env python3
"""May thu log chan doan tu app qua TCP 127.0.0.1:8787 (moi dong 1 JSON).

Dung (chay tu thu muc goc _patchx):
    python3 tools/remote_log_server.py
    python3 tools/remote_log_server.py --port 8787
    python3 tools/remote_log_server.py --out outputs/behavior/remote_logs/ten.jsonl

Ghi log vao: outputs/behavior/remote_logs/remote_<moc>.jsonl (them vao cuoi tep).

Luu y:
  - Dong khong phai JSON van duoc luu (kind=raw); JSON dang danh sach luu thanh kind=batch.
  - Mot dong loi KHONG lam ngat ket noi: app gui tiep van duoc ghi binh thuong.
  - Cong 8787 co the bi giao dien web (webui) chiem -> doi --port, nho sua ca phia app.
"""

import argparse
import json
import os
import socket
import socketserver
import sys
import threading
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT_DIR = os.path.join(ROOT, "outputs", "behavior", "remote_logs")
MAX_DONG = 256 * 1024          # 256 KiB: chan mot dong qua dai lam nghen bo nho
LOI_KET_NOI = (ConnectionError, TimeoutError, socket.timeout)


def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def chuan_hoa(text):
    """Doi 1 dong van ban thanh doi tuong JSON co khoa 'kind' — khong bao gio nem loi."""
    try:
        obj = json.loads(text)
    except Exception:
        return {"kind": "raw", "data": text}
    if isinstance(obj, dict):
        return obj
    if isinstance(obj, list):
        return {"kind": "batch", "so_muc": len(obj), "data": obj}
    return {"kind": "raw", "data": text}


class Handler(socketserver.StreamRequestHandler):
    timeout = 30          # giay: im lang qua lau thi dong ket noi (0 = khong gioi han)

    def _doc_mot_dong(self):
        """Doc 1 dong co gioi han do dai. Tra ve (du_lieu, bi_cat)."""
        raw = self.rfile.readline(MAX_DONG)
        if raw and len(raw) >= MAX_DONG and not raw.endswith(b"\n"):
            while True:                 # bo phan con lai cua dong qua dai
                them = self.rfile.readline(MAX_DONG)
                if not them or them.endswith(b"\n"):
                    break
            return raw[:MAX_DONG], True
        return raw, False

    def handle(self):
        addr = "%s:%s" % (self.client_address[0], self.client_address[1])
        self.server.bao("ket-noi", "app ket noi tu %s" % addr)
        try:
            while True:
                raw, bi_cat = self._doc_mot_dong()
                if not raw:
                    break
                line = raw.strip()
                if not line:
                    continue
                obj = chuan_hoa(line.decode("utf-8", "replace"))
                if bi_cat:
                    obj["bi_cat"] = True
                obj.setdefault("nhan_luc", now_str())
                obj.setdefault("nguon_may", addr)
                self.server.ghi(obj)
        except LOI_KET_NOI:
            pass                        # app tat / het thoi gian cho: dung lang le
        except Exception as e:          # mot dong loi khong duoc lam chet may thu
            self.server.bao("loi", "xu ly dong that bai: %s: %s" % (type(e).__name__, e))
        finally:
            self.server.bao("ket-noi", "app ngat ket noi %s" % addr)


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, out_path, timeout=None):
        super().__init__(addr, handler)
        self.out_path = out_path
        self.so_crash = 0
        self.so_su_kien = 0
        self.so_loi_ghi = 0
        self.im_lang = False
        self.khoa = threading.Lock()
        self.tep = open(out_path, "a", encoding="utf-8")   # mot tep duy nhat cho moi luong
        if timeout is not None:
            Handler.timeout = timeout or None

    def ghi(self, obj):
        """Ghi 1 su kien ra tep roi moi in — loi ghi khong lam ngat ket noi."""
        dong = json.dumps(obj, ensure_ascii=False)
        with self.khoa:
            try:
                self.tep.write(dong + "\n")
                self.tep.flush()
            except OSError as e:
                self.so_loi_ghi += 1
                if self.so_loi_ghi <= 3:
                    print("[%s] !!! KHONG GHI DUOC LOG: %s" % (now_str(), e), flush=True)
                return
        self.report(obj)

    def bao(self, tag, text):
        """Bao 1 dong ngan ra man hinh (khong ghi vao tep log JSON)."""
        if self.im_lang:
            return
        with self.khoa:
            print("[%s] %-9s %s" % (now_str(), tag, text), flush=True)

    def report(self, obj):
        self.so_su_kien += 1
        kind = obj.get("kind", "?")
        if kind == "crash":
            self.so_crash += 1
            dong = "[%s] !!! CRASH %s :: %s" % (now_str(), obj.get("type"), obj.get("message"))
            stack = obj.get("stack", "")
            if stack:
                dong += "\n            %s" % str(stack)[:700]
        elif kind == "error":
            dong = "[%s] ERROR %s :: %s" % (now_str(), obj.get("tag"), str(obj.get("error"))[:200])
        elif kind == "batch":
            dong = "[%s] %-9s %s muc :: %s" % (now_str(), kind, obj.get("so_muc"), str(obj.get("data"))[:200])
        else:
            detail = obj.get("data") or obj.get("tag") or ""
            dong = "[%s] %-9s %s" % (now_str(), kind, str(detail)[:200])
        if not self.im_lang:
            with self.khoa:
                print(dong, flush=True)

    def handle_error(self, request, client_address):
        # Khong in vet loi dai dong; bao 1 dong ngan roi chay tiep
        e = sys.exc_info()[1]
        self.bao("loi", "loi khong mong doi (%s) — da bo qua" % type(e).__name__)

    def tong_ket(self):
        try:
            self.tep.flush()
            self.tep.close()
        except OSError:
            pass


def duong_dan_moi(out_dir, moc):
    """Tranh ghi de: tep cung ten da ton tai thi them hau to."""
    goc = os.path.join(out_dir, "remote_%s" % moc)
    path = goc + ".jsonl"
    n = 1
    while os.path.exists(path):
        n += 1
        path = "%s_%d.jsonl" % (goc, n)
    return path


def main():
    ap = argparse.ArgumentParser(description="May thu log chan doan tu app qua TCP (moi dong 1 JSON).")
    ap.add_argument("--host", default="127.0.0.1", help="dia chi lang nghe (mac dinh 127.0.0.1)")
    ap.add_argument("--port", type=int, default=8787, help="cong lang nghe (mac dinh 8787)")
    ap.add_argument("--out", default="", help="tep log (mac dinh outputs/behavior/remote_logs/remote_<moc>.jsonl)")
    ap.add_argument("--timeout", type=int, default=30, help="giay im lang toi da moi ket noi (0 = khong gioi han)")
    ap.add_argument("--im", action="store_true", help="khong in tung dong su kien ra man hinh")
    args = ap.parse_args()

    if args.out:
        out_path = os.path.abspath(args.out)
        thu_muc = os.path.dirname(out_path)
        if thu_muc:
            os.makedirs(thu_muc, exist_ok=True)
    else:
        os.makedirs(OUT_DIR, exist_ok=True)
        out_path = duong_dan_moi(OUT_DIR, datetime.now().strftime("%Y%m%d_%H%M%S"))

    print("== MAY THU LOG CHAN DOAN ==", flush=True)
    print("  dia chi : %s:%d" % (args.host, args.port), flush=True)
    print("  tep log : %s" % out_path, flush=True)
    print("  ghi log : them vao cuoi tep (khong xoa du lieu cu)", flush=True)
    print("  cho app ket noi ... (Ctrl+C de dung)", flush=True)

    try:
        srv = Server((args.host, args.port), Handler, out_path, timeout=args.timeout)
    except OSError as e:
        if getattr(e, "errno", None) in (48, 98, 10048):
            print("!! Cong %d dang bi chiem (co the webui dang dung cong nay)." % args.port, flush=True)
            print("   -> doi cong: python3 tools/remote_log_server.py --port 8999 (nho sua ca phia app)", flush=True)
        else:
            print("!! Khong mo duoc cong %s:%d - %s" % (args.host, args.port, e), flush=True)
        return 1

    srv.im_lang = args.im
    try:
        with srv:
            srv.serve_forever()
    except KeyboardInterrupt:
        print("\n-- dung --", flush=True)
    finally:
        srv.tong_ket()
        print("  tong ket: %d su kien | %d crash | %d loi ghi"
              % (srv.so_su_kien, srv.so_crash, srv.so_loi_ghi), flush=True)
        print("  tep log : %s" % out_path, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
