# -*- coding: utf-8 -*-
"""
SMB 공유 폴더 파일 복사 프로그램

사용 전 아래 CONFIG 영역을 실제 환경에 맞게 수정하세요.
- DEVICE_TYPES / SHARE_NAME: 장비 종류에 따른 경로 구성
- SUB_JOBS: 복사할 하위 항목 목록 (전체 복사 / 날짜 범위 필터 복사)
- MODLOG_HEADERS: MODLOG 폴더 안에서 선택적으로 가져올 파일 종류

접속은 Windows의 net use 대신 pysmb 라이브러리로 직접 한다.
그래서 Win11에서 SMB1 클라이언트를 켜지 않아도 XP(SMB1) 장비에 접속할 수 있다.
빌드 환경(Python 3.4): pip install -r requirements.txt
"""

import calendar
import os
import re
import socket
import sys
import threading
import traceback
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
from datetime import datetime, timedelta

from smb.SMBConnection import SMBConnection
from smb.smb_structs import OperationFailure

# =========================================================
# CONFIG - 실제 환경에 맞게 아래 값을 수정하세요
# =========================================================

# 기본 사용자명 (GUI에서 수정 가능)
DEFAULT_USERNAME = "administrator"

# 공유 폴더 이름: 실제 경로는 \\<주소>\<SHARE_NAME>\<장비폴더>\... 형태
SHARE_NAME = "D"

# 이 PC를 SMB 상대에게 알릴 이름 (NetBIOS 이름, 15자 이하 영문)
CLIENT_NAME = "SMBCOPIER"

# 접속 대기 시간(초) / 파일 전송 중 응답 대기 시간(초)
CONNECT_TIMEOUT = 10
FILE_TIMEOUT = 60

# 장비 종류: 프로그램에 따라 \\<주소>\D\ 아래 폴더명이 다름
DEVICE_TYPES = [
    {"label": "발매기 (ATVM)", "folder": "ATVM"},
    {"label": "정산기 (AADM)", "folder": "AADM"},
]

# 복사할 하위 항목 (선택한 장비 종류의 경로 아래에서 복사)
# mode="all"        : 폴더 전체를 하위 폴더 포함해서 그대로 복사
# mode="date_range" : 폴더 내 파일 중, 파일명에서 date_regex로 추출한 날짜가
#                      사용자가 입력한 시작/종료 날짜 범위에 포함되는 파일만 복사
SUB_JOBS = [
    {
        "name": "DATA",
        "subpath": "DATA",
        "mode": "all",
    },
    {
        "name": "LOG",
        "subpath": "LOG",
        "mode": "date_range",
        "date_regex": r"(?:Log|UILog)(\d{6})\.txt$",
        "date_format": "%y%m%d",
    },
    {
        "name": "PRT",
        "subpath": "PRT",
        "mode": "date_range",
        "date_regex": r"(?:DF|OF)(\d{12})\.txt$",
        "date_format": "%y%m%d%H%M%S",
    },
]

# MODLOG 폴더는 헤더(파일 종류)를 개별적으로 선택해서 가져올 수 있음
MODLOG_SUBPATH = "MODLOG"
MODLOG_DATE_FORMAT = "%y%m%d"
MODLOG_HEADERS = [
    {"label": "지폐", "code": "Bill"},
    {"label": "동전", "code": "Coin"},
    {"label": "신용", "code": "Credit"},
    {"label": "지폐방출기", "code": "Dispenser"},
    {"label": "발매", "code": "Issuer"},
    {"label": "RF", "code": "Rfm"},
]

# =========================================================
# 내부 로직
# =========================================================


def sanitize_folder_name(name: str) -> str:
    """폴더명으로 쓸 수 없는 문자를 밑줄로 치환"""
    return re.sub(r'[\\/:*?"<>|]', "_", name.strip())


def get_app_dir() -> str:
    """실행 파일(exe)이 있는 폴더. PyInstaller로 빌드된 경우 sys.executable 기준,
    스크립트로 실행 중이면 이 .py 파일 기준."""
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


def remote_join(*parts) -> str:
    """공유 폴더 안의 경로를 SMB 형식(역슬래시)으로 연결"""
    return "\\".join(p.strip("\\/") for p in parts if p and p.strip("\\/"))


def unc_display(address: str, remote_path: str) -> str:
    """로그 표시용 UNC 경로 (\\\\주소\\공유\\경로)"""
    return "\\\\{0}\\{1}\\{2}".format(address, SHARE_NAME, remote_path)


def open_smb(address: str, username: str, password: str, log):
    """pysmb로 장비에 직접 SMB 접속.
    Windows의 net use / SMB1 클라이언트 기능을 쓰지 않으므로
    Win11에서 SMB1을 켜지 않아도 XP(SMB1) 장비에 접속할 수 있다.
    SMB1/SMB2는 상대 장비에 맞춰 자동으로 선택된다."""
    domain = ""
    if "\\" in username:
        domain, username = username.split("\\", 1)

    errors = []
    # 445(직접 TCP) 먼저, 안 되면 139(NetBIOS) 시도
    for port, direct_tcp in ((445, True), (139, False)):
        # NTLMv2 인증이 거부되면 NTLMv1로 재시도 (오래된 XP 설정 대비)
        for use_ntlm_v2 in (True, False):
            conn = SMBConnection(
                username, password, CLIENT_NAME, "*SMBSERVER",
                domain=domain, use_ntlm_v2=use_ntlm_v2, is_direct_tcp=direct_tcp,
            )
            try:
                ok = conn.connect(address, port, sock_family=socket.AF_INET, timeout=CONNECT_TIMEOUT)
            except (socket.error, OSError) as e:
                conn.close()
                errors.append("{0}번 포트 접속 불가: {1}".format(port, e))
                break  # 이 포트는 안 열려 있음 -> 다음 포트
            except Exception as e:
                conn.close()
                errors.append("{0}번 포트 통신 오류: {1!r}".format(port, e))
                break
            if ok:
                log("[연결] \\\\{0} 접속 성공 (포트 {1}, {2}, {3})".format(
                    address, port,
                    "SMB2" if conn.isUsingSMB2 else "SMB1",
                    "NTLMv2" if use_ntlm_v2 else "NTLMv1",
                ))
                return conn
            conn.close()
            errors.append("{0}번 포트 {1} 인증 실패".format(port, "NTLMv2" if use_ntlm_v2 else "NTLMv1"))

    raise RuntimeError(
        "\\\\{0} 접속 실패 (주소/사용자명/비밀번호를 확인하세요)\n- {1}".format(address, "\n- ".join(errors))
    )


def close_smb(conn, address: str, log):
    try:
        conn.close()
    except Exception:
        pass
    log("[연결 해제] \\\\{0}".format(address))


def remote_isdir(conn, remote_path: str) -> bool:
    try:
        return conn.getAttributes(SHARE_NAME, remote_path).isDirectory
    except OperationFailure:
        return False


def list_remote(conn, remote_path: str):
    """폴더 안의 항목 목록 ('.', '..' 제외)"""
    return [f for f in conn.listPath(SHARE_NAME, remote_path) if f.filename not in (".", "..")]


def download_file(conn, remote_file: str, shared_file, dst_file: str):
    """원격 파일을 로컬로 내려받고 수정 시간을 원본과 맞춘다."""
    try:
        with open(dst_file, "wb") as fobj:
            conn.retrieveFile(SHARE_NAME, remote_file, fobj, timeout=FILE_TIMEOUT)
    except Exception:
        # 중간에 실패하면 불완전한 파일이 남지 않도록 삭제
        try:
            os.remove(dst_file)
        except OSError:
            pass
        raise
    try:
        os.utime(dst_file, (shared_file.last_access_time, shared_file.last_write_time))
    except (OSError, ValueError, OverflowError):
        pass  # 시간 정보만 못 맞춘 것이므로 무시


def copy_all(conn, address: str, source: str, dest: str, log):
    if not remote_isdir(conn, source):
        raise RuntimeError("원본 폴더를 찾을 수 없습니다: {0}".format(unc_display(address, source)))
    count = 0
    # 하위 폴더까지 순회 (스택 사용)
    stack = [(source, dest)]
    while stack:
        remote_dir, local_dir = stack.pop()
        os.makedirs(local_dir, exist_ok=True)
        for f in list_remote(conn, remote_dir):
            remote_file = remote_join(remote_dir, f.filename)
            local_file = os.path.join(local_dir, f.filename)
            if f.isDirectory:
                stack.append((remote_file, local_file))
                continue
            download_file(conn, remote_file, f, local_file)
            count += 1
            log("  복사: {0} -> {1}".format(unc_display(address, remote_file), local_file))
    log("[완료] {0} : {1}개 파일 복사".format(unc_display(address, source), count))


def copy_date_range(conn, address: str, source: str, dest: str, date_regex: str, date_format: str,
                    start_date: datetime, end_date: datetime, log):
    if not remote_isdir(conn, source):
        raise RuntimeError("원본 폴더를 찾을 수 없습니다: {0}".format(unc_display(address, source)))
    os.makedirs(dest, exist_ok=True)
    pattern = re.compile(date_regex, re.IGNORECASE)
    # 종료일은 사용자가 날짜만 입력하므로, 그 날의 마지막 순간까지 포함시킴
    end_date_inclusive = end_date + timedelta(days=1) - timedelta(seconds=1)
    count = 0
    skipped = 0
    for f in list_remote(conn, source):
        if f.isDirectory:
            continue
        m = pattern.search(f.filename)
        if not m:
            skipped += 1
            continue
        try:
            file_date = datetime.strptime(m.group(1), date_format)
        except ValueError:
            skipped += 1
            continue
        if start_date <= file_date <= end_date_inclusive:
            remote_file = remote_join(source, f.filename)
            dst_file = os.path.join(dest, f.filename)
            download_file(conn, remote_file, f, dst_file)
            count += 1
            log("  복사: {0} -> {1}".format(unc_display(address, remote_file), dst_file))
        else:
            skipped += 1
    log("[완료] {0} : {1}개 파일 복사 (범위 밖/미매칭 {2}개 제외)".format(
        unc_display(address, source), count, skipped))


# =========================================================
# 날짜 선택용 팝업 달력 (표준 라이브러리만 사용)
# =========================================================


class DatePicker(ttk.Frame):
    def __init__(self, parent, initial=None):
        super().__init__(parent)
        self.var = tk.StringVar(value=(initial or datetime.now()).strftime("%Y-%m-%d"))
        self.entry = ttk.Entry(self, textvariable=self.var, width=12)
        self.entry.pack(side="left")
        ttk.Button(self, text="달력", width=4, command=self._open_calendar).pack(side="left", padx=(2, 0))
        self._popup = None
        self._cal_year = None
        self._cal_month = None

    def get(self) -> str:
        return self.var.get().strip()

    def _open_calendar(self):
        if self._popup is not None:
            self._popup.destroy()
            self._popup = None

        try:
            current = datetime.strptime(self.var.get().strip(), "%Y-%m-%d")
        except ValueError:
            current = datetime.now()
        self._cal_year = current.year
        self._cal_month = current.month

        self._popup = tk.Toplevel(self)
        self._popup.title("날짜 선택")
        self._popup.transient(self.winfo_toplevel())
        self._popup.resizable(False, False)
        self._popup.protocol("WM_DELETE_WINDOW", self._close_calendar)

        x = self.entry.winfo_rootx()
        y = self.entry.winfo_rooty() + self.entry.winfo_height()
        self._popup.geometry("+{0}+{1}".format(x, y))

        self._render_calendar()

        self._popup.update_idletasks()
        self._popup.deiconify()
        self._popup.lift()
        self._popup.attributes("-topmost", True)
        self._popup.focus_force()

    def _close_calendar(self):
        if self._popup is not None:
            self._popup.destroy()
            self._popup = None

    def _render_calendar(self):
        for w in self._popup.winfo_children():
            w.destroy()

        header = ttk.Frame(self._popup)
        header.pack(fill="x")
        ttk.Button(header, text="<<", width=3, command=lambda: self._change_month(-12)).pack(side="left")
        ttk.Button(header, text="<", width=3, command=lambda: self._change_month(-1)).pack(side="left")
        ttk.Label(header, text="{0}년 {1}월".format(self._cal_year, self._cal_month), width=10, anchor="center").pack(side="left")
        ttk.Button(header, text=">", width=3, command=lambda: self._change_month(1)).pack(side="left")
        ttk.Button(header, text=">>", width=3, command=lambda: self._change_month(12)).pack(side="left")

        grid = ttk.Frame(self._popup)
        grid.pack()
        for col, wd in enumerate(["월", "화", "수", "목", "금", "토", "일"]):
            ttk.Label(grid, text=wd, width=3, anchor="center").grid(row=0, column=col)

        cal = calendar.Calendar(firstweekday=0)
        for row, week in enumerate(cal.monthdayscalendar(self._cal_year, self._cal_month), start=1):
            for col, day in enumerate(week):
                if day == 0:
                    ttk.Label(grid, text="", width=3).grid(row=row, column=col)
                else:
                    ttk.Button(
                        grid, text=str(day), width=3,
                        command=lambda d=day: self._select_day(d)
                    ).grid(row=row, column=col)

    def _change_month(self, delta):
        total = self._cal_year * 12 + (self._cal_month - 1) + delta
        self._cal_year, m = divmod(total, 12)
        self._cal_month = m + 1
        self._render_calendar()

    def _select_day(self, day):
        self.var.set("{0:04d}-{1:02d}-{2:02d}".format(self._cal_year, self._cal_month, day))
        self._close_calendar()


# =========================================================
# GUI
# =========================================================


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("SMB 파일 복사 프로그램")
        self.geometry("780x760")
        self.resizable(True, True)

        self.job_vars = []
        self.modlog_header_vars = []
        self.address_var = tk.StringVar()
        self.username_var = tk.StringVar(value=DEFAULT_USERNAME)
        self.device_var = tk.StringVar(value=DEVICE_TYPES[0]["folder"])
        self.resolved_path_var = tk.StringVar()
        self.save_folder_var = tk.StringVar(value=datetime.now().strftime("%Y%m%d"))

        self._build_ui()

        self.address_var.trace("w", self._update_resolved_path)
        self.device_var.trace("w", self._update_resolved_path)
        self._update_resolved_path()

    def _build_ui(self):
        pad = {"padx": 8, "pady": 4}

        # 네트워크 접속 정보
        login_frame = ttk.LabelFrame(self, text="네트워크 접속 정보")
        login_frame.pack(fill="x", **pad)

        ttk.Label(login_frame, text="네트워크 주소 (IP):").grid(row=0, column=0, sticky="e", **pad)
        ttk.Entry(login_frame, textvariable=self.address_var, width=30).grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(login_frame, text="사용자명:").grid(row=1, column=0, sticky="e", **pad)
        ttk.Entry(login_frame, textvariable=self.username_var, width=20).grid(row=1, column=1, sticky="w", **pad)

        ttk.Label(login_frame, text="비밀번호:").grid(row=1, column=2, sticky="e", **pad)
        self.password_entry = ttk.Entry(login_frame, width=20, show="*")
        self.password_entry.grid(row=1, column=3, sticky="w", **pad)

        self.test_button = ttk.Button(login_frame, text="연결 확인", command=self._on_test_connection)
        self.test_button.grid(row=1, column=4, sticky="w", **pad)

        # 장비 종류
        device_frame = ttk.LabelFrame(self, text="장비 종류")
        device_frame.pack(fill="x", **pad)

        for dt in DEVICE_TYPES:
            ttk.Radiobutton(
                device_frame, text=dt["label"], value=dt["folder"], variable=self.device_var
            ).pack(side="left", padx=8, pady=4)

        ttk.Label(device_frame, textvariable=self.resolved_path_var, foreground="gray").pack(
            side="left", padx=16, pady=4
        )

        # 날짜 범위 (복사할 항목보다 위)
        date_frame = ttk.LabelFrame(self, text="날짜 범위 (LOG / MODLOG / PRT 에 적용)")
        date_frame.pack(fill="x", **pad)

        ttk.Label(date_frame, text="시작일:").grid(row=0, column=0, sticky="e", **pad)
        self.start_date_picker = DatePicker(date_frame, initial=datetime.now())
        self.start_date_picker.grid(row=0, column=1, sticky="w", **pad)

        ttk.Label(date_frame, text="종료일:").grid(row=0, column=2, sticky="e", **pad)
        self.end_date_picker = DatePicker(date_frame, initial=datetime.now())
        self.end_date_picker.grid(row=0, column=3, sticky="w", **pad)

        # 복사할 항목 선택
        job_frame = ttk.LabelFrame(self, text="복사할 항목 선택")
        job_frame.pack(fill="x", **pad)

        for job in SUB_JOBS:
            var = tk.BooleanVar(value=(job["subpath"] in ("DATA", "LOG")))
            cb = ttk.Checkbutton(job_frame, text=job["name"], variable=var)
            cb.pack(anchor="w", padx=8, pady=2)
            self.job_vars.append((job, var))

        modlog_frame = ttk.LabelFrame(job_frame, text="MODLOG (필요한 항목만 선택)")
        modlog_frame.pack(fill="x", padx=8, pady=(4, 8))

        modlog_select_row = ttk.Frame(modlog_frame)
        modlog_select_row.pack(anchor="w", padx=6, pady=(4, 0))
        ttk.Button(modlog_select_row, text="전체선택", width=8, command=self._select_all_modlog).pack(side="left")
        ttk.Button(modlog_select_row, text="전체해제", width=8, command=self._deselect_all_modlog).pack(side="left", padx=(4, 0))

        modlog_checks_row = ttk.Frame(modlog_frame)
        modlog_checks_row.pack(anchor="w")
        for header in MODLOG_HEADERS:
            var = tk.BooleanVar(value=False)
            cb = ttk.Checkbutton(modlog_checks_row, text="{0} ({1})".format(header["label"], header["code"]), variable=var)
            cb.pack(side="left", padx=6, pady=4)
            self.modlog_header_vars.append((header, var))

        # 저장 위치 (프로그램 폴더 아래 폴더명만 입력)
        dest_frame = ttk.LabelFrame(self, text="저장 위치 (프로그램 폴더 아래에 생성될 폴더명)")
        dest_frame.pack(fill="x", **pad)

        ttk.Entry(dest_frame, textvariable=self.save_folder_var, width=30).pack(side="left", padx=8, pady=4)

        # 실행 버튼
        button_row = ttk.Frame(self)
        button_row.pack(**pad)
        self.run_button = ttk.Button(button_row, text="복사 시작", command=self._on_run)
        self.run_button.pack(side="left", padx=4)

        self.progress = ttk.Progressbar(self, mode="indeterminate")
        self.progress.pack(fill="x", **pad)

        # 로그
        log_frame = ttk.LabelFrame(self, text="로그")
        log_frame.pack(fill="both", expand=True, **pad)
        self.log_box = scrolledtext.ScrolledText(log_frame, state="disabled", wrap="word")
        self.log_box.pack(fill="both", expand=True)

    def _select_all_modlog(self):
        for _, var in self.modlog_header_vars:
            var.set(True)

    def _deselect_all_modlog(self):
        for _, var in self.modlog_header_vars:
            var.set(False)

    def _update_resolved_path(self, *args):
        address = self.address_var.get().strip().strip("\\")
        device_folder = self.device_var.get()
        if address:
            self.resolved_path_var.set("→ \\\\{0}\\{1}\\{2}".format(address, SHARE_NAME, device_folder))
        else:
            self.resolved_path_var.set("→ (네트워크 주소를 입력하세요)")

    def log(self, message: str):
        def _append():
            self.log_box.configure(state="normal")
            self.log_box.insert("end", message + "\n")
            self.log_box.see("end")
            self.log_box.configure(state="disabled")
        self.after(0, _append)

    def _get_login_inputs(self):
        address = self.address_var.get().strip().strip("\\")
        username = self.username_var.get().strip()
        password = self.password_entry.get()
        device_folder = self.device_var.get()
        return address, username, password, device_folder

    def _set_busy(self, busy: bool):
        state = "disabled" if busy else "normal"
        self.run_button.configure(state=state)
        self.test_button.configure(state=state)
        if busy:
            self.progress.start(10)
        else:
            self.progress.stop()

    # ---- 연결 확인 ----

    def _on_test_connection(self):
        address, username, password, device_folder = self._get_login_inputs()
        if not address:
            messagebox.showerror("오류", "네트워크 주소를 입력하세요.")
            return
        if not username or not password:
            messagebox.showerror("오류", "사용자명과 비밀번호를 입력하세요.")
            return

        self._set_busy(True)
        thread = threading.Thread(
            target=self._test_connection,
            args=(address, username, password, device_folder),
            daemon=True,
        )
        thread.start()

    def _test_connection(self, address, username, password, device_folder):
        conn = None
        try:
            conn = open_smb(address, username, password, self.log)
            if remote_isdir(conn, device_folder):
                self.log("[확인] {0} 접근 가능".format(unc_display(address, device_folder)))
                self.after(0, lambda: messagebox.showinfo("연결 확인", "연결 성공: 해당 경로에 접근할 수 있습니다."))
            else:
                self.log("[확인] {0} 경로를 찾을 수 없습니다".format(unc_display(address, device_folder)))
                self.after(0, lambda: messagebox.showwarning(
                    "연결 확인", "공유 폴더 접속은 됐지만, 해당 장비 폴더를 찾을 수 없습니다.\n장비 종류나 주소를 다시 확인하세요."
                ))
        except Exception as e:
            msg = str(e)
            self.log("[확인 실패] {0}".format(msg))
            self.log(traceback.format_exc())
            self.after(0, lambda: messagebox.showerror("연결 확인", msg))
        finally:
            if conn is not None:
                close_smb(conn, address, self.log)
            self.after(0, lambda: self._set_busy(False))

    # ---- 복사 실행 ----

    def _on_run(self):
        address, username, password, device_folder = self._get_login_inputs()
        save_folder = sanitize_folder_name(self.save_folder_var.get())

        if not address:
            messagebox.showerror("오류", "네트워크 주소를 입력하세요.")
            return
        if not username or not password:
            messagebox.showerror("오류", "사용자명과 비밀번호를 입력하세요.")
            return
        if not save_folder:
            messagebox.showerror("오류", "저장 폴더 이름을 입력하세요.")
            return

        selected_jobs = [dict(job) for job, var in self.job_vars if var.get()]

        selected_headers = [h["code"] for h, var in self.modlog_header_vars if var.get()]
        if selected_headers:
            date_regex = r"(?:" + "|".join(re.escape(c) for c in selected_headers) + r")(\d{6})\.txt$"
            selected_jobs.append({
                "name": "MODLOG",
                "subpath": MODLOG_SUBPATH,
                "mode": "date_range",
                "date_regex": date_regex,
                "date_format": MODLOG_DATE_FORMAT,
            })

        if not selected_jobs:
            messagebox.showerror("오류", "복사할 항목을 하나 이상 선택하세요.")
            return

        needs_date = any(job["mode"] == "date_range" for job in selected_jobs)
        start_date = end_date = None
        if needs_date:
            try:
                start_date = datetime.strptime(self.start_date_picker.get(), "%Y-%m-%d")
                end_date = datetime.strptime(self.end_date_picker.get(), "%Y-%m-%d")
            except ValueError:
                messagebox.showerror("오류", "날짜 범위를 YYYY-MM-DD 형식으로 정확히 입력하세요.")
                return
            if start_date > end_date:
                messagebox.showerror("오류", "시작일이 종료일보다 늦을 수 없습니다.")
                return

        dest_root = os.path.join(get_app_dir(), save_folder)

        self._set_busy(True)

        thread = threading.Thread(
            target=self._run_jobs,
            args=(selected_jobs, address, username, password, device_folder, dest_root, start_date, end_date),
            daemon=True,
        )
        thread.start()

    def _run_jobs(self, jobs, address, username, password, device_folder, dest_root, start_date, end_date):
        conn = None
        try:
            conn = open_smb(address, username, password, self.log)

            for job in jobs:
                self.log("\n=== {0} 시작 ===".format(job["name"]))
                source = remote_join(device_folder, job["subpath"])
                dest = os.path.join(dest_root, job["name"])
                if job["mode"] == "all":
                    copy_all(conn, address, source, dest, self.log)
                elif job["mode"] == "date_range":
                    copy_date_range(
                        conn, address, source, dest,
                        job["date_regex"], job["date_format"],
                        start_date, end_date, self.log,
                    )

            self.log("\n모든 작업이 완료되었습니다.")
            self.after(0, lambda: messagebox.showinfo("완료", "파일 복사가 완료되었습니다."))
        except Exception as e:
            msg = str(e)
            self.log("\n[오류] {0}".format(msg))
            self.log(traceback.format_exc())
            self.after(0, lambda: messagebox.showerror("오류", msg))
        finally:
            if conn is not None:
                close_smb(conn, address, self.log)
            self.after(0, lambda: self._set_busy(False))


if __name__ == "__main__":
    app = App()
    app.mainloop()
