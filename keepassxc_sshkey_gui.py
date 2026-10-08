#!/usr/bin/env python3
"""
keepassxc-sshkey - graphical interface.

A thin front end over store_key() in keepassxc_sshkey.py. It exists so that
day-to-day use does not mean retyping a long command line.

Security notes
--------------
The vault password and any existing key passphrase are typed into masked
fields, kept in memory for the duration of the run, and never written
anywhere. The passphrase this tool generates is not shown, not logged, and
not returned to the caller - its only copy goes into the vault entry.

Because this window has to be operated by a person, it cannot be driven by
a script or an agent the way a command line can.

Requires tkinter, which ships with CPython on Windows and macOS. On Debian
and Ubuntu it is a separate package:  sudo apt install python3-tk
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import traceback
from pathlib import Path

# Make sure the core module is importable no matter where this file is
# started from or how it was launched.
sys.path.insert(0, str(Path(__file__).resolve().parent))

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover
    print(
        "keepassxc-sshkey: tkinter is not available in this Python.\n"
        "  Debian/Ubuntu : sudo apt install python3-tk\n"
        "  Fedora        : sudo dnf install python3-tkinter\n"
        "  Windows/macOS : use a Python built with tcl/tk (python.org builds have it)\n"
        "\n"
        "  The command line interface still works without tkinter:\n"
        "      keepassxc-sshkey <keyfile> --db <vault>",
        file=sys.stderr,
    )
    raise SystemExit(1)

import keepassxc_sshkey as core

APP_TITLE = "keepassxc-sshkey"

# --------------------------------------------------------------------------
# interface strings
#
# Chinese is the default because that is what the person using this build
# reads. Adding another language means copying this dict - nothing else in
# the file needs to change.
# --------------------------------------------------------------------------

TEXT = {
    "files": "文件",
    "key_label": "私钥文件",
    "key_pick": "从列表选",
    "key_browse": "浏览…",
    "db_label": "KeePassXC 库",
    "db_browse": "浏览…",
    "entry_label": "条目名称",
    "entry_hint": "留空 = 用私钥文件名",
    "secrets": "密码（只在内存里，不落盘）",
    "db_pass": "库主口令",
    "old_pass": "该私钥当前的口令",
    "show": "显示密码",
    "secrets_hint": "私钥没有口令就留空。",
    "newpass_frame": "新的私钥口令",
    "newpass_label": "将采用",
    "newpass_show": "显示",
    "newpass_again": "换一个",
    "newpass_hint": "这个口令由密码学安全随机数生成，会存进库条目的 Password 字段，\n"
                    "你不需要记住它。不满意就点「换一个」。\n"
                    "不勾选下面的「换成一个新的口令」时，这一行不使用。",
    "reencrypt": "换成一个新的口令",
    "keep_nopass": "这把私钥没有口令——\n"
                   "不勾选「换成一个新的口令」的话，库里就没有可存的口令了。\n"
                   "请勾上它，让工具生成一个新口令。",
    "keep_needpass": "请在「该私钥当前的口令」里填上它现在的口令，\n"
                     "或者勾选「换成一个新的口令」，让工具生成一个新的。",
    "keep_wrongpass": "这个口令打不开这把私钥，请检查后重试。",
    "status_checking": "校验口令…",
    "run": "存入库",
    "status_ready": "就绪",
    "status_working": "处理中…",
    "status_done": "完成",
    "status_failed": "失败",
    "log": "日志",
    "hello": "选一个私钥和库，然后点「存入库」。",
    "remember_db": "库路径会在第一次使用后记住。",
    "pick_key_title": "选择私钥文件",
    "pick_db_title": "选择 KeePassXC 库",
    "need_key": "先选一个私钥文件。",
    "need_key_missing": "找不到这个私钥文件：",
    "need_db": "先选 KeePassXC 库。",
    "need_pass": "请输入库主口令。",
    "starting": "开始…",
    "done_line": "完成。",
    "done_1": "磁盘上的私钥文件已用新口令保护。",
    "done_2": "新口令在库条目的 Password 字段里。",
    "done_backup": "旧版本保留在：",
    "done_noverify": "提示：没能回读校验存进去的值。",
    "failed_body": "出错，详情见日志。",
    "crash": "内部错误",
    "ok_body": "存入完成。\n\n磁盘上的私钥文件现在由一个新口令保护。\n那个口令在库条目的 Password 字段里，\n你不需要看到它，也不需要记住它。",
    "list_title": "选一个私钥",
    "list_none": "（没有找到任何私钥文件）",
    "list_scan": "扫描 ~/.ssh …",
}


# --------------------------------------------------------------------------
# a tiny settings file - paths only, never secrets
# --------------------------------------------------------------------------

def config_path() -> Path:
    if sys.platform.startswith("win"):
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / APP_TITLE / "config.json"


def load_config() -> dict:
    try:
        return json.loads(config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def save_config(data: dict) -> None:
    path = config_path()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass  # not worth interrupting the user over


def find_private_keys() -> list[Path]:
    """Private keys lying around in the usual places.

    Only the conventional key directories are scanned, and only files whose
    header says they are OpenSSH private keys - so this stays quick and
    never lists something that is not a key.
    """
    roots = [
        Path.home() / ".ssh",
        Path.home() / ".config" / "ssh",
    ]
    found: list[Path] = []
    seen: set[str] = set()

    for root in roots:
        if not root.is_dir():
            continue
        try:
            for entry in sorted(root.iterdir()):
                if not entry.is_file():
                    continue
                name = entry.name
                if name.startswith(".") or name.endswith((".pub", ".orig", ".known_hosts")):
                    continue
                if name in {"config", "known_hosts", "authorized_keys", "known_hosts.old"}:
                    continue
                if name in seen:
                    continue
                try:
                    head = entry.open("rb").read(40)
                except OSError:
                    continue
                if b"PRIVATE KEY" not in head:
                    continue
                seen.add(name)
                found.append(entry)
        except OSError:
            continue

    return found


# --------------------------------------------------------------------------
# the window
# --------------------------------------------------------------------------

class App:
    def __init__(self, root: tk.Tk, default_db: str = "") -> None:
        self.root = root
        self.cfg = load_config()
        self.events: queue.Queue[tuple[str, object]] = queue.Queue()
        self.running = False

        # A caller may hand in defaults (a private launcher, for instance, can
        # pre-fill the vault path). They win over the remembered config, and
        # nothing is baked into this file.
        if default_db:
            self.cfg["db"] = default_db

        root.title(APP_TITLE)
        root.minsize(660, 540)

        style = ttk.Style()
        try:
            style.theme_use("vista" if sys.platform.startswith("win") else "clam")
        except tk.TclError:
            pass

        outer = ttk.Frame(root, padding=12)
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(6, weight=1)

        # ---- paths --------------------------------------------------------
        paths = ttk.LabelFrame(outer, text=TEXT["files"], padding=10)
        paths.grid(row=0, column=0, sticky="ew")
        paths.columnconfigure(1, weight=1)

        self.key_var = tk.StringVar()
        self.db_var = tk.StringVar(value=self.cfg.get("db", ""))
        self.entry_var = tk.StringVar()

        r = 0
        ttk.Label(paths, text=TEXT["key_label"]).grid(row=r, column=0, sticky="w", padx=(0, 8))
        ttk.Entry(paths, textvariable=self.key_var).grid(row=r, column=1, sticky="ew")
        key_btns = ttk.Frame(paths)
        key_btns.grid(row=r, column=2, padx=(8, 0))
        ttk.Button(key_btns, text=TEXT["key_pick"], width=10,
                   command=self.pick_from_list).pack(side="left")
        ttk.Button(key_btns, text=TEXT["key_browse"], width=9,
                   command=self.pick_key).pack(side="left", padx=(6, 0))

        r += 1
        ttk.Label(paths, text=TEXT["db_label"]).grid(row=r, column=0, sticky="w", padx=(0, 8), pady=(8, 0))
        ttk.Entry(paths, textvariable=self.db_var).grid(row=r, column=1, sticky="ew", pady=(8, 0))
        ttk.Button(paths, text=TEXT["db_browse"], width=10,
                   command=self.pick_db).grid(row=r, column=2, padx=(8, 0), pady=(8, 0))

        r += 1
        ttk.Label(paths, text=TEXT["entry_label"]).grid(row=r, column=0, sticky="w", padx=(0, 8), pady=(8, 0))
        ttk.Entry(paths, textvariable=self.entry_var).grid(row=r, column=1, sticky="ew", pady=(8, 0))
        ttk.Label(paths, text=TEXT["entry_hint"], foreground="#777")\
            .grid(row=r, column=2, sticky="w", padx=(8, 0), pady=(8, 0))

        self.key_var.trace_add("write", lambda *_: self.autofill_entry())

        # ---- secrets ------------------------------------------------------
        secrets_frame = ttk.LabelFrame(outer, text=TEXT["secrets"], padding=10)
        secrets_frame.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        secrets_frame.columnconfigure(1, weight=1)

        self.db_pass_var = tk.StringVar()
        self.old_pass_var = tk.StringVar()

        ttk.Label(secrets_frame, text=TEXT["db_pass"]).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.db_pass_entry = ttk.Entry(secrets_frame, textvariable=self.db_pass_var, show="*")
        self.db_pass_entry.grid(row=0, column=1, sticky="ew")

        ttk.Label(secrets_frame, text=TEXT["old_pass"]).grid(row=1, column=0, sticky="w", padx=(0, 8), pady=(8, 0))
        self.old_pass_entry = ttk.Entry(secrets_frame, textvariable=self.old_pass_var, show="*")
        self.old_pass_entry.grid(row=1, column=1, sticky="ew", pady=(8, 0))

        self.show_secrets = tk.BooleanVar(value=False)
        ttk.Checkbutton(secrets_frame, text=TEXT["show"], variable=self.show_secrets,
                        command=self.toggle_secrets).grid(row=2, column=1, sticky="w", pady=(8, 0))

        ttk.Label(secrets_frame, text=TEXT["secrets_hint"], foreground="#777",
                  justify="left").grid(row=3, column=0, columnspan=2, sticky="w", pady=(8, 0))

        # ---- the passphrase that will be applied ---------------------------
        # Shown masked by default. You can look at it, and you can roll a new
        # one until you like it - but you cannot type your own, because the
        # whole point is that it came from a cryptographically secure
        # generator rather than from a human.
        np_frame = ttk.LabelFrame(outer, text=TEXT["newpass_frame"], padding=10)
        np_frame.grid(row=2, column=0, sticky="ew", pady=(10, 0))
        np_frame.columnconfigure(1, weight=1)

        self.new_pass_var = tk.StringVar(value=core.generate_passphrase())
        self.show_new = tk.BooleanVar(value=False)

        ttk.Label(np_frame, text=TEXT["newpass_label"]).grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.new_pass_entry = ttk.Entry(np_frame, textvariable=self.new_pass_var,
                                        show="*", state="readonly",
                                        font=("Consolas", 10))
        self.new_pass_entry.grid(row=0, column=1, sticky="ew")
        np_btns = ttk.Frame(np_frame)
        np_btns.grid(row=0, column=2, padx=(8, 0))
        self.show_new_check = ttk.Checkbutton(np_btns, text=TEXT["newpass_show"],
                                              variable=self.show_new,
                                              command=self.on_show_new_changed)
        self.show_new_check.pack(side="left")
        self.regen_button = ttk.Button(np_btns, text=TEXT["newpass_again"], width=10,
                                       command=self.regen_pass)
        self.regen_button.pack(side="left", padx=(10, 0))

        ttk.Label(np_frame, text=TEXT["newpass_hint"], foreground="#777",
                  justify="left").grid(row=1, column=0, columnspan=3, sticky="w", pady=(8, 0))

        # ---- options ------------------------------------------------------
        # Deliberately just one checkbox. A backup of the previous key file
        # is always kept - there is never a good reason not to - and the
        # log clears itself on every run, so neither needs a control.
        opts = ttk.Frame(outer)
        opts.grid(row=3, column=0, sticky="ew", pady=(10, 0))

        self.reencrypt = tk.BooleanVar(value=True)
        ttk.Checkbutton(opts, text=TEXT["reencrypt"], variable=self.reencrypt,
                        command=self.update_newpass_state).pack(side="left")
        self.update_newpass_state()   # start in sync with the default (ticked)

        # ---- action -------------------------------------------------------
        actions = ttk.Frame(outer)
        actions.grid(row=4, column=0, sticky="ew", pady=(14, 0))

        self.run_button = ttk.Button(actions, text=TEXT["run"], command=self.start, width=14)
        self.run_button.pack(side="left")

        self.status = ttk.Label(actions, text=TEXT["status_ready"])
        self.status.pack(side="left", padx=(18, 0))

        self.progress = ttk.Progressbar(actions, mode="indeterminate", length=150)

        # ---- log ----------------------------------------------------------
        log_frame = ttk.LabelFrame(outer, text=TEXT["log"], padding=(8, 6))
        log_frame.grid(row=6, column=0, sticky="nsew", pady=(14, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.log_text = tk.Text(log_frame, height=9, wrap="word", state="disabled",
                                font=("Consolas", 9))
        self.log_text.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        self.log_text.configure(yscrollcommand=scroll.set)

        self.append_log(TEXT["hello"])
        if not self.db_var.get():
            self.append_log(TEXT["remember_db"])

        self.root.after(100, self.drain)
        self.db_pass_entry.focus_set()

    # ---- small helpers ---------------------------------------------------

    def toggle_secrets(self) -> None:
        char = "" if self.show_secrets.get() else "*"
        self.db_pass_entry.configure(show=char)
        self.old_pass_entry.configure(show=char)

    def on_show_new_changed(self) -> None:
        """Reveal or hide the passphrase that is about to be applied."""
        self.new_pass_entry.configure(show="" if self.show_new.get() else "*")

    def update_newpass_state(self) -> None:
        """Grey the new-passphrase row out when it will not be used.

        The row only matters while "换成一个新的口令" is ticked; leaving it
        looking active would suggest a passphrase that is never applied.
        Only availability changes here - the show/hide choice is the
        user's and stays exactly as it was set.
        """
        in_use = bool(self.reencrypt.get())
        self.new_pass_entry.configure(state="readonly" if in_use else "disabled")
        self.show_new_check.configure(state="normal" if in_use else "disabled")
        self.regen_button.configure(state="normal" if in_use else "disabled")

    def regen_pass(self) -> None:
        """Roll a new passphrase.

        The show/hide setting is left exactly as the user set it - switching
        it back would just make them tick the box again to look at the new
        value.
        """
        self.new_pass_var.set(core.generate_passphrase())

    def append_log(self, text: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def autofill_entry(self) -> None:
        if self.entry_var.get().strip():
            return
        key = self.key_var.get().strip()
        if key:
            self.entry_var.set(Path(key).stem)

    def pick_key(self) -> None:
        initial = self.cfg.get("last_dir") or str(Path.home() / ".ssh")
        chosen = filedialog.askopenfilename(title=TEXT["pick_key_title"], initialdir=initial)
        if chosen:
            self.key_var.set(chosen)
            self.entry_var.set(Path(chosen).stem)
            self.cfg["last_dir"] = str(Path(chosen).parent)
            save_config(self.cfg)

    def pick_db(self) -> None:
        initial = self.cfg.get("last_dir") or str(Path.home())
        chosen = filedialog.askopenfilename(
            title=TEXT["pick_db_title"],
            initialdir=initial,
            filetypes=[("KeePassXC", "*.kdbx"), ("All files", "*.*")],
        )
        if chosen:
            self.db_var.set(chosen)
            self.cfg["db"] = chosen
            save_config(self.cfg)

    # ---- the key picker --------------------------------------------------

    def pick_from_list(self) -> None:
        keys = find_private_keys()
        win = tk.Toplevel(self.root)
        win.title(TEXT["list_title"])
        win.transient(self.root)
        win.grab_set()
        win.geometry("560x340")

        frame = ttk.Frame(win, padding=12)
        frame.pack(fill="both", expand=True)

        if not keys:
            ttk.Label(frame, text=TEXT["list_none"]).pack(anchor="w")
            ttk.Button(frame, text="OK", command=win.destroy).pack(anchor="e", pady=(12, 0))
            return

        ttk.Label(frame, text=TEXT["list_scan"]).pack(anchor="w")
        box = tk.Listbox(frame, height=12, font=("Consolas", 9))
        box.pack(fill="both", expand=True, pady=(8, 0))
        for path in keys:
            box.insert("end", str(path))
        box.selection_set(0)

        def choose(_event=None) -> None:
            sel = box.curselection()
            if sel:
                chosen = Path(box.get(sel[0]))
                self.key_var.set(str(chosen))
                self.entry_var.set(chosen.stem)
                win.destroy()

        box.bind("<Double-Button-1>", choose)
        btns = ttk.Frame(frame)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="OK", command=choose, width=12).pack(side="right")
        ttk.Button(btns, text="Cancel", command=win.destroy, width=12).pack(side="right", padx=(0, 8))

    # ---- running ---------------------------------------------------------

    def start(self) -> None:
        if self.running:
            return

        key = self.key_var.get().strip()
        db = self.db_var.get().strip()
        db_password = self.db_pass_var.get()

        if not key:
            messagebox.showwarning(APP_TITLE, TEXT["need_key"])
            return
        if not Path(key).is_file():
            messagebox.showerror(APP_TITLE, TEXT["need_key_missing"] + "\n" + key)
            return
        if not db:
            messagebox.showwarning(APP_TITLE, TEXT["need_db"])
            return
        if not db_password:
            messagebox.showwarning(APP_TITLE, TEXT["need_pass"])
            return

        if not self.reencrypt.get():
            # Keeping the current passphrase: make sure there is one to
            # keep, and that it really opens the key - before the whole
            # run commits to it.
            old_pass = self.old_pass_var.get()
            try:
                protected = core.is_protected(Path(key))
            except Exception:
                protected = None   # cannot tell - let the run itself report it
            if protected is False:
                messagebox.showwarning(APP_TITLE, TEXT["keep_nopass"])
                return
            if protected and not old_pass:
                messagebox.showwarning(APP_TITLE, TEXT["keep_needpass"])
                return
            if protected and old_pass:
                self.status.configure(text=TEXT["status_checking"])
                self.root.update_idletasks()
                try:
                    opens = core.verify_existing_passphrase(
                        core.find_tool("ssh-keygen"), Path(key), old_pass)
                except Exception:
                    opens = None   # cannot check here; the core checks again
                self.status.configure(text=TEXT["status_ready"])
                if opens is False:
                    messagebox.showwarning(APP_TITLE, TEXT["keep_wrongpass"])
                    return

        self.cfg["db"] = db
        save_config(self.cfg)

        self.running = True
        self.run_button.configure(state="disabled")
        self.status.configure(text=TEXT["status_working"])
        self.progress.pack(side="left", padx=(18, 0))
        self.progress.start(12)
        self.clear_log()
        self.append_log(TEXT["starting"])

        threading.Thread(
            target=self._work,
            args=(key, db, self.entry_var.get().strip(), db_password,
                  self.old_pass_var.get(), self.reencrypt.get(),
                  self.new_pass_var.get()),
            daemon=True,
        ).start()

    def _work(self, key: str, db: str, entry: str, db_password: str,
              old_passphrase: str, reencrypt: bool, new_passphrase: str) -> None:
        try:
            result = core.store_key(
                Path(key), Path(db), entry or Path(key).stem, db_password,
                old_passphrase=old_passphrase,
                # when the passphrase is not being changed, what goes into
                # the vault is the key's existing one
                new_passphrase=new_passphrase if reencrypt else old_passphrase,
                keep_backup=True,
                reencrypt_key=reencrypt,
                log=lambda m: self.events.put(("log", m)),
            )
            self.events.put(("done", result))
        except Exception:  # never let a thread die silently
            self.events.put(("crash", traceback.format_exc()))

    def drain(self) -> None:
        try:
            while True:
                kind, payload = self.events.get_nowait()
                if kind == "log":
                    self.append_log(str(payload))
                elif kind == "done":
                    self.finish(payload)
                elif kind == "crash":
                    self.append_log(TEXT["crash"])
                    self.append_log(str(payload))
                    self.finish(None)
        except queue.Empty:
            pass
        self.root.after(100, self.drain)

    def finish(self, result) -> None:
        self.running = False
        self.run_button.configure(state="normal")
        self.progress.stop()
        self.progress.pack_forget()
        # wipe the secrets from the widgets as soon as the run is over
        self.db_pass_var.set("")
        self.old_pass_var.set("")

        if result is None:
            self.status.configure(text=TEXT["status_failed"])
            messagebox.showerror(APP_TITLE, TEXT["failed_body"])
            return

        if not result.ok:
            self.status.configure(text=TEXT["status_failed"])
            self.append_log("")
            self.append_log("失败：" + result.message)
            messagebox.showerror(APP_TITLE, result.message)
            return

        self.status.configure(text=TEXT["status_done"])
        self.append_log("")
        self.append_log(TEXT["done_line"])
        self.append_log("  " + TEXT["done_1"])
        self.append_log("  " + TEXT["done_2"])
        if result.backup:
            self.append_log("  " + TEXT["done_backup"] + result.backup)
        if not result.verified:
            self.append_log("  " + TEXT["done_noverify"])

        messagebox.showinfo(APP_TITLE, TEXT["ok_body"])


def run_gui(default_db: str = "") -> int:
    root = tk.Tk()
    App(root, default_db=default_db)
    root.mainloop()
    return 0


def _cli() -> int:
    """Allow: python keepassxc_sshkey_gui.py [--db PATH]"""
    default_db = ""
    argv = sys.argv[1:]
    i = 0
    while i < len(argv):
        if argv[i] == "--db" and i + 1 < len(argv):
            default_db = argv[i + 1]
            i += 2
            continue
        if argv[i].startswith("--db="):
            default_db = argv[i].split("=", 1)[1]
        i += 1
    return run_gui(default_db)


if __name__ == "__main__":
    raise SystemExit(_cli())
