import sys
import threading
import queue
import math
import tkinter as tk
from tkinter import ttk
from tkinter import messagebox, filedialog, simpledialog
import os
import re
import time
import secrets
import subprocess
import importlib
import json
import tempfile
from cryptography.exceptions import InvalidTag

def ensure_package(pkg, import_name=None):
    try:
        importlib.import_module(import_name or pkg)
        return
    except Exception:
        pass
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        importlib.invalidate_caches()
        importlib.import_module(import_name or pkg)
    except Exception as e:
        try:
            r = tk.Tk()
            r.withdraw()
            messagebox.showerror("Dependency Install Error", str(e))
        except Exception:
            pass
        sys.exit(1)

ensure_package("openai", "openai")
ensure_package("cryptography", "cryptography")

from openai import OpenAI
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

os.environ.setdefault("PYTHONUTF8", "1")
try:
    sys.stdout.reconfigure(encoding="utf-8")
    sys.stderr.reconfigure(encoding="utf-8")
except Exception:
    pass

OPENAI_API_KEY = "INSERT API KEY HERE"
client = OpenAI(api_key=OPENAI_API_KEY, timeout=60.0, max_retries=1)

APP_TITLE = "ClatGPT Multi-Model Chatbot v1.00"
DISPLAY_NAMES = [
    "GPT-5", "GPT-5-mini", "GPT-5-nano",
    "GPT-4", "GPT-4o", "GPT-4o-mini",
    "GPT-4-o1", "GPT-4-o1-pro", "GPT-4-o1-mini",
    "GPT-4-o3", "GPT-4-o3-mini", "GPT-4-o3-pro",
    "GPT-4-o4-mini", "GPT-4.1", "GPT-4.1-mini", "GPT-4.1-nano",
    "GPT-4 Turbo",
    "GPT-3.5 Turbo"
]
MODEL_MAP = {
    "GPT-5": "gpt-5",
    "GPT-5-mini": "gpt-5-mini",
    "GPT-5-nano": "gpt-5-nano",
    "GPT-4": "gpt-4",
    "GPT-4o": "gpt-4o",
    "GPT-4o-mini": "gpt-4o-mini",
    "GPT-4-o1": "o1",
    "GPT-4-o1-pro": "o1-pro",
    "GPT-4-o1-mini": "o1-mini",
    "GPT-4-o3": "o3",
    "GPT-4-o3-mini": "o3-mini",
    "GPT-4-o3-pro": "o3-pro",
    "GPT-4-o4-mini": "o4-mini",
    "GPT-4.1": "gpt-4.1",
    "GPT-4.1-mini": "gpt-4.1-mini",
    "GPT-4.1-nano": "gpt-4.1-nano",
    "GPT-4 Turbo": "gpt-4-turbo",
    "GPT-3.5 Turbo": "gpt-3.5-turbo"
}

ASCII_RED = "#D32F2F"
ASCII_BLUE = "#1976D2"
BG_WHITE = "#FFFFFF"
MAX_TURNS_PER_MODEL = 40
STREAM_STALL_TIMEOUT_SEC = 25.0
STREAM_HARD_TIMEOUT_SEC = 180.0
ENC_HEADER = b"CHACHA20-POLY1305-256\n"

def get_banner_lines():
    return [
         "██████╗██╗      █████╗ ████████╗ ██████╗ ██████╗ ████████╗",
        "██╔════╝██║     ██╔══██╗╚══██╔══╝██╔════╝ ██╔══██╗╚══██╔══╝",
        "██║     ██║     ███████║   ██║   ██║  ███╗██████╔╝   ██║   ",
        "██║     ██║     ██╔══██║   ██║   ██║   ██║██╔═══╝    ██║   ",
        "╚██████╗███████╗██║  ██║   ██║   ╚██████╔╝██║        ██║   ",
        " ╚═════╝╚══════╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝        ╚═╝   ",
    ]

def _sanitize_text(s):
    t = re.sub(r'sk-[A-Za-z0-9_\-]{10,}', 'sk-***', str(s))
    t = re.sub(r'([A-Za-z]:\\\\[^\\n"]+|/[^\\s"]{2,})', '<path>', t)
    return t

def _cc20p_encrypt(key_bytes, data_bytes):
    nonce = secrets.token_bytes(12)
    aead = ChaCha20Poly1305(key_bytes)
    ct = aead.encrypt(nonce, data_bytes, ENC_HEADER)
    return nonce + ct

def _cc20p_decrypt(key_bytes, blob_bytes):
    if len(blob_bytes) < 13:
        raise ValueError("Invalid ciphertext")
    nonce = blob_bytes[:12]
    ct = blob_bytes[12:]
    aead = ChaCha20Poly1305(key_bytes)
    return aead.decrypt(nonce, ct, ENC_HEADER)

def _prompt_hex256_key(title, parent):
    result = [None]
    win = tk.Toplevel(parent)
    win.title(title)
    win.transient(parent)
    win.grab_set()
    win.resizable(False, False)
    frm = ttk.Frame(win, padding=12)
    frm.pack(fill="both", expand=True)
    ttk.Label(frm, text="Enter 256-bit key (64 hex chars, UPPERCASE):").grid(row=0, column=0, columnspan=4, sticky="w")
    key_var = tk.StringVar(value="")
    ent = ttk.Entry(frm, textvariable=key_var, width=68)
    ent.grid(row=1, column=0, columnspan=4, sticky="ew", pady=(6, 8))
    status_var = tk.StringVar(value="")
    ttk.Label(frm, textvariable=status_var, foreground="#B91C1C").grid(row=2, column=0, columnspan=4, sticky="w")
    def on_generate():
        key = secrets.token_bytes(32).hex().upper()
        key_var.set(key)
        status_var.set("Generated new key.")
    def on_copy():
        k = key_var.get().strip()
        if not k:
            status_var.set("No key to copy.")
            win.bell()
            return
        try:
            win.clipboard_clear()
            win.clipboard_append(k)
            status_var.set("Key copied to clipboard.")
        except Exception as e:
            status_var.set(_sanitize_text(e))
    def on_ok():
        s = key_var.get().strip().upper()
        if re.fullmatch(r"[0-9A-F]{64}", s):
            try:
                b = bytes.fromhex(s)
                if len(b) == 32:
                    result[0] = b
                    win.destroy()
                    return
            except Exception:
                pass
        status_var.set("Invalid key. Provide 64 hex characters.")
        win.bell()
    def on_cancel():
        result[0] = None
        win.destroy()
    gen_btn = ttk.Button(frm, text="Generate Key", command=on_generate)
    gen_btn.grid(row=3, column=0, sticky="w", pady=(10, 0))
    copy_btn = ttk.Button(frm, text="Copy Key", command=on_copy)
    copy_btn.grid(row=3, column=1, sticky="w", padx=(8, 0), pady=(10, 0))
    ok_btn = ttk.Button(frm, text="OK", command=on_ok)
    ok_btn.grid(row=3, column=2, sticky="e", pady=(10, 0))
    cancel_btn = ttk.Button(frm, text="Cancel", command=on_cancel)
    cancel_btn.grid(row=3, column=3, sticky="e", padx=(8, 0), pady=(10, 0))
    frm.grid_columnconfigure(0, weight=1)
    frm.grid_columnconfigure(1, weight=0)
    frm.grid_columnconfigure(2, weight=0)
    frm.grid_columnconfigure(3, weight=0)
    ent.focus_set()
    win.bind("<Return>", lambda e: on_ok())
    win.bind("<Escape>", lambda e: on_cancel())
    win.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (win.winfo_width() // 2)
    y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (win.winfo_height() // 2)
    try:
        win.geometry(f"+{max(0,x)}+{max(0,y)}")
    except Exception:
        pass
    parent.wait_window(win)
    return result[0]

def _config_dir():
    if sys.platform.startswith("win"):
        base = os.environ.get("APPDATA") or os.path.expanduser("~")
        return os.path.join(base, "ClatGPT")
    if sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
        return os.path.join(base, "ClatGPT")
    base = os.path.expanduser("~/.config")
    return os.path.join(base, "clatgpt")

def _config_file():
    return os.path.join(_config_dir(), "settings.json")

def _load_settings():
    try:
        path = _config_file()
        if not os.path.isfile(path):
            return {}
        with open(path, "rb") as f:
            data = f.read()
        return json.loads(data.decode("utf-8"))
    except Exception:
        return {}

def _atomic_write_bytes(path, data_bytes):
    d = os.path.dirname(path) or "."
    os.makedirs(d, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", dir=d)
    try:
        with os.fdopen(fd, "wb") as t:
            t.write(data_bytes)
            t.flush()
            os.fsync(t.fileno())
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass

def _save_settings(state):
    try:
        data = json.dumps(state, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
        _atomic_write_bytes(_config_file(), data)
        return True
    except Exception:
        return False

class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.configure(bg=BG_WHITE)
        self._settings = _load_settings()
        self.conversations = {}
        self.system_prompts = self._settings.get("system_prompts", {})
        last_model = self._settings.get("last_model", DISPLAY_NAMES[0])
        if last_model not in DISPLAY_NAMES:
            last_model = DISPLAY_NAMES[0]
        self.current_model_name = last_model
        self.streaming_thread = None
        self.stop_stream = threading.Event()
        self.stream_queue = queue.Queue()
        self.flush_job = None
        self.wrap_var = tk.BooleanVar(value=bool(self._settings.get("wrap", True)))
        self.status_var = tk.StringVar(value="Ready.")
        self.autosave_var = tk.BooleanVar(value=bool(self._settings.get("autosave_enabled", False)))
        self.autosave_path = self._settings.get("autosave_path", None)
        self.autosave_key_bytes = None
        self._last_autosave_ts = 0.0
        self.placeholder = "Type your message…"
        self.temperature_var = tk.DoubleVar(value=float(self._settings.get("temperature", 1.0)))
        self.temp_value_var = tk.StringVar(value=f"{float(self._settings.get('temperature', 1.0)):.2f}")
        self._loading_sys_prompt = False
        self._models_cache = set()
        self._models_cache_time = 0.0
        self._configure_style()
        self._build_layout()
        self._populate_models()
        self._select_initial_model()
        self._bind_shortcuts()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _configure_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Main.TFrame", background=BG_WHITE)
        style.configure("BannerRed.TLabel", background=BG_WHITE, foreground=ASCII_RED, font=("Courier New", 10, "bold"))
        style.configure("BannerBlue.TLabel", background=BG_WHITE, foreground=ASCII_BLUE, font=("Courier New", 11, "bold"))
        style.configure("Toolbar.TFrame", background=BG_WHITE)
        style.configure("Panel.TLabelframe", background=BG_WHITE)
        style.configure("Panel.TLabelframe.Label", background=BG_WHITE, foreground="#0F172A", font=("Segoe UI", 10, "bold"))
        style.configure("TLabel", background=BG_WHITE, foreground="#0F172A", font=("Segoe UI", 10))
        style.configure("TButton", font=("Segoe UI", 10), padding=(10, 6))

    def _build_layout(self):
        self.root.minsize(1000, 650)
        main = ttk.Frame(self.root, style="Main.TFrame", padding=10)
        main.pack(fill="both", expand=True)
        menubar = tk.Menu(self.root)
        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Open Encrypted Transcript…", command=self._open_encrypted_transcript)
        filemenu.add_command(label="Save Transcript…", command=self._save_transcript, accelerator="Ctrl+S")
        filemenu.add_checkbutton(label="Autosave Transcript", variable=self.autosave_var, command=self._toggle_autosave)
        filemenu.add_command(label="Set Autosave File…", command=self._choose_autosave_file)
        filemenu.add_command(label="Change Autosave Key…", command=self._change_autosave_key)
        filemenu.add_separator()
        filemenu.add_command(label="Clear Conversation", command=self._clear_conversation, accelerator="Ctrl+L")
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=filemenu)
        editmenu = tk.Menu(menubar, tearoff=0)
        editmenu.add_command(label="Copy", command=lambda: self.root.focus_get().event_generate("<<Copy>>"))
        editmenu.add_command(label="Paste", command=lambda: self.root.focus_get().event_generate("<<Paste>>"))
        editmenu.add_command(label="Select All", command=lambda: self.root.focus_get().event_generate("<<SelectAll>>"))
        menubar.add_cascade(label="Edit", menu=editmenu)
        viewmenu = tk.Menu(menubar, tearoff=0)
        viewmenu.add_checkbutton(label="Word Wrap", variable=self.wrap_var, command=self._apply_wrap)
        menubar.add_cascade(label="View", menu=viewmenu)
        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="About", command=lambda: messagebox.showinfo("About", "ClatGPT Chatbot. Copyright © 2025 Joshua M Clatney", parent=self.root))
        menubar.add_cascade(label="Help", menu=helpmenu)
        self.root.config(menu=menubar)
        banner = ttk.Frame(main, style="Main.TFrame")
        banner.pack(fill="x", pady=(0, 6))
        for line in get_banner_lines():
            ttk.Label(banner, text=line, style="BannerRed.TLabel").pack(fill="x")
        ttk.Label(banner, text="M U L T I   M O D E L   C H A T B O T    Version 1.00", style="BannerBlue.TLabel").pack(fill="x", pady=(4, 0))
        toolbar = ttk.Frame(main, style="Toolbar.TFrame")
        toolbar.pack(fill="x", pady=(4, 8))
        temp_frame = ttk.Frame(toolbar)
        temp_frame.pack(side="left", padx=(0, 12))
        ttk.Label(temp_frame, text="Temperature").pack(side="left", padx=(0, 6))
        self.temp_scale = ttk.Scale(temp_frame, from_=0.0, to=1.0, orient="horizontal", variable=self.temperature_var, length=220, command=self._on_temp_change)
        self.temp_scale.pack(side="left")
        self.temp_value = ttk.Label(temp_frame, textvariable=self.temp_value_var, width=4)
        self.temp_value.pack(side="left", padx=(6, 0))
        self.clear_conv_btn = ttk.Button(toolbar, text="Clear Conversation", command=self._clear_conversation)
        self.clear_conv_btn.pack(side="left")
        right_status = ttk.Frame(toolbar)
        right_status.pack(side="right")
        self.status_label = ttk.Label(right_status, textvariable=self.status_var)
        self.status_label.pack(side="right")
        body = ttk.Frame(main, style="Main.TFrame")
        body.pack(fill="both", expand=True)
        body.grid_columnconfigure(0, weight=0)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)
        left = ttk.Labelframe(body, text="Models", style="Panel.TLabelframe", padding=6)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 10))
        widest = max(len(n) for n in DISPLAY_NAMES)
        self.model_list = tk.Listbox(left, activestyle="dotbox", exportselection=False, height=len(DISPLAY_NAMES), width=widest + 2, relief="solid", borderwidth=1)
        self.model_list.pack(fill="both", expand=False, padx=2, pady=(0, 8))
        self.model_list.bind("<<ListboxSelect>>", self._on_model_select)
        sys_frame = ttk.Labelframe(left, text="System Prompt", padding=4, style="Panel.TLabelframe")
        sys_frame.pack(fill="x", expand=False)
        self.system_prompt_text = tk.Text(sys_frame, height=4, width=24, wrap="word", relief="solid", borderwidth=1, padx=6, pady=6, bg="#FFFFFF")
        self.system_prompt_text.pack(anchor="w")
        self.system_prompt_text.bind("<KeyRelease>", self._on_system_prompt_changed)
        chat_frame = ttk.Labelframe(body, text="Chat", style="Panel.TLabelframe", padding=6)
        chat_frame.grid(row=0, column=1, sticky="nsew")
        chat_frame.grid_columnconfigure(0, weight=1)
        chat_frame.grid_rowconfigure(0, weight=1)
        chat_frame.grid_rowconfigure(1, weight=0)
        transcript_wrap = ttk.Frame(chat_frame)
        transcript_wrap.grid(row=0, column=0, sticky="nsew", pady=(0, 6))
        self.transcript = tk.Text(transcript_wrap, wrap="word", state="disabled", bg="#FAFAFA", relief="flat", padx=8, pady=8)
        self.transcript.pack(side="left", fill="both", expand=True)
        scroll = ttk.Scrollbar(transcript_wrap, orient="vertical", command=self.transcript.yview)
        scroll.pack(side="right", fill="y")
        self.transcript.configure(yscrollcommand=scroll.set)
        self.transcript.tag_configure("user", foreground="#111827", font=("Segoe UI", 10, "bold"))
        self.transcript.tag_configure("assistant", foreground="#065F46", font=("Segoe UI", 10))
        self.transcript.tag_configure("modelname", foreground="#B91C1C", font=("Segoe UI", 9, "bold"))
        self._build_transcript_context_menu()
        entry_bar = ttk.Frame(chat_frame)
        entry_bar.grid(row=1, column=0, sticky="ew")
        entry_bar.grid_columnconfigure(0, weight=1)
        self.user_input = tk.Text(entry_bar, height=3, wrap="word", relief="solid", borderwidth=2, padx=8, pady=8, bg="#FFFFFF")
        self.user_input.grid(row=0, column=0, sticky="ew")
        self.user_input.bind("<Return>", self._enter_to_send)
        self.user_input.bind("<Shift-Return>", self._shift_enter_newline)
        self.user_input.bind("<Control-Return>", self._enter_to_send)
        self.user_input.bind("<FocusIn>", self._on_input_focus_in)
        self.user_input.bind("<FocusOut>", self._on_input_focus_out)
        btns = ttk.Frame(entry_bar)
        btns.grid(row=0, column=1, padx=(8, 0))
        self.send_btn = ttk.Button(btns, text="Send", command=self._send_message)
        self.send_btn.pack(fill="x")
        self.stop_btn = ttk.Button(btns, text="Stop", command=self._stop_streaming, state="disabled")
        self.stop_btn.pack(fill="x", pady=(6, 0))
        self._apply_wrap()
        self._show_model_header()
        self._set_placeholder()
        self._on_temp_change(None)

    def _build_transcript_context_menu(self):
        self.ctx = tk.Menu(self.root, tearoff=0)
        self.ctx.add_command(label="Copy", command=lambda: self.transcript.event_generate("<<Copy>>"))
        self.ctx.add_command(label="Select All", command=lambda: self.transcript.event_generate("<<SelectAll>>"))
        self.transcript.bind("<Button-3>", self._show_ctx)

    def _show_ctx(self, event):
        self.ctx.tk_popup(event.x_root, event.y_root)

    def _apply_wrap(self):
        self.transcript.configure(wrap="word" if self.wrap_var.get() else "none")
        self._settings["wrap"] = bool(self.wrap_var.get())
        _save_settings(self._settings)

    def _bind_shortcuts(self):
        self.root.bind("<Escape>", lambda e: self._stop_streaming())
        self.root.bind("<Control-s>", lambda e: self._save_transcript())
        self.root.bind("<Control-l>", lambda e: self._clear_conversation())

    def _populate_models(self):
        self.model_list.delete(0, "end")
        for name in DISPLAY_NAMES:
            self.model_list.insert("end", name)

    def _select_initial_model(self):
        idx = DISPLAY_NAMES.index(self.current_model_name)
        self.model_list.selection_clear(0, "end")
        self.model_list.selection_set(idx)
        self.model_list.see(idx)
        self._load_system_prompt_for_current()
        self._set_status("Ready.")
        self.user_input.focus_set()

    def _on_model_select(self, event):
        sel = self.model_list.curselection()
        if not sel:
            return
        self.current_model_name = self.model_list.get(sel[0])
        self._settings["last_model"] = self.current_model_name
        _save_settings(self._settings)
        self._set_status("Ready.")
        self._load_system_prompt_for_current()
        self._show_model_header()
        self.user_input.focus_set()

    def _load_system_prompt_for_current(self):
        mid = MODEL_MAP[self.current_model_name]
        prompt = self.system_prompts.get(mid, "")
        self._loading_sys_prompt = True
        self.system_prompt_text.delete("1.0", "end")
        if prompt:
            self.system_prompt_text.insert("1.0", prompt)
        self._loading_sys_prompt = False

    def _on_system_prompt_changed(self, event):
        if self._loading_sys_prompt:
            return
        mid = MODEL_MAP[self.current_model_name]
        text = self.system_prompt_text.get("1.0", "end").strip()
        self.system_prompts[mid] = text
        self._settings["system_prompts"] = self.system_prompts
        _save_settings(self._settings)

    def _clear_conversation(self):
        mid = MODEL_MAP[self.current_model_name]
        self.conversations[mid] = []
        self._clear_transcript()
        self._set_status("Conversation cleared.")
        self._persist_transcript()

    def _get_messages_for_model(self, model_id):
        if model_id not in self.conversations:
            self.conversations[model_id] = []
        return self.conversations[model_id]

    def _trim_history(self, model_id):
        msgs = self.conversations.get(model_id, [])
        if len(msgs) > MAX_TURNS_PER_MODEL:
            self.conversations[model_id] = msgs[-MAX_TURNS_PER_MODEL:]

    def _clear_transcript(self):
        self.transcript.configure(state="normal")
        self.transcript.delete("1.0", "end")
        self.transcript.configure(state="disabled")

    def _append_text(self, text, tag=None):
        self.transcript.configure(state="normal")
        self.transcript.insert("end", text + "\n", tag if tag else None)
        self.transcript.see("end")
        self.transcript.configure(state="disabled")

    def _append_inline(self, text, tag=None):
        self.transcript.configure(state="normal")
        self.transcript.insert("end", text, tag if tag else None)
        self.transcript.see("end")
        self.transcript.configure(state="disabled")

    def _show_model_header(self):
        self._append_text("", None)
        self._append_text(f"--- Chatting with {self.current_model_name} ---", "modelname")

    def _set_status(self, msg):
        self.status_var.set(msg)

    def _enter_to_send(self, event):
        self._send_message()
        return "break"

    def _shift_enter_newline(self, event):
        return None

    def _set_placeholder(self):
        if not self.user_input.get("1.0", "end").strip():
            self.user_input.insert("1.0", self.placeholder)
            self.user_input.configure(fg="#6B7280")

    def _on_input_focus_in(self, event):
        if self.user_input.get("1.0", "end").strip() == self.placeholder:
            self.user_input.delete("1.0", "end")
            self.user_input.configure(fg="#000000")

    def _on_input_focus_out(self, event):
        if not self.user_input.get("1.0", "end").strip():
            self._set_placeholder()

    def _on_temp_change(self, _):
        val = float(self.temperature_var.get())
        self.temp_value_var.set(f"{val:.2f}")
        self._settings["temperature"] = val
        _save_settings(self._settings)

    def _estimate_tokens(self, text):
        return int(math.ceil(len(text) / 4.0))

    def _build_request_messages(self, model_id, new_user_msg):
        msgs = []
        sp = self.system_prompts.get(model_id, "").strip()
        if sp:
            msgs.append({"role": "system", "content": sp})
        history = self._get_messages_for_model(model_id)
        msgs.extend(history)
        msgs.append({"role": "user", "content": new_user_msg})
        return msgs

    def _calc_input_tokens(self, request_messages):
        total = 0
        for m in request_messages:
            c = m.get("content", "")
            total += self._estimate_tokens(c)
        return total

    def _refresh_models_cache(self):
        now = time.monotonic()
        if now - self._models_cache_time < 300.0:
            return
        names = set()
        try:
            resp = client.models.list()
            for m in getattr(resp, "data", []):
                mid = getattr(m, "id", None) or getattr(m, "name", None)
                if mid:
                    names.add(mid)
        except Exception:
            names = set()
        self._models_cache = names
        self._models_cache_time = now

    def _model_supported(self, model_id):
        self._refresh_models_cache()
        if not self._models_cache:
            return True
        return model_id in self._models_cache

    def _send_message(self):
        if self.streaming_thread and self.streaming_thread.is_alive():
            return
        raw = self.user_input.get("1.0", "end").strip()
        if not raw or raw == self.placeholder:
            return
        model_id = MODEL_MAP[self.current_model_name]
        if not self._model_supported(model_id):
            self._append_text("Error: Model unavailable for this account or region.")
            self._set_status("Error.")
            return
        request_messages = self._build_request_messages(model_id, raw)
        approx_in = self._calc_input_tokens(request_messages)
        self._append_text(f"You: {raw}", "user")
        self.user_input.delete("1.0", "end")
        self._set_placeholder()
        self.stop_stream.clear()
        self.send_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.root.config(cursor="watch")
        self._set_status("Streaming response...")
        self._append_inline(f"{self.current_model_name}: ", "modelname")
        self.streaming_thread = threading.Thread(target=self._stream_response, args=(model_id, request_messages, approx_in), daemon=True)
        self.streaming_thread.start()
        self._start_flush_loop()
        self._persist_transcript()

    def _start_flush_loop(self):
        if self.flush_job is None:
            self.flush_job = self.root.after(30, self._flush_stream)

    def _flush_stream(self):
        flushed = False
        while not self.stream_queue.empty():
            try:
                chunk = self.stream_queue.get_nowait()
            except queue.Empty:
                break
            if chunk:
                self._append_inline(chunk, "assistant")
                flushed = True
        if self.streaming_thread and self.streaming_thread.is_alive() and not self.stop_stream.is_set():
            self.flush_job = self.root.after(30, self._flush_stream)
        else:
            self.flush_job = None
        if flushed and self.autosave_var.get() and self.autosave_path:
            self._persist_transcript()

    def _stop_streaming(self):
        if self.streaming_thread and self.streaming_thread.is_alive():
            self.stop_stream.set()
            self._set_status("Stopping...")

    def _stream_response(self, model_id, request_messages, approx_in_tokens):
        err = None
        reply_parts = []
        start = time.monotonic()
        last = start
        try:
            with client.responses.stream(
                model=model_id,
                input=request_messages,
                temperature=float(self.temperature_var.get()),
            ) as stream:
                for event in stream:
                    if self.stop_stream.is_set():
                        break
                    now = time.monotonic()
                    if now - start > STREAM_HARD_TIMEOUT_SEC:
                        break
                    if now - last > STREAM_STALL_TIMEOUT_SEC:
                        break
                    et = getattr(event, "type", "")
                    if "response.output_text.delta" in et:
                        delta = getattr(event, "delta", "") or ""
                        if delta:
                            reply_parts.append(delta)
                            self.stream_queue.put(delta)
                            last = now
                if not self.stop_stream.is_set():
                    final = stream.get_final_response()
                    if not self.stop_stream.is_set():
                        full = ""
                        try:
                            full = getattr(final, "output_text", "") or ""
                        except Exception:
                            full = ""
                        if full and not reply_parts:
                            reply_parts.append(full)
                            self.stream_queue.put(full)
            reply = "".join(reply_parts)
            if reply and not self.stop_stream.is_set():
                self.conversations[model_id] = self.conversations.get(model_id, [])
                self.conversations[model_id].append({"role": "user", "content": request_messages[-1]["content"]})
                self.conversations[model_id].append({"role": "assistant", "content": reply})
                self._trim_history(model_id)
        except Exception as e:
            err = _sanitize_text(e)
        finally:
            self.root.after(0, self._finish_stream, err)

    def _finish_stream(self, err):
        if self.flush_job is not None:
            try:
                self.root.after_cancel(self.flush_job)
            except Exception:
                pass
            self.flush_job = None
        while not self.stream_queue.empty():
            try:
                chunk = self.stream_queue.get_nowait()
            except queue.Empty:
                break
            if chunk:
                self._append_inline(chunk, "assistant")
        self._append_text("", None)
        if err:
            self._append_text(f"Error: {err}")
            self._set_status("Error.")
        else:
            if self.stop_stream.is_set():
                self._set_status("Stopped.")
            else:
                self._set_status("Ready.")
        self.root.config(cursor="")
        self.send_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.user_input.focus_set()
        self._persist_transcript()

    def _save_transcript(self):
        try:
            path = filedialog.asksaveasfilename(parent=self.root, defaultextension=".chat", filetypes=[("Encrypted Chat", "*.chat"), ("All Files", "*.*")])
            if not path:
                return
            key = _prompt_hex256_key("Encryption Key", self.root)
            if key is None:
                return
            content = self.transcript.get("1.0", "end")
            data = content.encode("utf-8")
            enc = _cc20p_encrypt(key, data)
            blob = ENC_HEADER + enc
            _atomic_write_bytes(path, blob)
            self._set_status("Saved encrypted transcript.")
        except Exception as e:
            messagebox.showerror("Save Error", _sanitize_text(e), parent=self.root)

    def _open_encrypted_transcript(self):
        try:
            path = filedialog.askopenfilename(parent=self.root, filetypes=[("Encrypted Chat", "*.chat"), ("All Files", "*.*")])
            if not path:
                return
            with open(path, "rb") as f:
                blob = f.read()
            if not blob.startswith(ENC_HEADER):
                messagebox.showerror("Open Error", "Invalid encrypted transcript.", parent=self.root)
                return
            key = _prompt_hex256_key("Decryption Key", self.root)
            if key is None:
                return
            enc = blob[len(ENC_HEADER):]
            try:
                dec = _cc20p_decrypt(key, enc)
            except InvalidTag:
                messagebox.showerror("Open Error", "Decryption failed: wrong key or corrupted file.", parent=self.root)
                return
            text = dec.decode("utf-8", errors="strict")
            self.transcript.configure(state="normal")
            self.transcript.delete("1.0", "end")
            self.transcript.insert("1.0", text)
            self.transcript.configure(state="disabled")
            self._set_status("Decrypted transcript opened.")
        except UnicodeDecodeError:
            messagebox.showerror("Open Error", "Decryption failed or wrong key.", parent=self.root)
        except Exception as e:
            messagebox.showerror("Open Error", _sanitize_text(e), parent=self.root)

    def _choose_autosave_file(self):
        path = filedialog.asksaveasfilename(parent=self.root, defaultextension=".chat", filetypes=[("Encrypted Chat", "*.chat"), ("All Files", "*.*")])
        if path:
            self.autosave_path = path
            self._settings["autosave_path"] = path
            _save_settings(self._settings)
            if self.autosave_var.get() and self.autosave_key_bytes is None:
                key = _prompt_hex256_key("Autosave Encryption Key", self.root)
                if key is None:
                    self._set_status("Autosave key required.")
                    return
                self.autosave_key_bytes = key
            self._persist_transcript()

    def _toggle_autosave(self):
        if self.autosave_var.get():
            if not self.autosave_path:
                self._choose_autosave_file()
            if self.autosave_key_bytes is None:
                key = _prompt_hex256_key("Autosave Encryption Key", self.root)
                if key is None:
                    self._set_status("Autosave key required.")
                    self.autosave_var.set(False)
                    self._settings["autosave_enabled"] = False
                    _save_settings(self._settings)
                    return
                self.autosave_key_bytes = key
            self._settings["autosave_enabled"] = True
            _save_settings(self._settings)
            self._persist_transcript()
        else:
            self._settings["autosave_enabled"] = False
            _save_settings(self._settings)
            self._set_status("Autosave off.")

    def _change_autosave_key(self):
        key = _prompt_hex256_key("New Autosave Encryption Key", self.root)
        if key is None:
            return
        self.autosave_key_bytes = key
        self._set_status("Autosave key updated.")
        self._persist_transcript()

    def _persist_transcript(self):
        if not self.autosave_var.get() or not self.autosave_path:
            return
        now = time.monotonic()
        if now - self._last_autosave_ts < 2.0:
            return
        try:
            if self.autosave_key_bytes is None:
                self._set_status("Autosave requires 256-bit key.")
                return
            content = self.transcript.get("1.0", "end")
            data = content.encode("utf-8")
            enc = _cc20p_encrypt(self.autosave_key_bytes, data)
            blob = ENC_HEADER + enc
            _atomic_write_bytes(self.autosave_path, blob)
            self._last_autosave_ts = now
            self._set_status("Autosaved encrypted transcript.")
        except Exception as e:
            self._set_status(f"Autosave error: {_sanitize_text(e)}")

    def _on_close(self):
        self._settings["last_model"] = self.current_model_name
        self._settings["temperature"] = float(self.temperature_var.get())
        self._settings["wrap"] = bool(self.wrap_var.get())
        self._settings["autosave_enabled"] = bool(self.autosave_var.get())
        self._settings["autosave_path"] = self.autosave_path
        self._settings["system_prompts"] = self.system_prompts
        _save_settings(self._settings)
        self._stop_streaming()
        if self.streaming_thread:
            try:
                self.streaming_thread.join(timeout=0.5)
            except Exception:
                pass
        self.root.after(100, self.root.destroy)

def main():
    try:
        import ctypes
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    root = tk.Tk()
    ChatGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()