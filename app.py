"""
Tkinter GUI for SSH file signing & verification.

Three tabs:
  - 签名   : sign a file with an OpenSSH private key
  - 验证   : verify a signature against a file
  - 生成密钥: create a new OpenSSH key pair
"""

from __future__ import annotations

import threading
import traceback
from pathlib import Path
from tkinter import Tk, StringVar, BooleanVar, filedialog, messagebox
from tkinter import ttk
import tkinter as tk

import sshsig


PADDING = {"padx": 6, "pady": 4}


def _browse_open(var: StringVar, title: str, filetypes=None):
    path = filedialog.askopenfilename(title=title, filetypes=filetypes or [("All files", "*.*")])
    if path:
        var.set(path)


def _browse_save(var: StringVar, title: str, defaultext: str = "", filetypes=None):
    path = filedialog.asksaveasfilename(
        title=title, defaultextension=defaultext, filetypes=filetypes or [("All files", "*.*")]
    )
    if path:
        var.set(path)


def _run_in_thread(target, on_done):
    """Run `target` in a background thread, then call `on_done(result, error)` on the main thread."""

    def runner():
        result, error = None, None
        try:
            result = target()
        except Exception as e:
            error = e
            traceback.print_exc()
        # schedule callback on the Tk main loop
        root = tk._default_root
        if root is not None:
            root.after(0, lambda: on_done(result, error))
        else:
            on_done(result, error)

    threading.Thread(target=runner, daemon=True).start()


# ---------------------------------------------------------------------------
# 签名 Tab
# ---------------------------------------------------------------------------

class SignTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.file_var = StringVar()
        self.key_var = StringVar()
        self.password_var = StringVar()
        self.namespace_var = StringVar(value=sshsig.DEFAULT_NAMESPACE)
        self.hash_var = StringVar(value=sshsig.DEFAULT_HASH)
        self.output_var = StringVar()
        self._build()

    def _build(self):
        row = 0
        ttk.Label(self, text="待签名文件:").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.file_var, width=50).grid(row=row, column=1, sticky="we", **PADDING)
        ttk.Button(
            self, text="浏览…",
            command=lambda: self._pick_file_and_default_output(),
        ).grid(row=row, column=2, **PADDING)

        row += 1
        ttk.Label(self, text="私钥文件:").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.key_var, width=50).grid(row=row, column=1, sticky="we", **PADDING)
        ttk.Button(
            self, text="浏览…",
            command=lambda: _browse_open(self.key_var, "选择 OpenSSH 私钥"),
        ).grid(row=row, column=2, **PADDING)

        row += 1
        ttk.Label(self, text="私钥密码 (可选):").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.password_var, show="•", width=50).grid(
            row=row, column=1, sticky="we", **PADDING
        )

        row += 1
        ttk.Label(self, text="命名空间:").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.namespace_var, width=50).grid(row=row, column=1, sticky="we", **PADDING)

        row += 1
        ttk.Label(self, text="哈希算法:").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Combobox(
            self, textvariable=self.hash_var, values=sorted(sshsig.SUPPORTED_HASHES),
            state="readonly", width=20,
        ).grid(row=row, column=1, sticky="w", **PADDING)

        row += 1
        ttk.Label(self, text="签名输出文件:").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.output_var, width=50).grid(row=row, column=1, sticky="we", **PADDING)
        ttk.Button(
            self, text="另存为…",
            command=lambda: _browse_save(
                self.output_var, "保存签名为", defaultext=".sig",
                filetypes=[("SSH signature", "*.sig"), ("All files", "*.*")],
            ),
        ).grid(row=row, column=2, **PADDING)

        row += 1
        self.sign_button = ttk.Button(self, text="签名", command=self._do_sign)
        self.sign_button.grid(row=row, column=1, sticky="e", **PADDING)

        row += 1
        self.status = tk.Text(self, height=8, width=70, state="disabled", wrap="word")
        self.status.grid(row=row, column=0, columnspan=3, sticky="nsew", **PADDING)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(row, weight=1)

    def _pick_file_and_default_output(self):
        _browse_open(self.file_var, "选择待签名文件")
        if self.file_var.get() and not self.output_var.get():
            self.output_var.set(self.file_var.get() + ".sig")

    def _do_sign(self):
        file_path = self.file_var.get().strip()
        key_path = self.key_var.get().strip()
        password = self.password_var.get()
        namespace = self.namespace_var.get().strip() or sshsig.DEFAULT_NAMESPACE
        hash_algo = self.hash_var.get().strip()
        out_path = self.output_var.get().strip()

        if not file_path or not Path(file_path).is_file():
            messagebox.showerror("错误", "请选择有效的待签名文件")
            return
        if not key_path or not Path(key_path).is_file():
            messagebox.showerror("错误", "请选择有效的私钥文件")
            return
        if not out_path:
            out_path = file_path + ".sig"
            self.output_var.set(out_path)

        self._set_status(f"正在签名 {file_path} …\n")
        self.sign_button.configure(state="disabled")

        pwd_bytes = password.encode() if password else None

        def task():
            loaded = sshsig.load_private_key(key_path, password=pwd_bytes)
            armored = sshsig.sign_file(
                file_path, loaded.private_key,
                namespace=namespace, hash_algo=hash_algo,
            )
            Path(out_path).write_bytes(armored.encode("ascii"))
            return loaded, armored

        def done(result, error):
            self.sign_button.configure(state="normal")
            if error:
                self._set_status(f"签名失败: {error}\n")
                messagebox.showerror("签名失败", str(error))
                return
            loaded, _armored = result
            fp = sshsig.public_key_fingerprint(loaded.public_key)
            self._set_status(
                f"签名成功 ✓\n"
                f"文件       : {file_path}\n"
                f"签名文件   : {out_path}\n"
                f"密钥类型   : {loaded.keytype}\n"
                f"密钥指纹   : {fp}\n"
                f"命名空间   : {namespace}\n"
                f"哈希算法   : {hash_algo}\n"
            )

        _run_in_thread(task, done)

    def _set_status(self, text: str):
        self.status.configure(state="normal")
        self.status.delete("1.0", "end")
        self.status.insert("1.0", text)
        self.status.configure(state="disabled")


# ---------------------------------------------------------------------------
# 验证 Tab
# ---------------------------------------------------------------------------

class VerifyTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.file_var = StringVar()
        self.sig_var = StringVar()
        self.pub_var = StringVar()
        self.namespace_var = StringVar()
        self.check_namespace_var = BooleanVar(value=False)
        self._build()

    def _build(self):
        row = 0
        ttk.Label(self, text="待验证文件:").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.file_var, width=50).grid(row=row, column=1, sticky="we", **PADDING)
        ttk.Button(
            self, text="浏览…",
            command=lambda: self._pick_file(),
        ).grid(row=row, column=2, **PADDING)

        row += 1
        ttk.Label(self, text="签名文件 (.sig):").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.sig_var, width=50).grid(row=row, column=1, sticky="we", **PADDING)
        ttk.Button(
            self, text="浏览…",
            command=lambda: _browse_open(
                self.sig_var, "选择签名文件",
                filetypes=[("SSH signature", "*.sig"), ("All files", "*.*")],
            ),
        ).grid(row=row, column=2, **PADDING)

        row += 1
        ttk.Label(self, text="期望的公钥 (可选):").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.pub_var, width=50).grid(row=row, column=1, sticky="we", **PADDING)
        ttk.Button(
            self, text="浏览…",
            command=lambda: _browse_open(
                self.pub_var, "选择公钥",
                filetypes=[("OpenSSH public key", "*.pub"), ("All files", "*.*")],
            ),
        ).grid(row=row, column=2, **PADDING)

        row += 1
        ttk.Checkbutton(
            self, text="同时校验命名空间为:", variable=self.check_namespace_var,
        ).grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.namespace_var, width=30).grid(row=row, column=1, sticky="w", **PADDING)

        row += 1
        self.verify_button = ttk.Button(self, text="验证", command=self._do_verify)
        self.verify_button.grid(row=row, column=1, sticky="e", **PADDING)

        row += 1
        self.status = tk.Text(self, height=10, width=70, state="disabled", wrap="word")
        self.status.grid(row=row, column=0, columnspan=3, sticky="nsew", **PADDING)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(row, weight=1)

    def _pick_file(self):
        _browse_open(self.file_var, "选择待验证文件")
        if self.file_var.get() and not self.sig_var.get():
            guess = self.file_var.get() + ".sig"
            if Path(guess).is_file():
                self.sig_var.set(guess)

    def _do_verify(self):
        file_path = self.file_var.get().strip()
        sig_path = self.sig_var.get().strip()
        pub_path = self.pub_var.get().strip()
        ns_check = self.check_namespace_var.get()
        ns = self.namespace_var.get().strip() if ns_check else None

        if not file_path or not Path(file_path).is_file():
            messagebox.showerror("错误", "请选择有效的待验证文件")
            return
        if not sig_path or not Path(sig_path).is_file():
            messagebox.showerror("错误", "请选择有效的签名文件")
            return
        if ns_check and not ns:
            messagebox.showerror("错误", "勾选了校验命名空间但未填写命名空间")
            return

        self._set_status(f"正在验证 {file_path} …\n")
        self.verify_button.configure(state="disabled")

        def task():
            expected_pub = None
            pub_comment = ""
            if pub_path:
                loaded = sshsig.load_public_key(pub_path)
                expected_pub = loaded.public_key
                pub_comment = loaded.comment
            armored = Path(sig_path).read_text()
            parsed = sshsig.verify_file(
                file_path, armored,
                expected_public_key=expected_pub,
                expected_namespace=ns,
            )
            return parsed, pub_comment

        def done(result, error):
            self.verify_button.configure(state="normal")
            if error:
                self._set_status(f"验证失败 ✗\n{error}\n")
                messagebox.showerror("验证失败", str(error))
                return
            parsed, pub_comment = result
            fp = sshsig.public_key_fingerprint(parsed.public_key)
            extra = ""
            if pub_path:
                extra = f"\n✓ 已确认签名出自指定公钥{(' (' + pub_comment + ')') if pub_comment else ''}"
            else:
                extra = (
                    "\n⚠ 未提供期望公钥, 仅验证了签名结构与文件内容的一致性。"
                    "\n  若要建立信任,请在验证时提供已知的公钥文件。"
                )
            self._set_status(
                f"验证成功 ✓\n"
                f"文件       : {file_path}\n"
                f"签名文件   : {sig_path}\n"
                f"密钥类型   : {parsed.keytype}\n"
                f"密钥指纹   : {fp}\n"
                f"命名空间   : {parsed.namespace}\n"
                f"哈希算法   : {parsed.hash_algo}\n"
                f"签名算法   : {parsed.sig_keytype}"
                + extra + "\n"
            )

        _run_in_thread(task, done)

    def _set_status(self, text: str):
        self.status.configure(state="normal")
        self.status.delete("1.0", "end")
        self.status.insert("1.0", text)
        self.status.configure(state="disabled")


# ---------------------------------------------------------------------------
# 生成密钥 Tab
# ---------------------------------------------------------------------------

KEY_TYPES = [
    ("Ed25519 (推荐)", "ed25519"),
    ("RSA 3072",       "rsa"),
    ("ECDSA P-256",    "ecdsa-p256"),
    ("ECDSA P-384",    "ecdsa-p384"),
    ("ECDSA P-521",    "ecdsa-p521"),
]


class GenerateTab(ttk.Frame):
    def __init__(self, master):
        super().__init__(master)
        self.type_var = StringVar(value=KEY_TYPES[0][0])
        self.path_var = StringVar()
        self.password_var = StringVar()
        self.password_confirm_var = StringVar()
        self.comment_var = StringVar()
        self._build()

    def _build(self):
        row = 0
        ttk.Label(self, text="密钥类型:").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Combobox(
            self, textvariable=self.type_var,
            values=[label for label, _ in KEY_TYPES],
            state="readonly", width=25,
        ).grid(row=row, column=1, sticky="w", **PADDING)

        row += 1
        ttk.Label(self, text="保存路径 (私钥):").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.path_var, width=50).grid(row=row, column=1, sticky="we", **PADDING)
        ttk.Button(
            self, text="另存为…",
            command=lambda: _browse_save(self.path_var, "保存私钥为"),
        ).grid(row=row, column=2, **PADDING)

        row += 1
        ttk.Label(self, text="密码 (可选):").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.password_var, show="•", width=50).grid(
            row=row, column=1, sticky="we", **PADDING
        )

        row += 1
        ttk.Label(self, text="再次输入密码:").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.password_confirm_var, show="•", width=50).grid(
            row=row, column=1, sticky="we", **PADDING
        )

        row += 1
        ttk.Label(self, text="注释 (可选):").grid(row=row, column=0, sticky="w", **PADDING)
        ttk.Entry(self, textvariable=self.comment_var, width=50).grid(row=row, column=1, sticky="we", **PADDING)

        row += 1
        self.gen_button = ttk.Button(self, text="生成密钥对", command=self._do_generate)
        self.gen_button.grid(row=row, column=1, sticky="e", **PADDING)

        row += 1
        self.status = tk.Text(self, height=10, width=70, state="disabled", wrap="word")
        self.status.grid(row=row, column=0, columnspan=3, sticky="nsew", **PADDING)

        self.columnconfigure(1, weight=1)
        self.rowconfigure(row, weight=1)

    def _do_generate(self):
        label = self.type_var.get()
        key_type = dict((lbl, kt) for lbl, kt in KEY_TYPES).get(label)
        if key_type is None:
            messagebox.showerror("错误", "请选择密钥类型")
            return
        path = self.path_var.get().strip()
        if not path:
            messagebox.showerror("错误", "请选择私钥保存路径")
            return
        if Path(path).exists():
            if not messagebox.askyesno("覆盖确认", f"{path} 已存在,是否覆盖?"):
                return
        pwd = self.password_var.get()
        if pwd != self.password_confirm_var.get():
            messagebox.showerror("错误", "两次输入的密码不一致")
            return
        comment = self.comment_var.get().strip()

        self._set_status(f"正在生成 {key_type} 密钥对 …\n")
        self.gen_button.configure(state="disabled")

        def task():
            loaded = sshsig.generate_keypair(
                key_type, path,
                password=pwd.encode() if pwd else None,
                comment=comment,
            )
            return loaded

        def done(result, error):
            self.gen_button.configure(state="normal")
            if error:
                self._set_status(f"生成失败: {error}\n")
                messagebox.showerror("生成失败", str(error))
                return
            loaded = result
            fp = sshsig.public_key_fingerprint(loaded.public_key)
            pub_path = path + ".pub"
            self._set_status(
                f"生成成功 ✓\n"
                f"私钥文件   : {path}\n"
                f"公钥文件   : {pub_path}\n"
                f"密钥类型   : {loaded.keytype}\n"
                f"密钥指纹   : {fp}\n"
            )

        _run_in_thread(task, done)

    def _set_status(self, text: str):
        self.status.configure(state="normal")
        self.status.delete("1.0", "end")
        self.status.insert("1.0", text)
        self.status.configure(state="disabled")


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------

def main():
    root = Tk()
    root.title("SSH 文件签名工具")
    root.geometry("760x520")

    notebook = ttk.Notebook(root)
    notebook.add(SignTab(notebook),     text="签名")
    notebook.add(VerifyTab(notebook),   text="验证")
    notebook.add(GenerateTab(notebook), text="生成密钥")
    notebook.pack(fill="both", expand=True, padx=8, pady=8)

    root.mainloop()


if __name__ == "__main__":
    main()
