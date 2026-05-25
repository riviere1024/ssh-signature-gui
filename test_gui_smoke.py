"""Smoke test: build the GUI without entering the main loop."""

import tkinter as tk
from tkinter import ttk

import app


def main():
    root = tk.Tk()
    root.withdraw()  # don't actually show a window
    notebook = ttk.Notebook(root)
    notebook.add(app.SignTab(notebook),     text="签名")
    notebook.add(app.VerifyTab(notebook),   text="验证")
    notebook.add(app.GenerateTab(notebook), text="生成密钥")
    notebook.pack(fill="both", expand=True)
    # Update once so geometry & widgets actually realize.
    root.update_idletasks()
    print("GUI smoke test: all three tabs built OK")
    root.destroy()


if __name__ == "__main__":
    main()
