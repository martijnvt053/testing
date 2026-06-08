#!/usr/bin/env python3
"""
Garmin File Transfer Tool
Zet bestanden over naar je Garmin horloge (aangesloten via USB).
Gebruik: python3 garmin_transfer.py
"""

import os
import shutil
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading


def find_garmin():
    volumes = "/Volumes"
    if not os.path.exists(volumes):
        return None
    for name in os.listdir(volumes):
        path = os.path.join(volumes, name)
        if "GARMIN" in name.upper() and os.path.isdir(path):
            return path
    return None


class GarminApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Garmin Bestandsoverzetter")
        self.geometry("700x500")
        self.resizable(True, True)

        self.garmin_path = None
        self._build_ui()
        self._detect_garmin()

    def _build_ui(self):
        # --- Top: status ---
        top = tk.Frame(self, pady=6)
        top.pack(fill="x", padx=10)

        tk.Label(top, text="Garmin apparaat:").pack(side="left")
        self.status_var = tk.StringVar(value="Zoeken...")
        self.status_label = tk.Label(top, textvariable=self.status_var, fg="gray")
        self.status_label.pack(side="left", padx=6)

        tk.Button(top, text="Vernieuwen", command=self._detect_garmin).pack(side="right")

        ttk.Separator(self, orient="horizontal").pack(fill="x", padx=10)

        # --- Middle: two-pane layout ---
        panes = tk.Frame(self)
        panes.pack(fill="both", expand=True, padx=10, pady=6)

        # Left: Garmin folder tree
        left = tk.LabelFrame(panes, text="Garmin mappen", width=300)
        left.pack(side="left", fill="both", expand=True, padx=(0, 4))
        left.pack_propagate(False)

        self.tree = ttk.Treeview(left, selectmode="browse")
        self.tree.pack(fill="both", expand=True, side="left")
        scrollbar = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)

        # Right: selected destination + file list
        right = tk.LabelFrame(panes, text="Bestanden om over te zetten")
        right.pack(side="right", fill="both", expand=True, padx=(4, 0))

        dest_row = tk.Frame(right)
        dest_row.pack(fill="x", pady=4, padx=4)
        tk.Label(dest_row, text="Doel:").pack(side="left")
        self.dest_var = tk.StringVar(value="(selecteer een map links)")
        tk.Label(dest_row, textvariable=self.dest_var, fg="blue", wraplength=250, justify="left").pack(side="left", padx=4)

        btn_row = tk.Frame(right)
        btn_row.pack(fill="x", padx=4, pady=2)
        tk.Button(btn_row, text="+ Bestand(en) toevoegen", command=self._add_files).pack(side="left")
        tk.Button(btn_row, text="Verwijder geselecteerde", command=self._remove_file).pack(side="left", padx=4)

        self.file_listbox = tk.Listbox(right, selectmode="extended")
        self.file_listbox.pack(fill="both", expand=True, padx=4, pady=4)

        # --- Bottom: transfer button + progress ---
        bottom = tk.Frame(self, pady=6)
        bottom.pack(fill="x", padx=10)

        self.progress = ttk.Progressbar(bottom, mode="determinate")
        self.progress.pack(fill="x", pady=(0, 4))

        self.transfer_btn = tk.Button(
            bottom, text="Overzetten naar Garmin",
            bg="#0066cc", fg="white", font=("Helvetica", 12, "bold"),
            command=self._start_transfer
        )
        self.transfer_btn.pack(fill="x")

        self.log_var = tk.StringVar()
        tk.Label(bottom, textvariable=self.log_var, fg="gray").pack()

    # ------------------------------------------------------------------

    def _detect_garmin(self):
        path = find_garmin()
        if path:
            self.garmin_path = path
            self.status_var.set(path)
            self.status_label.config(fg="green")
            self._populate_tree(path)
        else:
            self.garmin_path = None
            self.status_var.set("Niet gevonden — sluit je Garmin aan via USB en klik Vernieuwen")
            self.status_label.config(fg="red")
            self.tree.delete(*self.tree.get_children())

    def _populate_tree(self, root_path):
        self.tree.delete(*self.tree.get_children())
        self._insert_node("", root_path, os.path.basename(root_path) or root_path)

    def _insert_node(self, parent, path, label):
        node = self.tree.insert(parent, "end", text=label, values=(path,))
        try:
            entries = sorted(os.listdir(path))
        except PermissionError:
            return
        for entry in entries:
            full = os.path.join(path, entry)
            if os.path.isdir(full):
                self._insert_node(node, full, entry)

    def _on_tree_select(self, _event):
        sel = self.tree.selection()
        if sel:
            path = self.tree.item(sel[0], "values")[0]
            self.dest_var.set(path)

    def _add_files(self):
        files = filedialog.askopenfilenames(title="Kies bestanden")
        for f in files:
            if f not in self.file_listbox.get(0, "end"):
                self.file_listbox.insert("end", f)

    def _remove_file(self):
        for idx in reversed(self.file_listbox.curselection()):
            self.file_listbox.delete(idx)

    def _start_transfer(self):
        dest = self.dest_var.get()
        if not self.garmin_path or not os.path.isdir(dest):
            messagebox.showwarning("Geen doel", "Selecteer eerst een map op de Garmin (links).")
            return
        files = list(self.file_listbox.get(0, "end"))
        if not files:
            messagebox.showwarning("Geen bestanden", "Voeg eerst bestanden toe om over te zetten.")
            return
        self.transfer_btn.config(state="disabled")
        threading.Thread(target=self._do_transfer, args=(files, dest), daemon=True).start()

    def _do_transfer(self, files, dest):
        total = len(files)
        self.progress["maximum"] = total
        errors = []
        for i, src in enumerate(files, 1):
            self.log_var.set(f"Bezig: {os.path.basename(src)} ({i}/{total})")
            try:
                shutil.copy2(src, dest)
            except Exception as e:
                errors.append(f"{os.path.basename(src)}: {e}")
            self.progress["value"] = i
            self.update_idletasks()

        self.transfer_btn.config(state="normal")
        if errors:
            messagebox.showerror("Fouten", "\n".join(errors))
        else:
            messagebox.showinfo("Klaar!", f"{total} bestand(en) overgezet naar:\n{dest}")
        self.log_var.set("")
        self.progress["value"] = 0


if __name__ == "__main__":
    app = GarminApp()
    app.mainloop()
