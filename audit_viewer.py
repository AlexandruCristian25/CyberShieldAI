import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import time
import threading
import os
import csv
import re

LOG_FILE = "actions.log"

class AuditViewer:
    def __init__(self, root):
        self.root = root
        root.title("CyberShieldAI - Real-Time Audit Log")
        root.geometry("800x530")
        root.configure(bg="#1e1e1e")

        title_label = tk.Label(
            root, text="Real-Time Audit Log",
            font=("Segoe UI", 16, "bold"),
            fg="#00ff00", bg="#1e1e1e"
        )
        title_label.pack(pady=10)

        self.filter_var = tk.StringVar()
        filter_frame = tk.Frame(root, bg="#1e1e1e")
        filter_frame.pack(pady=5)

        tk.Label(filter_frame, text="Filter:", fg="#00ff00", bg="#1e1e1e").pack(side=tk.LEFT)
        self.filter_entry = tk.Entry(filter_frame, textvariable=self.filter_var, width=30)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        self.filter_entry.bind("<KeyRelease>", self.apply_filter)

        self.log_display = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=20, font=("Consolas", 10))
        self.log_display.configure(bg="#111", fg="#00ff00", insertbackground="white")
        self.log_display.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.log_display.tag_config("error", foreground="red", font=("Consolas", 10, "bold"))
        self.log_display.tag_config("warning", foreground="orange", font=("Consolas", 10, "bold"))
        self.log_display.tag_config("info", foreground="blue", font=("Consolas", 10, "bold"))
        self.log_display.tag_config("debug", foreground="lightgray", font=("Consolas", 10, "bold"))

        button_frame = tk.Frame(root, bg="#1e1e1e")
        button_frame.pack(pady=5)

        clear_button = tk.Button(button_frame, text="Clear", command=self.clear_log)
        clear_button.pack(side=tk.LEFT, padx=5)

        save_button = tk.Button(button_frame, text="Save Filtered", command=self.save_filtered)
        save_button.pack(side=tk.LEFT, padx=5)

        export_csv_button = tk.Button(button_frame, text="Export CSV", command=self.export_csv)
        export_csv_button.pack(side=tk.LEFT, padx=5)

        self.lines = []
        self.stop_thread = False
        threading.Thread(target=self.follow_log, daemon=True).start()

    def follow_log(self):
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w') as f:
                pass

        with open(LOG_FILE, 'r') as f:
            f.seek(0, os.SEEK_END)
            while not self.stop_thread:
                line = f.readline()
                if line:
                    self.lines.append(line)
                    self.root.after(0, self.apply_filter)
                else:
                    time.sleep(0.5)

    def apply_filter(self, event=None):
        filter_text = self.filter_var.get().lower()
        self.log_display.configure(state='normal')
        self.log_display.delete('1.0', tk.END)
        for line in self.lines:
            if filter_text in line.lower():
                tag = None
                line_upper = line.upper()
                if "ERROR" in line_upper:
                    tag = "error"
                elif "WARNING" in line_upper:
                    tag = "warning"
                elif "INFO" in line_upper:
                    tag = "info"
                elif "DEBUG" in line_upper:
                    tag = "debug"

                if tag:
                    self.log_display.insert(tk.END, line, tag)
                else:
                    self.log_display.insert(tk.END, line)
        self.log_display.yview(tk.END)
        self.log_display.configure(state='disabled')

    def clear_log(self):
        self.log_display.configure(state='normal')
        self.log_display.delete('1.0', tk.END)
        self.lines.clear()

    def save_filtered(self):
        content = self.log_display.get('1.0', tk.END).strip()
        if not content:
            messagebox.showinfo("Info", "Nothing to save. The log is empty.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".log",
            filetypes=[("Log files", "*.log"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filepath:
            try:
                with open(filepath, 'w') as f:
                    f.write(content)
                messagebox.showinfo("Success", f"Filtered log saved to {filepath}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save file: {e}")

    def export_csv(self):
        # Regex pentru a extrage timestamp, nivel și mesaj dintr-un format tipic
        pattern = re.compile(r"\[?(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\]? ?(?P<level>[A-Z]+)?[:\-]? ?(?P<message>.*)")

        filter_text = self.filter_var.get().lower()
        filtered_lines = [line for line in self.lines if filter_text in line.lower()]
        if not filtered_lines:
            messagebox.showinfo("Info", "Nothing to export. The log is empty or filter excludes all lines.")
            return

        filepath = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not filepath:
            return

        try:
            with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Timestamp", "Level", "Message"])

                for line in filtered_lines:
                    m = pattern.match(line)
                    if m:
                        timestamp = m.group("timestamp") or ""
                        level = m.group("level") or ""
                        message = m.group("message") or line.strip()
                    else:
                        timestamp = ""
                        level = ""
                        message = line.strip()
                    writer.writerow([timestamp, level, message])

            messagebox.showinfo("Success", f"Filtered log exported to CSV:\n{filepath}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export CSV: {e}")

if __name__ == "__main__":
    root = tk.Tk()
    app = AuditViewer(root)
    root.mainloop()