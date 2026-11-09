"""
Analyzer2 - Tkinter GUI
A desktop interface for the Network & System Misconfiguration Scanner.
"""

import sys
import os
import io
import threading
import tkinter as tk
from tkinter import messagebox, scrolledtext, ttk

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanner.scan_runner import run_scan


class AnalyzerGUI:
    """Main GUI application for Analyzer2."""

    def __init__(self, root):
        self.root = root
        self.root.title("Analyzer2 - Misconfiguration Scanner")
        self.root.geometry("900x650")
        self.root.minsize(700, 500)

        self.scan_results = None
        self._build_ui()

    def _build_ui(self):
        """Build the GUI layout."""
        # Header
        header_frame = tk.Frame(self.root, bg="#2c3e50", height=60)
        header_frame.pack(fill=tk.X)
        header_frame.pack_propagate(False)

        title_label = tk.Label(
            header_frame,
            text="Analyzer2 - Network & System Misconfiguration Scanner",
            font=("Helvetica", 16, "bold"),
            bg="#2c3e50",
            fg="white",
        )
        title_label.pack(pady=15)

        # Button frame
        button_frame = tk.Frame(self.root, pady=10)
        button_frame.pack(fill=tk.X, padx=20)

        self.scan_button = tk.Button(
            button_frame,
            text="Start Scan",
            command=self._start_scan,
            font=("Helvetica", 12),
            bg="#27ae60",
            fg="white",
            activebackground="#2ecc71",
            padx=20,
            pady=8,
            relief=tk.FLAT,
            cursor="hand2",
        )
        self.scan_button.pack(side=tk.LEFT, padx=5)

        self.report_button = tk.Button(
            button_frame,
            text="View Report",
            command=self._open_report,
            font=("Helvetica", 12),
            bg="#3498db",
            fg="white",
            activebackground="#5dade2",
            padx=20,
            pady=8,
            relief=tk.FLAT,
            cursor="hand2",
            state=tk.DISABLED,
        )
        self.report_button.pack(side=tk.LEFT, padx=5)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_frame = tk.Frame(self.root)
        status_frame.pack(fill=tk.X, padx=20)

        self.status_label = tk.Label(
            status_frame,
            textvariable=self.status_var,
            font=("Helvetica", 10),
            fg="#7f8c8d",
            anchor="w",
        )
        self.status_label.pack(side=tk.LEFT)

        self.progress = ttk.Progressbar(
            status_frame, mode="indeterminate", length=200
        )
        self.progress.pack(side=tk.RIGHT)

        # Results text area
        result_frame = tk.Frame(self.root, padx=20, pady=10)
        result_frame.pack(fill=tk.BOTH, expand=True)

        self.result_text = scrolledtext.ScrolledText(
            result_frame,
            font=("Consolas", 10),
            wrap=tk.WORD,
            bg="#1e1e1e",
            fg="#d4d4d4",
            insertbackground="white",
            selectbackground="#264f78",
        )
        self.result_text.pack(fill=tk.BOTH, expand=True)

        # Footer
        footer = tk.Label(
            self.root,
            text="Analyzer2 v1.0 | Checks against CIS Benchmarks & NIST Guidelines",
            font=("Helvetica", 9),
            fg="#95a5a6",
        )
        footer.pack(pady=5)

    def _start_scan(self):
        """Start the scan in a background thread."""
        self.scan_button.config(state=tk.DISABLED)
        self.report_button.config(state=tk.DISABLED)
        self.result_text.delete(1.0, tk.END)
        self.status_var.set("Scanning...")
        self.progress.start(10)

        thread = threading.Thread(target=self._run_scan_thread, daemon=True)
        thread.start()

    def _run_scan_thread(self):
        """Run the scan and capture output."""
        old_stdout = sys.stdout
        sys.stdout = captured = io.StringIO()

        try:
            self.scan_results = run_scan()
        except Exception as e:
            print(f"\nError during scan: {e}")
        finally:
            sys.stdout = old_stdout

        output = captured.getvalue()
        self.root.after(0, self._scan_complete, output)

    def _scan_complete(self, output):
        """Update the GUI after scan completes."""
        self.result_text.insert(tk.END, output)
        self.result_text.see(tk.END)

        self.scan_button.config(state=tk.NORMAL)
        self.progress.stop()

        if self.scan_results and self.scan_results.get("report_path"):
            self.report_button.config(state=tk.NORMAL)
            self.status_var.set(
                f"Scan complete - Report: {self.scan_results['report_path']}"
            )
        else:
            self.status_var.set("Scan complete")

    def _open_report(self):
        """Open the generated report file."""
        if not self.scan_results or not self.scan_results.get("report_path"):
            messagebox.showwarning("Warning", "No report available. Run a scan first.")
            return

        report_path = os.path.abspath(self.scan_results["report_path"])
        if os.path.exists(report_path):
            messagebox.showinfo(
                "Report Generated", f"Report saved at:\n{report_path}"
            )
            # Try to open the file with the default PDF viewer
            try:
                if sys.platform == "win32":
                    os.startfile(report_path)
                elif sys.platform == "darwin":
                    os.system(f'open "{report_path}"')
                else:
                    os.system(f'xdg-open "{report_path}" 2>/dev/null &')
            except Exception:
                pass
        else:
            messagebox.showerror("Error", f"Report file not found:\n{report_path}")


def run_gui():
    """Launch the Analyzer2 GUI."""
    root = tk.Tk()
    app = AnalyzerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    run_gui()
