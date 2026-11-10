"""Tkinter interface for offline phishing triage. No email content is rendered as HTML."""
import json
import sys
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

if __package__ in (None, ''):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from phishing_triage.analyzer import analyze_file


def report_directory():
    base = Path.home() / 'Documents' / 'Phishing Triage Reports'
    base.mkdir(parents=True, exist_ok=True)
    return base


class TriageApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title('Phishing Triage Assistant — Offline')
        self.geometry('830x650')
        self.minsize(650, 480)
        self.selected = None
        self.report = None
        self._build()

    def _build(self):
        frame = ttk.Frame(self, padding=18)
        frame.pack(fill='both', expand=True)
        ttk.Label(frame, text='Phishing Triage Assistant', font=('Segoe UI', 19, 'bold')).pack(anchor='w')
        ttk.Label(frame, text='Offline email analysis for nonprofit organizations — no links are opened or attachments executed.', wraplength=760).pack(anchor='w', pady=(3, 14))
        buttons = ttk.Frame(frame)
        buttons.pack(fill='x', pady=(0, 10))
        ttk.Button(buttons, text='1. Choose Email (.eml)', command=self.choose).pack(side='left', padx=(0, 8))
        self.analyze_btn = ttk.Button(buttons, text='2. Analyze Email', command=self.analyze, state='disabled')
        self.analyze_btn.pack(side='left', padx=(0, 8))
        self.save_btn = ttk.Button(buttons, text='3. Save Report', command=self.save, state='disabled')
        self.save_btn.pack(side='left', padx=(0, 8))
        ttk.Button(buttons, text='Open Reports Folder', command=self.open_folder).pack(side='left')
        self.file_label = ttk.Label(frame, text='No email selected', wraplength=760)
        self.file_label.pack(anchor='w', pady=(0, 8))
        self.status = ttk.Label(frame, text='Select an .eml file to begin.')
        self.status.pack(anchor='w', pady=(0, 8))
        self.output = tk.Text(frame, wrap='word', font=('Segoe UI', 11), padx=12, pady=12)
        scrollbar = ttk.Scrollbar(frame, command=self.output.yview)
        self.output.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side='right', fill='y')
        self.output.pack(fill='both', expand=True)
        self.output.insert('1.0', 'Results will appear here.\n\nIf an email looks suspicious, do not click its links or open its attachments. Contact your IT provider using a trusted channel.')
        self.output.configure(state='disabled')

    def choose(self):
        path = filedialog.askopenfilename(title='Choose a saved email', filetypes=[('Email files', '*.eml'), ('All files', '*.*')])
        if not path:
            return
        self.selected = Path(path)
        self.report = None
        self.file_label.configure(text=f'Selected: {self.selected.name}')
        self.analyze_btn.configure(state='normal')
        self.save_btn.configure(state='disabled')
        self.status.configure(text='Ready to analyze.')

    def show(self, content):
        self.output.configure(state='normal')
        self.output.delete('1.0', 'end')
        self.output.insert('1.0', content)
        self.output.configure(state='disabled')

    def analyze(self):
        if not self.selected:
            return
        try:
            self.report = analyze_file(self.selected)
        except (OSError, ValueError, TypeError) as exc:
            self.report = None
            self.save_btn.configure(state='disabled')
            messagebox.showerror('Analysis could not be completed', str(exc))
            return
        r = self.report
        h = r.get('headers', {})
        risk = r.get('risk', {})
        findings = r.get('findings', [])
        lines = [
            'EMAIL ANALYSIS RESULTS', '=' * 55,
            f"Subject: {h.get('subject', '(none)')}",
            f"From: {h.get('from', '(none)')}",
            f"Reply-To: {h.get('reply_to') or '(not provided)'}", '',
            f"Triage score: {risk.get('score', 'Not available')} / 100",
            f"Priority: {str(risk.get('severity', 'Not available')).replace('_', ' ').upper()}",
            'This is a heuristic triage score, not proof of maliciousness or safety.', '',
            f"Findings ({len(findings)}):",
        ]
        if findings:
            lines.extend(f"• {f.get('detail', f.get('type', 'Unknown finding'))}" for f in findings)
        else:
            lines.append('No indicators detected by the current rules. This does NOT mean the email is safe.')
        lines.extend(['', f"Unique URLs: {len(r.get('links', []))}"])
        for item in r.get('links', []):
            lines.append(f"• {item.get('url', '')}")
            if item.get('display_texts'):
                lines.append(f"  Displayed as: {', '.join(item['display_texts'])}")
        lines.extend(['', f"Attachments: {len(r.get('attachments', []))}"])
        for item in r.get('attachments', []):
            lines.append(f"• {item.get('filename', '')} ({item.get('size_bytes', 0)} bytes)")
            lines.append(f"  SHA-256: {item.get('sha256', '')}")
        lines.extend(['', 'RECOMMENDED NEXT STEP:', 'Do not interact with suspicious links or attachments. Verify unexpected requests using a known phone number or other trusted channel. Share the saved report securely with your IT provider.', '', 'Offline analysis only. No threat-intelligence checks performed.'])
        self.show('\n'.join(lines))
        self.save_btn.configure(state='normal')
        self.status.configure(text='Analysis complete. Review the findings and save a report if needed.')

    def save(self):
        if self.report is None:
            return
        name = f"triage_{datetime.now():%Y%m%d_%H%M%S}.json"
        destination = filedialog.asksaveasfilename(title='Save incident report', initialdir=str(report_directory()), initialfile=name, defaultextension='.json', filetypes=[('JSON report', '*.json')])
        if not destination:
            return
        try:
            Path(destination).write_text(json.dumps(self.report, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')
        except OSError as exc:
            messagebox.showerror('Could not save report', str(exc))
            return
        messagebox.showinfo('Report saved', f'Report saved to:\n{destination}\n\nTreat reports as sensitive: they may contain email addresses and URLs.')

    def open_folder(self):
        folder = report_directory()
        try:
            if sys.platform == 'win32':
                import os
                os.startfile(folder)
            elif sys.platform == 'darwin':
                import subprocess
                subprocess.Popen(['open', str(folder)])
            else:
                import subprocess
                subprocess.Popen(['xdg-open', str(folder)])
        except (OSError, FileNotFoundError) as exc:
            messagebox.showinfo('Reports folder', f'Folder: {folder}\n\nCould not open automatically: {exc}')


if __name__ == '__main__':
    TriageApp().mainloop()
