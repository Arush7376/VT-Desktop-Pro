import customtkinter as ctk
import os, json, time, threading
from tkinter import filedialog, messagebox, simpledialog
from fpdf import FPDF
import config
import ioc_detector
import vt_client

# ===== SETTINGS =====
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

VT_BASE = config.VT_BASE_URL
HISTORY_FILE = config.HISTORY_FILE


# ================= MAIN APP =================
class VTDesktop(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("VirusTotal Desktop Pro")
        self.geometry("1350x850")

        # 🔐 Ask API key securely (Check .env / environment first)
        self.api_key = config.get_api_key()
        if not self.api_key:
            input_key = simpledialog.askstring("API Key", "Enter VirusTotal API Key:", show="*")
            if input_key and config.validate_api_key(input_key):
                self.api_key = input_key.strip()
                if messagebox.askyesno("Save API Key", "Would you like to save this API key to .env for future sessions?"):
                    config.save_api_key(self.api_key)
            else:
                messagebox.showerror("Error", "Invalid or missing VirusTotal API Key.")
                self.destroy()
                return

        self.vt_client = vt_client.VTClient(self.api_key, base_url=VT_BASE)
        self.last_data = None
        self.summary = None
        self.engines = None
        self.current_ioc = None
        self.is_processing = False

        # ===== TOP BAR =====
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=20, pady=15)

        self.entry = ctk.CTkEntry(top, width=480, height=40,
                                  placeholder_text="Enter File path / Hash (MD5/SHA1/SHA256) / URL / IP / Domain")
        self.entry.pack(side="left", padx=10)

        # IOC Type Badge Indicator
        self.ioc_label = ctk.CTkLabel(top, text="[IOC Type: Ready]", font=("Arial", 12, "bold"), text_color="#3B82F6")
        self.ioc_label.pack(side="left", padx=8)

        self.upload_btn = ctk.CTkButton(top, text="Upload File", width=100,
                      command=self.select_file)
        self.upload_btn.pack(side="left", padx=4)

        self.analyze_btn = ctk.CTkButton(top, text="ANALYZE IOC", width=120,
                      command=self.run_scan)
        self.analyze_btn.pack(side="left", padx=4)

        ctk.CTkButton(top, text="Export PDF", command=self.export_pdf).pack(side="left", padx=4)
        ctk.CTkButton(top, text="Save JSON", command=self.save_json).pack(side="left", padx=4)
        ctk.CTkButton(top, text="History", command=self.show_history).pack(side="left", padx=4)

        # ===== TABS =====
        self.tabs = ctk.CTkTabview(self, width=1300)
        self.tabs.pack(expand=True, fill="both", padx=20, pady=10)

        self.tab_summary = self.tabs.add("Summary")
        self.tab_detection = self.tabs.add("Detections")
        self.tab_json = self.tabs.add("Raw JSON")

        self.summary_box = ctk.CTkTextbox(self.tab_summary, width=1200, height=650)
        self.summary_box.pack(pady=10)

        self.detect_box = ctk.CTkTextbox(self.tab_detection, width=1200, height=650)
        self.detect_box.pack(pady=10)

        self.json_box = ctk.CTkTextbox(self.tab_json, width=1200, height=650)
        self.json_box.pack(pady=10)

    # ===== FILE SELECT =====
    def select_file(self):
        path = filedialog.askopenfilename(title="Select file to scan")
        if path:
            self.entry.delete(0, 'end')
            self.entry.insert(0, path)
            self.run_scan()

    # ===== SCAN =====
    def run_scan(self):
        if self.is_processing:
            return

        target = self.entry.get().strip()
        if not target:
            return

        # 🧠 Intelligent IOC Detection
        ioc = ioc_detector.detect_ioc(target)
        self.current_ioc = ioc

        if not ioc["valid"]:
            self.ioc_label.configure(text=f"[IOC Type: {ioc['type']}]", text_color="#EF4444")
            messagebox.showerror("Invalid IOC", ioc["error"])
            return

        # Display detected IOC type badge
        self.ioc_label.configure(text=f"[IOC Type: {ioc['type']}] - Querying...", text_color="#F59E0B")
        self._set_buttons_state("disabled")
        self.is_processing = True

        # Non-blocking background execution
        threading.Thread(target=self._bg_fetch_report, args=(ioc, target), daemon=True).start()

    def _bg_fetch_report(self, ioc, target):
        report = self.vt_client.fetch_ioc_report(ioc)
        self.after(0, self._on_scan_completed, report, target, ioc)

    def _on_scan_completed(self, report, target, ioc):
        self.is_processing = False
        self._set_buttons_state("normal")

        status = report.get("status")

        if status == "success":
            self.ioc_label.configure(text=f"[IOC Type: {ioc['type']}]", text_color="#10B981")
            self.process_normalized_report(report, target)

        elif status == "not_found":
            self.ioc_label.configure(text=f"[IOC Type: {ioc['type']}] - Not Found", text_color="#EF4444")
            if ioc.get("is_file"):
                if messagebox.askyesno("File Not Found", "File hash not found in VirusTotal database.\nWould you like to upload it now for analysis?"):
                    self.upload_file(target)
            else:
                messagebox.showinfo("Not Found", report.get("error_message", "Target not found in VirusTotal database."))

        elif status == "invalid_api_key":
            self.ioc_label.configure(text=f"[IOC Type: {ioc['type']}] - Auth Error", text_color="#EF4444")
            messagebox.showerror("API Key Error", report.get("error_message", "Invalid VirusTotal API Key."))

        elif status == "rate_limit_exceeded":
            self.ioc_label.configure(text=f"[IOC Type: {ioc['type']}] - Rate Limited", text_color="#EF4444")
            messagebox.showerror("Quota Exceeded", report.get("error_message", "API Rate limit exceeded."))

        else:
            self.ioc_label.configure(text=f"[IOC Type: {ioc['type']}] - Error", text_color="#EF4444")
            messagebox.showerror("Error", report.get("error_message", "An error occurred during scan."))

    def _set_buttons_state(self, state: str):
        self.analyze_btn.configure(state=state)
        self.upload_btn.configure(state=state)

    # ===== UPLOAD =====
    def upload_file(self, filepath):
        if self.is_processing:
            return

        self.ioc_label.configure(text="[IOC Type: FILE] - Uploading...", text_color="#F59E0B")
        self._set_buttons_state("disabled")
        self.is_processing = True

        threading.Thread(target=self._bg_upload_file, args=(filepath,), daemon=True).start()

    def _bg_upload_file(self, filepath):
        res = self.vt_client.upload_file(filepath)
        self.after(0, self._on_upload_completed, res)

    def _on_upload_completed(self, res):
        self.is_processing = False
        self._set_buttons_state("normal")
        self.ioc_label.configure(text="[IOC Type: FILE]", text_color="#10B981")

        if res.get("success"):
            messagebox.showinfo("Uploaded", res.get("message", "File uploaded successfully.\nWait ~30 seconds and click ANALYZE IOC again."))
        else:
            messagebox.showerror("Upload Error", res.get("message", "Upload failed."))

    # ===== PROCESS DATA =====
    def process_normalized_report(self, report, target):
        self.last_data = report.get("raw_json", {})
        mal = report.get("malicious_count", 0)
        susp = report.get("suspicious_count", 0)
        det_count = report.get("detection_count", mal + susp)
        total = report.get("total_engines", 0)
        level = self.get_threat_level(det_count)

        self.summary = {
            "ioc_type": report.get("ioc_type", "N/A"),
            "level": level,
            "malicious": mal,
            "suspicious": susp,
            "detection_count": det_count,
            "total": total,
            "type": report.get("type_description", "N/A"),
            "size": report.get("size", "N/A"),
            "sha256": report.get("sha256", "N/A"),
            "md5": report.get("md5", "N/A"),
            "sha1": report.get("sha1", "N/A"),
            "reputation": report.get("reputation", 0),
            "tags": report.get("tags", []),
            "categories": report.get("categories", []),
            "first_submission_date": report.get("first_submission_date", "N/A"),
            "last_analysis_date": report.get("last_analysis_date", "N/A")
        }

        self.engines = report.get("engines", {})
        self.save_history(target)

        self.render_summary()
        self.render_detections()
        self.render_json()

    # ===== THREAT LEVEL =====
    def get_threat_level(self, detection_count):
        if detection_count == 0: return "SAFE"
        if detection_count < 5: return "LOW RISK"
        if detection_count < 15: return "MALICIOUS"
        return "CRITICAL"

    # ===== RENDER SUMMARY =====
    def render_summary(self):
        self.summary_box.delete("1.0", "end")
        s = self.summary

        tags_str = ", ".join(s['tags']) if s['tags'] else "None"
        cats_str = ", ".join(s['categories']) if s['categories'] else "None"

        text = f"""
IOC TYPE: {s['ioc_type']}
THREAT LEVEL: {s['level']}
DETECTION: {s['detection_count']} / {s['total']} (Malicious: {s['malicious']}, Suspicious: {s['suspicious']})

Type Description: {s['type']}
Size: {s['size']} bytes
SHA256: {s['sha256']}
MD5: {s['md5']}
SHA1: {s['sha1']}
Reputation Score: {s['reputation']}
First Submission Date: {s['first_submission_date']}
Last Analysis Date: {s['last_analysis_date']}
Categories: {cats_str}
Tags: {tags_str}
"""
        self.summary_box.insert("end", text)

    # ===== RENDER ENGINES =====
    def render_detections(self):
        self.detect_box.delete("1.0", "end")
        if not self.engines:
            self.detect_box.insert("end", "No engine detection details available.")
            return

        for eng, res in self.engines.items():
            r = res.get("result") or "clean"
            cat = res.get("category") or "undetected"
            self.detect_box.insert("end", f"{eng:25} {cat.upper():15} {r}\n")

    # ===== RAW JSON =====
    def render_json(self):
        self.json_box.delete("1.0", "end")
        self.json_box.insert("end", json.dumps(self.last_data, indent=2))

    # ===== HISTORY =====
    def save_history(self, target):
        data = []
        if os.path.exists(HISTORY_FILE):
            try:
                with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = []

        ioc_type = self.current_ioc.get("type", "N/A") if self.current_ioc else "N/A"
        data.append({"target": target, "type": ioc_type, "time": time.ctime()})

        try:
            with open(HISTORY_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4)
        except Exception:
            pass

    def show_history(self):
        if not os.path.exists(HISTORY_FILE):
            messagebox.showinfo("History", "No scan history recorded yet.")
            return
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            txt = "\n".join([f"{i['time']} → [{i.get('type', 'N/A')}] {i['target']}" for i in data])
            messagebox.showinfo("Scan History", txt if txt else "History is empty.")
        except Exception:
            messagebox.showerror("Error", "Failed to load scan history file.")

    # ===== EXPORT JSON =====
    def save_json(self):
        if not self.last_data:
            messagebox.showwarning("No Data", "No scan data available to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.last_data, f, indent=4)
                messagebox.showinfo("Saved", f"Raw JSON saved successfully to {os.path.basename(path)}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save JSON file: {e}")

    # ===== EXPORT PDF =====
    def export_pdf(self):
        if not self.summary:
            messagebox.showwarning("No Data", "No scan summary available to export.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".pdf")
        if not path: return

        try:
            pdf = FPDF()
            pdf.add_page()

            pdf.set_font("Arial", 'B', 18)
            pdf.cell(0, 10, "Malware Intelligence Report", ln=True)

            pdf.set_font("Arial", size=12)
            s = self.summary

            pdf.multi_cell(0, 8, f"""
IOC Type: {s['ioc_type']}
Threat Level: {s['level']}
Detection Ratio: {s['detection_count']} / {s['total']}

File Type: {s['type']}
SHA256: {s['sha256']}
MD5: {s['md5']}
SHA1: {s['sha1']}
Size: {s['size']}
Reputation: {s['reputation']}
First Submission: {s['first_submission_date']}
Last Analysis: {s['last_analysis_date']}
Tags: {", ".join(s['tags']) if s['tags'] else 'None'}
""")

            pdf.ln(5)
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, "Engine Detection Results", ln=True)

            pdf.set_font("Arial", size=8)
            for eng, res in self.engines.items():
                line = f"{eng}: {res.get('category')} -> {res.get('result')}"
                pdf.multi_cell(0, 5, line)

            pdf.output(path)
            messagebox.showinfo("Exported", f"PDF report saved successfully to {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate PDF: {e}")


# ===== RUN =====
if __name__ == "__main__":
    app = VTDesktop()
    app.mainloop()
