import customtkinter as ctk
import requests, os, base64, json, time
from tkinter import filedialog, messagebox, simpledialog
from fpdf import FPDF
import config
import ioc_detector

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

        self.headers = {"x-apikey": self.api_key}
        self.last_data = None
        self.summary = None
        self.engines = None
        self.current_ioc = None

        # ===== TOP BAR =====
        top = ctk.CTkFrame(self)
        top.pack(fill="x", padx=20, pady=15)

        self.entry = ctk.CTkEntry(top, width=480, height=40,
                                  placeholder_text="Enter File path / Hash (MD5/SHA1/SHA256) / URL / IP / Domain")
        self.entry.pack(side="left", padx=10)

        # IOC Type Badge Indicator
        self.ioc_label = ctk.CTkLabel(top, text="[IOC Type: Ready]", font=("Arial", 12, "bold"), text_color="#3B82F6")
        self.ioc_label.pack(side="left", padx=8)

        ctk.CTkButton(top, text="Upload File", width=100,
                      command=self.select_file).pack(side="left", padx=4)

        ctk.CTkButton(top, text="ANALYZE IOC", width=120,
                      command=self.run_scan).pack(side="left", padx=4)

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
        self.ioc_label.configure(text=f"[IOC Type: {ioc['type']}]", text_color="#10B981")

        try:
            res = requests.get(f"{VT_BASE}/{ioc['vt_endpoint']}", headers=self.headers)

            if res.status_code == 200:
                self.process_data(res.json(), target)

            elif res.status_code == 404 and ioc["is_file"]:
                self.upload_file(target)

            elif res.status_code in (401, 403):
                messagebox.showerror("API Key Error", f"Invalid or unauthorized API key (HTTP {res.status_code}). Please check your VirusTotal API key.")

            elif res.status_code == 429:
                messagebox.showerror("Quota Exceeded", "VirusTotal API rate limit or quota exceeded (HTTP 429).")

            else:
                messagebox.showerror("Error", f"API returned HTTP {res.status_code}")

        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ===== UPLOAD =====
    def upload_file(self, filepath):
        files = {"file": open(filepath, "rb")}
        r = requests.post(f"{VT_BASE}/files", headers=self.headers, files=files)

        if r.status_code == 200:
            messagebox.showinfo("Uploaded",
                                "File uploaded to VirusTotal.\nWait 30 seconds and click ANALYZE IOC again.")
        else:
            messagebox.showerror("Error", "Upload failed")

    # ===== PROCESS DATA =====
    def process_data(self, data, target):
        self.last_data = data
        attr = data['data']['attributes']
        stats = attr.get("last_analysis_stats", {})

        mal = stats.get("malicious", 0)
        total = sum(stats.values())
        level = self.get_threat_level(mal)

        ioc_hashes = self.current_ioc.get("hashes") if self.current_ioc else None

        self.summary = {
            "ioc_type": self.current_ioc.get("type", "N/A") if self.current_ioc else "N/A",
            "level": level,
            "malicious": mal,
            "total": total,
            "type": attr.get("type_description", "N/A"),
            "size": attr.get("size", "N/A"),
            "sha256": attr.get("sha256", ioc_hashes.get("sha256", "N/A") if ioc_hashes else "N/A"),
            "md5": attr.get("md5", ioc_hashes.get("md5", "N/A") if ioc_hashes else "N/A"),
            "sha1": attr.get("sha1", ioc_hashes.get("sha1", "N/A") if ioc_hashes else "N/A"),
            "reputation": attr.get("reputation", "N/A"),
            "tags": attr.get("tags", [])
        }

        self.engines = attr.get("last_analysis_results", {})
        self.save_history(target)

        self.render_summary()
        self.render_detections()
        self.render_json()

    # ===== THREAT LEVEL =====
    def get_threat_level(self, mal):
        if mal == 0: return "SAFE"
        if mal < 5: return "LOW RISK"
        if mal < 15: return "MALICIOUS"
        return "CRITICAL"

    # ===== RENDER SUMMARY =====
    def render_summary(self):
        self.summary_box.delete("1.0", "end")
        s = self.summary

        text = f"""
IOC TYPE: {s['ioc_type']}
THREAT LEVEL: {s['level']}
DETECTION: {s['malicious']} / {s['total']}

Type: {s['type']}
Size: {s['size']} bytes
SHA256: {s['sha256']}
MD5: {s.get('md5', 'N/A')}
SHA1: {s.get('sha1', 'N/A')}
Reputation: {s['reputation']}
Tags: {", ".join(s['tags'])}
"""
        self.summary_box.insert("end", text)

    # ===== RENDER ENGINES =====
    def render_detections(self):
        self.detect_box.delete("1.0", "end")
        for eng, res in self.engines.items():
            r = res.get("result", "clean")
            cat = res.get("category", "undetected")
            self.detect_box.insert("end", f"{eng:25} {cat.upper():15} {r}\n")

    # ===== RAW JSON =====
    def render_json(self):
        self.json_box.delete("1.0", "end")
        self.json_box.insert("end", json.dumps(self.last_data, indent=2))

    # ===== HISTORY =====
    def save_history(self, target):
        data = []
        if os.path.exists(HISTORY_FILE):
            data = json.load(open(HISTORY_FILE))
        ioc_type = self.current_ioc.get("type", "N/A") if self.current_ioc else "N/A"
        data.append({"target": target, "type": ioc_type, "time": time.ctime()})
        json.dump(data, open(HISTORY_FILE, "w"), indent=4)

    def show_history(self):
        if not os.path.exists(HISTORY_FILE):
            messagebox.showinfo("History", "No history yet")
            return
        data = json.load(open(HISTORY_FILE))
        txt = "\n".join([f"{i['time']} → [{i.get('type', 'N/A')}] {i['target']}" for i in data])
        messagebox.showinfo("Scan History", txt)

    # ===== EXPORT JSON =====
    def save_json(self):
        if not self.last_data: return
        path = filedialog.asksaveasfilename(defaultextension=".json")
        if path:
            json.dump(self.last_data, open(path, "w"), indent=4)

    # ===== EXPORT PDF =====
    def export_pdf(self):
        if not self.summary: return
        path = filedialog.asksaveasfilename(defaultextension=".pdf")
        if not path: return

        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Arial", 'B', 18)
        pdf.cell(0, 10, "Malware Intelligence Report", ln=True)

        pdf.set_font("Arial", size=12)
        s = self.summary

        pdf.multi_cell(0, 8, f"""
IOC Type: {s['ioc_type']}
Threat Level: {s['level']}
Detection Ratio: {s['malicious']} / {s['total']}

File Type: {s['type']}
SHA256: {s['sha256']}
MD5: {s.get('md5', 'N/A')}
SHA1: {s.get('sha1', 'N/A')}
Size: {s['size']}
Reputation: {s['reputation']}
Tags: {", ".join(s['tags'])}
""")

        pdf.ln(5)
        pdf.set_font("Arial", 'B', 14)
        pdf.cell(0, 10, "Engine Detection Results", ln=True)

        pdf.set_font("Arial", size=8)
        for eng, res in self.engines.items():
            line = f"{eng}: {res.get('category')} -> {res.get('result')}"
            pdf.multi_cell(0, 5, line)

        pdf.output(path)


# ===== RUN =====
if __name__ == "__main__":
    app = VTDesktop()
    app.mainloop()
