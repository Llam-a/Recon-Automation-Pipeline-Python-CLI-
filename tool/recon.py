import subprocess
import os
import json
import pandas as pd
import argparse
import time
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Cấu hình đường dẫn và tham số
CONFIG = {
    "SUBFINDER_THREADS": 20,
    "HTTPX_THREADS": 50,
    "HTTPX_RATE_LIMIT": 150,
    "RETRIES": 2, 
    "OUTPUT_DIR": "recon_results",
    # Đường dẫn wordlist mặc định trên Kali Linux
    "WORDLIST": "/usr/share/wordlists/dirb/common.txt" 
}

class ReconPipeline:
    def __init__(self, target_domain):
        # Làm sạch input
        self.target = target_domain.replace("https://", "").replace("http://", "").rstrip("/")
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.session_dir = os.path.join(CONFIG["OUTPUT_DIR"], f"{self.target}_{self.timestamp}")
        os.makedirs(self.session_dir, exist_ok=True)
        print(f"[*] Khởi tạo Recon Pipeline cho: {self.target}")
        print(f"[*] Output directory: {self.session_dir}")

    def run_command(self, command, retries=CONFIG["RETRIES"]):
        attempt = 0
        while attempt < retries:
            try:
                print(f"[*] Executing: {' '.join(command)}")
                result = subprocess.run(command, check=True, text=True, capture_output=True)
                return result.stdout
            except subprocess.CalledProcessError as e:
                attempt += 1
                wait_time = 2 ** attempt
                print(f"[!] Lỗi lệnh (Exit Code {e.returncode}). Thử lại sau {wait_time}s...")
                time.sleep(wait_time)
        print(f"[X] Lệnh thất bại sau {retries} lần thử.")
        return None

    def step_1_subdomain_enum(self):
        print("\n--- STEP 1: SUBDOMAIN ENUMERATION (SUBFINDER) ---")
        output_file = os.path.join(self.session_dir, "subdomains.txt")
        
        cmd = ["subfinder", "-d", self.target, "-t", str(CONFIG["SUBFINDER_THREADS"]), "-o", output_file, "-silent"]
        self.run_command(cmd)
        
        # Luôn thêm root domain
        with open(output_file, 'a') as f:
            f.write(f"{self.target}\n")
        
        # Lọc trùng
        with open(output_file, 'r') as f:
            subs = list(set(f.read().splitlines()))
        with open(output_file, 'w') as f:
            f.write('\n'.join(subs))

        print(f"[+] Subdomains found: {len(subs)}")
        return output_file

    def step_2_probing(self, input_file):
        print("\n--- STEP 2: PROBING (HTTPX) ---")
        json_output = os.path.join(self.session_dir, "httpx_results.json")
        
        cmd = [
            "httpx", "-l", input_file, 
            "-threads", str(CONFIG["HTTPX_THREADS"]), 
            "-rate-limit", str(CONFIG["HTTPX_RATE_LIMIT"]),
            "-title", "-tech-detect", "-status-code", "-follow-redirects", 
            "-json", "-o", json_output, "-silent"
        ]
        self.run_command(cmd)
        return json_output

    def step_3_content_discovery(self, httpx_json):
        """
        Bước mới: Dùng FFUF để quét thư mục ẩn (như CV mô tả)
        Chỉ quét các URL có status code 200/403 để tiết kiệm thời gian.
        """
        print("\n--- STEP 3: CONTENT DISCOVERY (FFUF) ---")
        
        # Kiểm tra wordlist
        if not os.path.exists(CONFIG["WORDLIST"]):
            print(f"[!] Không tìm thấy wordlist tại {CONFIG['WORDLIST']}. Bỏ qua bước này.")
            return

        live_targets = []
        try:
            with open(httpx_json, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    # Chỉ quét các trang web sống
                    if data.get("status_code") in [200, 403, 301, 302]:
                        live_targets.append(data.get("url"))
        except:
            return

        # Demo: Chỉ quét tối đa 3 targets đầu tiên để tránh treo máy lâu
        for url in live_targets[:3]:
            print(f"[*] Fuzzing: {url}")
            ffuf_out = os.path.join(self.session_dir, f"ffuf_{url.replace('://', '_').replace('/', '')}.json")
            cmd = [
                "ffuf", 
                "-u", f"{url}/FUZZ", 
                "-w", CONFIG["WORDLIST"],
                "-mc", "200,403", # Chỉ lấy code 200, 403
                "-o", ffuf_out, "-of", "json",
                "-t", "50", "-s" # Silent mode
            ]
            # Không dùng run_command có retry vì ffuf chạy lâu
            try:
                subprocess.run(cmd, timeout=60, capture_output=True) # Timeout 60s mỗi site
            except subprocess.TimeoutExpired:
                print("[!] Ffuf timed out (skip)")
            except Exception as e:
                print(f"[!] Ffuf error: {e}")

    def step_4_screenshot(self, input_json):
        print("\n--- STEP 4: VISUAL RECON (GOWITNESS) ---")
        live_urls_file = os.path.join(self.session_dir, "live_urls.txt")
        live_urls = []
        
        try:
            with open(input_json, 'r') as f:
                for line in f:
                    data = json.loads(line)
                    if data.get("url"):
                        live_urls.append(data.get("url"))
            
            if not live_urls:
                print("[!] Không có URL nào để chụp ảnh.")
                return

            with open(live_urls_file, 'w') as f:
                f.write('\n'.join(live_urls))
                
            screenshots_dir = os.path.join(self.session_dir, "screenshots")
            # Thêm --disable-db để tránh lỗi database lock
            # Thay --destination bằng --screenshot-path
            cmd = ["gowitness", "scan", "file", "-f", live_urls_file, "--screenshot-path", screenshots_dir, "--threads", "5"]
            self.run_command(cmd)
        except Exception as e:
            print(f"[!] Lỗi screenshot: {e}")

    def step_5_reporting(self, httpx_json):
        print("\n--- STEP 5: REPORTING ---")
        results = []
        try:
            with open(httpx_json, 'r') as f:
                for line in f:
                    results.append(json.loads(line))
            
            df = pd.DataFrame(results)
            cols = ["url", "status_code", "title", "webserver", "tech"]
            for c in cols:
                if c not in df.columns: df[c] = ""
            
            # Fix lỗi SettingWithCopyWarning bằng .copy()
            final_df = df[cols].copy()

            admin_keywords = ['admin', 'login', 'dashboard', 'portal']
            def check_suspicious(row):
                content = (str(row['url']) + str(row['title'])).lower()
                if any(kw in content for kw in admin_keywords):
                    return "YES"
                return "NO"

            final_df['Likely_Admin'] = final_df.apply(check_suspicious, axis=1)

            csv_path = os.path.join(self.session_dir, "final_report.csv")
            html_path = os.path.join(self.session_dir, "final_report.html")
            
            final_df.to_csv(csv_path, index=False)
            
            # HTML Searchable Template
            html_template = f"""
            <html>
            <head>
                <title>Recon Report - {self.target}</title>
                <link rel="stylesheet" type="text/css" href="https://cdn.datatables.net/1.11.5/css/jquery.dataTables.css">
                <script type="text/javascript" charset="utf8" src="https://code.jquery.com/jquery-3.5.1.js"></script>
                <script type="text/javascript" charset="utf8" src="https://cdn.datatables.net/1.11.5/js/jquery.dataTables.js"></script>
                <script>$(document).ready( function () {{ $('#reconTable').DataTable(); }} );</script>
                <style>body {{ font-family: sans-serif; padding: 20px; }}</style>
            </head>
            <body>
                <h1>Recon Report: {self.target}</h1>
                {final_df.to_html(index=False, table_id="reconTable", classes="display")}
            </body>
            </html>
            """
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_template)
            
            print(f"[+] Báo cáo: {html_path}")
            
        except Exception as e:
            print(f"[!] Lỗi báo cáo: {e}")

    def start(self):
        print(">>> BẮT ĐẦU RECON AUTOMATION PIPELINE (V3) <<<")
        subs_file = self.step_1_subdomain_enum()
        if subs_file:
            httpx_res = self.step_2_probing(subs_file)
            if httpx_res and os.path.exists(httpx_res):
                # Chạy Content Discovery (Ffuf) trước
                self.step_3_content_discovery(httpx_res)
                
                # Chạy Screenshot và Report song song
                with ThreadPoolExecutor(max_workers=2) as executor:
                    executor.submit(self.step_4_screenshot, httpx_res)
                    executor.submit(self.step_5_reporting, httpx_res)
        print("\n>>> HOÀN THÀNH <<<")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon Automation Pipeline (CV Standard)")
    parser.add_argument("-d", "--domain", required=True, help="Domain mục tiêu")
    args = parser.parse_args()
    pipeline = ReconPipeline(args.domain)
    pipeline.start()
