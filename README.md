# Recon Automation Pipeline (Python)

> A reproducible recon workflow orchestrating **Subfinder**, **Httpx**, **Ffuf**, and **Gowitness** with concurrent processing, smart retries, and searchable reporting.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![Status](https://img.shields.io/badge/Status-Active-success)

## Key Features
This tool automates the tedious parts of the reconnaissance phase, ensuring consistent and reproducible results.

* **Workflow Orchestration:** Automatically chains `subfinder` → `httpx` → `ffuf` → `gowitness`.
* **Performance:** Utilizes `ThreadPoolExecutor` for concurrent workers to speed up probing and screenshotting.
* **Resilience:** Implements **Exponential-Backoff Retries** to handle network instability and avoid false negatives.
* **Smart Filtering:**
    * **Scope-aware de-duplication:** Automatically filters duplicate subdomains.
    * **Heuristic Flags:** Tagging system to identify potential Admin Panels or Login portals.
* **Reporting:** Generates **Searchable HTML** reports (using DataTables) and CSV exports for easy analysis.

## Tech Stack & Tools
* **Core:** Python 3 (subprocess, pandas, concurrent.futures)
* **External Tools:**
    * [Subfinder](https://github.com/projectdiscovery/subfinder) (Passive Enumeration)
    * [Httpx](https://github.com/projectdiscovery/httpx) (Probing & Tech Detect)
    * [Ffuf](https://github.com/ffuf/ffuf) (Content Discovery / Fuzzing)
    * [Gowitness](https://github.com/sensepost/gowitness) (Visual Recon)

## Screenshots

### 1. Automated Workflow in Action

<img width="1483" height="765" alt="image" src="https://github.com/user-attachments/assets/bc2b9cd1-78ed-4463-a5a8-879dc4dbc7db" />

### 2. Searchable HTML Report
<img width="1918" height="937" alt="image" src="https://github.com/user-attachments/assets/39c9f0a7-de64-411d-9a1c-f158570f4a97" />

## 📦 Installation & Usage

1. **Prerequisites:**
   Ensure you have Go installed and the following tools in your PATH:
   ```bash
   go install -v [github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest](https://github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
   go install -v [github.com/projectdiscovery/httpx/cmd/httpx@latest](https://github.com/projectdiscovery/httpx/cmd/httpx@latest)
   go install -v [github.com/sensepost/gowitness@latest](https://github.com/sensepost/gowitness@latest)
   sudo apt install ffuf -y
   pip install pandas
   ```
## Output Structure
The tool organizes results by target and timestamp to maintain a clean history:
```
recon_results/
└── target.com_20251223_1000/
    ├── 📄 subdomains.txt       # Raw subdomains
    ├── 📄 httpx_results.json   # Tech stack & status codes
    ├── 📄 final_report.html    # Searchable Dashboard
    ├── 📄 final_report.csv     # Data export
    └── 📂 screenshots/         # Visual evidence
```
