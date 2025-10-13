# Recon Automation Pipeline (Python CLI)

Orchestrate: `subfinder` → `httpx` → `gowitness` → aggregate CSV with flags (admin/login, swagger, open dir).

## Yêu cầu
- Đã cài: `subfinder`, `httpx`, `gowitness` trong PATH
- Python 3.9+

## Chạy nhanh
```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python recon.py -d example.com -o outdir
```

Kết quả:
- `outdir/hosts.txt`, `outdir/alive.txt`, `outdir/httpx.json`
- `outdir/screenshots/` (gowitness)
- `outdir/aggregate.csv` (host, status, title, tech?, flags)
