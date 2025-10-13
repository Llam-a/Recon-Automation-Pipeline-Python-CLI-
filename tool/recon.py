import argparse, os, subprocess, json, csv, re
from datetime import datetime
import pandas as pd

FLAGS = [
    (re.compile(r'/admin\b', re.I), 'has_admin'),
    (re.compile(r'login', re.I), 'has_login'),
    (re.compile(r'swagger|api-docs|openapi', re.I), 'has_api_docs'),
    (re.compile(r'Index of /', re.I), 'open_dir'),
]

def run(cmd, outfile=None):
    print("[*] " + " ".join(cmd))
    p = subprocess.run(cmd, capture_output=True, text=True)
    if outfile:
        with open(outfile, "w", encoding="utf-8") as f:
            f.write(p.stdout)
    return p.stdout

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-d","--domain", required=True)
    ap.add_argument("-o","--out", required=True)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    hosts_file = os.path.join(args.out, "hosts.txt")
    alive_file = os.path.join(args.out, "alive.txt")
    httpx_json = os.path.join(args.out, "httpx.json")
    shots_dir = os.path.join(args.out, "screenshots")
    os.makedirs(shots_dir, exist_ok=True)

    # 1) subfinder
    run(["subfinder","-d",args.domain,"-silent"], outfile=hosts_file)

    # 2) httpx probe
    run(["httpx","-l",hosts_file,"-json","-o",httpx_json])

    # parse httpx json
    rows = []
    with open(httpx_json,"r",encoding="utf-8") as f:
        for line in f:
            try:
                obj = json.loads(line)
            except:
                continue
            url = obj.get("url","")
            title = obj.get("title","")
            status = obj.get("status-code")
            tech = ",".join(obj.get("webserver","") for _ in [0]) or ""
            flags = []
            body_preview = obj.get("body-preview","") or ""
            for rx, name in FLAGS:
                if rx.search(url) or rx.search(title) or rx.search(body_preview):
                    flags.append(name)
            rows.append({"url": url, "status": status, "title": title, "tech": tech, "flags": ";".join(sorted(set(flags)))})
    df = pd.DataFrame(rows).drop_duplicates(subset=["url"])
    df.to_csv(os.path.join(args.out,"aggregate.csv"), index=False)

    # 3) gowitness screenshots (best-effort)
    run(["gowitness","file","-f",httpx_json,"-P",shots_dir])

    print("[+] Done. Results in", args.out)

if __name__ == "__main__":
    main()
