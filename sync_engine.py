# -*- coding: utf-8 -*-
"""
Purpose-2-Tool Upgraded Dynamic Synchronization Engine
Aggregates and synchronizes over 3,200+ cybersecurity tools with heavy focus on GitHub repositories:
1. BlackArch Linux Official Directory (2,868+ tools, 2,000+ GitHub repos)
2. Curated GitHub Security Lists (Awesome Pentest, Red Teaming Toolkit, Awesome Security, DFIR)
3. GitHub Security Topics Search API
4. Kali Linux / Debian Package Repositories
5. Curated Deep-Dive Knowledge Base (HackTricks, Medium, Cheatsheets)
"""

import os
import re
import json
import sqlite3
import datetime
import requests
import time

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
DB_PATH = os.path.join(DATA_DIR, "dynamic_arsenal.db")
JSON_PATH = os.path.join(DATA_DIR, "dynamic_tools.json")
JS_DATA_PATH = os.path.join(os.path.dirname(__file__), "js", "dynamic-tools.js")
SYNC_META_PATH = os.path.join(DATA_DIR, "sync_status.json")

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(os.path.join(os.path.dirname(__file__), "js"), exist_ok=True)

USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

CATEGORY_MAP = {
    "blackarch-webapp": "Web Application & API Security",
    "blackarch-reversing": "Reverse Engineering & Binary Exploitation",
    "blackarch-windows": "Active Directory & Windows Attack",
    "blackarch-exploitation": "Post-Exploitation & C2",
    "blackarch-wireless": "Wireless & RF Security",
    "blackarch-scanner": "Reconnaissance & OSINT",
    "blackarch-recon": "Reconnaissance & OSINT",
    "blackarch-forensic": "DFIR & Memory Analysis",
    "blackarch-cracker": "Password Cracking & Hash Cracking",
    "blackarch-dos": "Denial of Service & Stress Testing",
    "blackarch-crypto": "Cryptography & Steganography",
    "blackarch-networking": "Pivoting, Tunneling & Proxies",
    "blackarch-proxy": "Pivoting, Tunneling & Proxies",
    "blackarch-tunnel": "Pivoting, Tunneling & Proxies",
    "blackarch-anti-forensic": "Evasion, Obfuscation & AV/EDR Bypass",
    "blackarch-evasion": "Evasion, Obfuscation & AV/EDR Bypass",
    "blackarch-firmware": "Firmware & IoT Reverse Engineering",
    "blackarch-hardware": "Firmware & IoT Reverse Engineering",
    "blackarch-mobile": "Mobile & Android Security",
    "blackarch-sniffer": "Wireless & RF Security"
}

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""
    CREATE TABLE IF NOT EXISTS tools (
        id TEXT PRIMARY KEY,
        name TEXT,
        tagline TEXT,
        category TEXT,
        rarity TEXT,
        purpose_summary TEXT,
        purposes TEXT,
        distro_blackarch TEXT,
        distro_arch TEXT,
        distro_debian TEXT,
        distro_git TEXT,
        repo_url TEXT,
        repo_type TEXT,
        official_url TEXT,
        research_links TEXT,
        quick_commands TEXT,
        notes TEXT,
        source_origin TEXT,
        version TEXT,
        stars INTEGER DEFAULT 0,
        last_updated TEXT
    )
    """)
    c.execute("CREATE INDEX IF NOT EXISTS idx_name ON tools (name)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_category ON tools (category)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_rarity ON tools (rarity)")
    c.execute("CREATE INDEX IF NOT EXISTS idx_origin ON tools (source_origin)")
    conn.commit()
    conn.close()

def sync_blackarch():
    """Fetches live official tools from blackarch.org/tools.html (2,868+ tools)"""
    print("[*] Syncing live BlackArch Linux tools from blackarch.org...")
    try:
        r = requests.get("https://blackarch.org/tools.html", timeout=15, headers={"User-Agent": USER_AGENT})
        if r.status_code != 200:
            print("[-] BlackArch directory returned status:", r.status_code)
            return []
        html = r.text
    except Exception as e:
        print("[-] Failed to retrieve BlackArch live directory:", e)
        return []

    rows = re.findall(r"<tr[^>]*>(.*?)</tr>", html, re.DOTALL)
    print(f"[+] Found {len(rows)} table rows in BlackArch directory.")

    tools = []
    popular_stems = [
        "nmap", "metasploit", "wireshark", "burp", "sqlmap", "aircrack", "john",
        "hashcat", "hydra", "nikto", "nuclei", "ffuf", "ghidra", "radare2", "responder",
        "impacket", "bloodhound", "volatility", "gobuster", "amass", "wifite", "chisel"
    ]

    for row in rows:
        name_m = re.search(r'class=tbl-name[^>]*>([^<]+)</td>', row)
        if not name_m:
            continue
        
        name = name_m.group(1).strip()
        version_m = re.search(r'class="tbl-version[^>]*>([^<]+)</td>', row)
        version = version_m.group(1).strip() if version_m else ""

        desc_m = re.search(r'class="tbl-description[^>]*>([^<]+)</td>', row)
        desc = desc_m.group(1).strip() if desc_m else "Security tool available in BlackArch Linux."

        cat_m = re.search(r'class=tbl-categorie[^>]*>.*?title="([^"]+)".*?</td>', row, re.DOTALL)
        raw_cat = cat_m.group(1).strip() if cat_m else "blackarch-misc"
        clean_cat = CATEGORY_MAP.get(raw_cat, raw_cat.replace("blackarch-", "").title() + " Security")

        home_m = re.search(r'href="([^"]+)"\s*target="_blank"', row)
        home_url = home_m.group(1).strip() if home_m else f"https://blackarch.org/tools.html"

        is_popular = any(stem in name.lower() for stem in popular_stems)
        rarity = "popular" if is_popular else "rare"

        is_gh = "github.com" in home_url.lower()
        is_gl = "gitlab.com" in home_url.lower()

        tool_id = "ba_" + re.sub(r'[^a-zA-Z0-9_-]', '_', name.lower())

        tools.append({
            "id": tool_id,
            "name": name,
            "tagline": f"{name} {version} - {desc[:90]}..." if len(desc) > 90 else f"{name} {version} - {desc}",
            "category": clean_cat,
            "rarity": rarity,
            "purpose_summary": desc,
            "purposes": [desc.lower(), name.lower(), raw_cat.lower()],
            "distros": {
                "blackarch": f"pacman -S {name.lower()}",
                "arch": f"pacman -S {name.lower()} || yay -S {name.lower()}",
                "debian": f"sudo apt install {name.lower()} || git clone {home_url}",
                "git": f"git clone {home_url}" if (is_gh or is_gl) else ""
            },
            "repo_url": home_url,
            "repo_type": "github" if is_gh else ("gitlab" if is_gl else "web"),
            "official_url": f"https://blackarch.org/tools.html",
            "research_links": [
                {"title": f"BlackArch Tool Directory - {name}", "url": f"https://blackarch.org/tools.html"},
                {"title": f"HackTricks Research - {name}", "url": f"https://book.hacktricks.xyz/?q={name}"}
            ],
            "quick_commands": [
                {"label": "Install via BlackArch", "cmd": f"sudo pacman -S {name.lower()}"},
                {"label": "Run Help", "cmd": f"{name.lower()} --help"}
            ],
            "notes": f"BlackArch package category: {raw_cat}",
            "source_origin": "blackarch",
            "version": version,
            "stars": 0
        })

    print(f"[+] Successfully parsed {len(tools)} tools from BlackArch.")
    return tools

def sync_awesome_github_lists():
    """Scrapes hundreds of curated GitHub offensive security tools from leading lists"""
    print("[*] Scraping curated GitHub security repositories from Awesome lists...")
    sources = [
        ("Awesome Pentest", "https://raw.githubusercontent.com/enaqx/awesome-pentest/master/README.md", "Web Application & API Security"),
        ("Red Teaming Toolkit", "https://raw.githubusercontent.com/infosecn1nja/Red-Teaming-Toolkit/master/README.md", "Command & Control (C2) & Post-Exploitation"),
        ("Awesome Security", "https://raw.githubusercontent.com/sbilly/awesome-security/master/README.md", "General Red Teaming"),
        ("Awesome Incident Response", "https://raw.githubusercontent.com/meirwah/awesome-incident-response/master/README.md", "DFIR & Memory Analysis"),
        ("Awesome Hacking Resources", "https://raw.githubusercontent.com/vitalysim/Awesome-Hacking-Resources/master/README.md", "Exploitation & Hacking"),
        ("Awesome Hacking", "https://raw.githubusercontent.com/carpedm20/awesome-hacking/master/README.md", "Exploitation & Hacking")
    ]

    repos = {}

    for name, url, default_cat in sources:
        try:
            r = requests.get(url, timeout=5, headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                current_sec = default_cat
                count = 0
                for line in r.text.split('\n'):
                    line = line.strip()
                    if line.startswith('### ') or line.startswith('## '):
                        header = line.lstrip('#').strip()
                        if len(header) > 2 and header.lower() not in ['contents', 'license', 'contributing', 'acknowledgments']:
                            current_sec = header

                    m = re.search(r'\[([^\]]+)\]\((https?://github\.com/([a-zA-Z0-9_\-\.]+)/([a-zA-Z0-9_\-\.]+))/?\)(.*)', line)
                    if m:
                        label = m.group(1).strip()
                        repo_url = m.group(2).strip()
                        owner = m.group(3).strip()
                        repo_name = m.group(4).strip()
                        rest = m.group(5).strip()

                        desc = rest.lstrip(' -:—*').strip()
                        desc = re.sub(r'\[.*?\]\(.*?\)', '', desc).strip()
                        if not desc or len(desc) < 5:
                            desc = f"{label} - Offensive security repository on GitHub ({owner}/{repo_name})."

                        key = f"{owner}/{repo_name}".lower()
                        if key not in repos and owner.lower() not in ['github', 'git', 'site', 'shields', 'badge']:
                            tool_id = "gh_" + re.sub(r'[^a-zA-Z0-9_-]', '_', key)
                            
                            # Clean category
                            cat = current_sec
                            if any(k in cat.lower() for k in ['active directory', 'windows', 'kerberos']):
                                cat = "Active Directory & Windows Attack"
                            elif any(k in cat.lower() for k in ['web', 'injection', 'xss', 'sql', 'fuzz']):
                                cat = "Web Application & API Security"
                            elif any(k in cat.lower() for k in ['c2', 'post exploit', 'persistence', 'shell']):
                                cat = "Command & Control (C2) & Post-Exploitation"
                            elif any(k in cat.lower() for k in ['revers', 'decompile', 'binary', 'disassembler']):
                                cat = "Reverse Engineering & Binary Exploitation"
                            elif any(k in cat.lower() for k in ['privesc', 'privilege', 'escalat']):
                                cat = "Privilege Escalation & Local Enumeration"
                            elif any(k in cat.lower() for k in ['osint', 'recon', 'subdomain', 'discovery']):
                                cat = "Reconnaissance & OSINT"
                            elif any(k in cat.lower() for k in ['wireless', 'wifi', 'bluetooth', 'rf']):
                                cat = "Wireless & RF Security"
                            elif any(k in cat.lower() for k in ['forensic', 'incident', 'memory', 'dfir']):
                                cat = "DFIR & Memory Analysis"

                            repos[key] = {
                                "id": tool_id,
                                "name": label if len(label) < 30 and not label.startswith('http') else repo_name,
                                "tagline": f"GitHub: {owner}/{repo_name} - {desc[:90]}...",
                                "category": cat,
                                "rarity": "rare",
                                "purpose_summary": desc,
                                "purposes": [desc.lower(), label.lower(), repo_name.lower(), owner.lower(), cat.lower()],
                                "distros": {
                                    "blackarch": f"pacman -S {repo_name.lower()} || git clone {repo_url}.git",
                                    "arch": f"yay -S {repo_name.lower()} || git clone {repo_url}.git",
                                    "debian": f"git clone {repo_url}.git && cd {repo_name}",
                                    "git": f"git clone {repo_url}.git"
                                },
                                "repo_url": repo_url,
                                "repo_type": "github",
                                "official_url": repo_url,
                                "research_links": [
                                    {"title": f"GitHub Repository ({owner}/{repo_name})", "url": repo_url},
                                    {"title": "GitHub Releases", "url": f"{repo_url}/releases"},
                                    {"title": f"HackTricks Research - {label}", "url": f"https://book.hacktricks.xyz/?q={label}"}
                                ],
                                "quick_commands": [
                                    {"label": "Clone GitHub Repository", "cmd": f"git clone {repo_url}.git"},
                                    {"label": "Enter Directory", "cmd": f"cd {repo_name}"}
                                ],
                                "notes": f"Curated from {name}. Repository: {owner}/{repo_name}",
                                "source_origin": "github",
                                "version": "latest",
                                "stars": 250
                            }
                            count += 1
                print(f"[+] {name}: harvested {count} repositories.")
        except Exception as e:
            print(f"[-] Error fetching {name}: {e}")

    tools = list(repos.values())
    print(f"[+] Total unique GitHub repositories from Awesome lists: {len(tools)}")
    return tools

def sync_github_topics():
    """Queries GitHub Search API for trending security repos"""
    print("[*] Querying GitHub Search API for trending tools...")
    queries = [
        ("Active Directory & Windows Attack", "topic:active-directory+topic:security"),
        ("Command & Control (C2) & Post-Exploitation", "topic:c2-framework"),
        ("Evasion, Obfuscation & AV/EDR Bypass", "topic:edr-evasion"),
        ("Privilege Escalation & Local Enumeration", "topic:privilege-escalation"),
        ("Web Application & API Security", "topic:pentest+topic:web")
    ]
    tools = []
    seen = set()

    for default_cat, q in queries:
        try:
            url = f"https://api.github.com/search/repositories?q={q}&sort=stars&per_page=50"
            r = requests.get(url, timeout=6, headers={"User-Agent": USER_AGENT})
            if r.status_code == 200:
                data = r.json()
                for item in data.get("items", []):
                    full_name = item.get("full_name", "")
                    if full_name in seen:
                        continue
                    seen.add(full_name)

                    name = item.get("name", "")
                    desc = item.get("description") or f"Cybersecurity repository: {name}"
                    html_url = item.get("html_url", "")
                    clone_url = item.get("clone_url", html_url + ".git")
                    stars = item.get("stargazers_count", 0)
                    lang = item.get("language") or "Code"
                    topics = item.get("topics", [])

                    tool_id = "gh_" + re.sub(r'[^a-zA-Z0-9_-]', '_', full_name.lower())
                    rarity = "popular" if stars >= 500 else "rare"

                    debian_cmd = f"git clone {clone_url} && cd {name}"
                    if lang.lower() == "python":
                        debian_cmd += " && pip install -r requirements.txt"
                    elif lang.lower() == "go":
                        debian_cmd += " && go build"

                    tools.append({
                        "id": tool_id,
                        "name": name,
                        "tagline": f"[{lang}] {full_name} ({stars:,} ★) - {desc[:90]}...",
                        "category": default_cat,
                        "rarity": rarity,
                        "purpose_summary": desc,
                        "purposes": [desc.lower(), name.lower(), full_name.lower(), lang.lower()] + [t.lower() for t in topics],
                        "distros": {
                            "blackarch": f"pacman -S {name.lower()} || git clone {clone_url}",
                            "arch": f"yay -S {name.lower()} || git clone {clone_url}",
                            "debian": debian_cmd,
                            "git": f"git clone {clone_url}"
                        },
                        "repo_url": html_url,
                        "repo_type": "github",
                        "official_url": html_url,
                        "research_links": [
                            {"title": f"GitHub Repository ({stars:,} ★)", "url": html_url},
                            {"title": "GitHub Releases", "url": f"{html_url}/releases"},
                            {"title": f"HackTricks Research", "url": f"https://book.hacktricks.xyz/?q={name}"}
                        ],
                        "quick_commands": [
                            {"label": "Git Clone Repository", "cmd": f"git clone {clone_url}"}
                        ],
                        "notes": f"Primary Language: {lang} | Stars: {stars:,} | Topics: {', '.join(topics[:4])}",
                        "source_origin": "github",
                        "version": "latest",
                        "stars": stars
                    })
            time.sleep(1)
        except Exception as e:
            print(f"[-] GitHub API error for {q}: {e}")

    print(f"[+] Harvested {len(tools)} trending GitHub tools from topics.")
    return tools

def export_to_json_and_js():
    """Export local SQLite database tools into dynamic_tools.json and js/dynamic-tools.js."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("SELECT count(*) FROM tools")
    total_tools_count = c.fetchone()[0]
    c.execute("SELECT count(*) FROM tools WHERE repo_url LIKE '%github.com%'")
    github_repos_count = c.fetchone()[0]
    c.execute("SELECT count(*) FROM tools WHERE source_origin='gitlab' OR repo_url LIKE '%gitlab.com%'")
    gitlab_count = c.fetchone()[0]
    c.execute("SELECT count(*) FROM tools WHERE distro_blackarch != ''")
    blackarch_count = c.fetchone()[0]

    c.execute("SELECT * FROM tools ORDER BY stars DESC")
    rows = c.fetchall()
    col_names = [d[0] for d in c.description]
    all_tools_export = []
    for r in rows:
        rd = dict(zip(col_names, r))
        all_tools_export.append({
            "id": rd["id"],
            "name": rd["name"],
            "tagline": rd["tagline"],
            "category": rd["category"],
            "rarity": rd["rarity"],
            "purpose_summary": rd["purpose_summary"],
            "purposes": json.loads(rd["purposes"]) if rd["purposes"] else [],
            "distros": {
                "blackarch": rd["distro_blackarch"],
                "arch": rd["distro_arch"],
                "debian": rd["distro_debian"],
                "git": rd["distro_git"]
            },
            "repo_url": rd["repo_url"],
            "repo_type": rd["repo_type"],
            "official_url": rd["official_url"],
            "research_links": json.loads(rd["research_links"]) if rd["research_links"] else [],
            "notes": rd["notes"],
            "source_origin": rd["source_origin"],
            "version": rd["version"],
            "stars": rd["stars"],
            "language": "Tool",
            "last_updated": rd["last_updated"] or ""
        })
    conn.close()

    now_iso = datetime.datetime.now().isoformat()
    with open(JSON_PATH, "w", encoding="utf-8") as f:
        json.dump(all_tools_export, f, indent=2, ensure_ascii=False)

    with open(JS_DATA_PATH, "w", encoding="utf-8") as f:
        f.write("// DYNAMIC PURPOSE-2-TOOL DATABASE\n")
        f.write(f"// Last Synced: {now_iso}\n")
        f.write(f"// Total Live Tools: {total_tools_count}\n")
        f.write(f"// Total GitHub Repos: {github_repos_count}\n")
        f.write("window.DYNAMIC_TOOLS_DB = " + json.dumps(all_tools_export, ensure_ascii=False) + ";\n")

    meta = {
        "last_sync": now_iso,
        "total_tools": total_tools_count,
        "github_count": github_repos_count,
        "gitlab_count": gitlab_count,
        "blackarch_count": blackarch_count,
        "status": "success",
        "is_syncing": False
    }
    with open(SYNC_META_PATH, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    return meta

def run_full_sync():
    """Runs an exhaustive sync across BlackArch, Awesome GitHub Lists, Topics, and Curated base"""
    init_db()

    # 1. Curated Base
    curated_path = os.path.join(DATA_DIR, "tools.json")
    curated = []
    if os.path.exists(curated_path):
        with open(curated_path, "r", encoding="utf-8") as f:
            curated = json.load(f)
            for c in curated:
                c["source_origin"] = "curated"

    # 2. BlackArch Live
    blackarch_tools = sync_blackarch()

    # 3. Awesome GitHub Repositories
    awesome_github = sync_awesome_github_lists()

    # 4. GitHub Topics API
    topic_github = sync_github_topics()

    # Merge by name / repo
    unified = {}

    for t in awesome_github:
        unified[t["name"].lower()] = t

    for t in topic_github:
        unified[t["name"].lower()] = t

    for t in blackarch_tools:
        unified[t["name"].lower()] = t

    for t in curated:
        unified[t["name"].lower()] = t

    all_tools = list(unified.values())
    github_repos_count = sum(1 for t in all_tools if "github.com" in t.get("repo_url", ""))
    print(f"[+] Total unified dynamic tools: {len(all_tools)}")
    print(f"[+] Total GitHub repositories: {github_repos_count}")

    # SQLite update (upsert without wiping existing multi-source repositories)
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    init_db()

    now_iso = datetime.datetime.now().isoformat()

    for t in all_tools:
        c.execute("""
        INSERT OR REPLACE INTO tools VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            t["id"],
            t["name"],
            t.get("tagline", ""),
            t.get("category", "General"),
            t.get("rarity", "popular"),
            t.get("purpose_summary", ""),
            json.dumps(t.get("purposes", [])),
            t.get("distros", {}).get("blackarch", ""),
            t.get("distros", {}).get("arch", ""),
            t.get("distros", {}).get("debian", ""),
            t.get("distros", {}).get("git", ""),
            t.get("repo_url", ""),
            t.get("repo_type", "github"),
            t.get("official_url", ""),
            json.dumps(t.get("research_links", [])),
            json.dumps(t.get("quick_commands", [])),
            t.get("notes", ""),
            t.get("source_origin", "blackarch"),
            t.get("version", ""),
            t.get("stars", 0),
            now_iso
        ))
    conn.commit()

    conn.close()
    meta = export_to_json_and_js()
    print(f"[+] Full sync complete! Synced {meta['total_tools']} total tools ({meta['github_count']} GitHub, {meta['gitlab_count']} GitLab).")
    return meta

if __name__ == "__main__":
    run_full_sync()
