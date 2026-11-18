# PURPOSE // 2 // TOOL 🎯⚡

```
  ██████╗ ██╗   ██╗██████╗ ██████╗  ██████╗ ███████╗      ██████╗     ████████╗ ██████╗  ██████╗ ██╗     
  ██╔══██╗██║   ██║██╔══██╗██╔══██╗██╔═══██╗██╔════╝      ╚════██╗    ╚══██╔══╝██╔═══██╗██╔═══██╗██║     
  ██████╔╝██║   ██║██████╔╝██████╔╝██║   ██║███████╗█████╗ █████╔╝       ██║   ██║   ██║██║   ██║██║     
  ██╔═══╝ ██║   ██║██╔══██╗██╔═══╝ ██║   ██║╚════██║╚════╝██╔═══╝        ██║   ██║   ██║██║   ██║██║     
  ██║     ╚██████╔╝██║  ██║██║     ╚██████╔╝███████║      ███████╗       ██║   ╚██████╔╝╚██████╔╝███████╗
  ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚═╝      ╚═════╝ ╚══════╝      ╚══════╝       ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
```

> **Operational Purpose-Driven Cybersecurity Arsenal & Deep Semantic Intelligence Engine**  
> Indexes **4,261+ security tools & platforms** across GitHub, GitLab, Codeberg, SourceForge, BlackArch, Debian, Kali, Practice Labs, and Vulnerability Disclosure Portals. Features a sub-0.1ms In-Memory Cache, a 12-Domain Deep Semantic Purpose Classifier, and a pitch-black OLED UI (`#000000`).

---

## ⚡ Quick Start

### 1. Launch with Batch Script (Windows)
Double-click **`start.bat`** or run from your terminal:
```cmd
start.bat
```
* Automatically checks dependencies (`fastapi`, `uvicorn`, `requests`, `pydantic`).
* Launches the federated backend server in the background on port `8080`.
* Opens your default browser at `http://localhost:8080`.

### 2. Stop Server
Double-click **`stop.bat`** or run from your terminal:
```cmd
stop.bat
```
* Safely finds and terminates active server processes on port `8080`.

### 3. Fully Offline / Standalone Mode
Double-click or open **`dashboard.html`** in any web browser.  
No server, Python, or internet connection required. All 4,261 tools and the client-side semantic classifier run 100% inside your browser's memory.

---

## 🧠 Key Features & Capabilities

### 1. 4,261+ Curated Tools & Public Cyber Ecosystem
Unified repository data from the world's premier cybersecurity sources:
* **2,743 GitHub Repositories** (Live worldwide discovery)
* **482 GitLab Projects** (Independent open-source repositories)
* **3,637 BlackArch Linux Official Packages** (Pre-compiled offensive tools)
* **5 Independent Code Forges** (Codeberg, SourceForge, sr.ht)
* **138 Curated Threat Portals, Practice Labs & Standards** (OWASP, MITRE ATT&CK, PortSwigger, NIST, CTF ranges)

### 2. Dual Search Console Architecture
The interface provides two dedicated search boxes engineered for distinct operational workflows:
* **🎯 Box 1: Purpose & Task Search (`/` key)**:
  * Powered by the **12-Domain Semantic Intelligence Engine**.
  * Input mission scenarios, techniques, or tactics (e.g. `radio forensic`, `bypass cloudflare`, `dump lsass`, `kerberoasting`, `wifi pmkid`).
  * Evaluates functional capabilities and applies strict domain qualification (e.g. eliminating Tor browsers from radio frequency queries).
* **⚡ Box 2: Direct Tool & Similar Alternatives Radar (`Ctrl+T` / `Alt+T` key)**:
  * Direct tool name, binary, or package search (e.g. `nmap`, `sqlmap`, `urh`, `ghidra`, `mimikatz`, `bloodhound`).
  * Pins the exact matching tool to the top with an `⚡ EXACT TARGET` badge.
  * Simultaneously discovers and ranks **functional peer alternatives** with an `⚡ SIMILAR ALTERNATIVE` badge using the curated similarity matrix (e.g. searching `nmap` surfaces `masscan`, `rustscan`, `naabu`; searching `sqlmap` surfaces `ghauri`, `commix`, `nosqlmap`).
* **Collaborative Dual Filtering**: Use both boxes together to pinpoint a specific tool or alternative within a broader operational objective.
* **Instant "Find Similar" Action**: Every tool card and dossier includes a `⚡ Find Similar` button to instantly launch similarity radar for that tool.

### 3. 12-Domain Deep Semantic Intelligence Engine
Unlike basic keyword search engines that match arbitrary text (e.g., matching *"Tor Browser sandbox"* for a *"radio forensic"* query because of generic words), Purpose-2-Tool uses **concept gating** and **word-boundary domain validation** across 12 disciplines:

1. **Radio Frequency (RF), SDR & EMF Forensics** (`TempestSDR`, `URH`, `inspectrum`, `SigDigger`, `gr-satellites`)
2. **Active Directory & Credential Extraction** (`impacket`, `secretsdump`, `certipy`, `rubeus`, `mimikatz`)
3. **Malware Analysis, Sandboxing & DFIR** (`remnux`, `cape sandbox`, `ghidra`, `yara`, `volatility3`)
4. **Automotive Security & CAN Bus Hacking** (`can-utils`, `savvycan`, `caringcaribou`, `scapy-can`)
5. **Cloud Security & Container Breakout** (`scoutsuite`, `prowler`, `pacu`, `cdk`, `deepce`)
6. **Web Application, API & GraphQL Security** (`sqlmap`, `caido`, `inql`, `graphql-cop`, `jwt-tool`, `ffuf`)
7. **Network Pivoting, Tunneling & C2** (`ligolo-ng`, `chisel`, `proxychains`, `havoc`, `sliver`, `rpivot`)
8. **Defense Evasion, EDR & AMSI Bypass** (`scarecrow`, `donut`, `chameleon`, `pe-sieve`, `invoke-obfuscation`)
9. **Wireless, Bluetooth (BLE) & NFC/RFID** (`hcxdumptool`, `aircrack-ng`, `wifite`, `proxmark3`, `ubertooth`)
10. **OSINT, Attack Surface & Reconnaissance** (`amass`, `subfinder`, `theharvester`, `spiderfoot`, `naabu`)
11. **IoT Firmware & Hardware Hacking** (`binwalk`, `firmwalker`, `firmadyne`, `flashrom`, `openocd`)
12. **Local Privilege Escalation (Linux/Windows)** (`peass-ng`, `linpeas`, `winpeas`, `godpotato`, `gtfobins`)

### 4. Persistent Self-Learning Loop
* Automatically learns user operational behavior through the `/api/intel/learn` endpoint.
* When you search for a purpose and investigate or bookmark a tool, the engine permanently associates that tool with the query in `data/learned_intelligence.json`.
* Subsequent searches for that query automatically prioritize and boost verified tools.

### 5. Interactive Multi-Distro Deployment Hub
Clicking any tool card opens a comprehensive dossier featuring tabbed installation and run commands:
* **🏴 BlackArch**: `sudo pacman -S <pkg>`
* **🏹 Arch / AUR**: `yay -S <pkg>`
* **🌀 Debian / Kali**: `sudo apt update && sudo apt install -y <pkg>`
* **🐙 Git & Source**: `git clone <repo_url> && cd <dir>`
* **⚡ Quick Run**: Pre-configured CLI invocation command with instant copy-to-clipboard.

### 6. High-Speed In-Memory Cache
* Thread-safe LRU in-memory cache server with 1800-second TTL.
* Delivers search queries in **0.05ms to 0.19ms**, allowing lag-free filtering across 4,261 tools.

### 7. Power-User Shortcuts & Tools
* **`/`** — Focus **Purpose & Task Search** input from anywhere.
* **`Ctrl+T` / `Alt+T`** — Focus **Direct Tool & Similar Alternatives** input.
* **`Esc`** — Clear search or close modals.
* **★ Bookmark** — Save favorite tools locally in browser storage.
* **Batch Script Generator** — Generate automated Bash/Zsh setup scripts to install multiple selected tools in one shot.
* **Custom Tools** — Add underground scripts or private repositories directly to your local database.

---

## 📁 Repository Structure

```
Purpose-2-Tool/
├── start.bat                 # One-click start script (Windows)
├── stop.bat                  # One-click stop script (Windows)
├── server.py                 # FastAPI backend server with federated live search
├── semantic_intelligence.py  # 12-domain semantic classifier & self-learning engine
├── sync_engine.py            # Upstream repository synchronization engine
├── bundle.py                 # Compiles CSS, JS, and HTML into standalone dashboard.html
├── index.html                # Web interface source
├── README.md                 # Project documentation
│
├── css/
│   └── style.css             # Pitch-black OLED theme stylesheet (#000000)
│
├── js/
│   ├── app.js                # Frontend application logic & live client search
│   └── dynamic-tools.js      # Full dynamic cache of 4,261 indexed tools
│
├── data/
│   ├── dynamic_arsenal.db    # SQLite authoritative database (4,261 records)
│   ├── dynamic_tools.json    # JSON dynamic tool cache
│   ├── learned_intelligence.json # Persistent self-learned query & intent memory
│   ├── sync_status.json      # Sync timestamps and repository counts
│   └── tools.json            # Curated offensive tool seed definitions
│
└── collected/
    ├── MASTER_CYBER_INDEX.json # Canonical index of curated portals, labs & standards
    └── README.md             # Curated resources reference
```

---

## 📡 REST API Reference

When `server.py` is running (`http://localhost:8080`):

### 1. `GET /api/tools`
Search and filter tools across the database with live federated enrichment:
```bash
curl "http://localhost:8080/api/tools?q=radio+forensic&source=gitlab&limit=10"
```
* **Parameters**:
  * `q` (string): Query terms or operational purpose (e.g. `dump lsass`, `radio forensic`, `canbus`).
  * `source` (string): `all`, `github`, `gitlab`, `forges`, `labs`, `resources`, `blackarch`, `arch`, `debian`, `kali`.
  * `category` (string): Category filter or `all`.
  * `distro` (string): `all`, `blackarch`, `arch`, `debian`, `git`.
  * `rarity` (string): `all`, `popular`, `rare`.
  * `sort_by` (string): `relevance`, `stars`, `popularity`, `updated`, `name_asc`, `name_desc`.
  * `live` (bool): `true` / `false` to enable live upstream querying.
  * `page` (int) & `limit` (int): Pagination controls.

### 2. `GET /api/sync/status`
Returns live synchronization statistics and in-memory cache health:
```bash
curl "http://localhost:8080/api/sync/status"
```

### 3. `POST /api/sync`
Triggers an asynchronous background upstream sync with BlackArch and curated registries:
```bash
curl -X POST "http://localhost:8080/api/sync"
```

### 4. `POST /api/intel/learn`
Feeds user behavioral selections back into the self-learning memory:
```bash
curl -X POST "http://localhost:8080/api/intel/learn" \
     -H "Content-Type: application/json" \
     -d '{"query": "radio forensic", "tool_id": "urh", "tool_name": "Universal Radio Hacker"}'
```

### 5. `POST /api/cache/clear`
Clears the in-memory retrieval cache:
```bash
curl -X POST "http://localhost:8080/api/cache/clear"
```

---

## 🛠️ Rebuilding the Standalone Dashboard

To recompile `index.html`, `css/style.css`, and `js/` into the standalone single-file distribution:
```bash
python bundle.py
```
Outputs the standalone distribution directly to your local artifact directory with zero external runtime dependencies.

---

## ⚖️ Legal & Ethical Notice

This software is designed solely for authorized cybersecurity research, defensive auditing, legal penetration testing, and education. Always obtain explicit permission before testing networks, devices, or systems you do not own.
