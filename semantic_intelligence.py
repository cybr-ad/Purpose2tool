"""
semantic_intelligence.py
========================
Deep Semantic Intent Reasoner, Operational Purpose Classifier,
and Persistent Self-Learning Intelligence Engine for Purpose-2-Tool.
"""

import os
import re
import json
import sqlite3
import datetime
import urllib.request
import urllib.parse
from typing import Dict, List, Set, Any, Optional, Tuple

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
LEARNED_INTEL_PATH = os.path.join(DATA_DIR, "learned_intelligence.json")
DB_PATH = os.path.join(DATA_DIR, "dynamic_arsenal.db")

# ----------------------------------------------------
# 1. CORE DOMAIN TAXONOMY & INTENT REASONING MATRIX
# ----------------------------------------------------

SEMANTIC_DOMAINS = {
    "RF_SDR_EMF": {
        "title": "Radio Frequency (RF), SDR & EMF Signal Forensics",
        "description": "Radio spectrum investigation, SDR demodulation, EMF/TEMPEST radiation eavesdropping, RF protocol reverse engineering.",
        "trigger_patterns": [
            r"\bradio\b", r"\brf\b", r"\bsdr\b", r"\bemf\b", r"\btempest\b", r"\bspectrum\b",
            r"\bsignal\b", r"\bdemodulat\w*\b", r"\biq\s*(data|file|capture|stream)\b",
            r"\brtl[-_]?sdr\b", r"\bhackrf\b", r"\bgnuradio\b", r"\bairspy\b", r"\blimesdr\b",
            r"\b433\s*mhz\b", r"\b868\s*mhz\b", r"\b915\s*mhz\b", r"\bwireless\s+forensic\w*\b"
        ],
        "mandatory_concepts": [
            "radio", "rf", "sdr", "signal", "spectrum", "demodulat", "iq", "emf", "tempest",
            "frequency", "spectrogram", "ism", "baseband", "telemetry", "transceiver", "rtl-sdr",
            "hackrf", "gnuradio", "urh", "inspectrum", "gqrx", "sdrangel", "satellite"
        ],
        "reject_if_missing_mandatory": True,
        "disqualify_penalty": 0.0,  # Completely eliminate irrelevant tools that lack RF affinity
        "primary_tools": [
            "urh", "universal radio hacker", "inspectrum", "tempestsdr", "sigdigger", "sdrangel",
            "gnuradio", "gqrx", "rtl_433", "gr-gsm", "proxmark3", "dump1090", "satnogs", "satnogs-decoders",
            "gr-satellites", "fosphor", "redsea", "dsdcc", "kalibrate-rtl", "killerbee", "hackrf"
        ],
        "expanded_keywords": [
            "sdr", "software defined radio", "demodulation", "iq captures", "fsk", "ask", "psk",
            "spectrogram", "waterfall", "tempest", "electromagnetic", "leakage", "eavesdropping",
            "rf reverse engineering", "wireless protocol", "ism band", "radio frequency"
        ]
    },
    "ACTIVE_DIRECTORY_CREDENTIALS": {
        "title": "Active Directory, Kerberos & Credential Extraction",
        "description": "NTDS.dit dumping, LSASS extraction, Kerberoasting, AS-REP roasting, AD CS certificate escalation, Pass-the-Hash.",
        "trigger_patterns": [
            r"\bntds\b", r"\blsass\b", r"\bkerberoast\w*\b", r"\bas[-_]?rep\b", r"\badcs\b",
            r"\bpass[-_]?the[-_]?hash\b", r"\bpth\b", r"\bactive\s+directory\b", r"\bdomain\s+controller\b",
            r"\bshadowcopy\b", r"\bsecretsdump\b", r"\bgpp\s+password\b"
        ],
        "mandatory_concepts": [
            "active directory", "ntds", "lsass", "kerberos", "ad cs", "certificate", "ticket",
            "impacket", "secretsdump", "mimikatz", "rubeus", "certipy", "bloodhound"
        ],
        "reject_if_missing_mandatory": False,
        "disqualify_penalty": 0.1,
        "primary_tools": [
            "impacket", "secretsdump", "certipy", "certify", "rubeus", "mimikatz", "bloodhound",
            "netexec", "crackmapexec", "nanodump", "lsassy", "pypykatz", "procdump"
        ],
        "expanded_keywords": [
            "active directory", "domain controller", "ntds.dit", "lsass.exe", "tgs", "spn",
            "esc1", "pkinit", "golden ticket", "silver ticket", "pass the hash", "ntlm"
        ]
    },
    "MALWARE_DFIR": {
        "title": "Malware Analysis, Reverse Engineering & DFIR",
        "description": "Static & dynamic executable analysis, sandboxing, decompiler analysis, memory forensics, triage.",
        "trigger_patterns": [
            r"\bmalware\b", r"\bsandbox\b", r"\byara\b", r"\bdecompile\w*\b", r"\bdisassembl\w*\b",
            r"\bghidra\b", r"\bfloss\b", r"\breverse\s+engineering\b", r"\bmemory\s+forensic\w*\b",
            r"\bvolatility\b", r"\bpe[-_]?sieve\b", r"\bunpack\w*\b"
        ],
        "mandatory_concepts": [
            "malware", "reverse", "ghidra", "yara", "disassembler", "decompiler", "volatility",
            "memory", "sandbox", "cape", "remnux", "artifact", "forensic", "binary"
        ],
        "reject_if_missing_mandatory": False,
        "disqualify_penalty": 0.2,
        "primary_tools": [
            "remnux", "cape sandbox", "ghidra", "yara", "yara-x", "capa", "floss", "volatility",
            "volatility3", "radare2", "x64dbg", "pe-sieve", "malwarebazaar", "cutter", "memprocfs"
        ],
        "expanded_keywords": [
            "malware analysis", "dynamic analysis", "static analysis", "reverse engineering",
            "disassembly", "decompilation", "memory forensics", "ram dump", "process injection"
        ]
    },
    "AUTOMOTIVE_CANBUS": {
        "title": "Automotive Security, CAN Bus & ECU Reverse Engineering",
        "description": "Controller Area Network (CAN), OBD-II diagnostic sniffing, ECU firmware extraction, UDS protocol analysis.",
        "trigger_patterns": [
            r"\bcanbus\b", r"\bcan[-_]?bus\b", r"\bobd[-_]?ii?\b", r"\becu\b", r"\bautomotive\b",
            r"\bcar\s+hack\w*\b", r"\buds\b", r"\bsavvycan\b"
        ],
        "mandatory_concepts": [
            "can", "canbus", "obd", "ecu", "automotive", "vehicle", "car", "uds", "savvycan"
        ],
        "reject_if_missing_mandatory": True,
        "disqualify_penalty": 0.0,
        "primary_tools": [
            "can-utils", "savvycan", "caringcaribou", "scapy-can", "candump", "cansniffer", "socketcand"
        ],
        "expanded_keywords": [
            "controller area network", "can bus", "obd-ii", "electronic control unit",
            "vehicle forensics", "automotive reverse engineering"
        ]
    },
    "CLOUD_CONTAINER_SECURITY": {
        "title": "Cloud Infrastructure, Container Breakout & Kubernetes",
        "description": "AWS, Azure, GCP audit, S3 bucket enumeration, Docker container escape, Kubernetes escalation.",
        "trigger_patterns": [
            r"\baws\b", r"\bazure\b", r"\bgcp\b", r"\bdocker\b", r"\bkubernetes\b", r"\bk8s\b",
            r"\bcontainer\s+breakout\b", r"\bs3\s+bucket\b", r"\bcloud\s+audit\b"
        ],
        "mandatory_concepts": [
            "cloud", "aws", "azure", "gcp", "docker", "kubernetes", "k8s", "container", "s3", "iam"
        ],
        "reject_if_missing_mandatory": False,
        "disqualify_penalty": 0.2,
        "primary_tools": [
            "scoutsuite", "prowler", "pacu", "cloudmapper", "cdk", "deepce", "roadtools", "peass-ng"
        ],
        "expanded_keywords": [
            "cloud audit", "container breakout", "docker escape", "privilege container", "s3 leak"
        ]
    },
    "WEB_API_GRAPHQL": {
        "title": "Web Application, API & GraphQL Exploitation",
        "description": "GraphQL introspection & injection, API pentesting, SSRF, SQLi, IDOR, JWT tampering, Web App Security.",
        "trigger_patterns": [
            r"\bgraphql\b", r"\bapi\s+pentest\w*\b", r"\bssrf\b", r"\bsqli?\b", r"\bjwt\b",
            r"\bxss\b", r"\bburp\b", r"\bweb\s+exploit\w*\b", r"\bidor\b", r"\brest\s+api\b"
        ],
        "mandatory_concepts": [
            "web", "http", "api", "graphql", "sql", "injection", "xss", "ssrf", "jwt", "rest", "fuzz"
        ],
        "reject_if_missing_mandatory": False,
        "disqualify_penalty": 0.2,
        "primary_tools": [
            "sqlmap", "caido", "zap", "ffuf", "inql", "graphql-cop", "jwt-tool", "nikto", "commix", "wafw00f", "katana", "nuclei"
        ],
        "expanded_keywords": [
            "graphql introspection", "api security", "ssrf vulnerability", "sql injection", "jwt crack", "web crawler"
        ]
    },
    "PIVOT_TUNNELING_C2": {
        "title": "Network Pivoting, Tunneling & Command and Control (C2)",
        "description": "SOCKS5 proxy chaining, TUN/TAP interface tunneling, reverse proxies, post-exploitation red team implants & beacons.",
        "trigger_patterns": [
            r"\bpivot\w*\b", r"\btunnel\w*\b", r"\bsocks5?\b", r"\bchisel\b", r"\bligolo\b",
            r"\bc2\b", r"\bcommand\s+and\s+control\b", r"\bbeacon\b", r"\bport\s+forward\w*\b"
        ],
        "mandatory_concepts": [
            "pivot", "tunnel", "socks", "proxy", "c2", "beacon", "implant", "forward", "ligolo", "chisel", "sliver", "havoc"
        ],
        "reject_if_missing_mandatory": False,
        "disqualify_penalty": 0.2,
        "primary_tools": [
            "ligolo-ng", "chisel", "proxychains", "rpivot", "gost", "havoc", "sliver", "mythic", "caldera", "covenant", "dnscat2"
        ],
        "expanded_keywords": [
            "network pivot", "socks5 proxy", "reverse socks", "traffic tunneling", "command and control beacon", "red team implant"
        ]
    },
    "DEFENSE_EVASION_EDR": {
        "title": "Defense Evasion, EDR Unhooking & AMSI Bypass",
        "description": "Direct system calls, runtime memory patching, DLL unhooking, AV evasion, and binary payload obfuscation.",
        "trigger_patterns": [
            r"\bedr\b", r"\bamsi\b", r"\bunhook\w*\b", r"\bsyscall\w*\b", r"\bevasion\b",
            r"\bobfuscat\w*\b", r"\bav\s+bypass\b", r"\bdefender\s+bypass\b"
        ],
        "mandatory_concepts": [
            "edr", "amsi", "evasion", "bypass", "unhook", "syscall", "obfuscation", "patch", "payload", "injection"
        ],
        "reject_if_missing_mandatory": False,
        "disqualify_penalty": 0.2,
        "primary_tools": [
            "scarecrow", "donut", "chameleon", "invoke-obfuscation", "amsitragger", "tartarus", "pe-sieve", "havoc"
        ],
        "expanded_keywords": [
            "amsi bypass", "edr evasion", "direct syscalls", "dll unhooking", "payload obfuscation", "process hollowing"
        ]
    },
    "WIRELESS_BLUETOOTH_NFC": {
        "title": "Wireless 802.11, Bluetooth (BLE) & NFC/RFID Hacking",
        "description": "Clientless PMKID capture, WPA2/WPA3 handshake cracking, Bluetooth Low Energy packet inspection, RFID/NFC clone & replay.",
        "trigger_patterns": [
            r"\bwifi\b", r"\bpmkid\b", r"\bwpa[23]?\b", r"\bbluetooth\b", r"\bble\b",
            r"\bnfc\b", r"\brfid\b", r"\bproxmark\b", r"\b802\.11\b"
        ],
        "mandatory_concepts": [
            "wifi", "wireless", "pmkid", "wpa", "bluetooth", "ble", "nfc", "rfid", "802.11", "aircrack", "proxmark"
        ],
        "reject_if_missing_mandatory": True,
        "disqualify_penalty": 0.0,
        "primary_tools": [
            "hcxdumptool", "hcxtools", "aircrack-ng", "wifite", "bettercap", "proxmark3", "crackle", "ubertooth", "killerbee"
        ],
        "expanded_keywords": [
            "pmkid capture", "wpa2 handshake", "wireless audit", "ble packet sniffer", "nfc clone", "rfid replay"
        ]
    },
    "OSINT_RECON_SUBDOMAIN": {
        "title": "OSINT, Attack Surface Management & Reconnaissance",
        "description": "Passive subdomain enumeration, open source intelligence, asset mapping, certificate transparency, threat intelligence.",
        "trigger_patterns": [
            r"\bosint\b", r"\bsubdomain\b", r"\brecon\b", r"\basset\s+discovery\b",
            r"\btheharvester\b", r"\bamass\b", r"\bspiderfoot\b", r"\bwhois\b"
        ],
        "mandatory_concepts": [
            "osint", "recon", "subdomain", "discovery", "enumerate", "intelligence", "dns", "whois", "shodan"
        ],
        "reject_if_missing_mandatory": False,
        "disqualify_penalty": 0.2,
        "primary_tools": [
            "amass", "subfinder", "theharvester", "spiderfoot", "sherlock", "holehe", "recon-ng", "naabu", "nuclei", "assetfinder"
        ],
        "expanded_keywords": [
            "subdomain enumeration", "attack surface", "open source intelligence", "reconnaissance", "threat intel"
        ]
    },
    "FIRMWARE_HARDWARE_IOT": {
        "title": "IoT Firmware Extraction & Hardware Hacking",
        "description": "Firmware binary unpacking, JTAG/UART serial debugging, SPI flash dumping, embedded Linux architecture reverse engineering.",
        "trigger_patterns": [
            r"\bfirmware\b", r"\bbinwalk\b", r"\bjtag\b", r"\buart\b", r"\biot\b",
            r"\bembedded\b", r"\bhardware\s+hack\w*\b", r"\bflashrom\b"
        ],
        "mandatory_concepts": [
            "firmware", "binwalk", "jtag", "uart", "iot", "embedded", "flash", "hardware", "rom", "spi"
        ],
        "reject_if_missing_mandatory": True,
        "disqualify_penalty": 0.0,
        "primary_tools": [
            "binwalk", "firmwalker", "firmadyne", "ghidra", "radare2", "flashrom", "openocd", "routersploit"
        ],
        "expanded_keywords": [
            "firmware extraction", "binwalk squashfs", "jtag pinout", "uart root shell", "iot security", "embedded linux"
        ]
    },
    "PRIVILEGE_ESCALATION": {
        "title": "Local Privilege Escalation & Audit (Linux & Windows)",
        "description": "Sudo misconfiguration abuse, Windows Token / UAC impersonation, kernel privilege escalation, automated audit.",
        "trigger_patterns": [
            r"\bprivesc\b", r"\bprivilege\s+escalation\b", r"\blinpeas\b", r"\bwinpeas\b",
            r"\buac\s+bypass\b", r"\btoken\s+impersonation\b", r"\bgtfobins\b"
        ],
        "mandatory_concepts": [
            "privesc", "privilege", "escalation", "root", "peas", "sudo", "uac", "impersonat", "token", "exploit"
        ],
        "reject_if_missing_mandatory": False,
        "disqualify_penalty": 0.1,
        "primary_tools": [
            "peass-ng", "linpeas", "winpeas", "beRoot", "juicypotato", "sweetpotato", "godpotato", "gtfobins"
        ],
        "expanded_keywords": [
            "privilege escalation", "sudo abuse", "uac bypass", "token impersonation", "kernel exploit", "suid binaries"
        ]
    }
}

# ----------------------------------------------------
# 2. PERSISTENT INTEL STORE CLASS
# ----------------------------------------------------

class PersistentSearchIntelligence:
    """Thread-safe persistent knowledge base that logs queries, extracts intents,
    and continuously upgrades the search engine with every user query."""
    
    def __init__(self, json_path: str = LEARNED_INTEL_PATH):
        self.json_path = json_path
        self.memory: Dict[str, Any] = self._load_memory()

    def _load_memory(self) -> Dict[str, Any]:
        if os.path.exists(self.json_path):
            try:
                with open(self.json_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                print(f"[!] Error loading learned intelligence: {e}")
        return {
            "version": "1.0.0",
            "total_queries_learned": 0,
            "intents": {}
        }

    def save_memory(self):
        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(self.memory, f, indent=2)
        except Exception as e:
            print(f"[!] Error persisting learned intelligence: {e}")

    def analyze_query_intent(self, q: str) -> Dict[str, Any]:
        """Deep semantic analysis to extract the operational domain, concepts, and requirements."""
        clean_q = q.lower().strip()
        tokens = [w for w in re.findall(r'[a-zA-Z0-9_-]+', clean_q) if len(w) > 1]
        
        detected_domain = None
        domain_data = None

        # Check semantic domain triggers
        for d_key, d_info in SEMANTIC_DOMAINS.items():
            for pat in d_info["trigger_patterns"]:
                if re.search(pat, clean_q):
                    detected_domain = d_key
                    domain_data = d_info
                    break
            if detected_domain:
                break

        # Check if already learned in memory
        learned_entry = self.memory.get("intents", {}).get(clean_q)
        if learned_entry:
            learned_entry["query_count"] = learned_entry.get("query_count", 0) + 1
            learned_entry["last_accessed"] = datetime.datetime.now().isoformat()
            self.save_memory()
            return learned_entry

        # Build fresh semantic intent record
        if detected_domain and domain_data:
            intent_record = {
                "query": q,
                "canonical_intent": domain_data["title"],
                "domain": detected_domain,
                "description": domain_data["description"],
                "mandatory_concepts": domain_data["mandatory_concepts"],
                "reject_if_missing_mandatory": domain_data["reject_if_missing_mandatory"],
                "disqualify_penalty": domain_data["disqualify_penalty"],
                "primary_tools": domain_data["primary_tools"],
                "expanded_terms": list(set(tokens + domain_data["expanded_keywords"])),
                "query_count": 1,
                "learned_at": datetime.datetime.now().isoformat(),
                "last_accessed": datetime.datetime.now().isoformat()
            }
        else:
            # Generic semantic intent
            intent_record = {
                "query": q,
                "canonical_intent": f"General Cybersecurity: {q.title()}",
                "domain": "GENERAL",
                "description": f"Targeted discovery for operational tool: {q}",
                "mandatory_concepts": tokens,
                "reject_if_missing_mandatory": False,
                "disqualify_penalty": 1.0,
                "primary_tools": [],
                "expanded_terms": tokens,
                "query_count": 1,
                "learned_at": datetime.datetime.now().isoformat(),
                "last_accessed": datetime.datetime.now().isoformat()
            }

        # Store in persistent memory (only index complete meaningful queries, ignore single/double char keystrokes)
        if len(clean_q) >= 3 and not clean_q.startswith('"'):
            self.memory.setdefault("intents", {})[clean_q] = intent_record
            self.memory["total_queries_learned"] = len(self.memory["intents"])
            self.save_memory()

        return intent_record

    def record_tool_interaction(self, query: str, tool_id: str, tool_name: str):
        """Learn and boost tool associations based on user operational clicks & bookmarks."""
        clean_q = query.lower().strip()
        if len(clean_q) < 3:
            return
        entry = self.memory.get("intents", {}).get(clean_q)
        if not entry:
            entry = self.analyze_query_intent(query)
        if entry:
            pts = entry.setdefault("primary_tools", [])
            t_name_lower = tool_name.lower()
            if t_name_lower not in pts:
                pts.insert(0, t_name_lower)
            entry["last_interaction"] = {
                "tool_id": tool_id,
                "tool_name": tool_name,
                "timestamp": datetime.datetime.now().isoformat()
            }
            self.save_memory()

    def cleanup_noise(self):
        """Purge partial keystroke noise shorter than 3 characters from learned memory."""
        if "intents" in self.memory:
            cleaned = {k: v for k, v in self.memory["intents"].items() if len(k) >= 3 and not k.startswith('"')}
            self.memory["intents"] = cleaned
            self.memory["total_queries_learned"] = len(cleaned)
            self.save_memory()

    def evaluate_tool_relevance(self, tool: Dict[str, Any], intent: Dict[str, Any], tokens: List[str]) -> Tuple[float, str]:
        """Compute semantic relevance score and determine if the tool satisfies the domain purpose."""
        name = (tool.get("name") or "").lower()
        tagline = (tool.get("tagline") or "").lower()
        purpose = (tool.get("purpose_summary") or "").lower()
        category = (tool.get("category") or "").lower()
        repo_url = (tool.get("repo_url") or "").lower()
        full_text = f"{name} {tagline} {purpose} {category} {repo_url}"

        domain = intent.get("domain", "GENERAL")
        primary_tools = intent.get("primary_tools", [])
        mandatory_concepts = intent.get("mandatory_concepts", [])
        reject_if_missing = intent.get("reject_if_missing_mandatory", False)
        disqualify_penalty = intent.get("disqualify_penalty", 1.0)

        # 1. Check Mandatory Domain Qualifier with boundary precision
        has_domain_affinity = False
        if mandatory_concepts:
            for mc in mandatory_concepts:
                if len(mc) <= 3:
                    if re.search(r'\b' + re.escape(mc) + r'\b', full_text):
                        has_domain_affinity = True
                        break
                else:
                    if mc in full_text:
                        has_domain_affinity = True
                        break

        # If a domain requires mandatory concept presence and tool has NONE, disqualify!
        if reject_if_missing and not has_domain_affinity:
            # Disqualify completely (prevents "Forensic Resistant Tor Browser" on radio forensic queries)
            return (0.0, "DISQUALIFIED_NO_DOMAIN_AFFINITY")

        score = 0.0

        # 2. Check if this is a recognized primary tool for this intent
        is_primary = False
        for pt in primary_tools:
            pt_clean = pt.lower()
            if pt_clean == name or f"/{pt_clean}" in repo_url or f"/{pt_clean}." in repo_url:
                score += 8000.0
                is_primary = True
                break
            elif pt_clean in name:
                score += 4000.0
                is_primary = True
                break

        # 3. Exact query matching
        clean_q = intent.get("query", "").lower().strip()
        if clean_q in name:
            score += 3500.0
        elif clean_q in purpose:
            score += 1500.0

        # 4. Multi-token match
        matched_tokens = sum(1 for t in tokens if t in full_text)
        if len(tokens) > 1 and matched_tokens == len(tokens):
            score += 1200.0
        elif matched_tokens > 0:
            score += matched_tokens * 200.0

        # 5. Expanded concepts & keywords
        for term in intent.get("expanded_terms", []):
            if len(term) > 3 and term in full_text:
                score += 45.0

        # 6. Quality & Stars traction
        stars = tool.get("stars") or 0
        if stars > 0:
            score += min(stars / 40.0, 300.0)
        if tool.get("rarity") == "popular":
            score += 50.0

        # 7. Apply disqualification penalty if lack domain affinity
        if not has_domain_affinity and disqualify_penalty < 1.0:
            score *= disqualify_penalty

        return (score, "VALID_MATCH" if score > 0 else "ZERO_SCORE")

    def score_tool_similarity(self, tool: Dict[str, Any], target_name: str) -> Tuple[float, str]:
        """
        Evaluate tool similarity and discover peer alternatives for a direct tool search query.
        Returns (score, similarity_type).
        """
        if not target_name:
            return (0.0, "NONE")

        target = target_name.lower().strip()
        name = (tool.get("name") or "").lower().strip()
        repo_url = (tool.get("repo_url") or "").lower().strip()
        category = (tool.get("category") or "").lower().strip()
        purpose = (tool.get("purpose_summary") or "").lower().strip()
        full_text = f"{name} {tool.get('tagline', '').lower()} {purpose} {category} {repo_url}"

        # 1. Exact Name Match
        if name == target or repo_url.endswith("/" + target) or f"/{target}." in repo_url:
            return (18000.0, "EXACT_MATCH")

        # 2. Derivative / Ecosystem tool (e.g. nmap-formatter, impacket-scripts)
        if name.startswith(target + "-") or name.startswith(target + "_") or name.endswith("-" + target):
            return (10000.0, "DERIVATIVE")

        # 3. Known Curated Alternatives
        curated_alts = CYBER_TOOL_ALTERNATIVES.get(target, [])
        for alt in curated_alts:
            alt_clean = alt.lower()
            if name == alt_clean or repo_url.endswith("/" + alt_clean) or f"/{alt_clean}." in repo_url:
                return (8500.0, "CURATED_ALTERNATIVE")
            elif alt_clean in name:
                return (6000.0, "SIMILAR_ALTERNATIVE")

        # Check reverse curated alternatives (e.g. target is 'masscan', matches 'nmap')
        for prime, alts in CYBER_TOOL_ALTERNATIVES.items():
            if prime == name and target in alts:
                return (8500.0, "CURATED_ALTERNATIVE")

        # 4. Direct Substring in tool name
        if target in name:
            return (5000.0, "NAME_SUBSTRING")

        # 5. Direct Substring in repository URL
        if f"/{target}" in repo_url:
            return (4000.0, "REPO_MATCH")

        # 6. Mentioned in purpose / capabilities (e.g. wrapper or GUI for that tool)
        if re.search(r'\b' + re.escape(target) + r'\b', full_text):
            return (2200.0, "CAPABILITY_PEER")

        return (0.0, "NOT_SIMILAR")

# ----------------------------------------------------
# 2. CURATED CYBERSECURITY ALTERNATIVES RADAR MATRIX
# ----------------------------------------------------

CYBER_TOOL_ALTERNATIVES: Dict[str, List[str]] = {
    # Network Scanning & Host Discovery
    "nmap": ["masscan", "rustscan", "naabu", "zmap", "unicornscan", "zenmap"],
    "masscan": ["nmap", "rustscan", "naabu", "zmap"],
    "rustscan": ["nmap", "masscan", "naabu"],
    "naabu": ["nmap", "rustscan", "masscan"],
    "zmap": ["masscan", "nmap", "rustscan"],
    
    # Web Application & SQL Injection
    "sqlmap": ["ghauri", "nosqlmap", "commix", "drupwn", "bbqsql", "sqlninja"],
    "ghauri": ["sqlmap", "nosqlmap", "commix"],
    "commix": ["sqlmap", "ghauri", "tplmap"],
    "burpsuite": ["zaproxy", "caido", "mitmproxy", "owasp zap"],
    "burp": ["zaproxy", "caido", "mitmproxy", "owasp zap"],
    "zaproxy": ["burpsuite", "caido", "mitmproxy"],
    "zap": ["burpsuite", "caido", "mitmproxy"],
    "caido": ["burpsuite", "zaproxy", "mitmproxy"],
    "nikto": ["nuclei", "wapiti", "arachni", "whatweb"],
    "nuclei": ["nikto", "jaeles", "snallygaster"],
    "ffuf": ["feroxbuster", "gobuster", "dirsearch", "wfuzz", "dirb"],
    "gobuster": ["ffuf", "feroxbuster", "dirsearch", "wfuzz"],
    "feroxbuster": ["ffuf", "gobuster", "dirsearch"],
    "dirsearch": ["ffuf", "gobuster", "feroxbuster"],
    "sublist3r": ["subfinder", "amass", "findomain", "assetfinder"],
    "subfinder": ["amass", "sublist3r", "findomain", "assetfinder"],
    "amass": ["subfinder", "sublist3r", "findomain", "recon-ng"],
    
    # Active Directory & Windows Credentials
    "mimikatz": ["pypykatz", "sharpkatz", "lsassy", "nanodump", "safetykatz", "procdump", "mimikittenz"],
    "pypykatz": ["mimikatz", "sharpkatz", "lsassy", "nanodump"],
    "lsassy": ["mimikatz", "pypykatz", "nanodump", "procdump"],
    "nanodump": ["mimikatz", "procdump", "lsassy", "minidump"],
    "bloodhound": ["sharphound", "bloodhound.py", "adalanche", "plumhound", "azurehound"],
    "sharphound": ["bloodhound", "adalanche", "azurehound"],
    "rubeus": ["kerbrute", "impacket", "kekeo"],
    "certipy": ["certify", "adcsfinder"],
    "certify": ["certipy", "adcsfinder"],
    "impacket": ["netexec", "crackmapexec", "responder"],
    "crackmapexec": ["netexec", "impacket"],
    "cme": ["netexec", "impacket"],
    "netexec": ["crackmapexec", "impacket"],
    "nxc": ["crackmapexec", "impacket"],
    "responder": ["inveigh", "mitm6", "pre2k"],
    "inveigh": ["responder", "mitm6"],
    
    # RF, SDR & EMF Signal Forensics
    "urh": ["inspectrum", "sigdigger", "tempestsdr", "gnuradio", "gqrx", "sdrangel", "rtl_433"],
    "universal radio hacker": ["urh", "inspectrum", "sigdigger", "tempestsdr", "gnuradio", "gqrx"],
    "inspectrum": ["urh", "sigdigger", "gnuradio", "tempestsdr"],
    "sigdigger": ["urh", "inspectrum", "gqrx", "sdrangel"],
    "tempestsdr": ["urh", "sigdigger", "inspectrum", "gnuradio"],
    "gqrx": ["sdrangel", "urh", "gnuradio", "cubicsdr"],
    "gnuradio": ["urh", "gqrx", "sdrangel", "inspectrum"],
    "rtl_433": ["urh", "inspectrum", "sigdigger", "dump1090"],
    "gr-satellites": ["satnogs-decoders", "satnogs-client", "gnuradio"],
    "satnogs": ["gr-satellites", "satnogs-decoders", "gnuradio", "gqrx"],
    "proxmark3": ["chameleonultra", "nfc-tools", "mfcuk", "mfoc"],
    
    # Malware Analysis & Reverse Engineering
    "ghidra": ["cutter", "radare2", "x64dbg", "angr", "ida", "binaryninja"],
    "radare2": ["cutter", "ghidra", "x64dbg", "angr"],
    "r2": ["cutter", "ghidra", "x64dbg", "angr"],
    "cutter": ["ghidra", "radare2", "x64dbg"],
    "x64dbg": ["ghidra", "cutter", "radare2"],
    "yara": ["capa", "floss", "pe-sieve"],
    "capa": ["yara", "floss", "pe-sieve"],
    "floss": ["capa", "pe-sieve"],
    "volatility": ["rekall", "memprocfs", "dwarf2json", "lime"],
    "volatility3": ["volatility", "rekall", "memprocfs"],
    "memprocfs": ["volatility", "volatility3", "rekall"],
    "remnux": ["cape sandbox", "ghidra", "floss"],
    "cape": ["remnux", "drakvuf"],
    
    # Password Cracking
    "hashcat": ["john", "john the ripper", "ophcrack", "crowbar"],
    "john": ["hashcat", "ophcrack", "crowbar"],
    "john the ripper": ["hashcat", "ophcrack", "crowbar"],
    "hydra": ["medusa", "patator", "crowbar", "ncrack"],
    "medusa": ["hydra", "patator", "ncrack"],
    
    # Wireless (Wi-Fi)
    "aircrack-ng": ["wifite", "hcxdumptool", "bettercap", "eaphammer"],
    "wifite": ["aircrack-ng", "hcxdumptool", "bettercap"],
    "hcxdumptool": ["hcxtools", "wifite", "aircrack-ng"],
    
    # Traffic & Sniffing
    "wireshark": ["tshark", "tcpdump", "termshark", "zeek", "suricata"],
    "tcpdump": ["tshark", "wireshark", "termshark"],
    "tshark": ["wireshark", "tcpdump"],
    "zeek": ["suricata", "snort", "wireshark"],
    "suricata": ["snort", "zeek", "wazuh"],
    "snort": ["suricata", "zeek"],
    
    # Secret Scanning
    "trufflehog": ["gitleaks", "git-hound", "shhgit", "detect-secrets"],
    "gitleaks": ["trufflehog", "git-hound", "detect-secrets"],
    
    # Defensive & SIEM
    "wazuh": ["osquery", "velociraptor", "security onion", "thehive"],
    "osquery": ["wazuh", "velociraptor", "kolide"],
    "velociraptor": ["wazuh", "osquery", "grr"],
    "thehive": ["misp", "cortex", "wazuh"]
}

# Global Singleton Engine
semantic_engine = PersistentSearchIntelligence()
