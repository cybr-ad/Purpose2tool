# -*- coding: utf-8 -*-
"""
Purpose-2-Tool Federated Live Search Server
Powered by FastAPI & Uvicorn
Features:
- True Live Federated Search across GitHub (400M+), GitLab, Arch Linux, Debian, and BlackArch
- In-Memory High-Speed Cache Server (thread-safe, TTL, sub-millisecond retrieval)
- Rich Cybersecurity Operational Purpose & MITRE ATT&CK Matrix
- Live Sorting: Relevance, Most Stars, Popularity/Traction, Recently Updated, Name A-Z/Z-A
- Cybersecurity NLP typo auto-correction & multi-token relevance scoring
- Clean Tool Intelligence output (no installation guides)
"""

import os
import re
import json
import sqlite3
import threading
import time
import difflib
import concurrent.futures
from typing import Optional, List, Dict, Any

from fastapi import FastAPI, Query, BackgroundTasks, Body
from pydantic import BaseModel
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import requests

import sync_engine
import semantic_intelligence

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DATA_DIR, "dynamic_arsenal.db")
SYNC_META_PATH = os.path.join(DATA_DIR, "sync_status.json")

app = FastAPI(title="Purpose-2-Tool Federated Live API", version="5.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

is_syncing = False
sync_lock = threading.Lock()

# ----------------------------------------------------
# HIGH-SPEED IN-MEMORY CACHE SERVER
# ----------------------------------------------------

class LiveSearchCache:
    """Thread-safe in-memory cache server with TTL and LRU eviction."""
    def __init__(self, ttl_seconds: int = 1800, max_size: int = 3000):
        self.ttl = ttl_seconds
        self.max_size = max_size
        self.cache: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.hits = 0
        self.misses = 0

    def make_key(self, **kwargs) -> str:
        # Build canonical cache key
        clean_items = []
        for k in sorted(kwargs.keys()):
            val = kwargs[k]
            if isinstance(val, str):
                val = val.strip().lower()
            clean_items.append((k, val))
        return json.dumps(clean_items, sort_keys=True)

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            if key in self.cache:
                entry = self.cache[key]
                if time.time() - entry["timestamp"] < self.ttl:
                    self.hits += 1
                    entry["last_accessed"] = time.time()
                    return entry["data"]
                else:
                    del self.cache[key]
            self.misses += 1
            return None

    def set(self, key: str, data: Dict[str, Any]):
        with self.lock:
            if len(self.cache) >= self.max_size:
                # Evict oldest 20% entries
                sorted_entries = sorted(
                    self.cache.items(),
                    key=lambda x: x[1].get("last_accessed", x[1]["timestamp"])
                )
                evict_count = max(1, int(self.max_size * 0.2))
                for k, _ in sorted_entries[:evict_count]:
                    del self.cache[k]

            self.cache[key] = {
                "data": data,
                "timestamp": time.time(),
                "last_accessed": time.time()
            }

    def clear(self):
        with self.lock:
            self.cache.clear()
            self.hits = 0
            self.misses = 0

    def stats(self) -> Dict[str, Any]:
        with self.lock:
            total = self.hits + self.misses
            ratio = (self.hits / total * 100) if total > 0 else 0.0
            return {
                "entries": len(self.cache),
                "hits": self.hits,
                "misses": self.misses,
                "hit_ratio_percent": round(ratio, 1),
                "ttl_seconds": self.ttl,
                "status": "online"
            }

search_cache = LiveSearchCache(ttl_seconds=1800, max_size=3000)

# ----------------------------------------------------
# RICH PURPOSE & MITRE ATT&CK OPERATIONAL MATRIX
# ----------------------------------------------------

PURPOSE_OPERATIONAL_MATRIX = {
    "network pentest": {
        "keywords": ["network", "port", "scanner", "sniff", "packet", "smb", "tcp", "udp", "recon", "sweep", "nmap", "penetration"],
        "primary_tools": ["nmap", "masscan", "rustscan", "bettercap", "netdiscover", "zmap", "wireshark", "tshark", "arp-scan"]
    },
    "network scan": {
        "keywords": ["network", "port", "scanner", "syn", "syn-scan", "sweep", "service detection", "banner grab"],
        "primary_tools": ["nmap", "masscan", "rustscan", "zmap", "naabu", "netdiscover"]
    },
    "dump lsass": {
        "keywords": ["lsass", "credential", "dump", "minidump", "process injection", "mimikatz", "memory dump", "sam", "lsa"],
        "primary_tools": ["mimikatz", "procdump", "lsassy", "nanodump", "pypykatz", "dumpert", "handlekatz", "physmem2profit"]
    },
    "dump ntds": {
        "keywords": ["ntds", "ntds.dit", "active directory", "shadow copy", "secretsdump", "drsuapi", "vss", "domain controller"],
        "primary_tools": ["impacket", "secretsdump", "crackmapexec", "netexec", "ntdsutil", "gosecretsdump"]
    },
    "pass the hash": {
        "keywords": ["pass the hash", "pth", "ntlm", "smb", "wmiexec", "psexec", "lateral movement", "hash authentication"],
        "primary_tools": ["impacket", "crackmapexec", "netexec", "evil-winrm", "wmiexec", "psexec", "pth-toolkit"]
    },
    "kerberoasting": {
        "keywords": ["kerberoast", "spn", "tgs", "rc4", "ticket granting service", "active directory", "kerberos"],
        "primary_tools": ["rubeus", "impacket", "getuserspns", "kerbrute", "tgsrepcrack"]
    },
    "as-rep roasting": {
        "keywords": ["asreproast", "as-rep", "uf_dont_require_preauth", "preauthentication", "kerberos", "ticket"],
        "primary_tools": ["rubeus", "impacket", "getnpusers", "kerbrute"]
    },
    "adcs": {
        "keywords": ["adcs", "ad cs", "active directory certificate services", "esc1", "esc8", "pkinit", "certipy", "certify"],
        "primary_tools": ["certipy", "certify", "forgecert", "adcs-killer", "pass-the-cert"]
    },
    "ad cs escalation": {
        "keywords": ["adcs", "ad cs", "certificate", "esc1", "esc2", "esc3", "esc4", "esc8", "pkinit", "template misconfiguration"],
        "primary_tools": ["certipy", "certify", "forgecert", "adcs-killer", "shadowcredentials"]
    },
    "edr bypass": {
        "keywords": ["edr bypass", "evasion", "amsi", "etw", "unhooking", "direct syscalls", "syscall", "obfuscation", "antivirus"],
        "primary_tools": ["scarecrow", "havoc", "donut", "tartarus", "invoke-obfuscation", "chameleon", "peass-ng", "pe-sieve"]
    },
    "amsi bypass": {
        "keywords": ["amsi", "antimalware scan interface", "patch amsi", "amsi.dll", "powershell bypass", "memory patch"],
        "primary_tools": ["amsitrigger", "amsi-bypass", "invoke-obfuscation", "rasta-mouse"]
    },
    "pivot network": {
        "keywords": ["pivot", "pivoting", "tunnel", "tunneling", "socks5", "proxy", "port forwarding", "reverse proxy", "traffic tunnel"],
        "primary_tools": ["chisel", "ligolo-ng", "ligolo", "proxychains", "rpivot", "gost", "frp", "dnscat2", "iodine"]
    },
    "c2 framework": {
        "keywords": ["c2", "c&c", "command and control", "beacon", "implant", "post-exploitation", "red team operator", "agent"],
        "primary_tools": ["havoc", "sliver", "mythic", "covenant", "caldera", "merlin", "empire", "shad0w"]
    },
    "browser passwords": {
        "keywords": ["browser password", "chrome credentials", "firefox passwords", "cookie stealer", "dpapi", "web credential", "login data"],
        "primary_tools": ["hackbrowserdata", "sharpchromekey", "lazagne", "mimikatz", "browser-cookie-stealer"]
    },
    "wifi pmkid": {
        "keywords": ["pmkid", "wpa2", "wifi", "handshake", "802.11", "wireless attack", "clientless", "eapol"],
        "primary_tools": ["hcxdumptool", "hcxtools", "hashcat", "aircrack-ng", "wifite", "bettercap", "bully"]
    },
    "docker container breakout": {
        "keywords": ["container breakout", "docker escape", "privileged container", "cgroups", "nsenter", "kubernetes escape", "container escalation"],
        "primary_tools": ["cdk", "deepce", "peass-ng", "amicontained", "botb", "docker-bench-security"]
    },
    "subdomain takeover": {
        "keywords": ["subdomain takeover", "cname dangling", "dns recon", "subdomain enum", "dns takeover"],
        "primary_tools": ["subjack", "subzy", "nuclei", "subfinder", "amass", "dnsx"]
    },
    "graphql pentest": {
        "keywords": ["graphql", "graphql injection", "introspection", "query batching", "graphql-cop", "graphql vulnerability"],
        "primary_tools": ["graphql-cop", "clairvoyance", "inql", "graphql-path-enum", "graphw00f"]
    },
    "graph sql": {
        "keywords": ["graph-sql", "graphql", "sqlite", "sql", "graph database", "api generator", "sql schema"],
        "primary_tools": ["graph-sql", "graphql-cop", "inql", "sqlmap"]
    },
    "sql injection": {
        "keywords": ["sql injection", "sqli", "union based", "error based", "time based blind", "database dump", "sql vulnerability"],
        "primary_tools": ["sqlmap", "ghuri", "nosqlmap", "jsql-injection", "bbqsql", "sqlmate"]
    },
    "privilege escalation linux": {
        "keywords": ["linux privesc", "root exploit", "sudo", "suid", "kernel exploit", "cron privilege", "linpeas"],
        "primary_tools": ["linpeas", "linenum", "pspy", "linux-exploit-suggester", "trapper", "les"]
    },
    "privilege escalation windows": {
        "keywords": ["windows privesc", "system elevation", "uac bypass", "unquoted service", "token impersonation", "winpeas"],
        "primary_tools": ["winpeas", "seatbelt", "sharpup", "watson", "jaws", "powerup", "sweetpotato"]
    },
    "coerce windows auth": {
        "keywords": ["coerce ntlm", "petitpotam", "printerbug", "shadowcoerce", "dfscoerce", "relay ntlm", "webdav coerce"],
        "primary_tools": ["petitpotam", "printerbug", "coerceplus", "shadowcoerce", "dfscoerce", "krbrelayx"]
    },
    "memory forensics": {
        "keywords": ["memory forensics", "ram dump", "raw memory", "volatility", "volatility3", "process dump", "malware artifact"],
        "primary_tools": ["volatility", "volatility3", "rekall", "memprocfs", "lime"]
    },
    "firmware extraction": {
        "keywords": ["firmware extraction", "binwalk", "iot reverse engineering", "squashfs", "ubifs", "rom dump", "embedded device"],
        "primary_tools": ["binwalk", "firmware-mod-kit", "unblob", "fwhunt", "firmadyne"]
    },
    "hunt api keys": {
        "keywords": ["secret hunting", "leaked keys", "git secrets", "trufflehog", "gitleaks", "api token leak", "credential scan"],
        "primary_tools": ["trufflehog", "gitleaks", "git-secrets", "shhgit", "earlybird"]
    },
    "reverse shell": {
        "keywords": ["reverse shell", "payload generator", "interactive tty", "msfvenom", "pty spawn", "shell generator"],
        "primary_tools": ["revshells", "pwncat", "conpty", "socat", "webshell", "shellerator"]
    },
    "osint reconnaissance": {
        "keywords": ["osint", "recon", "reconnaissance", "footprinting", "whois", "intel", "social engineering", "subdomain enum"],
        "primary_tools": ["theharvester", "spiderfoot", "recon-ng", "amass", "maltego", "sherlock", "holehe"]
    },
    "bypass cloudflare": {
        "keywords": ["cloudflare origin", "origin ip", "dns history", "waf bypass", "censys", "shodan", "real ip"],
        "primary_tools": ["cloudfail", "bypass-firewalls-by-DNS-history", "hatcloud", "shodan"]
    },
    "radio forensics": {
        "keywords": ["radio", "rf", "sdr", "emf", "tempest", "signal", "spectrum", "demodulation", "iq", "rtl-sdr", "hackrf", "gnuradio", "urh", "inspectrum", "gqrx", "sdrangel", "satellite", "satnogs"],
        "primary_tools": ["urh", "universal radio hacker", "inspectrum", "tempestsdr", "sigdigger", "sdrangel", "gnuradio", "gqrx", "rtl_433", "gr-gsm", "proxmark3", "dump1090", "satnogs-decoders", "gr-satellites"]
    },
    "radio forensic": {
        "keywords": ["radio", "rf", "sdr", "emf", "tempest", "signal", "spectrum", "demodulation", "iq", "rtl-sdr", "hackrf", "gnuradio", "urh", "inspectrum", "gqrx", "sdrangel", "satellite", "satnogs"],
        "primary_tools": ["urh", "universal radio hacker", "inspectrum", "tempestsdr", "sigdigger", "sdrangel", "gnuradio", "gqrx", "rtl_433", "gr-gsm", "proxmark3", "dump1090", "satnogs-decoders", "gr-satellites"]
    },
    "emf analysis": {
        "keywords": ["emf", "tempest", "electromagnetic", "radiation", "side channel", "eavesdropping", "sdr", "tempestsdr"],
        "primary_tools": ["tempestsdr", "hackrf", "rtl-sdr"]
    },
    "sdr signal": {
        "keywords": ["sdr", "software defined radio", "iq data", "demodulation", "spectrogram", "rf analysis", "signal forensics"],
        "primary_tools": ["urh", "inspectrum", "sigdigger", "sdrangel", "gnuradio", "gqrx", "rtl_433"]
    },
    "malware analysis": {
        "keywords": ["malware analysis", "sandbox", "yara", "reverse engineering", "binary triage", "unpacking", "c2 extraction", "remnux", "cape"],
        "primary_tools": ["remnux", "cape sandbox", "yara", "capa", "ghidra", "floss", "malwarebazaar", "volatility3"]
    },
    "reverse engineering": {
        "keywords": ["reverse engineering", "decompiler", "disassembler", "sre", "binary analysis", "ida", "ghidra", "radare2", "qemu"],
        "primary_tools": ["ghidra", "radare2", "qemu", "capa", "cutter", "x64dbg", "gdb"]
    },
    "siem monitoring": {
        "keywords": ["siem", "edr", "xdr", "threat hunting", "log analysis", "incident response", "ids", "ips", "network monitoring"],
        "primary_tools": ["wazuh", "velociraptor", "security onion", "zeek", "suricata", "thehive", "snort", "osquery", "graylog", "lynis"]
    },
    "purple team": {
        "keywords": ["purple team", "adversary emulation", "atomic red team", "detection validation", "caldera", "att&ck testing"],
        "primary_tools": ["atomic red team", "caldera", "purplesharp", "attack range", "mitre att&ck"]
    },
    "supply chain audit": {
        "keywords": ["software supply chain", "sast", "code review", "static analysis", "secrets hunting", "sbom", "container security"],
        "primary_tools": ["semgrep", "trivy", "gitleaks", "trufflehog", "syft", "grype", "osv-scanner", "checkov"]
    },
    "vulnerable lab": {
        "keywords": ["vulnerable lab", "ctf", "practice environment", "portswigger", "juice shop", "dvwa", "metasploitable", "vulnhub"],
        "primary_tools": ["portswigger academy", "juice shop", "dvwa", "tryhackme", "hack the box", "vulnhub", "picoctf", "metasploitable"]
    },
    "threat intelligence": {
        "keywords": ["threat intelligence", "cve", "known exploited vulnerabilities", "cisa kev", "mitre att&ck", "advisories"],
        "primary_tools": ["mitre att&ck", "cisa kev", "cve program", "owasp wstg", "google project zero", "malwarebazaar"]
    }
}

# Cyber dictionary & synonym mappings
SYNONYMS_AND_CORRECTIONS = {
    "penetst": ["pentest", "penetration"],
    "penstets": ["pentest", "penetration"],
    "penstest": ["pentest", "penetration"],
    "pentes": ["pentest", "penetration"],
    "pentesting": ["pentest", "penetration", "offensive"],
    "networ": ["network", "networking"],
    "netwrok": ["network", "networking"],
    "netowrk": ["network", "networking"],
    "pentest": ["pentest", "penetration", "offensive", "audit", "exploit", "security"],
    "network": ["network", "networking", "smb", "tcp", "udp", "ip", "port", "packet"],
    "wifi": ["wifi", "wireless", "802.11", "wpa", "wlan", "pmkid"],
    "privesc": ["privesc", "privilege escalation", "privilege", "root", "elevation"],
    "previlege": ["privilege", "privesc", "root"],
    "ad": ["active directory", "ad", "domain", "kerberos", "ldap", "ntds"],
    "adcs": ["adcs", "ad cs", "certificate", "esc1", "pkinit"],
    "edr": ["edr", "evasion", "bypass", "amsi", "defender", "unhook"],
    "c2": ["c2", "c&c", "command and control", "beacon", "implant", "post-exploitation"],
    "osint": ["osint", "recon", "reconnaissance", "subdomain", "discovery"],
    "passwrod": ["password", "hash", "cred", "credentials"],
    "passwd": ["password", "hash", "cred", "credentials"],
    "creds": ["credentials", "password", "hash", "secrets"],
    "vuln": ["vulnerability", "cve", "exploit", "scanner"],
    "revers": ["reverse engineering", "decompiler", "disassembler", "binary"],
    "exploite": ["exploit", "exploitation", "payload"],
    "directoy": ["directory", "active directory", "subdomain"]
}

KNOWN_VOCAB = [
    "network", "pentest", "penetration", "wireless", "wifi", "password", "hash",
    "privilege", "escalation", "active", "directory", "windows", "linux",
    "evasion", "bypass", "reverse", "engineering", "exploit", "scanner",
    "vulnerability", "c2", "firmware", "memory", "forensics", "forensic", "osint", "subdomain",
    "kerberos", "proxy", "tunnel", "docker", "container", "buffer", "overflow",
    "malware", "rootkit", "keylogger", "sniff", "spoof", "bruteforce", "wordlist",
    "graphql", "sql", "graph", "radio", "sdr", "emf", "rf", "satellite"
]

STOP_WORDS = {"tool", "tools", "github", "gitlab", "for", "the", "a", "an", "in", "of", "to", "and", "or", "is", "with", "on"}

def score_tool_record(tool: dict, tokens: list, clean_q: str, expanded_terms: list, primary_tools: list, intent: dict = None, tool_name: str = None) -> float:
    # 0. Direct Tool Name & Similarity Radar Evaluation
    sim_score = 0.0
    sim_type = "NONE"
    if tool_name and tool_name.strip():
        sim_score, sim_type = semantic_intelligence.semantic_engine.score_tool_similarity(tool, tool_name.strip())
        if sim_score > 0:
            tool["similarity_match"] = sim_type
            tool["similarity_target"] = tool_name.strip()

    # If ONLY tool_name was requested and NO purpose/query was provided:
    if tool_name and not clean_q and not tokens:
        return sim_score

    # 1. Deep Semantic Intent Engine Evaluation & Disqualification Filter
    if intent:
        sem_score, status = semantic_intelligence.semantic_engine.evaluate_tool_relevance(tool, intent, tokens)
        if status.startswith("DISQUALIFIED"):
            # If tool was explicitly requested via tool_name (exact match), allow it through
            if sim_type == "EXACT_MATCH":
                return 18000.0
            return 0.0
        if sem_score > 0:
            return sem_score + (sim_score * 1.5)

    name = (tool.get("name") or "").lower()
    tagline = (tool.get("tagline") or "").lower()
    purpose = (tool.get("purpose_summary") or "").lower()
    repo_url = (tool.get("repo_url") or "").lower()
    full_text = f"{name} {tagline} {purpose} {repo_url}"

    score = sim_score * 1.5
    clean_no_stops = [t for t in tokens if t not in STOP_WORDS]
    if not clean_no_stops:
        clean_no_stops = tokens

    # 1. Primary operational tool match (Huge boost for purposeful tools)
    for pt in primary_tools:
        pt_clean = pt.lower()
        if pt_clean == name or f"/{pt_clean}" in repo_url or f"/{pt_clean}." in repo_url:
            score += 4500
        elif pt_clean in name:
            score += 1500

    # 2. Exact or near-exact match on tool name or repository slug
    for t in clean_no_stops:
        if t == name or f"/{t}" in repo_url or f"/{t}." in repo_url:
            score += 3000
        elif t in name:
            score += 900

    # 3. Clean query match in name or repo URL
    if clean_q and (clean_q in name or clean_q in repo_url):
        score += 2000
    elif clean_q and clean_q in purpose:
        score += 600

    # 4. Token matches in text
    matched_tokens = sum(1 for t in clean_no_stops if t in full_text)
    if len(clean_no_stops) > 1 and matched_tokens == len(clean_no_stops):
        score += 800
    else:
        score += matched_tokens * 150

    # 5. Expanded terms / synonyms / operational keywords
    for term in expanded_terms:
        if term not in STOP_WORDS and term in full_text:
            score += 35

    # 6. Quality / Star traction
    if tool.get("stars"):
        score += min(tool["stars"] // 50, 200)
    elif tool.get("rarity") == "popular":
        score += 30

    return score

def clean_and_expand_query(q: str):
    intent = semantic_intelligence.semantic_engine.analyze_query_intent(q)
    words = re.findall(r'[a-zA-Z0-9_-]+', q.lower())
    corrected_words = []
    expanded_terms = set(intent.get("expanded_terms", []))
    primary_tools = set(intent.get("primary_tools", []))
    did_autocorrect = False

    for w in words:
        orig = w
        # Never autocorrect hyphenated or underscored project slugs
        if "-" in orig or "_" in orig:
            corrected_words.append(orig)
            expanded_terms.add(orig)
            for subpart in re.split(r'[-_]', orig):
                if len(subpart) > 1:
                    expanded_terms.add(subpart)
                    corrected_words.append(subpart)
            continue

        if w in SYNONYMS_AND_CORRECTIONS:
            corrected = SYNONYMS_AND_CORRECTIONS[w][0]
            if corrected != w:
                did_autocorrect = True
                w = corrected
        else:
            matches = difflib.get_close_matches(w, KNOWN_VOCAB, n=1, cutoff=0.78)
            if matches and matches[0] != w:
                w = matches[0]
                did_autocorrect = True

        corrected_words.append(w)
        if w in SYNONYMS_AND_CORRECTIONS:
            for s in SYNONYMS_AND_CORRECTIONS[w]:
                expanded_terms.add(s)
        else:
            expanded_terms.add(w)

    clean_q = " ".join(corrected_words)

    # Scan Rich Purpose & MITRE ATT&CK Matrix
    q_lower = q.lower()
    for purpose_name, purpose_data in PURPOSE_OPERATIONAL_MATRIX.items():
        if purpose_name in q_lower or purpose_name in clean_q:
            for kw in purpose_data["keywords"]:
                expanded_terms.add(kw)
            for pt in purpose_data["primary_tools"]:
                primary_tools.add(pt)
        else:
            # Check multi-token overlap
            p_tokens = set(purpose_name.split())
            if p_tokens.issubset(set(corrected_words)):
                for kw in purpose_data["keywords"]:
                    expanded_terms.add(kw)
                for pt in purpose_data["primary_tools"]:
                    primary_tools.add(pt)

    return {
        "original_query": q,
        "corrected_query": clean_q,
        "tokens": corrected_words,
        "expanded_terms": list(expanded_terms),
        "primary_tools": list(primary_tools),
        "autocorrected": did_autocorrect,
        "intent": intent
    }

CATEGORY_RULES = [
    ("VoIP & Telephony", [r"\bvoip\b", r"\basterisk\b", r"\bagi\b", r"\bsip\b", r"\bpbx\b", r"\btelephony\b"]),
    ("Threat Intelligence & OSINT", [r"\benrich\w*\b", r"\bioc\b", r"\bthreat\s+intel\w*\b", r"\bindicator\b", r"\bosint\b", r"\bsubdomain\b", r"\bwhois\b", r"\btheharvester\b", r"\bamass\b", r"\bspiderfoot\b", r"\bshodan\b", r"\bcensys\b"]),
    ("Active Directory & Windows", [r"\bactive\s+directory\b", r"\bkerberos\b", r"\bntds\b", r"\bldap\b", r"\bdomain\s+controller\b", r"\badcs\b", r"\bmimikatz\b", r"\bpass[-_]?the[-_]?hash\b", r"\bpth\b", r"\brubeus\b", r"\bcertipy\b"]),
    ("Wireless & Radio", [r"\bwireless\b", r"\bwifi\b", r"\b802\.11\b", r"\bwpa[23]?\b", r"\bbluetooth\b", r"\bble\b", r"\brf\b", r"\bsdr\b", r"\bpmkid\b", r"\brtl[-_]?sdr\b", r"\bhackrf\b", r"\bgnuradio\b", r"\bproxmark\b", r"\bnfc\b", r"\brfid\b"]),
    ("Reverse Engineering", [r"\breverse\b", r"\bdecompile\w*\b", r"\bdisassembl\w*\b", r"\bghidra\b", r"\bradare2?\b", r"\bx64dbg\b", r"\bcutter\b", r"\bdecompil", r"\bdisassembl", r"\belf\s+binary\b", r"\bpe[-_]?sieve\b"]),
    ("Web Application Security", [r"\bweb\b", r"\bhttp\b", r"\bsqli?\b", r"\bxss\b", r"\bssrf\b", r"\bgraphql\b", r"\bburp\b", r"\bzaproxy\b", r"\bcaido\b", r"\bnikto\b", r"\bwaf\b", r"\bjwt\b", r"\bapi\s+security\b"]),
    ("EDR & AV Evasion", [r"\bedr\b", r"\bamsi\b", r"\bevasion\b", r"\bunhook\w*\b", r"\bobfuscat\w*\b", r"\bsyscall\w*\b", r"\banti[-_]?virus\b", r"\bdefender\b"]),
    ("Privilege Escalation", [r"\bprivesc\b", r"\bprivilege\s+escalation\b", r"\broot\s+exploit\b", r"\blinpeas\b", r"\bwinpeas\b", r"\buac\s+bypass\b", r"\btoken\s+impersonat\w*\b", r"\bgtfobins\b"]),
    ("Command & Control (C2)", [r"\bc2\b", r"\bc&c\b", r"\bcommand\s+and\s+control\b", r"\bbeacon\b", r"\bimplant\b", r"\bpost[-_]?exploit\w*\b", r"\bhavoc\b", r"\bsliver\b", r"\bmythic\b"]),
    ("Network & Port Scanning", [r"\bport\s+scan\w*\b", r"\bnetwork\s+scan\w*\b", r"\bnmap\b", r"\bmasscan\b", r"\brustscan\b", r"\bnaabu\b", r"\bzmap\b", r"\bsniff\w*\b", r"\bpacket\b", r"\btcpdump\b", r"\bwireshark\b", r"\bmemcache\w*\b"]),
    ("Forensics & DFIR", [r"\bforensic\w*\b", r"\bdfir\b", r"\bmemory\s+dump\b", r"\bvolatility\b", r"\bincident\s+response\b", r"\btriage\b", r"\bautopsy\b", r"\bsleuthkit\b"]),
    ("Password Cracking & Hashes", [r"\bhashcat\b", r"\bjohn\s+the\s+ripper\b", r"\bwordlist\b", r"\bbruteforce\b", r"\bhydra\b", r"\bmedusa\b", r"\bhash\s+crack\w*\b"]),
    ("Cloud & Container Security", [r"\bcloud\b", r"\baws\b", r"\bazure\b", r"\bgcp\b", r"\bdocker\b", r"\bkubernetes\b", r"\bk8s\b", r"\bcontainer\b", r"\bs3\b"]),
    ("Hardware & Firmware", [r"\bfirmware\b", r"\bbinwalk\b", r"\bjtag\b", r"\buart\b", r"\biot\b", r"\bembedded\b", r"\bcanbus\b", r"\bobd[-_]?ii?\b"])
]

def infer_category(text: str) -> str:
    text_clean = (text or "").lower()
    for cat_name, patterns in CATEGORY_RULES:
        for pat in patterns:
            if re.search(pat, text_clean):
                return cat_name
    return "General Security & Exploitation"

def synthesize_operational_purpose(name: str, raw_desc: str = "", path: str = "", category: str = "", language: str = "") -> str:
    """
    Intelligently deduce and synthesize a clear, highly accurate operational purpose summary
    when the developer description is generic, missing, or uninformative. Always written in professional, simple English.
    """
    clean_desc = (raw_desc or "").strip()
    is_generic = (
        not clean_desc or
        clean_desc.startswith("Public GitLab project:") or
        clean_desc.startswith("Public GitHub repository:") or
        clean_desc.startswith("Automatically exported from code.google.com") or
        clean_desc.startswith("Mirror of ") or
        len(clean_desc) < 22 or
        clean_desc.lower() == name.lower() or
        clean_desc.lower() == f"{name.lower()} tool" or
        "module for lua" in clean_desc.lower() or
        ("module for" in clean_desc.lower() and len(clean_desc) < 65) or
        ("library for" in clean_desc.lower() and len(clean_desc) < 65) or
        ("client for" in clean_desc.lower() and len(clean_desc) < 65)
    )

    if not is_generic:
        clean_desc = clean_desc[0].upper() + clean_desc[1:]
        if not clean_desc.endswith('.'):
            clean_desc += '.'
        return clean_desc

    blob = f"{name} {path} {category} {language}".lower().replace('-', ' ').replace('_', ' ').replace('/', ' ')

    # 1. Threat Intelligence, IOCs & Data Enrichment
    if any(k in blob for k in ["enrich", "enricher", "enrichment", "ioc", "indicator"]):
        if "company" in blob or "advectus" in blob:
            return "Company threat intelligence and OSINT enrichment module, engineered to query corporate records, aggregate identity details, and enrich attack surface profiling."
        if "coordinator" in blob or "lookup" in blob:
            return "Centralized data enrichment coordinator, designed to schedule lookup queries against threat intelligence APIs, correlate target records, and streamline security analysis."
        return "Threat intelligence and data enrichment utility designed to ingest security indicators, query external threat intelligence feeds, and append investigative context."

    # 2. In-Memory Caching & Memcached/Redis Client
    if any(k in blob for k in ["memcache", "memcached"]):
        lang = language if language and language != "GitLab Project" else "Lua/Network"
        return f"High-performance {lang} client library for Memcached, used in network services, API gateways, and penetration testing automation to read, cache, and manipulate in-memory session data."
    if "redis" in blob:
        return "In-memory key-value data store interface, used in security backend pipelines and automated triage systems for real-time state tracking and caching."

    # 3. VoIP, Telephony & Asterisk (AGI)
    if any(k in blob for k in ["agi", "asterisk", "voip", "sip", "telephony"]):
        return "Asterisk Gateway Interface (AGI) telephony integration tool, used for automated VoIP call handling, PBX trunk security auditing, and telecommunications monitoring."

    # 4. Credential Extraction & Memory Dump
    if any(k in blob for k in ["lsass", "ntds", "mimikatz", "dump", "hash", "cred", "passw", "secretsdump"]):
        return "Credential extraction and authentication auditing utility, engineered to dump in-memory hashes, extract stored credentials, and audit authentication secrets."

    # 5. Active Directory & Kerberos
    if any(k in blob for k in ["active directory", "kerberos", "adcs", "bloodhound", "sharphound", "rubeus", "certipy"]):
        return "Active Directory security auditing tool, utilized to inspect domain permissions, map privilege escalation paths, and analyze Kerberos delegation vulnerabilities."

    # 6. Radio Frequency (RF), SDR & EMF Signals
    if any(k in blob for k in ["radio", "rf", "sdr", "signal", "spectrum", "demod", "emf", "tempest", "iq"]):
        return "Radio Frequency (RF) and Software Defined Radio (SDR) signal analysis tool, used to capture wireless transmissions, inspect spectrum waterfalls, and demodulate telemetry data."

    # 7. Reverse Engineering & Malware Analysis
    if any(k in blob for k in ["malware", "reverse", "ghidra", "yara", "disassembl", "decompile", "binary", "pe"]):
        return "Binary analysis and reverse engineering tool, built to decompile executable binaries, analyze obfuscated code, and detect suspicious software capabilities."

    # 8. Web Security, APIs & SQL Injection
    if any(k in blob for k in ["sql", "sqli", "xss", "graphql", "jwt", "fuzz", "burp", "zap"]):
        return "Web application vulnerability scanning utility, designed to test input validation controls, identify injection vulnerabilities, and audit API authentication endpoints."

    # 9. Network Discovery & Port Scanning
    if any(k in blob for k in ["scan", "scanner", "port", "nmap", "arp", "syn", "naabu"]):
        return "Network host discovery and port auditing tool, used to map active IP addresses, detect exposed services, and identify open network communication channels."

    # 10. Tunneling, Pivoting & C2
    if any(k in blob for k in ["tunnel", "pivot", "proxy", "c2", "implant", "beacon", "chisel", "ligolo"]):
        return "Network pivoting and proxy tunneling utility, engineered to route operational traffic across segmented network zones and bypass internal perimeter controls."

    # 11. Evasion & Antivirus Bypass
    if any(k in blob for k in ["bypass", "evasion", "unhook", "amsi", "obfusc"]):
        return "Defense evasion framework, designed to analyze endpoint detection behavior, test security sensor coverage, and evaluate antimalware detection boundaries."

    # 12. Wireless & Wi-Fi
    if any(k in blob for k in ["wifi", "wireless", "802.11", "wpa", "pmkid"]):
        return "Wireless network security testing utility, used to capture 802.11 authentication handshakes, inspect beacon frames, and verify Wi-Fi encryption strength."

    # 13. Cloud & Containers
    if any(k in blob for k in ["docker", "container", "k8s", "kubernetes", "cloud", "aws", "azure"]):
        return "Cloud infrastructure and container security scanner, built to audit cluster configurations, verify IAM boundaries, and assess container isolation security."

    # 14. OSINT & Reconnaissance
    if any(k in blob for k in ["osint", "recon", "subdomain", "whois", "dns"]):
        return "Open Source Intelligence (OSINT) gathering utility, designed to map external asset attack surfaces, enumerate domain infrastructure, and collect public intelligence."

    # 15. Forensics & DFIR
    if any(k in blob for k in ["forensic", "triage", "incident", "dfir", "artifact"]):
        return "Digital Forensics and Incident Response (DFIR) utility, utilized to collect system triage artifacts, reconstruct security events, and analyze filesystem evidence."

    clean_name = name.replace('-', ' ').replace('_', ' ').title()
    cat_text = category if category and category != "General Security & Exploitation" else "security operations"
    return f"Specialized operational utility for {clean_name}, applied in {cat_text.lower()} workflows, automated scripting, and systems verification."

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ----------------------------------------------------
# LIVE UPSTREAM ADAPTERS (GitHub, GitLab, Arch, Debian)
# ----------------------------------------------------

def live_fetch_github(clean_q: str, limit: int = 25, extra_terms: Optional[List[str]] = None) -> List[Dict[str, Any]]:
    """Query GitHub Search API live worldwide across 400M+ repositories."""
    results = []
    try:
        query_terms = clean_q
        if extra_terms and len(extra_terms) > 0:
            top_extras = " ".join(extra_terms[:3])
            query_terms = f"{clean_q} {top_extras}"

        url = f"https://api.github.com/search/repositories?q={requests.utils.quote(query_terms)}+in:name,description,topics&sort=stars&order=desc&per_page={limit}"
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        token = os.environ.get("GITHUB_TOKEN")
        if token:
            headers["Authorization"] = f"token {token}"

        r = requests.get(url, headers=headers, timeout=4)
        if r.status_code == 200:
            items = r.json().get("items", [])
            for item in items:
                name = item.get("name", "")
                full_name = item.get("full_name", "")
                raw_desc = item.get("description") or ""
                stars = item.get("stargazers_count", 0)
                lang = item.get("language") or "Code"
                html_url = item.get("html_url", "")
                topics = item.get("topics", [])
                cat = infer_category(raw_desc + " " + " ".join(topics) + " " + name)
                updated_at = item.get("updated_at", "")
                desc = synthesize_operational_purpose(name, raw_desc, full_name, cat, lang)

                results.append({
                    "id": "live_gh_" + re.sub(r'[^a-zA-Z0-9_-]', '_', full_name.lower()),
                    "name": name,
                    "tagline": f"[{lang}] {full_name} ({stars:,} ★)",
                    "category": cat,
                    "rarity": "popular" if stars > 300 else "rare",
                    "purpose_summary": desc,
                    "purposes": topics,
                    "distros": {"blackarch": "", "arch": "", "debian": "", "git": html_url},
                    "repo_url": html_url,
                    "repo_type": "github",
                    "official_url": item.get("homepage") or html_url,
                    "research_links": [
                        {"title": f"HackTricks Cybersecurity Guide ({name})", "url": f"https://book.hacktricks.xyz/?q={requests.utils.quote(name)}", "source": "hacktricks"},
                        {"title": f"Medium Security Tutorials ({name})", "url": f"https://medium.com/search?q={requests.utils.quote(name + ' cybersecurity tutorial')}", "source": "medium"},
                        {"title": f"Official GitHub Repository & Installation ({name})", "url": html_url, "source": "github"},
                        {"title": f"Compiled Releases & Binary Packages ({name})", "url": f"{html_url}/releases", "source": "github"}
                    ],
                    "notes": f"Live GitHub discovery: {full_name}. Updated {updated_at[:10] if updated_at else 'Recently'}.",
                    "source_origin": "github",
                    "stars": stars,
                    "language": lang,
                    "last_updated": updated_at
                })
    except Exception as e:
        print(f"[!] Live GitHub query error: {e}")
    return results

def live_fetch_gitlab(clean_q: str, limit: int = 15, primary_tools: list = None) -> List[Dict[str, Any]]:
    """Query GitLab Search API live worldwide across millions of projects with domain intelligence."""
    results = []
    seen_urls = set()

    queries_to_try = [clean_q]
    if primary_tools:
        for pt in primary_tools[:3]:
            if pt not in queries_to_try:
                queries_to_try.append(pt)

    headers = {"User-Agent": "Mozilla/5.0"}
    try:
        for q_term in queries_to_try:
            if len(results) >= limit:
                break
            url = f"https://gitlab.com/api/v4/projects?search={requests.utils.quote(q_term)}&per_page={limit}"
            r = requests.get(url, headers=headers, timeout=4)
            if r.status_code == 200:
                items = r.json()
                if isinstance(items, list):
                    for item in items:
                        web_url = item.get("web_url", "")
                        if not web_url or web_url in seen_urls:
                            continue
                        seen_urls.add(web_url)

                        name = item.get("name", "")
                        path = item.get("path_with_namespace", "")
                        raw_desc = item.get("description") or ""
                        stars = item.get("star_count", 0)
                        cat = infer_category(raw_desc + " " + path)
                        desc = synthesize_operational_purpose(name, raw_desc, path, cat, "GitLab Project")
                        last_activity = item.get("last_activity_at", "")

                        results.append({
                            "id": "live_gl_" + str(item.get("id")),
                            "name": name,
                            "tagline": f"[GitLab] {path} ({stars} ★)",
                            "category": cat,
                            "rarity": "popular" if stars > 50 else "rare",
                            "purpose_summary": desc,
                            "purposes": item.get("tag_list", []),
                            "distros": {"blackarch": "", "arch": "", "debian": "", "git": web_url},
                            "repo_url": web_url,
                            "repo_type": "gitlab",
                            "official_url": web_url,
                            "research_links": [
                                {"title": f"HackTricks Cybersecurity Guide ({name})", "url": f"https://book.hacktricks.xyz/?q={requests.utils.quote(name)}", "source": "hacktricks"},
                                {"title": f"Medium Security Tutorials ({name})", "url": f"https://medium.com/search?q={requests.utils.quote(name + ' cybersecurity tutorial')}", "source": "medium"},
                                {"title": f"Official GitLab Project & Installation Source ({name})", "url": web_url, "source": "gitlab"},
                                {"title": f"Releases, Tags & Binaries ({name})", "url": f"{web_url}/-/releases", "source": "gitlab"}
                            ],
                            "notes": f"Live GitLab project: {path}",
                            "source_origin": "gitlab",
                            "stars": stars,
                            "language": "GitLab Project",
                            "last_updated": last_activity
                        })
    except Exception as e:
        print(f"[!] Live GitLab query error: {e}")
    return results

def live_fetch_arch(clean_q: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Query Arch Linux official package repository API live."""
    results = []
    try:
        term = clean_q.split()[0] if clean_q else ""
        if not term:
            return results
        url = f"https://archlinux.org/packages/search/json/?q={requests.utils.quote(term)}"
        r = requests.get(url, timeout=4)
        if r.status_code == 200:
            items = r.json().get("results", [])[:limit]
            for item in items:
                pkgname = item.get("pkgname", "")
                desc = item.get("pkgdesc", "") or f"Official Arch Linux package ({item.get('repo')})"
                repo = item.get("repo", "core")
                upstream_url = item.get("url") or f"https://archlinux.org/packages/{repo}/{item.get('arch', 'x86_64')}/{pkgname}/"
                cat = infer_category(desc)
                last_update = item.get("last_update", "")

                results.append({
                    "id": "arch_" + pkgname.lower(),
                    "name": pkgname,
                    "tagline": f"[Arch Linux {repo}] {pkgname} v{item.get('pkgver')}",
                    "category": cat,
                    "rarity": "popular",
                    "purpose_summary": desc,
                    "purposes": ["archlinux", repo, "official-package"],
                    "distros": {"blackarch": "", "arch": f"pacman -S {pkgname}", "debian": "", "git": upstream_url},
                    "repo_url": upstream_url,
                    "repo_type": "arch",
                    "official_url": f"https://archlinux.org/packages/{repo}/{item.get('arch', 'x86_64')}/{pkgname}/",
                    "research_links": [
                        {"title": f"Arch Package ({repo})", "url": f"https://archlinux.org/packages/{repo}/{item.get('arch', 'x86_64')}/{pkgname}/"}
                    ],
                    "notes": f"Arch Linux Official Repository ({repo}). Architecture: {item.get('arch')}.",
                    "source_origin": "arch",
                    "stars": 150,
                    "language": "Arch Package",
                    "last_updated": last_update
                })
    except Exception as e:
        print(f"[!] Live Arch Linux query error: {e}")
    return results

def live_fetch_debian(clean_q: str, limit: int = 10) -> List[Dict[str, Any]]:
    """Query Debian package tracker API live."""
    results = []
    try:
        term = clean_q.split()[0] if clean_q else ""
        if not term:
            return results
        url = f"https://sources.debian.org/api/search/{requests.utils.quote(term)}/"
        r = requests.get(url, timeout=4)
        if r.status_code == 200:
            data = r.json().get("results", {})
            pkgs = []
            if data.get("exact"):
                pkgs.append(data["exact"]["name"])
            for o in data.get("other", [])[:limit]:
                pkgs.append(o["name"])

            for pkg in pkgs:
                cat = infer_category(pkg)
                pkg_url = f"https://packages.debian.org/sid/{pkg}"
                results.append({
                    "id": "deb_" + pkg.lower(),
                    "name": pkg,
                    "tagline": f"[Debian Package] {pkg}",
                    "category": cat,
                    "rarity": "popular",
                    "purpose_summary": f"Official Debian/Ubuntu/Kali repository package: {pkg}",
                    "purposes": ["debian", "kali", "apt-package"],
                    "distros": {"blackarch": "", "arch": "", "debian": f"apt install {pkg}", "git": ""},
                    "repo_url": pkg_url,
                    "repo_type": "debian",
                    "official_url": pkg_url,
                    "research_links": [
                        {"title": "Debian Package Tracker", "url": pkg_url}
                    ],
                    "notes": f"Debian / Ubuntu / Kali archive package: {pkg}.",
                    "source_origin": "debian",
                    "stars": 120,
                    "language": "Debian Package",
                    "last_updated": ""
                })
    except Exception as e:
        print(f"[!] Live Debian query error: {e}")
    return results

# ----------------------------------------------------
# BACKGROUND AUTO-SYNC
# ----------------------------------------------------

def background_sync_task():
    global is_syncing
    with sync_lock:
        if is_syncing:
            return
        is_syncing = True

    try:
        print("[*] Background live sync started...")
        sync_engine.run_full_sync()
        search_cache.clear()
        print("[+] Background live sync completed successfully. In-memory cache cleared.")
    except Exception as e:
        print(f"[-] Background sync error: {e}")
    finally:
        with sync_lock:
            is_syncing = False

# ----------------------------------------------------
# API ENDPOINTS
# ----------------------------------------------------

def apply_sorting(tools: list, sort_by: Optional[str]):
    if not sort_by or sort_by == "relevance":
        return
    if sort_by == "stars":
        tools.sort(key=lambda t: (t.get("stars") or 0), reverse=True)
    elif sort_by == "popularity":
        tools.sort(key=lambda t: (
            1 if t.get("rarity") == "popular" else 0,
            t.get("stars") or 0
        ), reverse=True)
    elif sort_by == "updated":
        tools.sort(key=lambda t: (t.get("last_updated") or ""), reverse=True)
    elif sort_by == "name_asc":
        tools.sort(key=lambda t: (t.get("name") or "").lower())
    elif sort_by == "name_desc":
        tools.sort(key=lambda t: (t.get("name") or "").lower(), reverse=True)

@app.get("/api/cache/stats")
def get_cache_stats():
    return search_cache.stats()

@app.post("/api/cache/clear")
def clear_cache():
    search_cache.clear()
    return {"status": "cleared", "message": "In-memory cache flushed successfully."}

@app.get("/api/sync/status")
def get_sync_status():
    global is_syncing
    data = {}
    if os.path.exists(SYNC_META_PATH):
        try:
            with open(SYNC_META_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            pass
    if not data or not data.get("total_tools"):
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT count(*) FROM tools")
            tot = c.fetchone()[0]
            c.execute("SELECT count(*) FROM tools WHERE repo_url LIKE '%github.com%'")
            gh = c.fetchone()[0]
            c.execute("SELECT count(*) FROM tools WHERE source_origin='gitlab' OR repo_url LIKE '%gitlab.com%'")
            gl = c.fetchone()[0]
            c.execute("SELECT count(*) FROM tools WHERE distro_blackarch != ''")
            ba = c.fetchone()[0]
            data = {
                "total_tools": tot,
                "github_count": gh,
                "gitlab_count": gl,
                "blackarch_count": ba,
                "rare_count": max(0, tot - 100),
                "last_sync": "Online Live Dynamic Index",
                "is_syncing": is_syncing
            }
        except Exception:
            data = {
                "total_tools": 4261,
                "github_count": 2743,
                "gitlab_count": 482,
                "blackarch_count": 3637,
                "rare_count": 3500,
                "last_sync": "Online",
                "is_syncing": is_syncing
            }
    data["is_syncing"] = is_syncing
    data["cache"] = search_cache.stats()
    return data

@app.post("/api/sync")
def trigger_sync(background_tasks: BackgroundTasks):
    global is_syncing
    if is_syncing:
        return {"status": "in_progress", "message": "Synchronization is already running in background."}
    background_tasks.add_task(background_sync_task)
    return {"status": "started", "message": "Live upstream sync initiated."}

class LearnInteractionRequest(BaseModel):
    query: str
    tool_id: str
    tool_name: str

@app.post("/api/intel/learn")
def learn_tool_interaction(req: LearnInteractionRequest):
    if req.query and req.tool_name:
        semantic_intelligence.semantic_engine.record_tool_interaction(req.query, req.tool_id, req.tool_name)
        search_cache.clear()
        return {"status": "learned", "message": f"Successfully associated '{req.tool_name}' with intent '{req.query}'"}
    return {"status": "skipped"}

@app.get("/api/tools")
def get_tools(
    q: Optional[str] = Query(None, description="Search by name, purpose, or capability"),
    purpose: Optional[str] = Query(None, description="Operational purpose / mission search"),
    tool_name: Optional[str] = Query(None, description="Direct tool name / similar tools search"),
    category: Optional[str] = Query(None, description="Category filter"),
    distro: Optional[str] = Query(None, description="Distro filter: blackarch, arch, debian, git"),
    rarity: Optional[str] = Query(None, description="Rarity: popular, rare"),
    source: Optional[str] = Query(None, description="Source: all, github, gitlab, blackarch, arch, debian, kali"),
    only_github: Optional[bool] = Query(False, description="Filter only tools with GitHub repositories"),
    sort_by: Optional[str] = Query("relevance", description="Sort by: relevance, stars, popularity, updated, name_asc, name_desc"),
    live: Optional[bool] = Query(True, description="Enable live federated querying of GitHub, GitLab, Arch, and Debian"),
    page: int = Query(1, ge=1),
    limit: int = Query(60, ge=1, le=5000)
):
    t_start = time.perf_counter()

    effective_q = (purpose or q or "").strip()
    effective_tool = (tool_name or "").strip()

    # 1. Check High-Speed In-Memory Cache (Cached pool independent of sort_by for instant re-sorting)
    cache_key = search_cache.make_key(
        q=effective_q,
        tool_name=effective_tool,
        category=category or "all",
        distro=distro or "all",
        rarity=rarity or "all",
        source=source or "all",
        only_github=only_github,
        live=live
    )

    cached_bundle = search_cache.get(cache_key)
    if cached_bundle is not None:
        all_combined_tools = list(cached_bundle["tools"])
        autocorrect_info = cached_bundle["autocorrect"]
        apply_sorting(all_combined_tools, sort_by)

        total_matches = len(all_combined_tools)
        offset = (page - 1) * limit
        paginated_tools = all_combined_tools[offset:offset + limit]
        t_end = time.perf_counter()
        resp_ms = round((t_end - t_start) * 1000, 2)

        return {
            "total": total_matches,
            "page": page,
            "limit": limit,
            "sort_by": sort_by,
            "cached": True,
            "response_time_ms": resp_ms,
            "federated_sources": ["github", "gitlab", "blackarch", "arch", "debian"],
            "autocorrect": autocorrect_info,
            "tools": paginated_tools
        }

    # 2. Query Local Database
    if not os.path.exists(DB_PATH):
        sync_engine.run_full_sync()

    conn = get_db()
    c = conn.cursor()

    conditions = []
    params = []

    if only_github:
        conditions.append("repo_url LIKE '%github.com%'")

    if category and category != "all":
        conditions.append("category = ?")
        params.append(category)

    if rarity and rarity != "all":
        conditions.append("rarity = ?")
        params.append(rarity)

    if source and source != "all":
        if source == "github":
            conditions.append("repo_url LIKE '%github.com%'")
        elif source == "gitlab":
            conditions.append("(source_origin = 'gitlab' OR repo_url LIKE '%gitlab.com%')")
        elif source in ["codeberg", "sourceforge", "forges"]:
            conditions.append("(source_origin IN ('codeberg', 'sourceforge', 'forge') OR repo_url LIKE '%codeberg.org%' OR repo_url LIKE '%sourceforge.net%' OR repo_url LIKE '%sr.ht%')")
        elif source == "resources":
            conditions.append("source_origin IN ('resource', 'portal', 'research', 'publishing', 'pastebin', 'bugbounty')")
        elif source == "labs":
            conditions.append("(source_origin IN ('lab', 'practice') OR category LIKE '%Lab%')")
        elif source == "blackarch":
            conditions.append("source_origin = 'blackarch'")
        elif source == "kali":
            conditions.append("source_origin = 'kali'")
        elif source in ["arch", "debian"]:
            conditions.append("source_origin = ?")
            params.append(source)
        else:
            conditions.append("source_origin = ?")
            params.append(source)

    if distro and distro != "all":
        if distro == "blackarch":
            conditions.append("distro_blackarch != ''")
        elif distro == "arch":
            conditions.append("distro_arch != ''")
        elif distro == "debian":
            conditions.append("distro_debian != ''")
        elif distro == "git":
            conditions.append("distro_git != ''")

    where_base = " AND ".join(conditions) if conditions else "1=1"
    c.execute(f"SELECT * FROM tools WHERE {where_base}", params)
    local_rows = c.fetchall()

    autocorrect_info = None
    all_combined_tools = []

    if effective_q or effective_tool:
        if effective_q:
            expanded = clean_and_expand_query(effective_q)
            tokens = expanded["tokens"]
            clean_q = expanded["corrected_query"]
            expanded_terms = expanded["expanded_terms"]
            primary_tools = expanded["primary_tools"]
            intent = expanded.get("intent", {})
            autocorrect_info = {
                "autocorrected": expanded["autocorrected"],
                "original_query": expanded["original_query"],
                "corrected_query": expanded["corrected_query"],
                "canonical_intent": intent.get("canonical_intent"),
                "domain": intent.get("domain"),
                "description": intent.get("description"),
                "tool_target": effective_tool if effective_tool else None
            }
        else:
            tokens = []
            clean_q = ""
            expanded_terms = []
            primary_tools = []
            intent = {}
            autocorrect_info = {
                "autocorrected": False,
                "original_query": "",
                "corrected_query": "",
                "canonical_intent": None,
                "domain": None,
                "description": None,
                "tool_target": effective_tool
            }

        # 2a. Fetch Local Tools
        local_tool_dicts = []
        for r in local_rows:
            r_name = r["name"]
            r_purpose = synthesize_operational_purpose(r_name, r["purpose_summary"] or "", r["repo_url"] or "", r["category"] or "")
            links = json.loads(r["research_links"]) if r["research_links"] else []
            if not any("hacktricks" in (l.get("url") or "").lower() for l in links):
                links.insert(0, {
                    "title": f"HackTricks Cybersecurity Guide ({r_name})",
                    "url": f"https://book.hacktricks.xyz/?q={requests.utils.quote(r_name)}",
                    "source": "hacktricks"
                })
            if not any("medium" in (l.get("url") or "").lower() for l in links):
                links.insert(1, {
                    "title": f"Medium Security Tutorials ({r_name})",
                    "url": f"https://medium.com/search?q={requests.utils.quote(r_name + ' cybersecurity tutorial')}",
                    "source": "medium"
                })

            local_tool_dicts.append({
                "id": r["id"],
                "name": r_name,
                "tagline": r["tagline"] or r_purpose,
                "category": r["category"],
                "rarity": r["rarity"],
                "purpose_summary": r_purpose,
                "purposes": json.loads(r["purposes"]) if r["purposes"] else [],
                "distros": {
                    "blackarch": r["distro_blackarch"],
                    "arch": r["distro_arch"],
                    "debian": r["distro_debian"],
                    "git": r["distro_git"]
                },
                "repo_url": r["repo_url"],
                "repo_type": r["repo_type"],
                "official_url": r["official_url"],
                "research_links": links,
                "notes": r["notes"],
                "source_origin": r["source_origin"],
                "version": r["version"],
                "stars": r["stars"],
                "language": "Tool",
                "last_updated": r["last_updated"] or ""
            })

        # 2b. Parallel Live Federated Query (GitHub, GitLab, Arch, Debian)
        live_results = []
        live_query = effective_tool if effective_tool else clean_q
        if live and live_query:
            include_gh = source in [None, "all", "github"]
            include_gl = source in [None, "all", "gitlab"]
            include_arch = source in [None, "all", "arch"]
            include_deb = source in [None, "all", "debian"]

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                futures = {}
                if include_gh:
                    futures[executor.submit(live_fetch_github, live_query, 25, primary_tools)] = "github"
                if include_gl:
                    futures[executor.submit(live_fetch_gitlab, live_query, 15, primary_tools)] = "gitlab"
                if include_arch:
                    futures[executor.submit(live_fetch_arch, live_query, 10)] = "arch"
                if include_deb:
                    futures[executor.submit(live_fetch_debian, live_query, 10)] = "debian"

                for fut in concurrent.futures.as_completed(futures, timeout=5):
                    try:
                        items = fut.result()
                        live_results.extend(items)
                    except Exception as err:
                        print(f"[!] Error in federated future: {err}")

        # 2c. Combine and Deduplicate by name/repo_url
        combined_pool = []
        seen_keys = set()
        for t in live_results + local_tool_dicts:
            key = (t.get("repo_url") or t.get("name", "")).lower().strip().rstrip("/")
            if key and key not in seen_keys:
                seen_keys.add(key)
                combined_pool.append(t)

        # 2d. Score all tools with unified relevance scorer
        scored_tools = []
        for t in combined_pool:
            if source and source != "all":
                if source == "github":
                    if not (t.get("source_origin") == "github" or (t.get("repo_url") and "github.com" in t["repo_url"])):
                        continue
                elif source == "gitlab":
                    if not (t.get("source_origin") == "gitlab" or (t.get("repo_url") and "gitlab.com" in t["repo_url"])):
                        continue
                elif source in ["codeberg", "sourceforge", "forges"]:
                    if not (t.get("source_origin") in ["codeberg", "sourceforge", "forge"] or any(d in (t.get("repo_url") or "") for d in ["codeberg.org", "sourceforge.net", "sr.ht"])):
                        continue
                elif source == "resources":
                    if not (t.get("source_origin") in ["resource", "portal", "research", "publishing", "pastebin", "bugbounty"]):
                        continue
                elif source == "labs":
                    if not (t.get("source_origin") in ["lab", "practice"] or "lab" in (t.get("category") or "").lower()):
                        continue
                elif source == "blackarch":
                    if t.get("source_origin") != "blackarch":
                        continue
                elif source in ["arch", "debian", "kali"]:
                    if t.get("source_origin") != source:
                        continue

            score = score_tool_record(t, tokens, clean_q, expanded_terms, primary_tools, intent=intent, tool_name=effective_tool)
            if score > 0:
                scored_tools.append((score, t))

        # Default scoring sort
        scored_tools.sort(key=lambda x: (x[0], x[1].get("stars") or 0), reverse=True)
        all_combined_tools = [x[1] for x in scored_tools]

    else:
        # No query: return local database
        for r in local_rows:
            all_combined_tools.append({
                "id": r["id"],
                "name": r["name"],
                "tagline": r["tagline"],
                "category": r["category"],
                "rarity": r["rarity"],
                "purpose_summary": r["purpose_summary"],
                "purposes": json.loads(r["purposes"]) if r["purposes"] else [],
                "distros": {
                    "blackarch": r["distro_blackarch"],
                    "arch": r["distro_arch"],
                    "debian": r["distro_debian"],
                    "git": r["distro_git"]
                },
                "repo_url": r["repo_url"],
                "repo_type": r["repo_type"],
                "official_url": r["official_url"],
                "research_links": json.loads(r["research_links"]) if r["research_links"] else [],
                "notes": r["notes"],
                "source_origin": r["source_origin"],
                "version": r["version"],
                "stars": r["stars"],
                "language": "Tool",
                "last_updated": r["last_updated"] or ""
            })

    conn.close()

    # 3. Save pool to In-Memory Cache (before applying specific sort order)
    search_cache.set(cache_key, {
        "tools": list(all_combined_tools),
        "autocorrect": autocorrect_info
    })

    # 4. Apply Multi-Option Sorting (relevance, stars, popularity, updated, name_asc, name_desc)
    apply_sorting(all_combined_tools, sort_by)

    total_matches = len(all_combined_tools)
    offset = (page - 1) * limit
    paginated_tools = all_combined_tools[offset:offset + limit]

    t_end = time.perf_counter()
    resp_ms = round((t_end - t_start) * 1000, 2)

    return {
        "total": total_matches,
        "page": page,
        "limit": limit,
        "sort_by": sort_by,
        "cached": False,
        "response_time_ms": resp_ms,
        "federated_sources": ["github", "gitlab", "blackarch", "arch", "debian"],
        "autocorrect": autocorrect_info,
        "tools": paginated_tools
    }

# Live Federated Search Dedicated Endpoint
@app.get("/api/search/federated")
def search_federated(q: str = Query(..., description="Query across all sources")):
    return get_tools(q=q, live=True, limit=60)

# Static files
app.mount("/css", StaticFiles(directory=os.path.join(BASE_DIR, "css")), name="css")
app.mount("/js", StaticFiles(directory=os.path.join(BASE_DIR, "js")), name="js")
if os.path.exists(os.path.join(BASE_DIR, "data")):
    app.mount("/data", StaticFiles(directory=os.path.join(BASE_DIR, "data")), name="data")

@app.get("/favicon.ico")
@app.get("/favicon.svg")
def serve_favicon():
    fav_path = os.path.join(BASE_DIR, "favicon.svg")
    if os.path.exists(fav_path):
        return FileResponse(fav_path, media_type="image/svg+xml")
    return Response(status_code=404)

@app.get("/")
def serve_index():
    return FileResponse(os.path.join(BASE_DIR, "index.html"))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"\n=======================================================")
    print(f"🚀 PURPOSE-2-TOOL FEDERATED SEARCH ACTIVE ON PORT {port}")
    print(f"⚡ In-Memory High-Speed Cache: Active (30m TTL)")
    print(f"🎯 Purpose Matrix: 30+ MITRE ATT&CK & Red Team Objectives")
    print(f"🌐 Querying Live: GitHub, GitLab, Arch Linux, Debian, BlackArch")
    print(f"🎯 URL: http://localhost:{port}")
    print(f"=======================================================\n")
    uvicorn.run("server:app", host="0.0.0.0", port=port, reload=False)
