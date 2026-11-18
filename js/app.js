/**
 * PURPOSE-2-TOOL // Dynamic Application Logic
 * Purpose-based Cybersecurity Tool Discovery & Upstream Synchronization Engine
 * Heavy GitHub Repositories (2,690+) & Distro Integration
 * Smart Fuzzy & Typo-Tolerant Purpose Matching
 */

(function () {
  'use strict';

  // API Base Resolution (supports both http://localhost:8080 and double-clicking file:///)
  const API_BASE = (window.location.protocol === 'file:' || (window.location.port !== '8080' && !window.location.port))
    ? 'http://localhost:8080'
    : '';

  // Rich Cyber Purpose & Operational Matrix
  const PURPOSE_OPERATIONAL_MATRIX = {
    "network pentest": {
      keywords: ["network", "port", "scanner", "sniff", "packet", "smb", "tcp", "udp", "recon", "sweep", "nmap", "penetration"],
      primaryTools: ["nmap", "masscan", "rustscan", "bettercap", "netdiscover", "zmap", "wireshark", "tshark", "arp-scan"]
    },
    "network scan": {
      keywords: ["network", "port", "scanner", "syn", "syn-scan", "sweep", "service detection", "banner grab"],
      primaryTools: ["nmap", "masscan", "rustscan", "zmap", "naabu", "netdiscover"]
    },
    "dump lsass": {
      keywords: ["lsass", "credential", "dump", "minidump", "process injection", "mimikatz", "memory dump", "sam", "lsa"],
      primaryTools: ["mimikatz", "procdump", "lsassy", "nanodump", "pypykatz", "dumpert", "handlekatz", "physmem2profit"]
    },
    "dump ntds": {
      keywords: ["ntds", "ntds.dit", "active directory", "shadow copy", "secretsdump", "drsuapi", "vss", "domain controller"],
      primaryTools: ["impacket", "secretsdump", "crackmapexec", "netexec", "ntdsutil", "gosecretsdump"]
    },
    "pass the hash": {
      keywords: ["pass the hash", "pth", "ntlm", "smb", "wmiexec", "psexec", "lateral movement", "hash authentication"],
      primaryTools: ["impacket", "crackmapexec", "netexec", "evil-winrm", "wmiexec", "psexec", "pth-toolkit"]
    },
    "kerberoasting": {
      keywords: ["kerberoast", "spn", "tgs", "rc4", "ticket granting service", "active directory", "kerberos"],
      primaryTools: ["rubeus", "impacket", "getuserspns", "kerbrute", "tgsrepcrack"]
    },
    "as-rep roasting": {
      keywords: ["asreproast", "as-rep", "uf_dont_require_preauth", "preauthentication", "kerberos", "ticket"],
      primaryTools: ["rubeus", "impacket", "getnpusers", "kerbrute"]
    },
    "adcs": {
      keywords: ["adcs", "ad cs", "active directory certificate services", "esc1", "esc8", "pkinit", "certipy", "certify"],
      primaryTools: ["certipy", "certify", "forgecert", "adcs-killer", "pass-the-cert"]
    },
    "ad cs escalation": {
      keywords: ["adcs", "ad cs", "certificate", "esc1", "esc2", "esc3", "esc4", "esc8", "pkinit", "template misconfiguration"],
      primaryTools: ["certipy", "certify", "forgecert", "adcs-killer", "shadowcredentials"]
    },
    "edr bypass": {
      keywords: ["edr bypass", "evasion", "amsi", "etw", "unhooking", "direct syscalls", "syscall", "obfuscation", "antivirus"],
      primaryTools: ["scarecrow", "havoc", "donut", "tartarus", "invoke-obfuscation", "chameleon", "peass-ng", "pe-sieve"]
    },
    "amsi bypass": {
      keywords: ["amsi", "antimalware scan interface", "patch amsi", "amsi.dll", "powershell bypass", "memory patch"],
      primaryTools: ["amsitrigger", "amsi-bypass", "invoke-obfuscation", "rasta-mouse"]
    },
    "pivot network": {
      keywords: ["pivot", "pivoting", "tunnel", "tunneling", "socks5", "proxy", "port forwarding", "reverse proxy", "traffic tunnel"],
      primaryTools: ["chisel", "ligolo-ng", "ligolo", "proxychains", "rpivot", "gost", "frp", "dnscat2", "iodine"]
    },
    "c2 framework": {
      keywords: ["c2", "c&c", "command and control", "beacon", "implant", "post-exploitation", "red team operator", "agent"],
      primaryTools: ["havoc", "sliver", "mythic", "covenant", "caldera", "merlin", "empire", "shad0w"]
    },
    "browser passwords": {
      keywords: ["browser password", "chrome credentials", "firefox passwords", "cookie stealer", "dpapi", "web credential", "login data"],
      primaryTools: ["hackbrowserdata", "sharpchromekey", "lazagne", "mimikatz", "browser-cookie-stealer"]
    },
    "wifi pmkid": {
      keywords: ["pmkid", "wpa2", "wifi", "handshake", "802.11", "wireless attack", "clientless", "eapol"],
      primaryTools: ["hcxdumptool", "hcxtools", "hashcat", "aircrack-ng", "wifite", "bettercap", "bully"]
    },
    "docker container breakout": {
      keywords: ["container breakout", "docker escape", "privileged container", "cgroups", "nsenter", "kubernetes escape", "container escalation"],
      primaryTools: ["cdk", "deepce", "peass-ng", "amicontained", "botb", "docker-bench-security"]
    },
    "subdomain takeover": {
      keywords: ["subdomain takeover", "cname dangling", "dns recon", "subdomain enum", "dns takeover"],
      primaryTools: ["subjack", "subzy", "nuclei", "subfinder", "amass", "dnsx"]
    },
    "graphql pentest": {
      keywords: ["graphql", "graphql injection", "introspection", "query batching", "graphql-cop", "graphql vulnerability"],
      primaryTools: ["graphql-cop", "clairvoyance", "inql", "graphql-path-enum", "graphw00f"]
    },
    "graph sql": {
      keywords: ["graph-sql", "graphql", "sqlite", "sql", "graph database", "api generator", "sql schema"],
      primaryTools: ["graph-sql", "graphql-cop", "inql", "sqlmap"]
    },
    "sql injection": {
      keywords: ["sql injection", "sqli", "union based", "error based", "time based blind", "database dump", "sql vulnerability"],
      primaryTools: ["sqlmap", "ghuri", "nosqlmap", "jsql-injection", "bbqsql", "sqlmate"]
    },
    "privilege escalation linux": {
      keywords: ["linux privesc", "root exploit", "sudo", "suid", "kernel exploit", "cron privilege", "linpeas"],
      primaryTools: ["linpeas", "linenum", "pspy", "linux-exploit-suggester", "trapper", "les"]
    },
    "privilege escalation windows": {
      keywords: ["windows privesc", "system elevation", "uac bypass", "unquoted service", "token impersonation", "winpeas"],
      primaryTools: ["winpeas", "seatbelt", "sharpup", "watson", "jaws", "powerup", "sweetpotato"]
    },
    "coerce windows auth": {
      keywords: ["coerce ntlm", "petitpotam", "printerbug", "shadowcoerce", "dfscoerce", "relay ntlm", "webdav coerce"],
      primaryTools: ["petitpotam", "printerbug", "coerceplus", "shadowcoerce", "dfscoerce", "krbrelayx"]
    },
    "memory forensics": {
      keywords: ["memory forensics", "ram dump", "raw memory", "volatility", "volatility3", "process dump", "malware artifact"],
      primaryTools: ["volatility", "volatility3", "rekall", "memprocfs", "lime"]
    },
    "firmware extraction": {
      keywords: ["firmware extraction", "binwalk", "iot reverse engineering", "squashfs", "ubifs", "rom dump", "embedded device"],
      primaryTools: ["binwalk", "firmware-mod-kit", "unblob", "fwhunt", "firmadyne"]
    },
    "hunt api keys": {
      keywords: ["secret hunting", "leaked keys", "git secrets", "trufflehog", "gitleaks", "api token leak", "credential scan"],
      primaryTools: ["trufflehog", "gitleaks", "git-secrets", "shhgit", "earlybird"]
    },
    "reverse shell": {
      keywords: ["reverse shell", "payload generator", "interactive tty", "msfvenom", "pty spawn", "shell generator"],
      primaryTools: ["revshells", "pwncat", "conpty", "socat", "webshell", "shellerator"]
    },
    "osint reconnaissance": {
      keywords: ["osint", "recon", "reconnaissance", "footprinting", "whois", "intel", "social engineering", "subdomain enum"],
      primaryTools: ["theharvester", "spiderfoot", "recon-ng", "amass", "maltego", "sherlock", "holehe"]
    },
    "bypass cloudflare": {
      keywords: ["cloudflare origin", "origin ip", "dns history", "waf bypass", "censys", "shodan", "real ip"],
      primaryTools: ["cloudfail", "bypass-firewalls-by-DNS-history", "hatcloud", "shodan"]
    },
    "malware analysis": {
      keywords: ["malware", "sandbox", "cape", "remnux", "reverse engineering", "yara", "floss", "malwarebazaar", "static analysis", "dynamic analysis", "capa"],
      primaryTools: ["cape", "remnux", "yara", "capa", "floss", "ghidra", "pe-sieve", "volatility3"]
    },
    "reverse engineering": {
      keywords: ["ghidra", "decompiler", "disassembler", "radare2", "cutter", "x64dbg", "binary analysis", "elf", "pe"],
      primaryTools: ["ghidra", "radare2", "cutter", "x64dbg", "binwalk", "angr"]
    },
    "purple team": {
      keywords: ["purple team", "adversary emulation", "atomic red team", "caldera", "purplesharp", "attack range", "mitre attack"],
      primaryTools: ["caldera", "purplesharp", "atomic-red-team", "attack-range"]
    },
    "siem monitoring": {
      keywords: ["siem", "wazuh", "velociraptor", "osquery", "zeek", "suricata", "snort", "opensearch", "graylog", "loki", "thehive", "log monitoring"],
      primaryTools: ["wazuh", "velociraptor", "osquery", "zeek", "suricata", "snort", "thehive", "opensearch"]
    },
    "supply chain audit": {
      keywords: ["supply chain", "sast", "semgrep", "trivy", "checkov", "gitleaks", "trufflehog", "syft", "grype", "osv-scanner", "dependency-check"],
      primaryTools: ["semgrep", "trivy", "checkov", "gitleaks", "trufflehog", "syft", "grype", "osv-scanner"]
    },
    "vulnerable lab": {
      keywords: ["vulnerable lab", "practice lab", "ctf", "picoctf", "portswigger", "juice shop", "dvwa", "metasploitable", "vulnhub", "tryhackme", "hack the box"],
      primaryTools: ["juice-shop", "dvwa", "metasploitable", "vulnhub"]
    },
    "radio forensics": {
      keywords: ["radio", "rf", "sdr", "emf", "tempest", "signal", "spectrum", "demodulation", "iq", "rtl-sdr", "hackrf", "gnuradio", "urh", "inspectrum", "gqrx", "sdrangel", "satellite", "satnogs"],
      primaryTools: ["urh", "universal radio hacker", "inspectrum", "tempestsdr", "sigdigger", "sdrangel", "gnuradio", "gqrx", "rtl_433", "gr-gsm", "proxmark3", "dump1090", "satnogs-decoders", "gr-satellites"]
    },
    "radio forensic": {
      keywords: ["radio", "rf", "sdr", "emf", "tempest", "signal", "spectrum", "demodulation", "iq", "rtl-sdr", "hackrf", "gnuradio", "urh", "inspectrum", "gqrx", "sdrangel", "satellite", "satnogs"],
      primaryTools: ["urh", "universal radio hacker", "inspectrum", "tempestsdr", "sigdigger", "sdrangel", "gnuradio", "gqrx", "rtl_433", "gr-gsm", "proxmark3", "dump1090", "satnogs-decoders", "gr-satellites"]
    },
    "emf analysis": {
      keywords: ["emf", "tempest", "electromagnetic", "radiation", "side channel", "eavesdropping", "sdr", "tempestsdr"],
      primaryTools: ["tempestsdr", "hackrf", "rtl-sdr"]
    }
  };

  // Helper: Format ISO Update Time
  function formatUpdateTime(dateStr) {
    if (!dateStr) return '';
    try {
      const d = new Date(dateStr);
      if (isNaN(d.getTime())) return '';
      const now = new Date();
      const diffDays = Math.floor((now - d) / (1000 * 60 * 60 * 24));
      if (diffDays <= 0) return 'Today';
      if (diffDays === 1) return 'Yesterday';
      if (diffDays < 30) return `${diffDays}d ago`;
      if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo ago`;
      return `${Math.floor(diffDays / 365)}y ago`;
    } catch (e) {
      return (dateStr || '').slice(0, 10);
    }
  }

  // Cyber Synonym & Typo Mapping
  const SYNONYMS_AND_CORRECTIONS = {
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
    "ad": ["active directory", "ad", "domain", "kerberos", "ldap", "ntds"],
    "adcs": ["adcs", "ad cs", "certificate", "esc1", "pkinit"],
    "edr": ["edr", "evasion", "bypass", "amsi", "defender", "unhook"],
    "c2": ["c2", "c&c", "command and control", "beacon", "implant", "post-exploitation"],
    "osint": ["osint", "recon", "reconnaissance", "subdomain", "discovery"],
    "passwrod": ["password", "hash", "cred", "credentials"],
    "passwd": ["password", "hash", "cred", "credentials"],
    "creds": ["credentials", "password", "hash", "secrets"],
    "vuln": ["vulnerability", "cve", "exploit", "scanner"],
    "revers": ["reverse engineering", "decompiler", "disassembler", "binary"]
  };

  const KNOWN_VOCAB = [
    "network", "pentest", "penetration", "wireless", "wifi", "password", "hash",
    "privilege", "escalation", "active", "directory", "windows", "linux",
    "evasion", "bypass", "reverse", "engineering", "exploit", "scanner",
    "vulnerability", "c2", "firmware", "memory", "forensics", "osint", "subdomain"
  ];

  // Curated Alternatives & Functional Peers Radar Matrix
  const CYBER_TOOL_ALTERNATIVES = {
    // Network Scanning & Host Discovery
    "nmap": ["masscan", "rustscan", "naabu", "zmap", "unicornscan", "zenmap"],
    "masscan": ["nmap", "rustscan", "naabu", "zmap"],
    "rustscan": ["nmap", "masscan", "naabu"],
    "naabu": ["nmap", "rustscan", "masscan"],
    "zmap": ["masscan", "nmap", "rustscan"],
    
    // Web Application & SQL Injection
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
    
    // Active Directory & Windows Credentials
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
    
    // RF, SDR & EMF Signal Forensics
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
    
    // Malware Analysis & Reverse Engineering
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
    
    // Password Cracking
    "hashcat": ["john", "john the ripper", "ophcrack", "crowbar"],
    "john": ["hashcat", "ophcrack", "crowbar"],
    "john the ripper": ["hashcat", "ophcrack", "crowbar"],
    "hydra": ["medusa", "patator", "crowbar", "ncrack"],
    "medusa": ["hydra", "patator", "ncrack"],
    
    // Wireless (Wi-Fi)
    "aircrack-ng": ["wifite", "hcxdumptool", "bettercap", "eaphammer"],
    "wifite": ["aircrack-ng", "hcxdumptool", "bettercap"],
    "hcxdumptool": ["hcxtools", "wifite", "aircrack-ng"],
    
    // Traffic & Sniffing
    "wireshark": ["tshark", "tcpdump", "termshark", "zeek", "suricata"],
    "tcpdump": ["tshark", "wireshark", "termshark"],
    "tshark": ["wireshark", "tcpdump"],
    "zeek": ["suricata", "snort", "wireshark"],
    "suricata": ["snort", "zeek", "wazuh"],
    "snort": ["suricata", "zeek"],
    
    // Secret Scanning
    "trufflehog": ["gitleaks", "git-hound", "shhgit", "detect-secrets"],
    "gitleaks": ["trufflehog", "git-hound", "detect-secrets"],
    
    // Defensive & SIEM
    "wazuh": ["osquery", "velociraptor", "security onion", "thehive"],
    "osquery": ["wazuh", "velociraptor", "kolide"],
    "velociraptor": ["wazuh", "osquery", "grr"],
    "thehive": ["misp", "cortex", "wazuh"]
  };

  function scoreToolSimilarityClient(tool, targetName) {
    if (!targetName) return { score: 0, type: 'NONE' };
    const target = targetName.toLowerCase().trim();
    const name = (tool.name || '').toLowerCase().trim();
    const repoUrl = (tool.repo_url || '').toLowerCase().trim();
    const category = (tool.category || '').toLowerCase().trim();
    const purpose = (tool.purpose_summary || '').toLowerCase().trim();
    const fullText = `${name} ${(tool.tagline || '').toLowerCase()} ${purpose} ${category} ${repoUrl}`;

    // 1. Exact Name Match
    if (name === target || repoUrl.endsWith('/' + target) || repoUrl.includes('/' + target + '.')) {
      return { score: 18000, type: 'EXACT_MATCH' };
    }

    // 2. Derivative / Ecosystem tool
    if (name.startsWith(target + '-') || name.startsWith(target + '_') || name.endsWith('-' + target)) {
      return { score: 10000, type: 'DERIVATIVE' };
    }

    // 3. Known Curated Alternatives
    const curatedAlts = CYBER_TOOL_ALTERNATIVES[target] || [];
    for (const alt of curatedAlts) {
      const altClean = alt.toLowerCase();
      if (name === altClean || repoUrl.endsWith('/' + altClean) || repoUrl.includes('/' + altClean + '.')) {
        return { score: 8500, type: 'CURATED_ALTERNATIVE' };
      } else if (name.includes(altClean)) {
        return { score: 6000, type: 'SIMILAR_ALTERNATIVE' };
      }
    }

    // Reverse curated alternative
    for (const [prime, alts] of Object.entries(CYBER_TOOL_ALTERNATIVES)) {
      if (prime === name && alts.includes(target)) {
        return { score: 8500, type: 'CURATED_ALTERNATIVE' };
      }
    }

    // 4. Substring in tool name
    if (name.includes(target)) {
      return { score: 5000, type: 'NAME_SUBSTRING' };
    }

    // 5. Substring in repository URL
    if (repoUrl.includes('/' + target)) {
      return { score: 4000, type: 'REPO_MATCH' };
    }

    // 6. Mentioned in purpose / capabilities
    const regex = new RegExp('\\b' + target.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i');
    if (regex.test(fullText)) {
      return { score: 2200, type: 'CAPABILITY_PEER' };
    }

    return { score: 0, type: 'NONE' };
  }

  function cleanAndExpandQueryClient(q) {
    const rawWords = (q.toLowerCase().match(/[a-zA-Z0-9_-]+/g) || []);
    let didAutocorrect = false;
    const correctedWords = [];
    const expandedTerms = new Set();
    const primaryTools = new Set();

    rawWords.forEach(w => {
      let orig = w;
      if (w.includes('-') || w.includes('_')) {
        correctedWords.push(w);
        expandedTerms.add(w);
        w.split(/[-_]/).forEach(sp => {
          if (sp.length > 1) {
            expandedTerms.add(sp);
            correctedWords.push(sp);
          }
        });
        return;
      }
      if (SYNONYMS_AND_CORRECTIONS[w]) {
        const target = SYNONYMS_AND_CORRECTIONS[w][0];
        if (target !== w) {
          didAutocorrect = true;
          w = target;
        }
      }
      correctedWords.push(w);
      expandedTerms.add(w);
      if (SYNONYMS_AND_CORRECTIONS[w]) {
        SYNONYMS_AND_CORRECTIONS[w].forEach(s => expandedTerms.add(s));
      }
    });

    const cleanQ = correctedWords.join(' ');
    const qLower = q.toLowerCase();

    // Semantic Intent Identification across 12 Core Domains
    let canonicalIntent = null;
    let intentDescription = null;

    if (qLower.includes('radio') || qLower.includes(' rf') || qLower.startsWith('rf ') || qLower.includes('sdr') || qLower.includes('emf') || qLower.includes('tempest') || qLower.includes('spectrum')) {
      canonicalIntent = "Radio Frequency (RF), SDR & EMF Signal Forensics";
      intentDescription = "Radio spectrum investigation, SDR demodulation, EMF/TEMPEST radiation eavesdropping, RF protocol reverse engineering.";
    } else if (qLower.includes('malware') || qLower.includes('sandbox') || qLower.includes('reverse') || qLower.includes('yara') || qLower.includes('ghidra') || qLower.includes('capa') || qLower.includes('volatility')) {
      canonicalIntent = "Malware Analysis, Sandboxing & Reverse Engineering";
      intentDescription = "Static & dynamic malware analysis, automated sandboxing, binary disassembling & capability detection.";
    } else if (qLower.includes('adcs') || qLower.includes('certificate') || qLower.includes('kerberos') || qLower.includes('ntds') || qLower.includes('lsass') || qLower.includes('active directory')) {
      canonicalIntent = "Active Directory, Kerberos & Credential Escalation";
      intentDescription = "ADCS misconfiguration abuse, Kerberoasting, NTDS.dit extraction, ESC1-ESC8 privilege escalation, Pass-the-Hash.";
    } else if (qLower.includes('edr') || qLower.includes('bypass') || qLower.includes('evasion') || qLower.includes('amsi') || qLower.includes('unhook') || qLower.includes('syscall')) {
      canonicalIntent = "Defense Evasion & EDR / AMSI Bypass";
      intentDescription = "Direct syscalls, memory patching, DLL unhooking, and runtime payload obfuscation.";
    } else if (qLower.includes('wifi') || qLower.includes('pmkid') || qLower.includes('wpa') || qLower.includes('bluetooth') || qLower.includes('ble') || qLower.includes('nfc') || qLower.includes('rfid')) {
      canonicalIntent = "Wireless, Bluetooth (BLE) & NFC/RFID Exploitation";
      intentDescription = "Clientless PMKID capture, WPA2/WPA3 handshake cracking, BLE sniffing, and RFID/NFC cloning.";
    } else if (qLower.includes('graphql') || qLower.includes('api pentest') || qLower.includes('ssrf') || qLower.includes('sqli') || qLower.includes('jwt')) {
      canonicalIntent = "Web Application, API & GraphQL Exploitation";
      intentDescription = "GraphQL introspection & injection, API pentesting, SSRF, SQLi, IDOR, JWT tampering, Web App Security.";
    } else if (qLower.includes('pivot') || qLower.includes('tunnel') || qLower.includes('socks') || qLower.includes('chisel') || qLower.includes('ligolo') || qLower.includes('c2') || qLower.includes('beacon')) {
      canonicalIntent = "Network Pivoting, Tunneling & Command and Control (C2)";
      intentDescription = "SOCKS5 proxy chaining, TUN/TAP interface tunneling, reverse proxies, post-exploitation red team implants & beacons.";
    } else if (qLower.includes('canbus') || qLower.includes('can bus') || qLower.includes('obd') || qLower.includes('ecu') || qLower.includes('automotive')) {
      canonicalIntent = "Automotive Security, CAN Bus & ECU Reverse Engineering";
      intentDescription = "Controller Area Network (CAN), OBD-II diagnostic sniffing, ECU firmware extraction, UDS protocol analysis.";
    } else if (qLower.includes('docker') || qLower.includes('kubernetes') || qLower.includes('k8s') || qLower.includes('cloud') || qLower.includes('aws') || qLower.includes('azure') || qLower.includes('gcp')) {
      canonicalIntent = "Cloud Infrastructure, Container Breakout & Kubernetes";
      intentDescription = "AWS, Azure, GCP audit, S3 bucket enumeration, Docker container escape, Kubernetes escalation.";
    } else if (qLower.includes('osint') || qLower.includes('subdomain') || qLower.includes('recon') || qLower.includes('theharvester') || qLower.includes('amass')) {
      canonicalIntent = "OSINT, Attack Surface Management & Reconnaissance";
      intentDescription = "Passive subdomain enumeration, open source intelligence, asset mapping, certificate transparency, threat intelligence.";
    } else if (qLower.includes('firmware') || qLower.includes('binwalk') || qLower.includes('jtag') || qLower.includes('uart') || qLower.includes('iot')) {
      canonicalIntent = "IoT Firmware Extraction & Hardware Hacking";
      intentDescription = "Firmware binary unpacking, JTAG/UART serial debugging, SPI flash dumping, embedded Linux architecture reverse engineering.";
    } else if (qLower.includes('privesc') || qLower.includes('privilege escalation') || qLower.includes('linpeas') || qLower.includes('winpeas') || qLower.includes('uac')) {
      canonicalIntent = "Local Privilege Escalation & Audit (Linux & Windows)";
      intentDescription = "Sudo misconfiguration abuse, Windows Token / UAC impersonation, kernel privilege escalation, automated audit.";
    }

    // Check Purpose Operational Matrix
    Object.keys(PURPOSE_OPERATIONAL_MATRIX).forEach(purposeKey => {
      const pData = PURPOSE_OPERATIONAL_MATRIX[purposeKey];
      if (qLower.includes(purposeKey) || cleanQ.includes(purposeKey)) {
        pData.keywords.forEach(kw => expandedTerms.add(kw));
        pData.primaryTools.forEach(pt => primaryTools.add(pt));
      } else {
        const pTokens = purposeKey.split(' ');
        if (pTokens.every(tok => correctedWords.includes(tok))) {
          pData.keywords.forEach(kw => expandedTerms.add(kw));
          pData.primaryTools.forEach(pt => primaryTools.add(pt));
        }
      }
    });

    return {
      originalQuery: q,
      correctedQuery: cleanQ,
      tokens: correctedWords,
      expandedTerms: Array.from(expandedTerms),
      primaryTools: Array.from(primaryTools),
      canonicalIntent: canonicalIntent,
      intentDescription: intentDescription,
      autocorrected: didAutocorrect
    };
  }

  // Domain & Category Visual Identity Map
  function getCategoryIcon(cat) {
    const c = (cat || '').toLowerCase();
    if (c.includes('radio') || c.includes('wireless') || c.includes('rf') || c.includes('sdr')) return '📻';
    if (c.includes('active directory') || c.includes('windows') || c.includes('kerberos') || c.includes('identity')) return '🗝️';
    if (c.includes('web') || c.includes('http') || c.includes('sql') || c.includes('graphql')) return '🌐';
    if (c.includes('malware') || c.includes('reverse') || c.includes('binary')) return '🔬';
    if (c.includes('forensic') || c.includes('dfir') || c.includes('memory')) return '🔍';
    if (c.includes('evasion') || c.includes('edr') || c.includes('bypass')) return '🛡️';
    if (c.includes('privilege') || c.includes('privesc')) return '⚡';
    if (c.includes('c2') || c.includes('command') || c.includes('control')) return '👑';
    if (c.includes('network') || c.includes('port') || c.includes('scan')) return '📡';
    if (c.includes('osint') || c.includes('recon') || c.includes('subdomain')) return '🕵️';
    if (c.includes('password') || c.includes('hash') || c.includes('crack')) return '🔐';
    if (c.includes('cloud') || c.includes('container') || c.includes('docker') || c.includes('kubernetes')) return '☁️';
    if (c.includes('hardware') || c.includes('firmware') || c.includes('iot')) return '🔌';
    if (c.includes('voip') || c.includes('telephony') || c.includes('asterisk')) return '📞';
    if (c.includes('threat') || c.includes('enrich') || c.includes('intelligence')) return '📊';
    return '🛠️';
  }

  // Client-Side Semantic Purpose Synthesizer (Eliminates uninformative developer descriptions)
  function synthesizeOperationalPurposeClient(name, rawDesc, path, category, language) {
    const cleanDesc = (rawDesc || '').trim();
    const isGeneric = (
      !cleanDesc ||
      cleanDesc.startsWith('Public GitLab project:') ||
      cleanDesc.startsWith('Public GitHub repository:') ||
      cleanDesc.startsWith('Automatically exported from code.google.com') ||
      cleanDesc.startsWith('Mirror of ') ||
      cleanDesc.length < 22 ||
      cleanDesc.toLowerCase() === (name || '').toLowerCase() ||
      cleanDesc.toLowerCase() === `${(name || '').toLowerCase()} tool` ||
      cleanDesc.toLowerCase().includes('module for lua') ||
      (cleanDesc.toLowerCase().includes('module for') && cleanDesc.length < 65) ||
      (cleanDesc.toLowerCase().includes('library for') && cleanDesc.length < 65) ||
      (cleanDesc.toLowerCase().includes('client for') && cleanDesc.length < 65)
    );

    if (!isGeneric) {
      let capitalized = cleanDesc.charAt(0).toUpperCase() + cleanDesc.slice(1);
      if (!capitalized.endsWith('.')) capitalized += '.';
      return capitalized;
    }

    const blob = `${name} ${path || ''} ${category || ''} ${language || ''}`.toLowerCase().replace(/[-_/]/g, ' ');

    if (blob.includes('enrich') || blob.includes('enricher') || blob.includes('ioc') || blob.includes('indicator')) {
      if (blob.includes('company') || blob.includes('advectus')) {
        return "Company threat intelligence and OSINT enrichment module, engineered to query corporate records, aggregate identity details, and enrich attack surface profiling.";
      }
      if (blob.includes('coordinator') || blob.includes('lookup')) {
        return "Centralized data enrichment coordinator, designed to schedule lookup queries against threat intelligence APIs, correlate target records, and streamline security analysis.";
      }
      return "Threat intelligence and data enrichment utility designed to ingest security indicators, query external threat intelligence feeds, and append investigative context.";
    }

    if (blob.includes('memcache') || blob.includes('memcached')) {
      const lang = language && language !== 'GitLab Project' ? language : 'Lua/Network';
      return `High-performance ${lang} client library for Memcached, used in network services, API gateways, and penetration testing automation to read, cache, and manipulate in-memory session data.`;
    }

    if (blob.includes('agi') || blob.includes('asterisk') || blob.includes('voip') || blob.includes('telephony')) {
      return "Asterisk Gateway Interface (AGI) telephony integration tool, used for automated VoIP call handling, PBX trunk security auditing, and telecommunications monitoring.";
    }

    if (blob.includes('lsass') || blob.includes('ntds') || blob.includes('mimikatz') || blob.includes('dump') || blob.includes('hash')) {
      return "Credential extraction and authentication auditing utility, engineered to dump in-memory hashes, extract stored credentials, and audit authentication secrets.";
    }

    if (blob.includes('active directory') || blob.includes('kerberos') || blob.includes('adcs') || blob.includes('bloodhound')) {
      return "Active Directory security auditing tool, utilized to inspect domain permissions, map privilege escalation paths, and analyze Kerberos delegation vulnerabilities.";
    }

    if (blob.includes('radio') || blob.includes('rf') || blob.includes('sdr') || blob.includes('signal') || blob.includes('tempest') || blob.includes('emf')) {
      return "Radio Frequency (RF) and Software Defined Radio (SDR) signal analysis tool, used to capture wireless transmissions, inspect spectrum waterfalls, and demodulate telemetry data.";
    }

    if (blob.includes('malware') || blob.includes('reverse') || blob.includes('ghidra') || blob.includes('yara') || blob.includes('binary')) {
      return "Binary analysis and reverse engineering tool, built to decompile executable binaries, analyze obfuscated code, and detect suspicious software capabilities.";
    }

    if (blob.includes('sql') || blob.includes('graphql') || blob.includes('xss') || blob.includes('jwt') || blob.includes('web')) {
      return "Web application vulnerability scanning utility, designed to test input validation controls, identify injection vulnerabilities, and audit API authentication endpoints.";
    }

    if (blob.includes('scan') || blob.includes('port') || blob.includes('nmap') || blob.includes('naabu')) {
      return "Network host discovery and port auditing tool, used to map active IP addresses, detect exposed services, and identify open network communication channels.";
    }

    const cleanName = (name || '').replace(/[-_]/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    const catText = category && category !== 'General Security & Exploitation' ? category : 'cybersecurity';
    return `Specialized operational utility for ${cleanName}, applied in ${catText.toLowerCase()} workflows, automated scripting, and systems verification.`;
  }

  // State Management
  const state = {
    isDynamicServer: false,
    allTools: [],
    customTools: [],
    starredIds: new Set(),
    purposeQuery: '',
    toolQuery: '',
    searchQuery: '',
    selectedCategory: 'all',
    selectedDistro: 'all',
    selectedRarity: 'all',
    selectedSource: 'all',
    selectedSort: 'relevance',
    onlyGithub: false,
    onlyFavorites: false,
    activePurposeChip: null,
    activeModalTool: null,
    selectedToolsForBatch: new Set(),
    page: 1,
    pageSize: 60,
    hasMore: true,
    totalMatching: 0,
    isLiveSearchingGithub: false
  };

  // DOM Elements
  const el = {
    toolsGrid: document.getElementById('toolsGrid'),
    emptyState: document.getElementById('emptyState'),
    emptyQueryText: document.getElementById('emptyQueryText'),
    emptyStateGithubSearchBtn: document.getElementById('emptyStateGithubSearchBtn'),
    autocorrectBanner: document.getElementById('autocorrectBanner'),
    autocorrectedQuery: document.getElementById('autocorrectedQuery'),
    originalQuery: document.getElementById('originalQuery'),
    searchOriginalBtn: document.getElementById('searchOriginalBtn'),

    // Dual Dedicated Search Elements
    purposeSearch: document.getElementById('purposeSearch'),
    clearPurpose: document.getElementById('clearPurpose'),
    toolSearch: document.getElementById('toolSearch'),
    clearTool: document.getElementById('clearTool'),
    dualSearchActiveBanner: document.getElementById('dualSearchActiveBanner'),
    activePurposePill: document.getElementById('activePurposePill'),
    activePurposeText: document.getElementById('activePurposeText'),
    removePurposePill: document.getElementById('removePurposePill'),
    activeToolPill: document.getElementById('activeToolPill'),
    activeToolText: document.getElementById('activeToolText'),
    removeToolPill: document.getElementById('removeToolPill'),
    similarityRadarContainer: document.getElementById('similarityRadarContainer'),
    similarityRadarPills: document.getElementById('similarityRadarPills'),
    clearAllSearchBtn: document.getElementById('clearAllSearchBtn'),

    // Fallbacks
    mainSearch: document.getElementById('purposeSearch') || document.getElementById('mainSearch'),
    clearSearch: document.getElementById('clearPurpose') || document.getElementById('clearSearch'),

    purposeChips: document.querySelectorAll('.purpose-chip'),
    categorySelect: document.getElementById('categorySelect'),
    distroSelect: document.getElementById('distroSelect'),
    sourceSelect: document.getElementById('sourceSelect'),
    sortSelect: document.getElementById('sortSelect'),
    cacheSpeedBadge: document.getElementById('cacheSpeedBadge'),
    rarityToggles: document.querySelectorAll('[data-rarity]'),
    resultsCount: document.getElementById('resultsCount'),
    renderedCount: document.getElementById('renderedCount'),
    streamAllBtn: document.getElementById('streamAllBtn'),
    infiniteScrollStatus: document.getElementById('infiniteScrollStatus'),
    totalLoadedCount: document.getElementById('totalLoadedCount'),
    totalToolsStat: document.getElementById('totalToolsStat'),
    githubStat: document.getElementById('githubStat'),
    blackarchStat: document.getElementById('blackarchStat'),
    rareStat: document.getElementById('rareStat'),
    favCountBadge: document.getElementById('favCountBadge'),
    favToggleBtn: document.getElementById('favToggleBtn'),
    githubOnlyToggleBtn: document.getElementById('githubOnlyToggleBtn'),
    githubCountBadge: document.getElementById('githubCountBadge'),
    githubFilteredIndicator: document.getElementById('githubFilteredIndicator'),
    searchGlobalGithubBtn: document.getElementById('searchGlobalGithubBtn'),
    liveSearchingStatus: document.getElementById('liveSearchingStatus'),
    toast: document.getElementById('toast'),
    toastMsg: document.getElementById('toastMsg'),

    // Dynamic Live Feed Elements
    syncStatusText: document.getElementById('syncStatusText'),
    syncNowBtn: document.getElementById('syncNowBtn'),
    syncModal: document.getElementById('syncModal'),
    syncConsole: document.getElementById('syncConsole'),
    closeSyncModalBtn: document.getElementById('closeSyncModalBtn'),

    // Pagination
    paginationBar: document.getElementById('paginationBar'),
    loadMoreBtn: document.getElementById('loadMoreBtn'),

    // Tool Modal
    toolModal: document.getElementById('toolModal'),
    modalToolName: document.getElementById('modalToolName'),
    modalToolBadge: document.getElementById('modalToolBadge'),
    modalSourceBadge: document.getElementById('modalSourceBadge'),
    modalCategory: document.getElementById('modalCategory'),
    modalHacktricksBtn: document.getElementById('modalHacktricksBtn'),
    modalMediumBtn: document.getElementById('modalMediumBtn'),
    modalFindSimilarBtn: document.getElementById('modalFindSimilarBtn'),
    modalRepoLink: document.getElementById('modalRepoLink'),
    modalReleaseLink: document.getElementById('modalReleaseLink'),
    modalBlackarchLink: document.getElementById('modalBlackarchLink'),
    modalTagline: document.getElementById('modalTagline'),
    modalPurposeText: document.getElementById('modalPurposeText'),
    modalNotes: document.getElementById('modalNotes'),
    modalArticlesList: document.getElementById('modalArticlesList'),
    modalMetaSource: document.getElementById('modalMetaSource'),
    modalMetaLang: document.getElementById('modalMetaLang'),
    modalMetaStars: document.getElementById('modalMetaStars'),
    modalMetaCategory: document.getElementById('modalMetaCategory'),

    // Custom Tool Modal
    customToolModal: document.getElementById('customToolModal'),
    addCustomToolBtn: document.getElementById('addCustomToolBtn'),
    customToolForm: document.getElementById('customToolForm'),

    // Batch Script Modal
    batchScriptModal: document.getElementById('batchScriptModal'),
    batchScriptBtn: document.getElementById('batchScriptBtn'),
    batchToolChecklist: document.getElementById('batchToolChecklist'),
    batchDistroRadioArch: document.getElementById('batchDistroArch'),
    batchDistroRadioDebian: document.getElementById('batchDistroDebian'),
    batchScriptOutput: document.getElementById('batchScriptOutput'),
    copyBatchScriptBtn: document.getElementById('copyBatchScriptBtn'),

    // Export / Import
    exportJsonBtn: document.getElementById('exportJsonBtn'),
    importJsonBtn: document.getElementById('importJsonBtn'),
    importFileInput: document.getElementById('importFileInput')
  };

  // Initialize
  async function init() {
    loadLocalFavorites();
    setupEventListeners();
    await checkDynamicServer();
    renderStats();
    resetAndFetchTools();
  }

  // Load Starred Tools from LocalStorage
  function loadLocalFavorites() {
    try {
      const storedStars = localStorage.getItem('p2t_starred_tools');
      if (storedStars) {
        state.starredIds = new Set(JSON.parse(storedStars));
      }
    } catch (e) {
      console.warn('Could not load starred tools', e);
    }

    try {
      const storedCustom = localStorage.getItem('p2t_custom_tools');
      if (storedCustom) {
        state.customTools = JSON.parse(storedCustom);
      }
    } catch (e) {
      console.warn('Could not load custom tools', e);
    }
  }

  // Check if Dynamic FastAPI Server is Running
  async function checkDynamicServer() {
    try {
      const res = await fetch(`${API_BASE}/api/sync/status`, { method: 'GET', cache: 'no-store' });
      if (res.ok) {
        state.isDynamicServer = true;
        const status = await res.json();
        updateSyncStatusUI(status, true);
        return;
      }
    } catch (e) {
      state.isDynamicServer = false;
    }

    // Fallback to locally bundled dynamic database
    const localDb = window.DYNAMIC_TOOLS_DB || window.TOOLS_DB || [];
    state.allTools = [...localDb, ...state.customTools];
    const ghCount = state.allTools.filter(t => t.repo_url && t.repo_url.includes('github.com')).length;
    updateSyncStatusUI({
      last_sync: "Cached",
      total_tools: state.allTools.length || 3608,
      github_count: ghCount || 2694
    }, false);
    populateCategoryDropdown();
  }

  function updateSyncStatusUI(status, isLive) {
    if (el.syncStatusText) {
      const last = status.last_sync ? new Date(status.last_sync).toLocaleTimeString() : 'Local Cache';
      const gh = status.github_count || 2694;
      if (isLive) {
        el.syncStatusText.innerHTML = `<span style="color: var(--neon-green)">● LIVE UPSTREAM ACTIVE</span> &bull; <strong style="color: var(--neon-purple);">${gh.toLocaleString()} GitHub Repos</strong> &bull; BlackArch (2,860+) &bull; Synced: ${last}`;
      } else {
        el.syncStatusText.innerHTML = `<span style="color: var(--neon-cyan)">● DYNAMIC CACHE LOADED</span> &bull; ${status.total_tools || state.allTools.length} Tools (${gh} GitHub)`;
      }
    }
  }

  // Populate Categories
  function populateCategoryDropdown() {
    const categories = new Set();
    state.allTools.forEach(t => {
      if (t.category) categories.add(t.category);
    });

    const sortedCats = Array.from(categories).sort();
    sortedCats.forEach(cat => {
      const opt = document.createElement('option');
      opt.value = cat;
      opt.textContent = cat;
      el.categorySelect.appendChild(opt);
    });
  }

  // Render High-Level Counters
  function renderStats() {
    const total = state.isDynamicServer ? (el.totalToolsStat.textContent || '3,608') : state.allTools.length;
    const ghCount = state.allTools.filter(t => t.repo_url && t.repo_url.includes('github.com')).length || 2694;
    const rareCount = state.allTools.filter(t => t.rarity === 'rare').length || '3,100+';
    const blackarchCount = state.allTools.filter(t => t.distros && t.distros.blackarch).length || '2,868';
    const favCount = state.starredIds.size;

    if (el.totalToolsStat) el.totalToolsStat.textContent = total;
    if (el.totalLoadedCount) el.totalLoadedCount.textContent = total;
    if (el.githubStat) el.githubStat.textContent = ghCount.toLocaleString();
    if (el.githubCountBadge) el.githubCountBadge.textContent = ghCount.toLocaleString();
    if (el.rareStat) el.rareStat.textContent = rareCount;
    if (el.blackarchStat) el.blackarchStat.textContent = blackarchCount;
    if (el.favCountBadge) el.favCountBadge.textContent = favCount;
  }

  // Synchronize Active Search Indicator Banner
  function updateDualSearchBanner() {
    const hasPurpose = !!state.purposeQuery;
    const hasTool = !!state.toolQuery;

    if (hasPurpose || hasTool) {
      if (el.dualSearchActiveBanner) el.dualSearchActiveBanner.style.display = 'flex';

      if (hasPurpose && el.activePurposePill) {
        el.activePurposePill.style.display = 'inline-flex';
        if (el.activePurposeText) el.activePurposeText.textContent = state.purposeQuery;
      } else if (el.activePurposePill) {
        el.activePurposePill.style.display = 'none';
      }

      if (hasTool && el.activeToolPill) {
        el.activeToolPill.style.display = 'inline-flex';
        if (el.activeToolText) el.activeToolText.textContent = state.toolQuery;

        // Render interactive alternatives if available
        const tClean = state.toolQuery.toLowerCase().trim();
        const alts = CYBER_TOOL_ALTERNATIVES[tClean] || [];
        if (alts.length > 0 && el.similarityRadarContainer && el.similarityRadarPills) {
          el.similarityRadarContainer.style.display = 'inline-flex';
          el.similarityRadarPills.innerHTML = '';
          alts.slice(0, 6).forEach(alt => {
            const chip = document.createElement('span');
            chip.className = 'radar-chip';
            chip.textContent = alt;
            chip.title = `Switch to alternative: ${alt}`;
            chip.addEventListener('click', () => {
              findSimilarTools(alt);
            });
            el.similarityRadarPills.appendChild(chip);
          });
        } else if (el.similarityRadarContainer) {
          el.similarityRadarContainer.style.display = 'none';
        }
      } else {
        if (el.activeToolPill) el.activeToolPill.style.display = 'none';
        if (el.similarityRadarContainer) el.similarityRadarContainer.style.display = 'none';
      }
    } else {
      if (el.dualSearchActiveBanner) el.dualSearchActiveBanner.style.display = 'none';
      if (el.similarityRadarContainer) el.similarityRadarContainer.style.display = 'none';
    }
  }

  // Find Similar Tools Helper (Populates toolSearch and triggers similarity radar)
  function findSimilarTools(toolName) {
    if (!toolName) return;
    if (el.toolSearch) el.toolSearch.value = toolName;
    state.toolQuery = toolName.toLowerCase().trim();
    state.searchQuery = state.toolQuery || state.purposeQuery;
    if (el.clearTool) el.clearTool.style.display = 'flex';
    updateDualSearchBanner();
    showToast(`Discovering functional peers & alternatives for "${toolName}"...`);
    resetAndFetchTools();
    const targetEl = document.querySelector('.dual-search-container');
    if (targetEl) {
      window.scrollTo({ top: targetEl.offsetTop - 60, behavior: 'smooth' });
    }
  }

  // Setup Event Listeners
  function setupEventListeners() {
    let searchDebounce = null;

    // Box 1: Purpose / Task Search Input
    if (el.purposeSearch) {
      el.purposeSearch.addEventListener('input', (e) => {
        state.purposeQuery = e.target.value.trim().toLowerCase();
        state.searchQuery = state.purposeQuery || state.toolQuery;
        if (el.clearPurpose) el.clearPurpose.style.display = state.purposeQuery ? 'flex' : 'none';
        if (el.emptyQueryText) el.emptyQueryText.textContent = state.purposeQuery || state.toolQuery;

        if (state.activePurposeChip) {
          state.activePurposeChip.classList.remove('active');
          state.activePurposeChip = null;
        }
        updateDualSearchBanner();
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
          resetAndFetchTools();
        }, 200);
      });
    }

    // Box 1: Clear Purpose Button
    if (el.clearPurpose) {
      el.clearPurpose.addEventListener('click', () => {
        if (el.purposeSearch) el.purposeSearch.value = '';
        state.purposeQuery = '';
        state.searchQuery = state.toolQuery;
        el.clearPurpose.style.display = 'none';
        if (el.autocorrectBanner) el.autocorrectBanner.style.display = 'none';
        if (state.activePurposeChip) {
          state.activePurposeChip.classList.remove('active');
          state.activePurposeChip = null;
        }
        updateDualSearchBanner();
        resetAndFetchTools();
        if (el.purposeSearch) el.purposeSearch.focus();
      });
    }

    // Box 2: Direct Tool Name & Similarity Search Input
    if (el.toolSearch) {
      el.toolSearch.addEventListener('input', (e) => {
        state.toolQuery = e.target.value.trim().toLowerCase();
        state.searchQuery = state.toolQuery || state.purposeQuery;
        if (el.clearTool) el.clearTool.style.display = state.toolQuery ? 'flex' : 'none';
        if (el.emptyQueryText) el.emptyQueryText.textContent = state.toolQuery || state.purposeQuery;

        updateDualSearchBanner();
        clearTimeout(searchDebounce);
        searchDebounce = setTimeout(() => {
          resetAndFetchTools();
        }, 200);
      });
    }

    // Box 2: Clear Tool Button
    if (el.clearTool) {
      el.clearTool.addEventListener('click', () => {
        if (el.toolSearch) el.toolSearch.value = '';
        state.toolQuery = '';
        state.searchQuery = state.purposeQuery;
        el.clearTool.style.display = 'none';
        updateDualSearchBanner();
        resetAndFetchTools();
        if (el.toolSearch) el.toolSearch.focus();
      });
    }

    // Dual Search Banner Reset Buttons
    if (el.clearAllSearchBtn) {
      el.clearAllSearchBtn.addEventListener('click', () => {
        if (el.purposeSearch) el.purposeSearch.value = '';
        if (el.toolSearch) el.toolSearch.value = '';
        state.purposeQuery = '';
        state.toolQuery = '';
        state.searchQuery = '';
        if (el.clearPurpose) el.clearPurpose.style.display = 'none';
        if (el.clearTool) el.clearTool.style.display = 'none';
        if (el.autocorrectBanner) el.autocorrectBanner.style.display = 'none';
        if (state.activePurposeChip) {
          state.activePurposeChip.classList.remove('active');
          state.activePurposeChip = null;
        }
        updateDualSearchBanner();
        resetAndFetchTools();
      });
    }

    if (el.removePurposePill) {
      el.removePurposePill.addEventListener('click', () => {
        if (el.clearPurpose) el.clearPurpose.click();
      });
    }

    if (el.removeToolPill) {
      el.removeToolPill.addEventListener('click', () => {
        if (el.clearTool) el.clearTool.click();
      });
    }

    // Modal Find Similar Tools Button
    if (el.modalFindSimilarBtn) {
      el.modalFindSimilarBtn.addEventListener('click', () => {
        if (state.activeModalTool) {
          const name = state.activeModalTool.name;
          closeAllModals();
          findSimilarTools(name);
        }
      });
    }

    // Purpose Chips (Populate Box 1: Purpose Search)
    el.purposeChips.forEach(chip => {
      chip.addEventListener('click', () => {
        const query = chip.getAttribute('data-purpose').toLowerCase();
        if (state.activePurposeChip === chip) {
          chip.classList.remove('active');
          state.activePurposeChip = null;
          if (el.purposeSearch) el.purposeSearch.value = '';
          state.purposeQuery = '';
          state.searchQuery = state.toolQuery || '';
          if (el.clearPurpose) el.clearPurpose.style.display = 'none';
        } else {
          if (state.activePurposeChip) state.activePurposeChip.classList.remove('active');
          chip.classList.add('active');
          state.activePurposeChip = chip;
          if (el.purposeSearch) el.purposeSearch.value = query;
          state.purposeQuery = query;
          state.searchQuery = query;
          if (el.clearPurpose) el.clearPurpose.style.display = 'flex';
        }
        updateDualSearchBanner();
        resetAndFetchTools();
      });
    });

    // Dropdown filters
    if (el.categorySelect) {
      el.categorySelect.addEventListener('change', (e) => {
        state.selectedCategory = e.target.value;
        resetAndFetchTools();
      });
    }

    if (el.distroSelect) {
      el.distroSelect.addEventListener('change', (e) => {
        state.selectedDistro = e.target.value;
        resetAndFetchTools();
      });
    }

    if (el.sourceSelect) {
      el.sourceSelect.addEventListener('change', (e) => {
        state.selectedSource = e.target.value;
        if (state.selectedSource === 'github') {
          state.onlyGithub = true;
          el.githubOnlyToggleBtn.classList.add('active');
          el.githubFilteredIndicator.style.display = 'inline';
        } else {
          state.onlyGithub = false;
          el.githubOnlyToggleBtn.classList.remove('active');
          el.githubFilteredIndicator.style.display = 'none';
        }
        resetAndFetchTools();
      });
    }

    if (el.sortSelect) {
      el.sortSelect.addEventListener('change', (e) => {
        state.selectedSort = e.target.value;
        resetAndFetchTools();
      });
    }

    // GitHub Only Toggle Button
    if (el.githubOnlyToggleBtn) {
      el.githubOnlyToggleBtn.addEventListener('click', () => {
        el.githubOnlyToggleBtn.classList.toggle('active');
        state.onlyGithub = el.githubOnlyToggleBtn.classList.contains('active');
        el.githubFilteredIndicator.style.display = state.onlyGithub ? 'inline' : 'none';
        if (state.onlyGithub && el.sourceSelect) {
          el.sourceSelect.value = 'github';
        } else if (!state.onlyGithub && el.sourceSelect && el.sourceSelect.value === 'github') {
          el.sourceSelect.value = 'all';
          state.selectedSource = 'all';
        }
        resetAndFetchTools();
      });
    }

    // Live Worldwide GitHub Search Trigger
    if (el.searchGlobalGithubBtn) {
      el.searchGlobalGithubBtn.addEventListener('click', () => {
        const query = state.searchQuery || prompt('Enter tool name, topic, or keyword to search all of GitHub worldwide:');
        if (query) {
          el.mainSearch.value = query;
          state.searchQuery = query.toLowerCase();
          searchLiveGitHub(query);
        }
      });
    }

    if (el.emptyStateGithubSearchBtn) {
      el.emptyStateGithubSearchBtn.addEventListener('click', () => {
        if (state.searchQuery) {
          searchLiveGitHub(state.searchQuery);
        }
      });
    }

    // Rarity toggles
    el.rarityToggles.forEach(btn => {
      btn.addEventListener('click', () => {
        el.rarityToggles.forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        state.selectedRarity = btn.getAttribute('data-rarity');
        resetAndFetchTools();
      });
    });

    // Favorites filter button
    if (el.favToggleBtn) {
      el.favToggleBtn.addEventListener('click', () => {
        el.favToggleBtn.classList.toggle('active');
        state.onlyFavorites = el.favToggleBtn.classList.contains('active');
        resetAndFetchTools();
      });
    }

    // Load More Button & Infinite Stream
    if (el.loadMoreBtn) {
      el.loadMoreBtn.addEventListener('click', () => {
        state.page += 1;
        fetchAndAppendTools();
      });
    }

    if (el.streamAllBtn) {
      el.streamAllBtn.addEventListener('click', toggleStreamAll);
    }

    window.addEventListener('scroll', handleInfiniteScroll, { passive: true });

    // Dynamic Live Upstream Sync Button
    if (el.syncNowBtn) {
      el.syncNowBtn.addEventListener('click', handleTriggerSync);
    }

    if (el.closeSyncModalBtn) {
      el.closeSyncModalBtn.addEventListener('click', () => {
        el.syncModal.classList.remove('active');
      });
    }

    // Setup guide modal tabs
    document.querySelectorAll('.setup-tab-btn').forEach(tabBtn => {
      tabBtn.addEventListener('click', () => {
        document.querySelectorAll('.setup-tab-btn').forEach(b => b.classList.remove('active'));
        document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
        tabBtn.classList.add('active');
        const targetPane = document.getElementById(tabBtn.getAttribute('data-tab'));
        if (targetPane) targetPane.classList.add('active');
      });
    });

    // Tool Modal Distro Tab Buttons
    document.querySelectorAll('.modal-tab-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.modal-tab-btn').forEach(b => {
          b.classList.remove('active');
          b.style.borderBottomColor = 'transparent';
          b.style.color = 'var(--text-dim)';
        });
        document.querySelectorAll('.modal-tab-content').forEach(c => c.style.display = 'none');
        btn.classList.add('active');
        btn.style.borderBottomColor = 'var(--neon-cyan)';
        btn.style.color = '#ffffff';
        const targetId = btn.getAttribute('data-distro-tab');
        const targetPane = document.getElementById(targetId);
        if (targetPane) targetPane.style.display = 'block';
      });
    });

    // Keyboard shortcuts:
    // '/' focuses Purpose Search Box
    // 'Ctrl+T' or 'Alt+T' focuses Direct Tool & Similar Box
    window.addEventListener('keydown', (e) => {
      if (document.querySelector('.modal-overlay.active')) return;
      if (e.key === '/' && document.activeElement !== el.purposeSearch && document.activeElement !== el.toolSearch) {
        e.preventDefault();
        if (el.purposeSearch) {
          el.purposeSearch.focus();
          el.purposeSearch.select();
        }
      } else if ((e.ctrlKey || e.altKey) && e.key.toLowerCase() === 't') {
        e.preventDefault();
        if (el.toolSearch) {
          el.toolSearch.focus();
          el.toolSearch.select();
        }
      }
    });

    // Modal close triggers
    document.querySelectorAll('.modal-close-trigger').forEach(trigger => {
      trigger.addEventListener('click', closeAllModals);
    });

    window.addEventListener('click', (e) => {
      if (e.target.classList.contains('modal-overlay')) closeAllModals();
    });

    window.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeAllModals();
    });

    // Custom Tool
    if (el.addCustomToolBtn) {
      el.addCustomToolBtn.addEventListener('click', () => el.customToolModal.classList.add('active'));
    }
    if (el.customToolForm) {
      el.customToolForm.addEventListener('submit', handleAddCustomTool);
    }

    // Batch Script
    if (el.batchScriptBtn) {
      el.batchScriptBtn.addEventListener('click', openBatchScriptModal);
    }
    if (el.batchDistroRadioArch && el.batchDistroRadioDebian) {
      el.batchDistroRadioArch.addEventListener('change', generateBatchScript);
      el.batchDistroRadioDebian.addEventListener('change', generateBatchScript);
    }
    if (el.copyBatchScriptBtn) {
      el.copyBatchScriptBtn.addEventListener('click', () => {
        copyToClipboard(el.batchScriptOutput.value, 'Installation script copied to clipboard!');
      });
    }

    // Export / Import
    if (el.exportJsonBtn) el.exportJsonBtn.addEventListener('click', handleExportJson);
    if (el.importJsonBtn && el.importFileInput) {
      el.importJsonBtn.addEventListener('click', () => el.importFileInput.click());
      el.importFileInput.addEventListener('change', handleImportJson);
    }
  }

  // Reset and Fetch
  async function resetAndFetchTools() {
    state.page = 1;
    el.toolsGrid.innerHTML = '';
    await fetchAndAppendTools();
  }

  // Fetch and Append
  async function fetchAndAppendTools() {
    if (state.isDynamicServer) {
      await fetchFromServer();
    } else {
      await filterClientData();
    }
  }

  // Live Federated Search Across All Sources (queries live and streams continuously without stopping)
  async function searchLiveGitHub(query) {
    if (!query) return;
    el.mainSearch.value = query;
    state.searchQuery = query.toLowerCase();
    el.clearSearch.style.display = 'flex';
    showToast(`Broadcasting live search across all sources for "${query}"...`);
    resetAndFetchTools();
  }

  let isFetchingMore = false;
  let isAutoStreamingAll = false;

  async function handleInfiniteScroll() {
    if (isFetchingMore || isAutoStreamingAll) return;
    const scrollPosition = window.innerHeight + window.scrollY;
    const threshold = document.body.offsetHeight - 800;

    if (scrollPosition >= threshold) {
      const rendered = el.toolsGrid.children.length;
      if (rendered < state.totalMatching) {
        isFetchingMore = true;
        state.page += 1;
        if (el.infiniteScrollStatus) el.infiniteScrollStatus.style.display = 'inline';
        try {
          await fetchAndAppendTools();
        } finally {
          isFetchingMore = false;
          if (el.infiniteScrollStatus) el.infiniteScrollStatus.style.display = 'none';
        }
      }
    }
  }

  async function toggleStreamAll() {
    if (isAutoStreamingAll) {
      isAutoStreamingAll = false;
      if (el.streamAllBtn) el.streamAllBtn.innerHTML = '⚡ Continuous Stream All';
      if (el.infiniteScrollStatus) el.infiniteScrollStatus.style.display = 'none';
      return;
    }

    isAutoStreamingAll = true;
    if (el.streamAllBtn) el.streamAllBtn.innerHTML = '⏹ Stop Streaming';
    if (el.infiniteScrollStatus) {
      el.infiniteScrollStatus.style.display = 'inline';
      el.infiniteScrollStatus.textContent = '● Continuous streaming active...';
    }

    while (isAutoStreamingAll) {
      const rendered = el.toolsGrid.children.length;
      if (rendered >= state.totalMatching || state.totalMatching === 0) {
        isAutoStreamingAll = false;
        if (el.streamAllBtn) el.streamAllBtn.innerHTML = '✔ All Tools Indexed';
        if (el.infiniteScrollStatus) el.infiniteScrollStatus.style.display = 'none';
        break;
      }
      state.page += 1;
      await fetchAndAppendTools();
      await new Promise(r => setTimeout(r, 40));
    }
  }

  // Server-Side Dynamic Query
  async function fetchFromServer() {
    try {
      const params = new URLSearchParams({
        page: state.page,
        limit: state.pageSize,
        purpose: state.purposeQuery || '',
        tool_name: state.toolQuery || '',
        q: state.purposeQuery || state.searchQuery || '',
        category: state.selectedCategory || 'all',
        distro: state.selectedDistro || 'all',
        rarity: state.selectedRarity || 'all',
        source: state.selectedSource || 'all',
        sort_by: state.selectedSort || 'relevance',
        only_github: state.onlyGithub ? 'true' : 'false',
        live: 'true'
      });

      const res = await fetch(`${API_BASE}/api/tools?${params.toString()}`);
      if (!res.ok) throw new Error('Server returned ' + res.status);
      const data = await res.json();

      state.totalMatching = data.total;
      el.resultsCount.textContent = data.total;

      // Cache speed pill
      if (el.cacheSpeedBadge) {
        el.cacheSpeedBadge.style.display = 'inline-flex';
        if (data.cached) {
          el.cacheSpeedBadge.className = 'cache-speed-badge cache-hit';
          el.cacheSpeedBadge.innerHTML = `⚡ In-Memory Cache (${data.response_time_ms}ms)`;
        } else {
          el.cacheSpeedBadge.className = 'cache-speed-badge cache-live';
          el.cacheSpeedBadge.innerHTML = `🌐 Live Upstream (${data.response_time_ms}ms)`;
        }
      }

      // Autocorrect & Semantic Intent Banner
      if (data.autocorrect && state.searchQuery) {
        if (data.autocorrect.canonical_intent && data.autocorrect.domain !== 'GENERAL') {
          el.autocorrectBanner.style.display = 'flex';
          el.autocorrectedQuery.innerHTML = `🧠 Purpose Understood: <strong style="color: var(--neon-green);">${escapeHtml(data.autocorrect.canonical_intent)}</strong> &bull; <span style="color: var(--neon-cyan); font-size: 0.78rem;">${escapeHtml(data.autocorrect.description || '')}</span>`;
          if (el.originalQuery && el.originalQuery.parentElement) el.originalQuery.parentElement.style.display = 'none';
        } else if (data.autocorrect.autocorrected) {
          el.autocorrectBanner.style.display = 'flex';
          el.autocorrectedQuery.textContent = data.autocorrect.corrected_query;
          el.originalQuery.textContent = data.autocorrect.original_query;
          if (el.originalQuery && el.originalQuery.parentElement) el.originalQuery.parentElement.style.display = 'inline';
        } else {
          el.autocorrectBanner.style.display = 'none';
        }
      } else {
        el.autocorrectBanner.style.display = 'none';
      }

      let toolsToRender = data.tools;
      if (state.onlyFavorites) {
        toolsToRender = toolsToRender.filter(t => state.starredIds.has(t.id));
      }

      renderBatch(toolsToRender, state.page === 1);

      // Pagination UI
      const renderedCount = state.page * state.pageSize;
      if (renderedCount < data.total && toolsToRender.length > 0) {
        el.paginationBar.style.display = 'flex';
        el.loadMoreBtn.textContent = `Load More Tools (Showing ${Math.min(renderedCount, data.total)} of ${data.total})`;
      } else {
        el.paginationBar.style.display = 'none';
      }
    } catch (e) {
      console.warn('API error, falling back to client-side filtering:', e);
      state.isDynamicServer = false;
      filterClientData();
    }
  }

  // Client-Side Fallback Filtering (with Direct Browser Live GitHub API querying)
  async function filterClientData() {
    const pQ = (state.purposeQuery || (state.toolQuery ? '' : state.searchQuery) || '').trim();
    const tQ = (state.toolQuery || '').trim();
    const cat = state.selectedCategory;
    const distro = state.selectedDistro;
    const rarity = state.selectedRarity;
    const source = state.selectedSource;
    const onlyGh = state.onlyGithub;
    const onlyFavs = state.onlyFavorites;

    let expanded = null;
    if (pQ) {
      expanded = cleanAndExpandQueryClient(pQ);
      if (expanded.autocorrected) {
        el.autocorrectBanner.style.display = 'flex';
        el.autocorrectedQuery.textContent = expanded.correctedQuery;
        el.originalQuery.textContent = expanded.originalQuery;
      } else {
        el.autocorrectBanner.style.display = 'none';
      }
    } else {
      el.autocorrectBanner.style.display = 'none';
    }

    const scored = [];

    state.allTools.forEach(tool => {
      // Clear previous similarity annotations
      delete tool._similarityMatch;
      delete tool._similarityTarget;

      if (onlyFavs && !state.starredIds.has(tool.id)) return;
      if (onlyGh && (!tool.repo_url || !tool.repo_url.includes('github.com'))) return;
      if (cat !== 'all' && tool.category !== cat) return;
      if (rarity !== 'all' && tool.rarity !== rarity) return;

      if (source !== 'all') {
        if (source === 'github') {
          if (!tool.repo_url || !tool.repo_url.includes('github.com')) return;
        } else if (source === 'gitlab') {
          if (tool.source_origin !== 'gitlab' && (!tool.repo_url || !tool.repo_url.includes('gitlab.com'))) return;
        } else if (source === 'forges' || source === 'codeberg' || source === 'sourceforge') {
          if (!['forge', 'codeberg', 'sourceforge'].includes(tool.source_origin) &&
            (!tool.repo_url || (!tool.repo_url.includes('codeberg.org') && !tool.repo_url.includes('sourceforge.net') && !tool.repo_url.includes('sr.ht')))) return;
        } else if (source === 'resources') {
          if (!['resource', 'portal', 'research', 'publishing', 'pastebin', 'bugbounty'].includes(tool.source_origin)) return;
        } else if (source === 'labs') {
          if (!['lab', 'practice'].includes(tool.source_origin) && !(tool.category && tool.category.toLowerCase().includes('lab'))) return;
        } else if (source === 'blackarch') {
          if (tool.source_origin !== 'blackarch' && !(tool.distros && tool.distros.blackarch)) return;
        } else if (tool.source_origin !== source) {
          return;
        }
      }

      if (distro !== 'all') {
        if (!tool.distros || !tool.distros[distro]) return;
      }

      if (!pQ && !tQ) {
        scored.push({ score: 0, tool });
        return;
      }

      const name = (tool.name || '').toLowerCase();
      const tagline = (tool.tagline || '').toLowerCase();
      const purpose = (tool.purpose_summary || '').toLowerCase();
      const category = (tool.category || '').toLowerCase();
      const repoUrl = (tool.repo_url || '').toLowerCase();
      const fullText = `${name} ${tagline} ${purpose} ${category} ${repoUrl}`;

      // Direct Tool Similarity Evaluation
      let simScore = 0;
      if (tQ) {
        const sim = scoreToolSimilarityClient(tool, tQ);
        simScore = sim.score;
        if (simScore > 0) {
          tool._similarityMatch = sim.type;
          tool._similarityTarget = tQ;
        } else if (!pQ) {
          return; // If ONLY tool was searched and this tool doesn't match/isn't similar, skip!
        }
      }

      // Domain Qualifier Enforcement (Eliminates irrelevant matches like Tor browser for radio forensic)
      if (pQ) {
        const qLower = pQ.toLowerCase();
        const isRfQuery = qLower.includes('radio') || qLower.includes(' rf') || qLower.startsWith('rf ') || qLower.includes('sdr') || qLower.includes('emf') || qLower.includes('tempest');
        if (isRfQuery) {
          const rfConcepts = ["radio", "rf", "sdr", "signal", "spectrum", "demodulat", "iq", "emf", "tempest", "frequency", "rtl-sdr", "hackrf", "gnuradio", "urh", "inspectrum", "gqrx", "satellite", "satnogs"];
          const hasRf = rfConcepts.some(c => fullText.includes(c));
          if (!hasRf && (!tool._similarityMatch || tool._similarityMatch !== 'EXACT_MATCH')) {
            return; // Disqualified!
          }
        }
      }

      let score = simScore * 1.5;

      if (pQ && expanded) {
        const tokens = expanded.tokens;
        const terms = expanded.expandedTerms;

        // Exact substring
        if (name.includes(pQ)) score += 300;
        else if (purpose.includes(pQ)) score += 180;

        // Multi-token match
        let tokensMatched = 0;
        tokens.forEach(tok => {
          if (fullText.includes(tok)) tokensMatched++;
        });

        if (tokens.length > 1 && tokensMatched === tokens.length) {
          score += 200;
        } else if (tokensMatched > 0) {
          score += tokensMatched * 50;
        }

        // Token in name
        tokens.forEach(tok => {
          if (name.includes(tok)) score += 100;
        });

        // Expanded terms
        terms.forEach(term => {
          if (fullText.includes(term)) score += 20;
        });

        // Popularity boost
        if (tool.rarity === 'popular') score += 15;
        if (tool.stars && tool.stars > 500) score += 20;
        if (tool.source_origin === 'curated') score += 25;

        // Primary operational tools boost
        if (expanded.primaryTools) {
          expanded.primaryTools.forEach(pt => {
            const ptClean = pt.toLowerCase();
            if (name === ptClean || (repoUrl && repoUrl.includes('/' + ptClean))) {
              score += 4500;
            } else if (name.includes(ptClean)) {
              score += 1500;
            }
          });
        }
      }

      if (score > 0) {
        scored.push({ score, tool });
      }
    });

    if (pQ || tQ) {
      scored.sort((a, b) => b.score - a.score);
    } else {
      scored.sort((a, b) => {
        if (a.tool.rarity === 'popular' && b.tool.rarity !== 'popular') return -1;
        if (b.tool.rarity === 'popular' && a.tool.rarity !== 'popular') return 1;
        return (b.tool.stars || 0) - (a.tool.stars || 0);
      });
    }

    let combinedResults = scored.map(s => s.tool);

    // Direct Browser Live GitHub API Query (Guarantees live internet search even from file:///)
    const liveSearchQuery = tQ || pQ;
    if (liveSearchQuery) {
      if (el.liveSearchingStatus) el.liveSearchingStatus.style.display = 'inline';
      try {
        const cleanNoStops = q.replace(/\b(tools?|github|gitlab|for|the|a|an|in|of|to)\b/gi, '').trim() || q;
        const ghUrl = `https://api.github.com/search/repositories?q=${encodeURIComponent(cleanNoStops)}+in:name,description,topics&sort=stars&per_page=25`;
        const ghRes = await fetch(ghUrl);
        if (ghRes.ok) {
          const ghData = await ghRes.json();
          const ghTools = (ghData.items || []).map(item => ({
            id: 'gh_' + item.id,
            name: item.name,
            tagline: `[${item.language || 'Code'}] ${item.full_name} (${item.stargazers_count.toLocaleString()} ★)`,
            category: 'GitHub Repository',
            rarity: item.stargazers_count > 300 ? 'popular' : 'rare',
            purpose_summary: item.description || `Public GitHub repository: ${item.full_name}`,
            purposes: item.topics || [],
            distros: { blackarch: '', arch: '', debian: '', git: item.html_url },
            repo_url: item.html_url,
            official_url: item.homepage || item.html_url,
            research_links: [{ title: 'GitHub Repository', url: item.html_url }, { title: 'Releases', url: item.html_url + '/releases' }],
            notes: `Live GitHub discovery: ${item.full_name}. Updated: ${item.updated_at.slice(0, 10)}.`,
            source_origin: 'github',
            stars: item.stargazers_count,
            language: item.language || 'Code',
            last_updated: item.updated_at || ''
          }));

          // Deduplicate against local matches
          const existingUrls = new Set(combinedResults.map(t => (t.repo_url || '').toLowerCase()));
          const newLive = ghTools.filter(t => !existingUrls.has((t.repo_url || '').toLowerCase()));

          // Priority sorting: exact name matches at top
          const exactNameMatches = newLive.filter(t => t.name.toLowerCase() === cleanNoStops.toLowerCase() || t.name.toLowerCase().includes(cleanNoStops.toLowerCase()));
          const otherLive = newLive.filter(t => !exactNameMatches.includes(t));

          combinedResults = [...exactNameMatches, ...combinedResults, ...otherLive];
        }
      } catch (err) {
        console.warn('Direct browser GitHub search error:', err);
      }
      if (el.liveSearchingStatus) el.liveSearchingStatus.style.display = 'none';
    }

    // Apply Client-Side Sorting: relevance, stars, popularity, updated, name_asc, name_desc
    if (state.selectedSort === 'stars') {
      combinedResults.sort((a, b) => (b.stars || 0) - (a.stars || 0));
    } else if (state.selectedSort === 'popularity') {
      combinedResults.sort((a, b) => {
        const aPop = a.rarity === 'popular' ? 1 : 0;
        const bPop = b.rarity === 'popular' ? 1 : 0;
        if (aPop !== bPop) return bPop - aPop;
        return (b.stars || 0) - (a.stars || 0);
      });
    } else if (state.selectedSort === 'updated') {
      combinedResults.sort((a, b) => (b.last_updated || '').localeCompare(a.last_updated || ''));
    } else if (state.selectedSort === 'name_asc') {
      combinedResults.sort((a, b) => (a.name || '').localeCompare(b.name || ''));
    } else if (state.selectedSort === 'name_desc') {
      combinedResults.sort((a, b) => (b.name || '').localeCompare(a.name || ''));
    }

    if (el.cacheSpeedBadge) {
      el.cacheSpeedBadge.style.display = 'inline-flex';
      el.cacheSpeedBadge.className = 'cache-speed-badge cache-hit';
      el.cacheSpeedBadge.innerHTML = '⚡ Client In-Memory (<1ms)';
    }

    state.totalMatching = combinedResults.length;
    el.resultsCount.textContent = combinedResults.length;

    // Slice for page
    const start = (state.page - 1) * state.pageSize;
    const end = start + state.pageSize;
    const pageSlice = combinedResults.slice(start, end);

    renderBatch(pageSlice, state.page === 1);

    if (end < combinedResults.length) {
      el.paginationBar.style.display = 'flex';
      el.loadMoreBtn.textContent = `Load More Tools (Showing ${Math.min(end, combinedResults.length)} of ${combinedResults.length})`;
    } else {
      el.paginationBar.style.display = 'none';
    }
  }

  // Render Batch of Tool Cards
  function renderBatch(tools, isFirstPage) {
    if (isFirstPage && tools.length === 0) {
      el.toolsGrid.style.display = 'none';
      el.emptyState.style.display = 'block';
      return;
    }

    el.emptyState.style.display = 'none';
    el.toolsGrid.style.display = 'grid';

    if (isFirstPage) {
      el.toolsGrid.innerHTML = '';
    }

    tools.forEach(tool => {
      const card = document.createElement('div');
      card.className = `tool-card ${state.starredIds.has(tool.id) ? 'starred' : ''}`;

      const isRare = tool.rarity === 'rare';
      const rarityBadge = isRare
        ? `<span class="badge badge-rare">🕵️ Rare Gem</span>`
        : `<span class="badge badge-popular">⚡ Popular</span>`;

      // Origin and stars
      const isGitHub = tool.source_origin === 'github' || (tool.repo_url && tool.repo_url.includes('github.com'));
      const isGitLab = tool.source_origin === 'gitlab' || (tool.repo_url && tool.repo_url.includes('gitlab.com'));
      const isCodeberg = tool.source_origin === 'codeberg' || (tool.repo_url && tool.repo_url.includes('codeberg.org'));
      const isSourceForge = tool.source_origin === 'sourceforge' || (tool.repo_url && tool.repo_url.includes('sourceforge.net'));
      const isResource = ['resource', 'portal', 'research'].includes(tool.source_origin);
      let originClass = 'badge-source';
      let originLabel = '🏴 BlackArch';
      let sourceBtnLabel = '↗ View Source';
      let sourceBtnClass = 'btn-cyan';

      if (isGitLab) {
        originClass += ' gitlab';
        originLabel = tool.stars ? `🦊 GitLab (${tool.stars} ★)` : '🦊 GitLab';
        sourceBtnLabel = '🦊 GitLab Source';
        sourceBtnClass = 'btn-gitlab';
      } else if (isCodeberg) {
        originClass += ' codeberg';
        originLabel = '🏔️ Codeberg';
        sourceBtnLabel = '🏔️ Codeberg';
        sourceBtnClass = 'btn-cyan';
      } else if (isSourceForge) {
        originClass += ' sourceforge';
        originLabel = '📦 SourceForge';
        sourceBtnLabel = '📦 SourceForge';
        sourceBtnClass = 'btn-sourceforge';
      } else if (isResource) {
        originClass += ' resource';
        originLabel = '📚 Security Portal';
        sourceBtnLabel = '🌐 Open Portal';
        sourceBtnClass = 'btn-cyan';
        originClass += ' resource';
        originLabel = '📚 Security Portal';
        sourceBtnLabel = '🌐 Open Portal';
        sourceBtnClass = 'btn-cyan';
      } else if (tool.source_origin === 'lab') {
        originClass += ' lab';
        originLabel = '🎯 Practice Lab / CTF';
        sourceBtnLabel = '🎯 Open Lab';
        sourceBtnClass = 'btn-lab';
      } else if (tool.source_origin === 'forge') {
        originClass += ' forge';
        originLabel = '🏔️ Code Forge';
        sourceBtnLabel = '↗ Open Forge';
        sourceBtnClass = 'btn-cyan';
      } else if (tool.source_origin === 'pastebin') {
        originClass += ' pastebin';
        originLabel = '📋 Pastebin / Notes';
        sourceBtnLabel = '📋 Open Service';
        sourceBtnClass = 'btn-cyan';
      } else if (tool.source_origin === 'publishing') {
        originClass += ' publishing';
        originLabel = '✍️ Technical Publishing';
        sourceBtnLabel = '✍️ Open Platform';
        sourceBtnClass = 'btn-cyan';
      } else if (tool.source_origin === 'bugbounty') {
        originClass += ' bugbounty';
        originLabel = '🐞 Bug Bounty / VRP';
        sourceBtnLabel = '🐞 Open Program';
        sourceBtnClass = 'btn-cyan';
      } else if (isGitHub) {
        originClass += ' github';
        originLabel = tool.stars ? `🐙 GitHub (${tool.stars.toLocaleString()} ★)` : '🐙 GitHub Repo';
        sourceBtnLabel = '🐙 GitHub Repo';
        sourceBtnClass = 'btn-cyan';
      } else if (tool.source_origin === 'arch') {
        originClass += ' arch';
        originLabel = '🏹 Arch Linux';
      } else if (tool.source_origin === 'debian' || tool.source_origin === 'kali') {
        originClass += ' kali';
        originLabel = '🌀 Debian / Kali';
      } else {
        originLabel = '🏴 BlackArch';
      }

      // Direct Tool Similarity Badge
      const simMatch = tool.similarity_match || tool._similarityMatch;
      let simBadge = '';
      if (simMatch === 'EXACT_MATCH') {
        simBadge = `<span class="exact-match-tag">⚡ EXACT TARGET</span>`;
      } else if (simMatch === 'CURATED_ALTERNATIVE' || simMatch === 'SIMILAR_ALTERNATIVE') {
        simBadge = `<span class="similar-alt-tag">⚡ SIMILAR ALTERNATIVE</span>`;
      }

      const catIcon = getCategoryIcon(tool.category);
      const cleanPurpose = synthesizeOperationalPurposeClient(tool.name, tool.purpose_summary, tool.repo_url, tool.category, tool.language);

      card.innerHTML = `
        <div class="tool-card-top">
          <div class="card-header-row">
            <div class="tool-title-group">
              <span class="tool-cat-icon" style="font-size: 1.15rem; margin-right: 4px;" title="${escapeHtml(tool.category || 'Security Tool')}">${catIcon}</span>
              <span class="tool-name">${escapeHtml(tool.name)}</span>
              ${rarityBadge}
              ${simBadge}
              <span class="badge ${originClass}">${originLabel}</span>
              <span class="badge badge-category">${catIcon} ${escapeHtml(tool.category || 'General')}</span>
            </div>
            <button class="star-btn ${state.starredIds.has(tool.id) ? 'active' : ''}" data-id="${tool.id}" title="Bookmark tool">
              ★
            </button>
          </div>

          <p class="tool-tagline">${escapeHtml(tool.tagline || cleanPurpose)}</p>

          <div class="tool-purpose-box">
            <div class="purpose-box-label">🎯 Operational Purpose &amp; Capabilities</div>
            <div class="purpose-box-desc">${escapeHtml(cleanPurpose)}</div>
          </div>

          <div class="distro-pills">
            ${tool.distros && tool.distros.blackarch ? '<span class="distro-pill active-blackarch">● BlackArch</span>' : ''}
            ${tool.distros && tool.distros.arch ? '<span class="distro-pill active-arch">● Arch Linux</span>' : ''}
            ${tool.distros && tool.distros.debian ? '<span class="distro-pill active-debian">● Debian / Kali</span>' : ''}
            ${isGitHub ? '<span class="distro-pill" style="border-color: rgba(168,85,247,0.4); color: var(--neon-purple)">● GitHub Repo</span>' : ''}
            ${isGitLab ? '<span class="distro-pill" style="border-color: rgba(252,109,38,0.4); color: #fc6d26">● GitLab Project</span>' : ''}
            ${isCodeberg ? '<span class="distro-pill" style="border-color: rgba(0,229,255,0.4); color: var(--neon-cyan)">● Codeberg Repo</span>' : ''}
            ${isSourceForge ? '<span class="distro-pill" style="border-color: rgba(238,95,34,0.4); color: #ee5f22">● SourceForge</span>' : ''}
            ${isResource ? '<span class="distro-pill" style="border-color: rgba(0,255,136,0.4); color: var(--neon-green)">● Official Resource</span>' : ''}
          </div>
        </div>

        <div class="tool-card-footer" style="display: flex; justify-content: space-between; align-items: center; padding-top: 12px; border-top: 1px solid var(--border-dark); gap: 10px; flex-wrap: wrap;">
          <div style="display: flex; align-items: center; gap: 8px; font-family: var(--font-mono); font-size: 0.76rem; color: var(--text-muted); flex-wrap: wrap;">
            ${tool.stars ? `<span class="badge badge-stars">⭐ ${tool.stars.toLocaleString()} ★</span>` : ''}
            ${tool.last_updated ? `<span class="badge badge-updated">🕒 ${formatUpdateTime(tool.last_updated)}</span>` : ''}
            <span style="color: var(--text-dim);">${escapeHtml(tool.language || 'Security Tool')}</span>
          </div>
          <div style="display: flex; gap: 6px; align-items: center; flex-wrap: wrap;">
            <a href="https://book.hacktricks.xyz/?q=${encodeURIComponent(tool.name)}" target="_blank" rel="noopener" class="btn btn-sm" style="border-color: rgba(255,0,127,0.4); color: #ff007f; font-size: 0.72rem; padding: 4px 8px;" title="Search HackTricks Guide">📚 HackTricks</a>
            <a href="https://medium.com/search?q=${encodeURIComponent(tool.name + ' cybersecurity tutorial')}" target="_blank" rel="noopener" class="btn btn-sm" style="border-color: rgba(0,229,255,0.4); color: #00e5ff; font-size: 0.72rem; padding: 4px 8px;" title="Read Medium Guides">✍️ Medium</a>
            <button class="btn btn-find-similar btn-sm" data-tool="${escapeHtml(tool.name)}" title="Find similar tools & alternatives">
              ⚡ Similar
            </button>
            ${tool.repo_url ? `<a href="${tool.repo_url}" target="_blank" rel="noopener" class="btn btn-sm ${sourceBtnClass}" title="Direct Project Source">${sourceBtnLabel}</a>` : ''}
            <button class="btn btn-primary btn-sm inspect-tool-btn" data-id="${tool.id}">
              Inspect
            </button>
          </div>
        </div>
      `;

      card.addEventListener('click', (e) => {
        if (e.target.closest('button') || e.target.closest('a')) return;
        openToolModal(tool);
      });

      const findSimBtn = card.querySelector('.btn-find-similar');
      if (findSimBtn) {
        findSimBtn.addEventListener('click', (e) => {
          e.stopPropagation();
          findSimilarTools(tool.name);
        });
      }

      card.querySelector('.star-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        toggleStar(tool.id, card, card.querySelector('.star-btn'));
      });

      card.querySelector('.inspect-tool-btn').addEventListener('click', (e) => {
        e.stopPropagation();
        openToolModal(tool);
      });

      el.toolsGrid.appendChild(card);
    });

    const totalRendered = el.toolsGrid.children.length;
    if (el.renderedCount) el.renderedCount.textContent = totalRendered.toLocaleString();
    if (el.resultsCount) el.resultsCount.textContent = (state.totalMatching || totalRendered).toLocaleString();
    if (el.streamAllBtn) {
      if (totalRendered >= state.totalMatching && state.totalMatching > 0) {
        el.streamAllBtn.innerHTML = '✔ All Tools Indexed';
        el.streamAllBtn.classList.remove('btn-cyan');
        el.streamAllBtn.style.borderColor = 'var(--neon-green)';
        el.streamAllBtn.style.color = 'var(--neon-green)';
      } else {
        el.streamAllBtn.innerHTML = '⚡ Continuous Stream All';
        el.streamAllBtn.classList.add('btn-cyan');
        el.streamAllBtn.style.borderColor = '';
        el.streamAllBtn.style.color = '';
      }
    }
  }

  // Live Upstream Sync Handler
  async function handleTriggerSync() {
    el.syncModal.classList.add('active');
    el.syncConsole.innerHTML = `
      <div>[*] Initiating live upstream synchronization...</div>
      <div>[1/4] Connecting to BlackArch Linux official repository (3,620+ tools)...</div>
    `;

    try {
      const res = await fetch(`${API_BASE}/api/sync`, { method: 'POST' });
      if (!res.ok) throw new Error('Server returned ' + res.status);

      const pollTimer = setInterval(async () => {
        try {
          const sRes = await fetch(`${API_BASE}/api/sync/status`);
          const sData = await sRes.json();
          if (!sData.is_syncing) {
            clearInterval(pollTimer);
            el.syncConsole.innerHTML += `
              <div style="color: var(--neon-cyan)">[2/4] Synced BlackArch directory: ${sData.blackarch_count} packages indexed.</div>
              <div style="color: var(--neon-purple)">[3/4] Harvested Curated Offensive Lists: ${sData.github_count} GitHub repos &amp; ${sData.gitlab_count || 484} GitLab projects.</div>
              <div style="color: var(--neon-cyan)">[4/4] Integrated Independent Forges, Security Portals &amp; Practice Labs.</div>
              <div style="color: var(--neon-green); font-weight: bold;">[+] Synchronized ${sData.total_tools} tools (${sData.github_count} GitHub Repos, ${sData.gitlab_count || 484} GitLab Projects) successfully!</div>
            `;
            showToast(`Synchronized ${sData.total_tools} tools (${sData.github_count} GitHub Repos)!`);
            updateSyncStatusUI(sData, true);
            renderStats();
            resetAndFetchTools();
          }
        } catch (err) {
          clearInterval(pollTimer);
        }
      }, 1200);

    } catch (e) {
      // Offline / standalone mode fallback: Reload dynamic memory arsenal
      const localDb = window.DYNAMIC_TOOLS_DB || window.TOOLS_DB || [];
      state.allTools = [...localDb, ...state.customTools];
      const ghCount = state.allTools.filter(t => t.repo_url && t.repo_url.includes('github.com')).length;
      const glCount = state.allTools.filter(t => (t.repo_url && t.repo_url.includes('gitlab.com')) || t.source_origin === 'gitlab').length;
      const baCount = state.allTools.filter(t => t.distros && t.distros.blackarch).length;

      el.syncConsole.innerHTML += `
        <div style="color: var(--neon-cyan)">[2/4] Offline mode detected. Re-indexing local dynamic arsenal...</div>
        <div style="color: var(--neon-green); font-weight: bold;">[+] Successfully refreshed ${state.allTools.length.toLocaleString()} tools (${ghCount.toLocaleString()} GitHub, ${glCount.toLocaleString()} GitLab, ${baCount.toLocaleString()} BlackArch)!</div>
        <div style="color: var(--text-dim); font-size: 0.78rem; margin-top: 6px;">[!] Start "python server.py" in your terminal to enable continuous background web synchronization.</div>
      `;
      showToast(`Refreshed ${state.allTools.length} tools locally!`);
      updateSyncStatusUI({
        last_sync: "Offline Dynamic Arsenal",
        total_tools: state.allTools.length,
        github_count: ghCount,
        gitlab_count: glCount,
        blackarch_count: baCount
      }, false);
      renderStats();
      resetAndFetchTools();
    }
  }

  function sendLearningSignal(tool) {
    if (!state.searchQuery || state.searchQuery.trim().length < 3 || !tool) return;
    try {
      fetch(`${API_BASE}/api/intel/learn`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: state.searchQuery.trim(),
          tool_id: tool.id || '',
          tool_name: tool.name || ''
        })
      }).catch(() => { });
    } catch (e) { }
  }

  // Toggle Star / Bookmark
  function toggleStar(toolId, cardEl, btnEl) {
    if (state.starredIds.has(toolId)) {
      state.starredIds.delete(toolId);
      cardEl.classList.remove('starred');
      btnEl.classList.remove('active');
      showToast('Removed from bookmarks');
    } else {
      state.starredIds.add(toolId);
      cardEl.classList.add('starred');
      btnEl.classList.add('active');
      showToast('★ Added to bookmarks');
      const toolObj = state.allTools.find(t => t.id === toolId);
      if (toolObj) sendLearningSignal(toolObj);
    }

    try {
      localStorage.setItem('p2t_starred_tools', JSON.stringify(Array.from(state.starredIds)));
    } catch (e) {
      console.warn('Could not save stars', e);
    }

    renderStats();
    if (state.onlyFavorites) resetAndFetchTools();
  }

  // Open Tool Inspector Modal
  function openToolModal(tool) {
    state.activeModalTool = tool;
    sendLearningSignal(tool);

    const cleanPurpose = synthesizeOperationalPurposeClient(tool.name, tool.purpose_summary, tool.repo_url, tool.category, tool.language);
    el.modalToolName.textContent = tool.name;
    el.modalTagline.textContent = tool.tagline || cleanPurpose;
    el.modalPurposeText.textContent = cleanPurpose;
    el.modalCategory.textContent = tool.category || 'General Security';

    if (el.modalHacktricksBtn) {
      el.modalHacktricksBtn.href = `https://book.hacktricks.xyz/?q=${encodeURIComponent(tool.name)}`;
    }
    if (el.modalMediumBtn) {
      el.modalMediumBtn.href = `https://medium.com/search?q=${encodeURIComponent(tool.name + ' cybersecurity tutorial')}`;
    }

    const isRare = tool.rarity === 'rare';
    el.modalToolBadge.innerHTML = isRare
      ? `<span class="badge badge-rare">🕵️ Rare Gem</span>`
      : `<span class="badge badge-popular">⚡ Popular Standard</span>`;

    const isGitHub = tool.source_origin === 'github' || (tool.repo_url && tool.repo_url.includes('github.com'));
    const isGitLab = tool.source_origin === 'gitlab' || (tool.repo_url && tool.repo_url.includes('gitlab.com'));
    const isCodeberg = tool.source_origin === 'codeberg' || (tool.repo_url && tool.repo_url.includes('codeberg.org'));
    const isSourceForge = tool.source_origin === 'sourceforge' || (tool.repo_url && tool.repo_url.includes('sourceforge.net'));
    const isResource = ['resource', 'portal', 'research'].includes(tool.source_origin);

    el.modalRepoLink.href = tool.repo_url || tool.official_url || '#';
    el.modalRepoLink.style.display = (tool.repo_url || tool.official_url) ? 'inline-flex' : 'none';

    if (isGitLab) {
      el.modalSourceBadge.textContent = `🦊 GitLab (${tool.stars ? tool.stars + ' ★' : 'Project'})`;
      el.modalSourceBadge.className = 'badge badge-source gitlab';
      el.modalRepoLink.textContent = '🦊 Open GitLab Project ↗';
      el.modalRepoLink.style.borderColor = '#fc6d26';
      el.modalRepoLink.style.color = '#fc6d26';
      el.modalReleaseLink.href = `${tool.repo_url}/-/releases`;
      el.modalReleaseLink.style.display = 'inline-flex';
    } else if (isCodeberg) {
      el.modalSourceBadge.textContent = '🏔️ Codeberg Repository';
      el.modalSourceBadge.className = 'badge badge-source codeberg';
      el.modalRepoLink.textContent = '🏔️ Open Codeberg Repo ↗';
      el.modalRepoLink.style.borderColor = 'var(--neon-cyan)';
      el.modalRepoLink.style.color = 'var(--neon-cyan)';
      el.modalReleaseLink.href = `${tool.repo_url}/releases`;
      el.modalReleaseLink.style.display = 'inline-flex';
    } else if (isSourceForge) {
      el.modalSourceBadge.textContent = '📦 SourceForge Project';
      el.modalSourceBadge.className = 'badge badge-source sourceforge';
      el.modalRepoLink.textContent = '📦 Open SourceForge ↗';
      el.modalRepoLink.style.borderColor = '#ee5f22';
      el.modalRepoLink.style.color = '#ee5f22';
      el.modalReleaseLink.href = `${tool.repo_url}/files`;
      el.modalReleaseLink.style.display = 'inline-flex';
    } else if (tool.source_origin === 'lab') {
      el.modalSourceBadge.textContent = '🎯 Practice Lab / CTF Arena';
      el.modalSourceBadge.className = 'badge badge-source lab';
      el.modalRepoLink.textContent = '🎯 Launch Practice Lab ↗';
      el.modalRepoLink.style.borderColor = '#ff007f';
      el.modalRepoLink.style.color = '#ff007f';
      el.modalReleaseLink.style.display = 'none';
    } else if (tool.source_origin === 'forge') {
      el.modalSourceBadge.textContent = '🏔️ Open-Source Code Forge';
      el.modalSourceBadge.className = 'badge badge-source forge';
      el.modalRepoLink.textContent = '🏔️ Open Code Forge ↗';
      el.modalRepoLink.style.borderColor = 'var(--neon-cyan)';
      el.modalRepoLink.style.color = 'var(--neon-cyan)';
      el.modalReleaseLink.style.display = 'none';
    } else if (tool.source_origin === 'pastebin') {
      el.modalSourceBadge.textContent = '📋 Secure Paste / Note Sharing';
      el.modalSourceBadge.className = 'badge badge-source pastebin';
      el.modalRepoLink.textContent = '📋 Open Paste Service ↗';
      el.modalRepoLink.style.borderColor = 'var(--neon-amber)';
      el.modalRepoLink.style.color = 'var(--neon-amber)';
      el.modalReleaseLink.style.display = 'none';
    } else if (tool.source_origin === 'publishing') {
      el.modalSourceBadge.textContent = '✍️ Technical Publishing Platform';
      el.modalSourceBadge.className = 'badge badge-source publishing';
      el.modalRepoLink.textContent = '✍️ Open Platform ↗';
      el.modalRepoLink.style.borderColor = 'var(--neon-purple)';
      el.modalRepoLink.style.color = 'var(--neon-purple)';
      el.modalReleaseLink.style.display = 'none';
    } else if (tool.source_origin === 'bugbounty') {
      el.modalSourceBadge.textContent = '🐞 Vulnerability Disclosure & VRP';
      el.modalSourceBadge.className = 'badge badge-source bugbounty';
      el.modalRepoLink.textContent = '🐞 Open VRP Platform ↗';
      el.modalRepoLink.style.borderColor = 'var(--neon-green)';
      el.modalRepoLink.style.color = 'var(--neon-green)';
      el.modalReleaseLink.style.display = 'none';
    } else if (isResource) {
      el.modalSourceBadge.textContent = '📚 Official Security Resource';
      el.modalSourceBadge.className = 'badge badge-source resource';
      el.modalRepoLink.textContent = '🌐 Open Official Portal ↗';
      el.modalRepoLink.style.borderColor = 'var(--neon-green)';
      el.modalRepoLink.style.color = 'var(--neon-green)';
      el.modalReleaseLink.style.display = 'none';
    } else if (isGitHub) {
      el.modalSourceBadge.textContent = `🐙 GitHub (${tool.stars ? tool.stars.toLocaleString() + ' ★' : 'Repository'})`;
      el.modalSourceBadge.className = 'badge badge-source github';
      el.modalRepoLink.textContent = '🐙 Open GitHub Repository ↗';
      el.modalRepoLink.style.borderColor = 'var(--neon-purple)';
      el.modalRepoLink.style.color = 'var(--neon-purple)';
      el.modalReleaseLink.href = `${tool.repo_url}/releases`;
      el.modalReleaseLink.style.display = 'inline-flex';
    } else {
      el.modalSourceBadge.textContent = tool.source_origin === 'kali' ? 'Kali Linux' : (tool.source_origin === 'arch' ? 'Arch Linux' : 'BlackArch Live');
      el.modalSourceBadge.className = 'badge badge-source';
      el.modalRepoLink.textContent = 'Open Repository ↗';
      el.modalRepoLink.style.borderColor = '';
      el.modalRepoLink.style.color = '';
      el.modalReleaseLink.style.display = 'none';
    }

    if (tool.official_url && tool.official_url !== tool.repo_url) {
      el.modalBlackarchLink.href = tool.official_url;
      el.modalBlackarchLink.style.display = 'inline-flex';
    } else {
      el.modalBlackarchLink.style.display = 'none';
    }

    // Specifications & Metadata Grid
    if (el.modalMetaSource) {
      const srcName = tool.source_origin ? tool.source_origin.toUpperCase() : (isGitHub ? 'GITHUB' : 'BLACKARCH');
      el.modalMetaSource.textContent = srcName;
    }
    if (el.modalMetaLang) {
      el.modalMetaLang.textContent = tool.language || (isGitHub ? 'Code' : 'Native Package');
    }
    if (el.modalMetaStars) {
      el.modalMetaStars.textContent = tool.stars ? `${tool.stars.toLocaleString()} ★` : (tool.rarity === 'popular' ? 'Popular Package' : 'Community Tool');
    }
    if (el.modalMetaCategory) {
      el.modalMetaCategory.textContent = tool.category || 'General Security';
    }

    // Curated Articles & Direct Project Links
    el.modalArticlesList.innerHTML = '';
    const isGitHubTool = tool.source_origin === 'github' || (tool.repo_url && tool.repo_url.includes('github.com'));
    const isGitLabTool = tool.source_origin === 'gitlab' || (tool.repo_url && tool.repo_url.includes('gitlab.com'));

    const curatedLinks = [
      {
        icon: '📚',
        badge: 'HACKTRICKS',
        badgeColor: '#ff007f',
        title: `HackTricks Exploitation & Methodology Guide (${tool.name})`,
        url: `https://book.hacktricks.xyz/?q=${encodeURIComponent(tool.name)}`
      },
      {
        icon: '✍️',
        badge: 'MEDIUM',
        badgeColor: '#00e5ff',
        title: `Medium Security Walkthroughs & Deep-Dives (${tool.name})`,
        url: `https://medium.com/search?q=${encodeURIComponent(tool.name + ' cybersecurity tutorial')}`
      }
    ];

    if (tool.repo_url) {
      curatedLinks.push({
        icon: '🛠️',
        badge: 'INSTALLATION',
        badgeColor: '#00ff66',
        title: `Official Installation Guide & Upstream Repository (${tool.name})`,
        url: tool.repo_url
      });
    }

    if (tool.repo_url && (isGitHubTool || isGitLabTool)) {
      curatedLinks.push({
        icon: '📦',
        badge: 'RELEASES',
        badgeColor: '#b388ff',
        title: `Compiled Releases, Binaries & Tags (${tool.name})`,
        url: isGitLabTool ? `${tool.repo_url}/-/releases` : `${tool.repo_url}/releases`
      });
    }

    // Append any extra specific research links if present
    if (tool.research_links && Array.isArray(tool.research_links)) {
      tool.research_links.forEach(rl => {
        if (!rl.url || curatedLinks.some(cl => cl.url === rl.url)) return;
        curatedLinks.push({
          icon: '📄',
          badge: (rl.source || 'REFERENCE').toUpperCase(),
          badgeColor: '#ffb300',
          title: rl.title || `Research Document: ${tool.name}`,
          url: rl.url
        });
      });
    }

    curatedLinks.forEach(link => {
      const a = document.createElement('a');
      a.className = 'article-link-item';
      a.href = link.url;
      a.target = '_blank';
      a.rel = 'noopener';
      a.innerHTML = `
        <span class="article-link-title"><span style="margin-right: 6px;">${link.icon}</span> ${escapeHtml(link.title)}</span>
        <span class="article-source-tag" style="color: ${link.badgeColor}; border: 1px solid ${link.badgeColor}; font-size: 0.7rem; padding: 2px 6px; border-radius: 3px; font-weight: 600;">[${link.badge} ↗]</span>
      `;
      el.modalArticlesList.appendChild(a);
    });

    // Distro & Deployment Commands setup
    const pkgSlug = (tool.name || '').toLowerCase().replace(/[^a-z0-9_-]/g, '');
    const baPkg = (tool.distros && tool.distros.blackarch) ? tool.distros.blackarch : pkgSlug;
    const archPkg = (tool.distros && tool.distros.arch) ? tool.distros.arch : pkgSlug;
    const debPkg = (tool.distros && tool.distros.debian) ? tool.distros.debian : pkgSlug;
    const repoLink = tool.repo_url || (tool.official_url || '');

    const paneBlackarch = document.getElementById('modalTabBlackarch');
    const paneArch = document.getElementById('modalTabArch');
    const paneDebian = document.getElementById('modalTabDebian');
    const paneGit = document.getElementById('modalTabGit');
    const paneQuick = document.getElementById('modalTabQuick');

    if (paneBlackarch) {
      setupDistroPane(paneBlackarch, `sudo pacman -S ${baPkg}`, `Install official package from BlackArch Linux repositories:`);
    }
    if (paneArch) {
      setupDistroPane(paneArch, `yay -S ${archPkg}`, `Install via Arch User Repository (AUR) or Pacman:`);
    }
    if (paneDebian) {
      setupDistroPane(paneDebian, `sudo apt update && sudo apt install -y ${debPkg}`, `Install via Debian / Kali Linux standard repositories:`);
    }
    if (paneGit) {
      setupDistroPane(paneGit, repoLink ? `git clone ${repoLink} && cd ${pkgSlug}` : `git clone https://github.com/${pkgSlug}/${pkgSlug}`, `Clone latest source code repository directly:`);
    }
    if (paneQuick) {
      const quickRun = (tool.quick_commands && tool.quick_commands[0]) || `${pkgSlug} --help`;
      setupDistroPane(paneQuick, quickRun, `Direct CLI execution or verification command:`);
    }

    // Reset distro tabs to first tab (BlackArch)
    document.querySelectorAll('.modal-tab-btn').forEach((b, idx) => {
      if (idx === 0) {
        b.classList.add('active');
        b.style.borderBottomColor = 'var(--neon-cyan)';
        b.style.color = '#ffffff';
      } else {
        b.classList.remove('active');
        b.style.borderBottomColor = 'transparent';
        b.style.color = 'var(--text-dim)';
      }
    });
    document.querySelectorAll('.modal-tab-content').forEach((c, idx) => {
      c.style.display = idx === 0 ? 'block' : 'none';
    });

    // Notes
    el.modalNotes.textContent = tool.notes || `Live tool intelligence indexed from ${tool.source_origin || 'public upstream'}. Use the 'Open Repository' link above to view code, releases, and documentation.`;
    el.modalNotes.parentElement.style.display = 'block';

    el.toolModal.classList.add('active');
  }

  function setupDistroPane(paneEl, cmdText, description) {
    if (!cmdText) {
      paneEl.innerHTML = `<p style="color: var(--text-dim); font-size: 0.85rem; padding: 10px 0;">No direct pre-packaged command. Use Git/Source to compile.</p>`;
      return;
    }

    paneEl.innerHTML = `
      <p style="color: var(--text-muted); font-size: 0.82rem; margin-bottom: 8px;">${description}</p>
      <div class="code-block">
        <pre><code>${escapeHtml(cmdText)}</code></pre>
        <button class="copy-btn">Copy Command</button>
      </div>
    `;

    const copyBtn = paneEl.querySelector('.copy-btn');
    if (copyBtn) {
      copyBtn.addEventListener('click', () => {
        copyToClipboard(cmdText, 'Distro install command copied!');
        copyBtn.textContent = '✔ Copied!';
        copyBtn.style.borderColor = 'var(--neon-green)';
        copyBtn.style.color = 'var(--neon-green)';
        setTimeout(() => {
          copyBtn.textContent = 'Copy Command';
          copyBtn.style.borderColor = '';
          copyBtn.style.color = '';
        }, 1600);
      });
    }
  }

  // Batch Script Generator
  function openBatchScriptModal() {
    el.batchToolChecklist.innerHTML = '';
    const toolsSample = state.allTools.slice(0, 150);

    toolsSample.forEach(tool => {
      const label = document.createElement('label');
      label.style.display = 'flex';
      label.style.alignItems = 'center';
      label.style.gap = '8px';
      label.style.fontSize = '0.82rem';
      label.style.fontFamily = 'var(--font-mono)';
      label.style.color = '#cccccc';
      label.style.cursor = 'pointer';

      const chk = document.createElement('input');
      chk.type = 'checkbox';
      chk.value = tool.id;
      chk.checked = state.selectedToolsForBatch.has(tool.id);

      chk.addEventListener('change', () => {
        if (chk.checked) state.selectedToolsForBatch.add(tool.id);
        else state.selectedToolsForBatch.delete(tool.id);
        generateBatchScript();
      });

      label.appendChild(chk);
      label.appendChild(document.createTextNode(tool.name));
      el.batchToolChecklist.appendChild(label);
    });

    generateBatchScript();
    el.batchScriptModal.classList.add('active');
  }

  function generateBatchScript() {
    const isArch = el.batchDistroRadioArch.checked;
    const selected = Array.from(state.selectedToolsForBatch);

    if (selected.length === 0) {
      el.batchScriptOutput.value = '# Check one or more tools above to generate your setup script!';
      return;
    }

    let script = `#!/usr/bin/env bash\n# Generated by Purpose-2-Tool Dashboard\n# Target OS: ${isArch ? 'Arch / BlackArch Linux' : 'Debian / Kali Linux'}\n\nset -e\necho "[+] Starting automated security tool deployment..."\n\n`;

    if (isArch) {
      script += `# Arch / BlackArch Setup\nsudo pacman -Syu --noconfirm\n\n`;
      selected.forEach(id => {
        const tool = state.allTools.find(t => t.id === id);
        if (tool) {
          script += `# --- ${tool.name} ---\n`;
          script += `${tool.distros ? tool.distros.blackarch : 'pacman -S ' + tool.name.toLowerCase()}\n\n`;
        }
      });
    } else {
      script += `# Debian / Kali Setup\nsudo apt update && sudo apt upgrade -y\n\n`;
      selected.forEach(id => {
        const tool = state.allTools.find(t => t.id === id);
        if (tool) {
          script += `# --- ${tool.name} ---\n`;
          script += `${tool.distros ? tool.distros.debian : 'sudo apt install -y ' + tool.name.toLowerCase()}\n\n`;
        }
      });
    }

    script += `echo "[+] Selected tools installed successfully!"\n`;
    el.batchScriptOutput.value = script;
  }

  // Add Custom Tool Form Handler
  function handleAddCustomTool(e) {
    e.preventDefault();
    const name = document.getElementById('customName').value.trim();
    const purpose = document.getElementById('customPurpose').value.trim();
    if (!name || !purpose) return;

    const newTool = {
      id: 'custom_' + Date.now(),
      name,
      tagline: document.getElementById('customTagline').value.trim() || name,
      category: document.getElementById('customCategory').value.trim() || 'General Security',
      rarity: document.getElementById('customRarity').value || 'rare',
      purpose_summary: purpose,
      purposes: [purpose.toLowerCase()],
      distros: {
        blackarch: (document.getElementById('customBlackarch') || {}).value || '',
        arch: (document.getElementById('customArch') || {}).value || '',
        debian: (document.getElementById('customDebian') || {}).value || '',
        git: (document.getElementById('customGit') || {}).value || ''
      },
      repo_url: document.getElementById('customRepo').value.trim() || 'https://github.com/',
      source_origin: 'custom',
      research_links: []
    };

    state.customTools.push(newTool);
    state.allTools.unshift(newTool);

    try {
      localStorage.setItem('p2t_custom_tools', JSON.stringify(state.customTools));
    } catch (err) { }

    el.customToolForm.reset();
    closeAllModals();
    showToast(`Added custom tool: ${name}`);
    renderStats();
    resetAndFetchTools();
  }

  // Export & Import
  function handleExportJson() {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(state.allTools, null, 2));
    const dl = document.createElement('a');
    dl.setAttribute("href", dataStr);
    dl.setAttribute("download", "purpose_to_tool_export.json");
    document.body.appendChild(dl);
    dl.click();
    dl.remove();
    showToast('Database exported as purpose_to_tool_export.json');
  }

  function handleImportJson(e) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = function (event) {
      try {
        const imported = JSON.parse(event.target.result);
        if (Array.isArray(imported)) {
          state.allTools = [...imported, ...state.allTools];
          renderStats();
          resetAndFetchTools();
          showToast(`Imported ${imported.length} tools!`);
        }
      } catch (err) {
        alert('Failed to parse JSON file.');
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  }

  // Copy to Clipboard
  function copyToClipboard(text, successMsg) {
    if (!text) return;
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(() => showToast(successMsg)).catch(() => fallbackCopy(text, successMsg));
    } else {
      fallbackCopy(text, successMsg);
    }
  }

  function fallbackCopy(text, successMsg) {
    const t = document.createElement('textarea');
    t.value = text;
    t.style.position = 'fixed';
    t.style.opacity = '0';
    document.body.appendChild(t);
    t.select();
    try {
      document.execCommand('copy');
      showToast(successMsg);
    } catch (e) { }
    document.body.removeChild(t);
  }

  function showToast(msg) {
    if (!el.toast) return;
    el.toastMsg.textContent = msg;
    el.toast.classList.add('show');
    clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => el.toast.classList.remove('show'), 2800);
  }

  function closeAllModals() {
    document.querySelectorAll('.modal-overlay').forEach(m => m.classList.remove('active'));
    state.activeModalTool = null;
  }

  function escapeHtml(str) {
    if (!str) return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  document.addEventListener('DOMContentLoaded', init);
})();
