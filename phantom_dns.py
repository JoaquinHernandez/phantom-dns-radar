import os
import sys
import json
import math
import time
from datetime import datetime, timezone

# ANSI Color & Styling Tokens
RESET   = "\033[0m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RED     = "\033[38;5;196m"
GREEN   = "\033[38;5;48m"
CYAN    = "\033[38;5;51m"
AMBER   = "\033[38;5;214m"
MAGENTA = "\033[38;5;201m"
GRAY    = "\033[38;5;242m"

BANNER = f"""{CYAN}{BOLD}
 ██████╗ ██╗  ██╗ █████╗ ███╗   ██╗████████╗ ██████╗ ███╗   ███╗
 ██╔══██╗██║  ██║██╔══██╗████╗  ██║╚══██╔══╝██╔═══██╗████╗ ████║
 ██████╔╝███████║███████║██╔██╗ ██║   ██║   ██║   ██║██╔████╔██║
 ██╔═══╝ ██╔══██║██╔══██║██║╚██╗██║   ██║   ██║   ██║██║╚██╔╝██║
 ██║     ██║  ██║██║  ██║██║ ╚████║   ██║   ╚██████╔╝██║ ╚═╝ ██║
 ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝
{RESET}{AMBER} » PHANTOM-DNS: DGA, TUNNELING & FAST-FLUX THREAT RADAR «{RESET}
"""

class PhantomDNSRadar:
    def __init__(self, config_path="config.json", telemetry_path="dns_telemetry.json"):
        if not os.path.exists(config_path) or not os.path.exists(telemetry_path):
            print(f"{RED}[-] Error: Missing configuration or telemetry JSON file.{RESET}")
            sys.exit(1)

        with open(config_path, "r") as f:
            self.config = json.load(f)

        with open(telemetry_path, "r") as f:
            self.telemetry = json.load(f).get("queries", [])

        self.entropy_thresh = self.config.get("dga_entropy_threshold", 3.6)
        self.vowel_ratio_thresh = self.config.get("min_vowel_ratio", 0.2)
        self.fast_flux_thresh = self.config.get("fast_flux_ip_threshold", 4)
        self.tunnel_len_thresh = self.config.get("tunneling_query_length_threshold", 35)
        self.mitre = self.config.get("mitre_mappings", {})

    def calculate_entropy(self, text):
        """Calculates Shannon Entropy (randomness) on domain labels."""
        if not text:
            return 0.0
        entropy = 0.0
        length = len(text)
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def calculate_vowel_ratio(self, text):
        """Calculates ratio of vowels to consonants to detect non-human algorithmic domains."""
        vowels = set("aeiou")
        letters = [c.lower() for c in text if c.isalpha()]
        if not letters:
            return 0.0
        vowel_count = sum(1 for c in letters if c in vowels)
        return vowel_count / len(letters)

    def analyze(self):
        print(BANNER)
        print(f"{BOLD}Initializing DNS Telemetry Threat Sweep...{RESET}\n")

        phases = [
            "Calculating Shannon Entropy on second-level domains",
            "Evaluating linguistic vowel/consonant distribution ratios",
            "Inspecting subdomains for covert DNS tunneling data encoding",
            "Auditing Fast-Flux multi-A-record resolution sets"
        ]
        for phase in phases:
            time.sleep(0.2)
            print(f"  {CYAN}▸{RESET} {phase}...")

        print("\n" + "=" * 85 + "\n")
        print(f"{BOLD}{'DOMAIN / QUERY':<36} {'SOURCE IP':<14} {'CLASSIFICATION':<18} {'SEVERITY'}{RESET}")
        print("-" * 85)

        findings = []

        for record in self.telemetry:
            domain = record.get("domain", "")
            src_ip = record.get("client_ip", "Unknown")
            resolved_ips = record.get("resolved_ips", [])
            subdomain = domain.split(".")[0]

            # 1. DNS Tunneling Check (Long payload / high entropy query)
            if len(domain) >= self.tunnel_len_thresh and ("-" in subdomain or "=" in subdomain):
                findings.append({
                    "domain": domain,
                    "src": src_ip,
                    "type": "DNS Covert Tunneling",
                    "severity": "CRITICAL",
                    "mitre": self.mitre.get("DNS_TUNNELING"),
                    "details": f"Query payload exceeds length threshold ({len(domain)} chars)."
                })
                print(f"{(domain[:32] + '...'):<36} {src_ip:<14} {RED}{'DNS Tunneling':<18}{RESET} {RED}{'CRITICAL'}{RESET}")
                continue

            # 2. Fast-Flux Infrastructure Check
            if len(resolved_ips) >= self.fast_flux_thresh:
                findings.append({
                    "domain": domain,
                    "src": src_ip,
                    "type": "Fast-Flux IP Rotation",
                    "severity": "HIGH",
                    "mitre": self.mitre.get("FAST_FLUX"),
                    "details": f"Resolved across {len(resolved_ips)} rotating A-record endpoints."
                })
                print(f"{(domain[:32] + '...'):<36} {src_ip:<14} {AMBER}{'Fast-Flux':<18}{RESET} {AMBER}{'HIGH'}{RESET}")
                continue

            # 3. DGA (Domain Generation Algorithm) Check
            entropy = self.calculate_entropy(subdomain)
            vowel_ratio = self.calculate_vowel_ratio(subdomain)

            if entropy >= self.entropy_thresh and vowel_ratio < self.vowel_ratio_thresh:
                findings.append({
                    "domain": domain,
                    "src": src_ip,
                    "type": "DGA Botnet Domain",
                    "severity": "CRITICAL",
                    "mitre": self.mitre.get("DGA"),
                    "details": f"Entropy: {entropy:.2f} | Vowel Ratio: {vowel_ratio:.2f}"
                })
                print(f"{domain:<36} {src_ip:<14} {RED}{'DGA Signature':<18}{RESET} {RED}{'CRITICAL'}{RESET}")
            else:
                print(f"{domain:<36} {src_ip:<14} {GREEN}{'Clean / Normal':<18}{RESET} {GRAY}OK{RESET}")

        print("=" * 85)
        print(f"\n{BOLD}Threat Hunting Results:{RESET} Flagged {RED}{len(findings)}{RESET} active DNS anomalies.\n")

        if findings:
            print(f"{AMBER}{BOLD}[🛠️ SOC INVESTIGATION DIRECTIVES]{RESET}")
            for idx, item in enumerate(findings, start=1):
                print(f"  {CYAN}#{idx} [{item['severity']}]{RESET} {BOLD}{item['domain']}{RESET}")
                print(f"     ├─ Classification: {item['type']}")
                print(f"     ├─ MITRE ATT&CK:   {item['mitre']}")
                print(f"     └─ Forensic Note:  {item['details']}\n")

if __name__ == "__main__":
    radar = PhantomDNSRadar()
    radar.analyze()
