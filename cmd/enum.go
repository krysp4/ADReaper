package cmd

import (
	"context"
	"fmt"
	"strings"

	"adreaper/internal/output"
	"adreaper/internal/recon"
	"adreaper/internal/workspace"

	"github.com/spf13/cobra"
)

var enumCmd = &cobra.Command{
	Use:   "enum",
	Short: "Enumerate Active Directory objects",
}

func init() {
	enumCmd.AddCommand(enumUsersCmd)
	enumCmd.AddCommand(enumComputersCmd)
	enumCmd.AddCommand(enumGroupsCmd)
	enumCmd.AddCommand(enumSharesCmd)
	enumCmd.AddCommand(enumACLsCmd)
	enumCmd.AddCommand(enumTrustsCmd)
	enumCmd.AddCommand(enumDomainCmd)
	enumCmd.AddCommand(enumADCSCmd)
	enumCmd.AddCommand(enumLocalAdminsCmd)
	enumCmd.AddCommand(enumTreeCmd)
	enumCmd.AddCommand(enumAllCmd)
	enumCmd.AddCommand(enumDumpCmd)
}

// ── enum users ────────────────────────────────────────────────────────────────

var (
	enumUsersSPNOnly   bool
	enumUsersASREPOnly bool
	enumUsersAdminOnly bool
	enumUsersDeleg     bool
)

var enumUsersCmd = &cobra.Command{
	Use:   "users",
	Short: "Enumerate user accounts",
	Long: `Enumerate AD user accounts with detailed attribute analysis.
Flags allow filtering to specific attack-relevant subsets.

Examples:
  adreaper enum users -d corp.local --dc-ip 10.10.10.1 -u admin -p P@ss
  adreaper enum users --spn-only     # Kerberoastable targets
  adreaper enum users --asrep-only   # AS-REP roastable targets
  adreaper enum users --deleg        # Delegation misconfigurations`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ws, _ := workspace.New(opts.WorkspaceDir, opts.Domain)
		ctx := context.Background()

		output.Section("User Enumeration")
		output.Info("Connecting to LDAP: %s", opts.LDAPAddr())

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return fmt.Errorf("LDAP connect: %w", err)
		}
		defer ldapCl.Close()

		var users []recon.User

		switch {
		case enumUsersSPNOnly:
			output.Info("Querying Kerberoastable users (SPN set, not disabled)...")
			users, err = ldapCl.QuerySPNUsers(ctx)
		case enumUsersASREPOnly:
			output.Info("Querying AS-REP roastable users (no Kerberos pre-auth)...")
			users, err = ldapCl.QueryASREPUsers(ctx)
		default:
			output.Info("Querying all user accounts...")
			users, err = ldapCl.QueryUsers(ctx)
		}
		if err != nil {
			return err
		}

		output.Success("Found %d users", len(users))

		var rows [][]string
		for _, u := range users {
			if enumUsersAdminOnly && !u.AdminCount {
				continue
			}
			if enumUsersDeleg && !u.UnconstrainedDelegation && len(u.ConstrainedDelegation) == 0 {
				continue
			}
			flags := buildUserFlags(u)
			rows = append(rows, []string{u.SAMAccountName, u.UPN, flags, u.Description})
		}

		output.PrintTable([]string{"SAMAccountName", "UPN", "Flags", "Description"}, rows)

		if ws != nil {
			_ = ws.SaveJSON("users.json", users)
		}
		return nil
	},
}

func init() {
	enumUsersCmd.Flags().BoolVar(&enumUsersSPNOnly, "spn-only", false, "Only show Kerberoastable users (SPN set)")
	enumUsersCmd.Flags().BoolVar(&enumUsersASREPOnly, "asrep-only", false, "Only show AS-REP roastable users")
	enumUsersCmd.Flags().BoolVar(&enumUsersAdminOnly, "admin-only", false, "Only show adminCount=1 users")
	enumUsersCmd.Flags().BoolVar(&enumUsersDeleg, "deleg", false, "Only show accounts with delegation configured")

	enumGroupsCmd.Flags().StringVar(&enumGroupsName, "name", "", "Filter by specific group name")

	// Assuming infraScanTarget is defined elsewhere or will be defined.
	// If not, this line will cause a compilation error.
	// enumSharesCmd.Flags().StringVarP(&infraScanTarget, "target", "t", "", "Target host (defaults to --dc-ip)")

	// Assuming infraScanCmd and infraScanNoPing are defined elsewhere or will be defined.
	// If not, these lines will cause a compilation error.
	// infraScanCmd.Flags().BoolVar(&infraScanNoPing, "no-ping", false, "Skip host discovery")
}

func buildUserFlags(u recon.User) string {
	var f string
	if !u.Enabled {
		f += "[DISABLED] "
	}
	if u.AdminCount {
		f += "[ADMIN] "
	}
	if u.NoKerbPreauth {
		f += "[ASREP] "
	}
	if len(u.SPNs) > 0 {
		f += "[SPN] "
	}
	if u.UnconstrainedDelegation {
		f += "[UNCONSTRAINED-DELEG] "
	}
	if len(u.ConstrainedDelegation) > 0 {
		f += "[CONSTRAINED-DELEG] "
	}
	if u.PasswordNeverExpires {
		f += "[NO-PWD-EXP] "
	}
	if f == "" {
		f = "-"
	}
	return f
}

// ── enum computers ───────────────────────────────────────────────────────────

var enumComputersCmd = &cobra.Command{
	Use:   "computers",
	Short: "Enumerate computer accounts",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Computer Enumeration")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		comps, err := ldapCl.QueryComputers(ctx)
		if err != nil {
			return err
		}
		output.Success("Found %d computers", len(comps))

		var rows [][]string
		for _, c := range comps {
			flags := ""
			if c.IsDC {
				flags += "[DC] "
			}
			if c.UnconstrainedDelegation {
				flags += "[UNCONSTRAINED-DELEG] "
			}
			if c.LAPSEnabled && c.LAPSPassword != "" {
				flags += "[LAPS-READABLE] "
			}
			if flags == "" {
				flags = "-"
			}
			rows = append(rows, []string{c.SAMAccountName, c.DNSHostName, c.OperatingSystem, flags})
		}
		output.PrintTable([]string{"SAMAccountName", "DNS", "OS", "Flags"}, rows)
		return nil
	},
}

// ── enum groups ──────────────────────────────────────────────────────────────

var (
	enumGroupsName string
)

var enumGroupsCmd = &cobra.Command{
	Use:   "groups",
	Short: "Enumerate groups (and their members)",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Group Enumeration")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		groups, err := ldapCl.QueryGroups(ctx)
		var rows [][]string
		for _, g := range groups {
			// Substring match for name if requested (check both SAM and DN)
			if enumGroupsName != "" {
				matches := strings.Contains(strings.ToLower(g.SAMAccountName), strings.ToLower(enumGroupsName)) ||
					strings.Contains(strings.ToLower(g.DN), strings.ToLower(enumGroupsName))
				if !matches {
					continue
				}
			}

			admin := "-"
			if g.AdminCount {
				admin = "YES"
			}

			desc := g.Description
			if len(desc) > 60 {
				desc = desc[:57] + "..."
			}

			rows = append(rows, []string{g.SAMAccountName, fmt.Sprintf("%d", len(g.Members)), admin, desc})
		}

		if len(rows) == 0 && enumGroupsName != "" {
			output.Warn("Search for group '%s' returned 0 matches (Filtered from %d total groups)", enumGroupsName, len(groups))
			output.Info("Tip: If the lab is in Spanish, try localized terms like 'Usuarios', 'Equipos', or 'Admins'.")
		} else {
			output.Success("Found %d groups (Displaying %d after filters)", len(groups), len(rows))
			output.PrintTable([]string{"Name", "Members", "AdminCount", "Description"}, rows)
		}
		return nil
	},
}

// ── enum shares ──────────────────────────────────────────────────────────────

var enumSharesCmd = &cobra.Command{
	Use:   "shares",
	Short: "Enumerate SMB shares on the DC",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		output.Section("SMB Share Enumeration")

		smbCl, err := recon.NewSMBClient(opts)
		if err != nil {
			return err
		}
		defer smbCl.Close()

		shares, err := smbCl.ListShares()
		if err != nil {
			return err
		}
		output.Success("Found %d shares", len(shares))
		var rows [][]string
		for _, s := range shares {
			rows = append(rows, []string{s.Name, s.Remark, s.Access})
		}
		output.PrintTable([]string{"Share", "Remark", "Access"}, rows)
		return nil
	},
}

// ── enum acls ────────────────────────────────────────────────────────────────

var enumACLsCmd = &cobra.Command{
	Use:   "acls",
	Short: "Enumerate dangerous ACLs on privileged AD objects",
	Long: `Checks ACLs on high-value targets: Domain root, Domain Admins, AdminSDHolder.
Flags dangerous permissions: GenericAll, WriteDACL, WriteOwner, DCSync rights.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("ACL Analysis — High-Value Targets")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		entries, err := ldapCl.QueryDangerousACLs(ctx)
		if err != nil {
			return err
		}
		if len(entries) == 0 {
			output.Success("No dangerous ACLs found on monitored objects")
			return nil
		}

		output.Warn("Found %d DANGEROUS ACL entries!", len(entries))
		var rows [][]string
		for _, a := range entries {
			rows = append(rows, []string{a.Object, a.Principal, a.Right, a.AceType})
		}
		output.PrintTable([]string{"Object", "Principal", "Right", "Type"}, rows)
		return nil
	},
}

// ── enum trusts ──────────────────────────────────────────────────────────────

var enumTrustsCmd = &cobra.Command{
	Use:   "trusts",
	Short: "Enumerate domain trust relationships",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Domain Trusts")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		trusts, err := ldapCl.QueryTrusts(ctx)
		if err != nil {
			return err
		}
		output.Success("Found %d trust relationships", len(trusts))
		var rows [][]string
		for _, t := range trusts {
			sidFilter := "NO"
			if t.IsSIDFiltered {
				sidFilter = "YES"
			}
			rows = append(rows, []string{t.Partner, t.Direction, t.TrustType, sidFilter})
		}
		output.PrintTable([]string{"Partner", "Direction", "Type", "SID-Filtered"}, rows)
		return nil
	},
}

// ── enum domain ──────────────────────────────────────────────────────────────

var enumDomainCmd = &cobra.Command{
	Use:   "domain",
	Short: "Enumerate domain policy and password policy",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Domain Information")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		info, err := ldapCl.QueryDomainInfo(ctx)
		if err != nil {
			return err
		}

		output.Info("Domain:                 %s", info.Name)
		output.Info("Base DN:               %s", info.DN)
		output.Info("Domain Functional Level: %d (%s)", info.FunctionalLevel, flToName(info.FunctionalLevel))
		output.Info("Machine Account Quota: %d", info.MachineAccountQuota)
		fmt.Println()
		output.Info("Password Policy:")
		output.Info("  Min Length:          %d", info.MinPasswordLength)
		output.Info("  Complexity:          %v", info.PasswordComplexity)
		output.Info("  Max Age:             %s", info.MaxPasswordAge)
		output.Info("  Lockout Threshold:   %d", info.LockoutThreshold)
		output.Info("  Lockout Duration:    %s", info.LockoutDuration)

		if info.MachineAccountQuota > 0 {
			output.Warn("ms-DS-MachineAccountQuota = %d — non-admin users can add machines (NoPac prerequisite!)", info.MachineAccountQuota)
		}
		return nil
	},
}

func flToName(level int) string {
	m := map[int]string{
		0: "Windows 2000",
		1: "Windows Server 2003 Interim",
		2: "Windows Server 2003",
		3: "Windows Server 2008",
		4: "Windows Server 2008 R2",
		5: "Windows Server 2012",
		6: "Windows Server 2012 R2",
		7: "Windows Server 2016 or higher", // Ver-7 covers 2019/2022 domain levels
	}
	if n, ok := m[level]; ok {
		return n
	}
	return "Unknown"
}

// ── enum adcs ────────────────────────────────────────────────────────────────

var enumADCSCmd = &cobra.Command{
	Use:   "adcs",
	Short: "Enumerate Active Directory Certificate Services (ADCS)",
	Long:  "Enumerates Certificate Authorities and certificate templates, flagging ESC1-ESC8 misconfigurations.",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if !opts.IsAuthenticated() {
			output.Warn("ADCS enumeration requires authentication. Please provide -u and -p.")
			return fmt.Errorf("authentication required")
		}
		ctx := context.Background()
		output.Section("ADCS Enumeration")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		cas, templates, err := ldapCl.QueryADCS(ctx)
		if err != nil {
			output.Warn("ADCS not found or not accessible: %v", err)
			return nil
		}

		output.Success("Found %d Certificate Authorities", len(cas))
		for _, ca := range cas {
			output.Info("  CA: %s (%s)", ca.Name, ca.DNSHostName)
		}

		output.Success("Found %d certificate templates", len(templates))
		var rows [][]string
		for _, t := range templates {
			vulns := buildTemplateVulns(t)
			rows = append(rows, []string{t.Name, t.DisplayName, vulns})
		}
		output.PrintTable([]string{"Name", "DisplayName", "Vulnerabilities"}, rows)

		if ws, _ := workspace.New(opts.WorkspaceDir, opts.Domain); ws != nil {
			_ = ws.SaveJSON("adcs_templates.json", templates)
		}
		return nil
	},
}

func buildTemplateVulns(t recon.CertTemplate) string {
	var v string
	if t.EnrolleeSuppliesSAN && t.ClientAuth && !t.RequiresManagerApproval {
		v += "[ESC1] "
	}
	if t.AnyPurpose && !t.RequiresManagerApproval {
		v += "[ESC2] "
	}
	if t.IsEnrollmentAgent {
		v += "[ESC3] "
	}
	if len(t.WritePermissions) > 0 {
		v += "[ESC4] "
	}
	if v == "" {
		v = "-"
	}
	return v
}

// ── enum tree ────────────────────────────────────────────────────────────────

var (
	enumTreeShare string
	enumTreePath  string
	enumTreeDepth int
)

var enumTreeCmd = &cobra.Command{
	Use:   "tree",
	Short: "Display a visual tree of an SMB share",
	Long: `Recursively lists files and directories in an SMB share in a tree format.
Allows visual exploration of remote file systems.

Example:
  adreaper enum tree -d lab.local --dc-ip 10.10.10.1 -u admin -p pass --share SYSVOL
  adreaper enum tree --share 'C$' --depth 2`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}

		smbCl, err := recon.NewSMBClient(opts)
		if err != nil {
			return err
		}
		defer smbCl.Close()

		// Global Root for the tree (Hostname/IP)
		globalRoot := &output.TreeEntry{
			Name:  opts.DCIP,
			IsDir: true,
		}

		if enumTreeShare == "" {
			output.Section("SMB Global Tree View")
			output.Info("Querying all accessible shares...")
			shares, err := smbCl.ListShares()
			if err != nil {
				return err
			}

			for _, sh := range shares {
				if sh.Access == "DENIED" || sh.Name == "IPC$" {
					continue
				}
				globalRoot.Children = append(globalRoot.Children, &output.TreeEntry{
					Name:  sh.Name,
					IsDir: true,
				})
			}
			output.PrintTree(globalRoot)
			output.Info("Use --share <name> to explore specific contents, or --share all for exhaustive recon.")
			return nil
		}

		// Trim quotes if passed by shell
		enumTreeShare = strings.Trim(enumTreeShare, "'\"")

		if strings.ToLower(enumTreeShare) == "all" {
			output.Section("Exhaustive SMB Tree Recon (All Shares)")
			output.Info("Scanning every accessible share with depth %d...", enumTreeDepth)

			shares, err := smbCl.ListShares()
			if err != nil {
				return err
			}

			for _, sh := range shares {
				if sh.Access == "DENIED" || sh.Name == "IPC$" {
					continue
				}
				output.Info("Walking share: %s...", sh.Name)
				tree, _ := smbCl.WalkTree(sh.Name, ".", enumTreeDepth)
				if tree != nil {
					globalRoot.Children = append(globalRoot.Children, tree)
				}
			}
			fmt.Println()
			output.PrintTree(globalRoot)
			return nil
		}

		output.Section(fmt.Sprintf("SMB Tree: %s", enumTreeShare))
		output.Info("Connecting to SMB share...")

		if enumTreePath == "" {
			enumTreePath = "."
		}

		tree, err := smbCl.WalkTree(enumTreeShare, enumTreePath, enumTreeDepth)
		if err != nil {
			return fmt.Errorf("walk tree: %w", err)
		}

		if tree == nil {
			output.Warn("No results found or share inaccessible.")
			return nil
		}

		output.PrintTree(tree)
		return nil
	},
}

func init() {
	enumTreeCmd.Flags().StringVarP(&enumTreeShare, "share", "s", "", "SMB share to walk (required)")
	enumTreeCmd.Flags().StringVarP(&enumTreePath, "path", "P", ".", "Starting sub-path within the share")
	enumTreeCmd.Flags().IntVarP(&enumTreeDepth, "depth", "D", 3, "Maximum depth of recursion")
}

// ── enum local-admins ────────────────────────────────────────────────────────

var enumLocalAdminsCmd = &cobra.Command{
	Use:   "local-admins",
	Short: "Local Admin Hunt — Identify where users have local administrative rights via GPO",
	Long: `Analyzes Group Policy Objects (GPO) to find 'Restricted Groups' and 'Group Policy Preferences' 
that modify local administrators. Cross-references SIDs to find domain users with local admin access.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		if !opts.IsAuthenticated() {
			return fmt.Errorf("local-admin hunting requires valid credentials")
		}

		ctx := context.Background()
		output.Section("Local Admin Hunting (via GPO)")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		smbCl, err := recon.NewSMBClient(opts)
		if err != nil {
			return fmt.Errorf("SMB connect (SYSVOL access): %w", err)
		}
		defer smbCl.Close()

		results, err := ldapCl.FindLocalAdmins(ctx, smbCl)
		if err != nil {
			return err
		}

		if len(results) == 0 {
			output.Info("No local administrative mappings found in GPOs")
			return nil
		}

		var rows [][]string
		for _, r := range results {
			rows = append(rows, []string{r.Principal, r.PolicyTarget, r.Source})
		}

		output.PrintTable([]string{"PRINCIPAL (User/Group)", "GPO NAME", "POLICY SOURCE"}, rows)
		return nil
	},
}

// ── enum all ─────────────────────────────────────────────────────────────────

var enumAllCmd = &cobra.Command{
	Use:   "all",
	Short: "Comprehensive Domain Audit — Gather high-level stats from all categories",
	Long: `Performs a shallow but wide-reaching discovery of the entire domain environment.
Summarizes counts for users, computers, groups, GPOs, and trusts to map the operational surface.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Domain-Wide Reconnaissance (Super-Enum)")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		output.Info("Performing breadth-first discovery of domain objects...")
		summary, err := ldapCl.QueryAll(ctx)
		if err != nil {
			return err
		}

		output.Success("Aggregate Domain Report Extracted")
		fmt.Println()

		var rows [][]string
		rows = append(rows, []string{"Users", fmt.Sprintf("%d", summary.UserCount), "Personnel/Service identites"})
		rows = append(rows, []string{"Computers", fmt.Sprintf("%d", summary.ComputerCount), "Workstations, Servers, and DCs"})
		rows = append(rows, []string{"Groups", fmt.Sprintf("%d", summary.GroupCount), "Permission containers"})
		rows = append(rows, []string{"Trusts", fmt.Sprintf("%d", summary.TrustCount), "Inter-domain relationships"})
		rows = append(rows, []string{"OUs", fmt.Sprintf("%d", summary.OUCount), "Deployment containers"})
		rows = append(rows, []string{"GPOs", fmt.Sprintf("%d", summary.GPOCount), "Configuration policies"})

		output.PrintTable([]string{"CATEGORY", "COUNT", "DESCRIPTION"}, rows)

		output.Info("Use specific 'enum <category>' commands for detailed attribute inspection.")
		return nil
	},
}

// ── enum dump ─────────────────────────────────────────────────────────────────

var enumDumpCmd = &cobra.Command{
	Use:   "dump",
	Short: "Total Visibility Dump — Extract ALL users, computers, and groups",
	Long: `Performs a massive data extraction of all primary AD objects.
Displays Usernames, Computer Names, and Group Names in a single combined list for exhaustive reconnaissance.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}
		ctx := context.Background()
		output.Section("Total AD Object Dump")

		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			return err
		}
		defer ldapCl.Close()

		output.Info("Extracting all primary directory objects (this may take a moment)...")
		users, comps, groups, err := ldapCl.QueryDump(ctx)
		if err != nil {
			return err
		}

		output.Success("Extraction complete: %d Objects found", len(users)+len(comps)+len(groups))

		// 1. Users Section
		if len(users) > 0 {
			output.Section("Domain Users")
			var userRows [][]string
			for _, u := range users {
				userRows = append(userRows, []string{u.SAMAccountName, u.UPN, u.Description})
			}
			output.PrintTable([]string{"SAMACCOUNTNAME", "UPN", "DESCRIPTION"}, userRows)
		}

		// 2. Computers Section
		if len(comps) > 0 {
			output.Section("Domain Computers")
			var compRows [][]string
			for _, c := range comps {
				compRows = append(compRows, []string{c.SAMAccountName, c.DNSHostName, c.OperatingSystem})
			}
			output.PrintTable([]string{"SAMACCOUNTNAME", "DNS HOSTNAME", "OPERATING SYSTEM"}, compRows)
		}

		// 3. Groups Section
		if len(groups) > 0 {
			output.Section("Domain Groups")
			var groupRows [][]string
			for _, g := range groups {
				groupRows = append(groupRows, []string{g.SAMAccountName, fmt.Sprintf("%d", len(g.Members)), g.Description})
			}
			output.PrintTable([]string{"GROUP NAME", "MEMBERS", "DESCRIPTION"}, groupRows)
		}

		output.Info("Use specific 'enum <category>' commands for deeper attribute analysis.")
		return nil
	},
}
