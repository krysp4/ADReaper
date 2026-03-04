package cmd

import (
	"context"
	"time"

	"adreaper/internal/bloodhound"
	"adreaper/internal/output"
	"adreaper/internal/recon"
	"adreaper/internal/workspace"

	"github.com/spf13/cobra"
)

var autopilotCmd = &cobra.Command{
	Use:   "autopilot",
	Short: "Fully automated engagement orchestration (Phase 1-5)",
	Long: `Executes a full chained attack sequence:
  1. Infrastructure Scan & OS Detection
  2. AD Enumeration (Users, Groups, ADCS)
  3. Kerberoasting & AS-REP Roasting
  4. BloodHound Telemetry Collection
  5. Critical File Harvesting
  6. Professional HTML Reporting`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := opts.Validate(); err != nil {
			return err
		}

		ctx := context.Background()
		startTime := time.Now()

		output.Section("AUTOPILOT: MISSION START")

		reportData := output.HTMLReportData{
			Domain:    opts.Domain,
			DCIP:      opts.DCIP,
			Timestamp: startTime.Format(time.RFC1123),
		}

		// --- PHASE 1: RECON ---
		output.Info("[Phase 1] Infrastructure Reconnaissance...")
		scanner := recon.NewInfraScanner()
		ports := []int{88, 135, 139, 389, 445, 636, 3268, 3269, 5985}
		scanRes, _ := scanner.ScanPorts(ctx, opts.DCIP, ports, true)
		output.Success("  → OS Detected: %s", scanRes.OS)

		// --- PHASE 2: ENUM ---
		output.Info("[Phase 2] AD Enumeration...")
		ldapCl, err := recon.NewLDAPClient(opts)
		if err != nil {
			output.Warn("  → LDAP Enumeration failed: %v", err)
		} else {
			defer ldapCl.Close()
			users, _ := ldapCl.QueryUsers(ctx)
			groups, _ := ldapCl.QueryGroups(ctx)
			cas, _, _ := ldapCl.QueryADCS(ctx)
			output.Success("  → Found %d users and %d groups.", len(users), len(groups))
			reportData.UsersCount = len(users)
			reportData.GroupsCount = len(groups)
			reportData.AdcsCount = len(cas)
			if len(cas) > 0 {
				output.Success("  → ADCS identified: %d CAs.", len(cas))
			}

			// --- PHASE 4: BLOODHOUND ---
			output.Info("[Phase 4] Collecting BloodHound Telemetry...")
			collector := bloodhound.NewCollector(ldapCl, opts)
			result, err := collector.Collect(ctx)
			if err == nil {
				ws, _ := workspace.New(opts.WorkspaceDir, opts.Domain)
				files, _ := collector.SaveJSON(ws.Dir, result)
				output.Success("  → BloodHound data saved: %d files.", len(files))
			}
		}

		// --- PHASE 5: HARVESTING ---
		output.Info("[Phase 5] Loot Harvesting...")
		smbCl, err := recon.NewSMBClient(opts)
		if err == nil {
			defer smbCl.Close()
			exts := []string{"kdbx", "conf", "txt"}
			_ = smbCl.Spider("LabUsers", exts, func(path string, data []byte) {
				output.Success("  → Found Loot: %s", path)
				reportData.Loot = append(reportData.Loot, path)
			})
		}

		// --- PHASE 6: REPORTING ---
		output.Info("[Phase 6] Generating Professional Report...")
		reportData.Artifacts, _ = output.DiscoverArtifacts(opts.WorkspaceDir)
		reportPath, err := output.GenerateHTMLReport(opts.WorkspaceDir, reportData)
		if err == nil {
			output.Success("  → Report generated: %s", reportPath)
		}

		output.Section("MISSION ACCOMPLISHED")
		output.Info("Total Time: %v", time.Since(startTime))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(autopilotCmd)
}
