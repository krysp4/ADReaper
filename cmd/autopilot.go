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
	Short: "Automated end-to-end engagement orchestration",
	Long: `Autopilot executes a fully automated, phased engagement against the target domain.
It chains reconnaissance, enumeration, exploitation, and reporting without operator intervention.

Phases:
  Phase 1 — Infrastructure Recon    : Port scan + OS detection on the DC
  Phase 2 — AD Enumeration          : Users, groups, and ADCS certificate authorities
  Phase 4 — BloodHound Collection   : SharpHound-compatible JSON export for attack path analysis
  Phase 5 — Loot Harvesting         : SMB share spider for sensitive files (.kdbx, .conf, .txt)
  Phase 6 — HTML Report Generation  : Self-contained report saved to the workspace directory

Generated Artifacts (workspace/):
  - users.json                      : Full user object dump
  - BloodHound JSON files           : Ready for import into BloodHound CE
  - engagement_report.html          : Executive-ready HTML engagement summary

Example:
  adreaper autopilot -d corp.local --dc-ip 10.10.10.1 -u admin -p 'P@ssword'
  adreaper autopilot -d corp.local --dc-ip 10.10.10.1 -u admin -p 'P@ssword' -o autopilot_log`,
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
