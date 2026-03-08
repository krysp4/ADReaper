package cmd

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"adreaper/internal/output"
	"adreaper/internal/recon"

	"github.com/spf13/cobra"
)

var infraCmd = &cobra.Command{
	Use:   "infra",
	Short: "Infrastructure reconnaissance — port scanning and DNS enumeration",
	Long: `The 'infra' module provides network-level reconnaissance before or alongside LDAP enumeration.

Subcommands:
  scan    TCP port scan with service detection and OS fingerprinting
  dns     Enumerate Domain Controllers and Global Catalogs via SRV DNS records`,
}

var (
	infraScanTarget     string
	infraScanPorts      string
	infraScanAggressive bool
	infraScanNoPing     bool
	infraScanPn         bool
	infraScanSave       string
)

var infraScanCmd = &cobra.Command{
	Use:   "scan",
	Short: "TCP port scan with service detection and OS fingerprinting",
	Long: `Multi-threaded TCP port scanner with service banner grabbing and heuristic OS detection.

Default Ports (Top 20 for AD environments):
  21 FTP, 22 SSH, 53 DNS, 80 HTTP, 88 Kerberos, 135 RPC, 139/445 SMB
  389 LDAP, 443 HTTPS, 464 Kpasswd, 636 LDAPS, 1433 MSSQL
  3268/3269 GC LDAP, 3389 RDP, 5985/5986 WinRM, 9389 AD Web Services

Flags:
  --ports 80,443,445    Scan specific ports
  --ports all           Scan all 65535 TCP ports (slow!)
  -A                    Aggressive: enables deep OS/service fingerprinting
  -Pn                   Skip host discovery (Nmap style)
  --save results.txt    Save the report to a text file

Examples:
  adreaper infra scan --dc-ip 10.10.10.1
  adreaper infra scan --dc-ip 10.10.10.1 --ports all -A
  adreaper infra scan --dc-ip 10.10.10.1 --ports 80,443,445 --save scan.txt`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if infraScanTarget == "" {
			infraScanTarget = opts.DCIP
		}
		if infraScanTarget == "" {
			return fmt.Errorf("target host is required (--target)")
		}

		ctx := context.Background()
		output.Section(fmt.Sprintf("Infra Scan: %s", infraScanTarget))

		if infraScanNoPing || infraScanPn {
			output.Info("Host discovery disabled (No-Ping mode).")
		}

		// Parse ports
		var ports []int
		lowerPorts := strings.ToLower(infraScanPorts)
		if lowerPorts == "all" {
			output.Info("Scanning ALL ports (65535)... This may take a while.")
			for i := 1; i <= 65535; i++ {
				ports = append(ports, i)
			}
		} else if infraScanPorts == "" {
			// Top 20 common ports for AD environments
			ports = []int{21, 22, 53, 80, 88, 135, 139, 389, 443, 445, 464, 593, 636, 1433, 3268, 3269, 3389, 5985, 5986, 9389}
		} else {
			parts := strings.Split(infraScanPorts, ",")
			for _, p := range parts {
				val, err := strconv.Atoi(strings.TrimSpace(p))
				if err == nil {
					ports = append(ports, val)
				}
			}
		}

		scanner := recon.NewInfraScanner()
		scanner.Options = opts // Pass credentials for deep fingerprinting

		var outMu sync.Mutex
		var linesPrinted int32

		// Initial bar positioning
		if infraScanSave == "" {
			outMu.Lock()
			output.PrintProgressBar(0, len(ports))
			fmt.Println()
			outMu.Unlock()
		}

		// Automatic Progress Ticker (Sticky Top Bar)
		stopProgress := make(chan struct{})
		if infraScanSave == "" {
			go func() {
				ticker := time.NewTicker(250 * time.Millisecond)
				defer ticker.Stop()
				for {
					select {
					case <-stopProgress:
						outMu.Lock()
						n := int(atomic.LoadInt32(&linesPrinted))
						// Move UP n+1 lines to Bar, Clear it, Print final bar
						fmt.Printf("\033[%dF\033[2K", n+1)
						output.PrintProgressBar(len(ports), len(ports))
						// Move back DOWN to stay below
						fmt.Printf("\033[%dE", n+1)
						outMu.Unlock()
						return
					case <-ticker.C:
						outMu.Lock()
						n := int(atomic.LoadInt32(&linesPrinted))
						prog := int(atomic.LoadUint32(&scanner.Progress))
						if prog > len(ports) {
							prog = len(ports)
						}
						// Move UP n+1 lines to Bar, Clear it, Print bar
						fmt.Printf("\033[%dF\033[2K", n+1)
						output.PrintProgressBar(prog, len(ports))
						// Move back DOWN to where we were
						fmt.Printf("\033[%dE", n+1)
						outMu.Unlock()
					}
				}
			}()
		}

		res, err := scanner.ScanPorts(ctx, infraScanTarget, ports, infraScanAggressive)
		if infraScanSave == "" {
			close(stopProgress)
			fmt.Println() // Final spacing after scan report
		}
		if err != nil {
			return err
		}

		// Sort ports for output
		sort.Slice(res.Ports, func(i, j int) bool {
			return res.Ports[i].Port < res.Ports[j].Port
		})

		if len(res.Ports) == 0 {
			output.Warn("No open ports found on %s.", infraScanTarget)
			output.Info("Hint: The host might be down, filtered by a firewall, or the timeout (3s) might be too short for this network segment.")
			return nil
		}

		output.Info("Detected OS: %s", output.SuccessStr(res.OS))
		if res.HostInfo != nil {
			if res.HostInfo.OSVersion != "" {
				output.Info("OS Details:  %s", output.SuccessStr(res.HostInfo.OSVersion))
			}
			if res.HostInfo.DomainName != "" {
				output.Info("AD Domain:   %s", output.InfoStr(res.HostInfo.DomainName))
			}
		}
		fmt.Println()

		var rows [][]string
		for _, p := range res.Ports {
			banner := res.Banners[p.Port]
			rows = append(rows, []string{
				strconv.Itoa(p.Port),
				p.State,
				p.Service,
				banner,
			})
		}

		output.PrintTable([]string{"PORT", "STATE", "SERVICE", "BANNER"}, rows)

		if infraScanSave != "" {
			saveInfraReport(infraScanSave, res)
		}

		return nil
	},
}

var infraDnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "Enumerate Domain Controllers and Global Catalogs via SRV DNS records",
	Long: `Performs SRV record queries to enumerate the Active Directory infrastructure:
  - _ldap._tcp.dc._msdcs.<domain>      : Domain Controllers
  - _gc._tcp.<domain>                  : Global Catalogs (multi-domain forests)

SRV records are the authoritative method Windows uses to locate DCs.
Useful when --dc-ip is not known or to validate the DC topology.

Requires: --domain (-d) flag

Example:
  adreaper infra dns -d corp.local`,
	RunE: func(cmd *cobra.Command, args []string) error {
		output.Section(fmt.Sprintf("DNS Recon: %s", opts.Domain))
		client := recon.NewDNSClient(opts)
		ctx := context.Background()

		output.Info("Querying Domain Controllers (SRV)...")
		dcs, _ := client.EnumerateDCs(ctx, opts.Domain)
		if len(dcs) > 0 {
			var rows [][]string
			for _, dc := range dcs {
				rows = append(rows, []string{dc.Hostname, dc.IP, fmt.Sprintf("%d", dc.Port)})
			}
			output.PrintTable([]string{"HOSTNAME", "IP", "PORT"}, rows)
		} else {
			output.Warn("No Domain Controllers found via SRV.")
		}

		output.Info("Querying Global Catalogs (SRV)...")
		gcs, _ := client.QueryGlobalCatalog(ctx, opts.Domain)
		if len(gcs) > 0 {
			var rows [][]string
			for _, gc := range gcs {
				rows = append(rows, []string{gc.Hostname, gc.IP, fmt.Sprintf("%d", gc.Port)})
			}
			output.PrintTable([]string{"HOSTNAME", "IP", "PORT"}, rows)
		}

		return nil
	},
}

func saveInfraReport(path string, res recon.ScanResult) {
	output.Info("Saving report to %s...", path)
	f, err := os.Create(path)
	if err != nil {
		output.Error("Could not create report: %v", err)
		return
	}
	defer f.Close()

	fmt.Fprintf(f, "ADReaper Infra Scan Report\n")
	fmt.Fprintf(f, "Target: %s\n", res.Host)
	fmt.Fprintf(f, "OS:     %s\n", res.OS)
	if res.HostInfo != nil {
		fmt.Fprintf(f, "OS Det: %s\n", res.HostInfo.OSVersion)
	}
	fmt.Fprintf(f, "\nPORT\tSTATE\tSERVICE\tBANNER\n")
	fmt.Fprintf(f, "----\t-----\t-------\t------\n")
	for _, p := range res.Ports {
		fmt.Fprintf(f, "%d\t%s\t%s\t%s\n", p.Port, p.State, p.Service, res.Banners[p.Port])
	}
}

func init() {
	infraScanCmd.Flags().StringVarP(&infraScanTarget, "target", "t", "", "Target host to scan (defaults to --dc-ip)")
	infraScanCmd.Flags().StringVar(&infraScanPorts, "ports", "", "Ports to scan (e.g. 80,445 or 'all')")
	infraScanCmd.Flags().BoolVarP(&infraScanAggressive, "aggressive", "A", false, "Enable deep fingerprinting")
	infraScanCmd.Flags().BoolVar(&infraScanNoPing, "no-ping", false, "Skip host discovery")
	infraScanCmd.Flags().BoolVar(&infraScanPn, "Pn", false, "Skip host discovery (Nmap style)")
	infraScanCmd.Flags().Lookup("Pn").NoOptDefVal = "true" // Handle -Pn correctly
	infraScanCmd.Flags().StringVarP(&infraScanSave, "save", "s", "", "Save results to a .txt file")

	infraCmd.AddCommand(infraScanCmd)
	infraCmd.AddCommand(infraDnsCmd)
	rootCmd.AddCommand(infraCmd)
}
