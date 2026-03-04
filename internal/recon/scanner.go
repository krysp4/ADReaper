package recon

import (
	"adreaper/internal/config"
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ScanResult holds findings for a single host.
type ScanResult struct {
	Host     string
	Ports    []PortResult
	OS       string
	Banners  map[int]string
	HostInfo *HostInfo
}

// HostInfo contains deep fingerprinting data.
type HostInfo struct {
	NetBIOSName string
	DomainName  string
	ForestName  string
	OSVersion   string
	BuildNumber string
}

// PortResult holds status for a single port.
type PortResult struct {
	Port    int
	State   string // Open, Closed, Filtered
	Service string
}

// InfraScanner performs infrastructure reconnaissance.
type InfraScanner struct {
	Timeout     time.Duration
	Threads     int
	OnPortFound func(PortResult)
	Progress    uint32 // Atomic counter for total ports checked
	Options     *config.Options
}

// NewInfraScanner creates a new scanner with defaults.
func NewInfraScanner() *InfraScanner {
	return &InfraScanner{
		Timeout: 3 * time.Second,
		Threads: 50,
	}
}

// ScanPorts performs a TCP port scan on a target.
func (s *InfraScanner) ScanPorts(ctx context.Context, target string, ports []int, aggressive bool) (ScanResult, error) {
	result := ScanResult{
		Host:    target,
		Banners: make(map[int]string),
	}

	if aggressive {
		result.HostInfo = s.Fingerprint(target)
	}

	// Scanner is now silent to allow caller (infra Cmd) to control UI flow

	var wg sync.WaitGroup
	portChan := make(chan int, s.Threads)
	resChan := make(chan PortResult, len(ports))

	for i := 0; i < s.Threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for port := range portChan {
				addr := fmt.Sprintf("%s:%d", target, port)
				conn, err := net.DialTimeout("tcp", addr, s.Timeout)
				if err != nil {
					atomic.AddUint32(&s.Progress, 1)
					continue
				}

				// Port is open
				name := s.lookupService(port)
				pr := PortResult{Port: port, State: "Open", Service: name}
				resChan <- pr
				if s.OnPortFound != nil {
					s.OnPortFound(pr)
				}

				// Try to grab banner
				_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
				banner := make([]byte, 1024)
				n, _ := conn.Read(banner)
				if n > 0 {
					result.Banners[port] = strings.TrimSpace(string(banner[:n]))
				}
				conn.Close()
				atomic.AddUint32(&s.Progress, 1)
			}
		}()
	}

	for _, p := range ports {
		portChan <- p
	}
	close(portChan)
	wg.Wait()
	close(resChan)

	for p := range resChan {
		result.Ports = append(result.Ports, p)
	}

	// Try to detect OS via common banners or specific ports
	result.OS = s.detectOS(result)

	// Automatic refinement: if ports 389 or 445 are open, we can almost always get the exact OS
	// even if aggressive mode wasn't requested.
	if result.HostInfo == nil {
		hasADPorts := false
		for _, p := range result.Ports {
			if p.Port == 389 || p.Port == 445 || p.Port == 636 {
				hasADPorts = true
				break
			}
		}
		if hasADPorts {
			result.HostInfo = s.Fingerprint(target)
		}
	}

	// Final override: if we have a detailed OS version, use it as the primary OS string
	if result.HostInfo != nil && result.HostInfo.OSVersion != "" {
		result.OS = result.HostInfo.OSVersion
	}

	return result, nil
}

func (s *InfraScanner) lookupService(port int) string {
	common := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		88:   "kerberos",
		110:  "pop3",
		135:  "msrpc",
		139:  "netbios-ssn",
		143:  "imap",
		389:  "ldap",
		443:  "https",
		445:  "microsoft-ds",
		464:  "kpasswd",
		593:  "http-rpc-epmap",
		636:  "ldaps",
		1433: "ms-sql-s",
		3268: "ldap-gc",
		3269: "ldaps-gc",
		3389: "ms-wbt-server",
		5985: "wsman",
		5986: "wsman-ssl",
	}
	if name, ok := common[port]; ok {
		return name
	}
	return "unknown"
}

func (s *InfraScanner) detectOS(res ScanResult) string {
	// Simple heuristic based OS detection
	hasRDP := false
	hasSMB := false
	hasWinRM := false
	hasSSH := false

	for _, p := range res.Ports {
		switch p.Port {
		case 3389:
			hasRDP = true
		case 445:
			hasSMB = true
		case 5985, 5986:
			hasWinRM = true
		case 22:
			hasSSH = true
		}
	}

	// Banner analysis
	for _, banner := range res.Banners {
		lower := strings.ToLower(banner)
		if strings.Contains(lower, "ubuntu") || strings.Contains(lower, "debian") {
			return "Linux (Ubuntu/Debian)"
		}
		if strings.Contains(lower, "microsoft") {
			return "Windows"
		}
	}

	if hasSMB && (hasRDP || hasWinRM) {
		return "Windows Server"
	}
	if hasSMB {
		return "Windows (Probable)"
	}
	if hasRDP || hasWinRM {
		return "Windows (RDP/WinRM)"
	}
	if hasSSH {
		return "Linux/Unix"
	}
	return "Unknown"
}

// Fingerprint attempts to gather deep host info via SMB and LDAP.
func (s *InfraScanner) Fingerprint(target string) *HostInfo {
	info := &HostInfo{}

	// 1. Try LDAP Discovery (Port 389)
	ldapAddr := fmt.Sprintf("%s:389", target)
	lConn, err := net.DialTimeout("tcp", ldapAddr, 1*time.Second)
	if err == nil {
		lConn.Close()
		// If we have options/credentials, use them
		var opts *config.Options
		if s.Options != nil {
			opts = s.Options
			opts.DCIP = target
			opts.LDAPPort = 389
		} else {
			opts = &config.Options{DCIP: target, LDAPPort: 389, LDAPTimeout: 2 * time.Second}
		}

		ldCl, err := NewLDAPClient(opts)
		if err == nil {
			defer ldCl.Close()
			osVer, err := ldCl.DiscoverOSUnauthenticated(context.Background())
			if err == nil {
				info.OSVersion = osVer
			}
		}
	}

	// 2. Try SMB Discovery (Port 445) if LDAP failed or to supplement
	if info.OSVersion == "" {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", target), 1*time.Second)
		if err == nil {
			conn.Close()
			info.OSVersion = "Windows Server (Probable)"
		}
	}

	return info
}
