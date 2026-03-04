package recon

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"

	"adreaper/internal/config"
)

// DNSClient wraps DNS queries for AD reconnaissance.
type DNSClient struct {
	server string
	client *dns.Client
}

// DCRecord holds domain controller information from DNS.
type DCRecord struct {
	Hostname string
	IP       string
	Port     uint16
	Priority uint16
	Weight   uint16
}

// NewDNSClient creates a DNS client targeting the specified server.
func NewDNSClient(opts *config.Options) *DNSClient {
	server := opts.DCIP
	if server == "" {
		hosts, _ := net.LookupHost(opts.Domain + ".")
		if len(hosts) > 0 {
			server = hosts[0]
		}
	}
	if !strings.Contains(server, ":") {
		server = server + ":53"
	}
	return &DNSClient{
		server: server,
		client: &dns.Client{Timeout: 5 * time.Second},
	}
}

// EnumerateDCs discovers Domain Controllers via SRV records.
func (d *DNSClient) EnumerateDCs(ctx context.Context, domain string) ([]DCRecord, error) {
	var dcs []DCRecord

	// Key SRV records for AD DC discovery
	srvTargets := []string{
		"_ldap._tcp.dc._msdcs." + domain + ".",
		"_kerberos._tcp.dc._msdcs." + domain + ".",
		"_ldap._tcp." + domain + ".",
	}

	seen := map[string]bool{}
	for _, target := range srvTargets {
		records, err := d.querySRV(ctx, target)
		if err != nil {
			continue
		}
		for _, r := range records {
			if seen[r.Hostname] {
				continue
			}
			seen[r.Hostname] = true
			// Resolve hostname → IP
			ips, _ := d.resolveA(ctx, r.Hostname)
			if len(ips) > 0 {
				r.IP = ips[0]
			}
			dcs = append(dcs, r)
		}
	}
	return dcs, nil
}

// ZoneTransfer attempts an AXFR zone transfer (rarely succeeds but always worth trying).
func (d *DNSClient) ZoneTransfer(ctx context.Context, domain string) ([]string, error) {
	t := &dns.Transfer{}
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(domain))

	ch, err := t.In(m, d.server)
	if err != nil {
		return nil, fmt.Errorf("zone transfer refused: %w", err)
	}

	var records []string
	for env := range ch {
		if env.Error != nil {
			return records, env.Error
		}
		for _, rr := range env.RR {
			records = append(records, rr.String())
		}
	}
	return records, nil
}

// ResolveHost resolves a hostname to its A/AAAA records.
func (d *DNSClient) ResolveHost(ctx context.Context, hostname string) ([]string, error) {
	ips, err := d.resolveA(ctx, dns.Fqdn(hostname))
	if err != nil {
		return nil, err
	}
	return ips, nil
}

// ReverseLookup performs a PTR lookup for the given IP.
func (d *DNSClient) ReverseLookup(ctx context.Context, ip string) (string, error) {
	arpa, err := dns.ReverseAddr(ip)
	if err != nil {
		return "", err
	}
	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)
	r, _, err := d.client.ExchangeContext(ctx, m, d.server)
	if err != nil {
		return "", err
	}
	for _, a := range r.Answer {
		if ptr, ok := a.(*dns.PTR); ok {
			return ptr.Ptr, nil
		}
	}
	return "", fmt.Errorf("no PTR record for %s", ip)
}

// QueryGlobalCatalog attempts to discover GC servers via DNS.
func (d *DNSClient) QueryGlobalCatalog(ctx context.Context, domain string) ([]DCRecord, error) {
	return d.querySRV(ctx, "_gc._tcp."+domain+".")
}

func (d *DNSClient) querySRV(ctx context.Context, name string) ([]DCRecord, error) {
	m := new(dns.Msg)
	m.SetQuestion(name, dns.TypeSRV)
	r, _, err := d.client.ExchangeContext(ctx, m, d.server)
	if err != nil {
		return nil, err
	}
	var records []DCRecord
	for _, a := range r.Answer {
		if srv, ok := a.(*dns.SRV); ok {
			records = append(records, DCRecord{
				Hostname: strings.TrimSuffix(srv.Target, "."),
				Port:     srv.Port,
				Priority: srv.Priority,
				Weight:   srv.Weight,
			})
		}
	}
	return records, nil
}

func (d *DNSClient) resolveA(ctx context.Context, fqdn string) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(fqdn, dns.TypeA)
	r, _, err := d.client.ExchangeContext(ctx, m, d.server)
	if err != nil {
		return nil, err
	}
	var ips []string
	for _, a := range r.Answer {
		if rec, ok := a.(*dns.A); ok {
			ips = append(ips, rec.A.String())
		}
	}
	return ips, nil
}
