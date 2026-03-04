package recon

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	ldap "github.com/go-ldap/ldap/v3"

	"adreaper/internal/config"
)

// ── UAC bit flags ─────────────────────────────────────────────────────────────

const (
	UACAccountDisable          uint32 = 0x0002
	UACPasswordNotRequired     uint32 = 0x0020
	UACWorkstationTrustAccount uint32 = 0x1000
	UACServerTrustAccount      uint32 = 0x2000 // Domain Controller
	UACDontExpirePassword      uint32 = 0x10000
	UACTrustedForDelegation    uint32 = 0x80000  // unconstrained delegation — DANGEROUS
	UACDontReqPreauth          uint32 = 0x400000 // AS-REP roastable
	UACTrustedToAuthForDeleg   uint32 = 0x1000000
)

// ── Structs ───────────────────────────────────────────────────────────────────

// User represents an AD user account.
type User struct {
	SAMAccountName          string
	UPN                     string
	DN                      string
	Description             string
	UAC                     uint32
	Enabled                 bool
	AdminCount              bool
	NoKerbPreauth           bool     // AS-REP roastable
	SPNs                    []string // Kerberoastable if non-empty
	MemberOf                []string
	LastLogon               time.Time
	PasswordLastSet         time.Time
	BadPwdCount             int
	UnconstrainedDelegation bool
	ConstrainedDelegation   []string
	PasswordNeverExpires    bool
	PasswordNotRequired     bool
	DisplayName             string
	Title                   string
	Department              string
	Mail                    string
	SID                     string
}

// Computer represents an AD computer account.
type Computer struct {
	SAMAccountName          string
	DNSHostName             string
	OperatingSystem         string
	OSVersion               string
	LastLogon               time.Time
	UAC                     uint32
	Enabled                 bool
	SPNs                    []string
	IsDC                    bool
	UnconstrainedDelegation bool
	ConstrainedDelegation   []string
	RBCD                    string // msDS-AllowedToActOnBehalfOfOtherIdentity (raw)
	LAPSEnabled             bool
	LAPSPassword            string // ms-Mcs-AdmPwd — immediate win if readable!
	DisplayName             string
	SID                     string
}

// Group represents an AD group.
type Group struct {
	SAMAccountName string
	DN             string
	Description    string
	Members        []string
	AdminCount     bool
	GroupType      int32
}

// DomainSummary provides high-level domain statistics.
type DomainSummary struct {
	UserCount     int
	ComputerCount int
	GroupCount    int
	TrustCount    int
	OUCount       int
	GPOCount      int
}

// DomainInfo aggregates domain-level policy.
type DomainInfo struct {
	Name                string
	DN                  string
	FunctionalLevel     int
	MachineAccountQuota int
	MaxPasswordAge      time.Duration
	MinPasswordLength   int
	LockoutThreshold    int
	LockoutDuration     time.Duration
	ObservationWindow   time.Duration
	PasswordComplexity  bool
}

// Trust represents a domain trust relationship.
type Trust struct {
	Name          string
	Partner       string
	Direction     string // INBOUND | OUTBOUND | BIDIRECTIONAL
	TrustType     string
	Attributes    uint32
	IsSIDFiltered bool
	IsTransitive  bool
}

// ACLEntry represents a dangerous ACE on a high-value object.
type ACLEntry struct {
	Object      string
	Principal   string
	Right       string
	AceType     string
	IsDangerous bool
	ObjectGUID  string
}

// CA is an ADCS Certificate Authority.
type CA struct {
	Name        string
	DNSHostName string
	DN          string
}

// CertTemplate is an ADCS certificate template with vulnerability flags.
type CertTemplate struct {
	Name                    string
	DN                      string
	DisplayName             string
	SchemaVersion           int
	Enabled                 bool
	RequiresManagerApproval bool
	EnrolleeSuppliesSAN     bool // CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT — ESC1
	AnyPurpose              bool // ESC2
	IsEnrollmentAgent       bool // ESC3
	ClientAuth              bool
	PKIFlag                 uint32
	ExtendedKeyUsage        []string
	EnrollmentRights        []string
	WritePermissions        []string
}

// OU represents an Organizational Unit.
type OU struct {
	Name string
	DN   string
	GUID string
}

// GPO represents a Group Policy Object.
type GPO struct {
	Name        string
	DisplayName string
	DN          string
	GUID        string
	Path        string
}

// Container represents an AD container.
type Container struct {
	Name string
	DN   string
	GUID string
}

// ── LDAPClient ────────────────────────────────────────────────────────────────

// LDAPClient wraps go-ldap with AD-specific helpers.
type LDAPClient struct {
	conn *ldap.Conn
	opts *config.Options
}

// NewLDAPClient connects to LDAP/LDAPS and authenticates.
func NewLDAPClient(opts *config.Options) (*LDAPClient, error) {
	var (
		conn *ldap.Conn
		err  error
	)
	if opts.UseLDAPS {
		tlsCfg := &tls.Config{
			ServerName:         opts.DCIP,
			InsecureSkipVerify: true, //nolint:gosec // pentest tool, self-signed certs expected
		}
		conn, err = ldap.DialURL(
			fmt.Sprintf("ldaps://%s:%d", opts.DCIP, opts.LDAPPort),
			ldap.DialWithTLSConfig(tlsCfg),
		)
	} else {
		conn, err = ldap.DialURL(fmt.Sprintf("ldap://%s:%d", opts.DCIP, opts.LDAPPort))
	}
	if err != nil {
		return nil, fmt.Errorf("LDAP dial: %w", err)
	}
	conn.SetTimeout(opts.LDAPTimeout)

	cl := &LDAPClient{conn: conn, opts: opts}
	if err := cl.bind(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("LDAP bind: %w", err)
	}
	return cl, nil
}

// bind performs LDAP authentication (simple bind with UPN format).
func (c *LDAPClient) bind() error {
	if !c.opts.IsAuthenticated() {
		return c.conn.UnauthenticatedBind("")
	}
	// Simple bind: user@domain.local
	// Note: Pass-the-Hash over LDAP requires NTLM SASL — not in go-ldap main branch.
	// For PTH use the SMB module (go-smb2 supports NTLM hash natively).
	upn := c.opts.Username
	if !strings.Contains(upn, "@") {
		upn = fmt.Sprintf("%s@%s", upn, strings.ToLower(c.opts.Domain))
	}
	return c.conn.Bind(upn, c.opts.Password)
}

// Close releases the LDAP connection.
func (c *LDAPClient) Close() {
	if c.conn != nil {
		c.conn.Close()
	}
}

// Modify executes an LDAP modify request.
func (c *LDAPClient) Modify(mr *ldap.ModifyRequest) error {
	return c.conn.Modify(mr)
}

// SearchRaw executes a raw LDAP search request.
func (c *LDAPClient) SearchRaw(sr *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return c.conn.Search(sr)
}

// Search executes a paged LDAP search under BaseDN.
func (c *LDAPClient) Search(ctx context.Context, filter string, attrs []string) ([]*ldap.Entry, error) {
	return c.SearchBase(ctx, c.opts.BaseDN(), filter, attrs)
}

func (c *LDAPClient) SearchBase(ctx context.Context, base, filter string, attrs []string) ([]*ldap.Entry, error) {
	var entries []*ldap.Entry
	paging := ldap.NewControlPaging(1000)

	for {
		select {
		case <-ctx.Done():
			return entries, ctx.Err()
		default:
		}
		sr := ldap.NewSearchRequest(
			base,
			ldap.ScopeWholeSubtree,
			ldap.NeverDerefAliases, 0,
			int(c.opts.LDAPTimeout.Seconds()),
			false,
			filter,
			attrs,
			[]ldap.Control{paging},
		)
		res, err := c.conn.Search(sr)
		if err != nil {
			return nil, err
		}
		entries = append(entries, res.Entries...)
		ctrl := ldap.FindControl(res.Controls, ldap.ControlTypePaging)
		if pgCtrl, ok := ctrl.(*ldap.ControlPaging); ok && len(pgCtrl.Cookie) > 0 {
			paging.SetCookie(pgCtrl.Cookie)
		} else {
			break
		}
	}
	return entries, nil
}

// ── User Queries ──────────────────────────────────────────────────────────────

var userAttrs = []string{
	"sAMAccountName", "userPrincipalName", "distinguishedName",
	"description", "userAccountControl", "memberOf",
	"lastLogonTimestamp", "pwdLastSet", "badPwdCount",
	"adminCount", "servicePrincipalName", "msDS-AllowedToDelegateTo",
	"displayName", "title", "department", "mail", "objectSid",
}

// QueryUsers returns all user accounts.
func (c *LDAPClient) QueryUsers(ctx context.Context) ([]User, error) {
	return c.queryUsers(ctx, "(&(objectCategory=person)(objectClass=user))")
}

// QuerySPNUsers returns accounts with SPNs set (Kerberoastable targets).
func (c *LDAPClient) QuerySPNUsers(ctx context.Context) ([]User, error) {
	return c.queryUsers(ctx,
		"(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*)(!userAccountControl:1.2.840.113556.1.4.803:=2))")
}

// QueryASREPUsers returns accounts with no Kerberos pre-auth required (AS-REP roastable).
// UAC bit 0x400000 (4194304) = DONT_REQ_PREAUTH
func (c *LDAPClient) QueryASREPUsers(ctx context.Context) ([]User, error) {
	return c.queryUsers(ctx,
		"(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304)(!userAccountControl:1.2.840.113556.1.4.803:=2))")
}

func (c *LDAPClient) queryUsers(ctx context.Context, filter string) ([]User, error) {
	entries, err := c.Search(ctx, filter, userAttrs)
	if err != nil {
		return nil, err
	}
	users := make([]User, 0, len(entries))
	for _, e := range entries {
		users = append(users, parseUser(e))
	}
	return users, nil
}

// ── Computer Queries ──────────────────────────────────────────────────────────

// QueryComputers returns all computer accounts.
func (c *LDAPClient) QueryComputers(ctx context.Context) ([]Computer, error) {
	attrs := []string{
		"sAMAccountName", "dNSHostName", "operatingSystem", "operatingSystemVersion",
		"lastLogonTimestamp", "userAccountControl", "servicePrincipalName",
		"msDS-AllowedToDelegateTo", "msDS-AllowedToActOnBehalfOfOtherIdentity",
		"ms-Mcs-AdmPwd", "displayName", "objectSid",
	}
	entries, err := c.Search(ctx, "(objectClass=computer)", attrs)
	if err != nil {
		return nil, err
	}
	comps := make([]Computer, 0, len(entries))
	for _, e := range entries {
		comps = append(comps, parseComputer(e))
	}
	return comps, nil
}

// ── Group Queries ─────────────────────────────────────────────────────────────

// QueryGroups returns all AD groups.
func (c *LDAPClient) QueryGroups(ctx context.Context) ([]Group, error) {
	attrs := []string{"sAMAccountName", "cn", "distinguishedName", "description", "member", "adminCount", "groupType"}
	entries, err := c.Search(ctx, "(objectClass=group)", attrs)
	if err != nil {
		return nil, err
	}
	groups := make([]Group, 0, len(entries))
	for _, e := range entries {
		groups = append(groups, parseGroup(e))
	}
	return groups, nil
}

// QueryAll performs a broad discovery of key domain metrics.
func (c *LDAPClient) QueryAll(ctx context.Context) (DomainSummary, error) {
	summary := DomainSummary{}

	// Broad counts
	users, _ := c.Search(ctx, "(&(objectCategory=person)(objectClass=user))", []string{"dn"})
	summary.UserCount = len(users)

	comps, _ := c.Search(ctx, "(objectClass=computer)", []string{"dn"})
	summary.ComputerCount = len(comps)

	groups, _ := c.Search(ctx, "(objectClass=group)", []string{"dn"})
	summary.GroupCount = len(groups)

	trusts, _ := c.Search(ctx, "(objectClass=trustedDomain)", []string{"dn"})
	summary.TrustCount = len(trusts)

	ous, _ := c.Search(ctx, "(objectClass=organizationalUnit)", []string{"dn"})
	summary.OUCount = len(ous)

	gpos, _ := c.SearchBase(ctx, "CN=Policies,CN=System,"+c.opts.BaseDN(), "(objectClass=groupPolicyContainer)", []string{"dn"})
	summary.GPOCount = len(gpos)

	return summary, nil
}

// QueryDump returns all users, computers, and groups.
func (c *LDAPClient) QueryDump(ctx context.Context) ([]User, []Computer, []Group, error) {
	users, err := c.QueryUsers(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	computers, err := c.QueryComputers(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	groups, err := c.QueryGroups(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	return users, computers, groups, nil
}

// ── Domain Info ───────────────────────────────────────────────────────────────

// QueryDomainInfo returns domain-level policy attributes.
func (c *LDAPClient) QueryDomainInfo(ctx context.Context) (*DomainInfo, error) {
	sr := ldap.NewSearchRequest(
		c.opts.BaseDN(), ldap.ScopeBaseObject,
		ldap.NeverDerefAliases, 1, 0, false,
		"(objectClass=*)",
		[]string{
			"ms-DS-MachineAccountQuota", "maxPwdAge", "minPwdLength",
			"lockoutThreshold", "lockoutDuration", "lockOutObservationWindow",
			"pwdProperties", "msDS-Behavior-Version",
		},
		nil,
	)
	res, err := c.conn.Search(sr)
	if err != nil {
		return nil, err
	}
	if len(res.Entries) == 0 {
		return nil, fmt.Errorf("domain object not found")
	}
	e := res.Entries[0]
	return &DomainInfo{
		Name:                c.opts.Domain,
		DN:                  c.opts.BaseDN(),
		FunctionalLevel:     entryInt(e, "msDS-Behavior-Version"),
		MachineAccountQuota: entryInt(e, "ms-DS-MachineAccountQuota"),
		MinPasswordLength:   entryInt(e, "minPwdLength"),
		LockoutThreshold:    entryInt(e, "lockoutThreshold"),
		PasswordComplexity:  entryInt(e, "pwdProperties")&1 == 1,
		MaxPasswordAge:      intervalToDuration(entryInt64(e, "maxPwdAge")),
		LockoutDuration:     intervalToDuration(entryInt64(e, "lockoutDuration")),
		ObservationWindow:   intervalToDuration(entryInt64(e, "lockOutObservationWindow")),
	}, nil
}

// ── Trust Queries ─────────────────────────────────────────────────────────────

// QueryTrusts returns domain trust objects.
func (c *LDAPClient) QueryTrusts(ctx context.Context) ([]Trust, error) {
	entries, err := c.Search(ctx, "(objectClass=trustedDomain)",
		[]string{"name", "trustPartner", "trustDirection", "trustType", "trustAttributes"})
	if err != nil {
		return nil, err
	}
	trusts := make([]Trust, 0, len(entries))
	for _, e := range entries {
		a := uint32(entryInt(e, "trustAttributes"))
		trusts = append(trusts, Trust{
			Name:          getAttributeValue(e, "name"),
			Partner:       getAttributeValue(e, "trustPartner"),
			Direction:     trustDirection(entryInt(e, "trustDirection")),
			TrustType:     trustTypeStr(entryInt(e, "trustType")),
			Attributes:    a,
			IsSIDFiltered: a&0x4 != 0,
			IsTransitive:  a&0x8 != 0,
		})
	}
	return trusts, nil
}

func trustDirection(d int) string {
	switch d {
	case 1:
		return "INBOUND"
	case 2:
		return "OUTBOUND"
	case 3:
		return "BIDIRECTIONAL"
	}
	return "UNKNOWN"
}

func trustTypeStr(t int) string {
	switch t {
	case 1:
		return "WINDOWS_NON_AD"
	case 2:
		return "WINDOWS_AD"
	case 3:
		return "MIT"
	}
	return "UNKNOWN"
}

// ── ACL Analysis ──────────────────────────────────────────────────────────────

var hvtSuffixes = []string{
	"CN=Domain Admins,CN=Users",
	"CN=Enterprise Admins,CN=Users",
	"CN=Schema Admins,CN=Users",
	"CN=Administrators,CN=Builtin",
	"CN=Backup Operators,CN=Builtin",
	"CN=Account Operators,CN=Builtin",
	"CN=AdminSDHolder,CN=System",
}

const (
	maskGenericAll   uint32 = 0x10000000
	maskGenericWrite uint32 = 0x40000000
	maskWriteDACL    uint32 = 0x00040000
	maskWriteOwner   uint32 = 0x00080000
	maskAllExtRight  uint32 = 0x00000100
)

var dcsyncGUIDs = map[string]string{
	"1131f6ad9c0711d1f79f00c04fc2dcd2": "DS-Replication-Get-Changes",
	"1131f6aa9c0711d1f79f00c04fc2dcd2": "DS-Replication-Get-Changes-All",
}

// QueryDangerousACLs checks ACLs on high-value AD objects for dangerous permissions.
func (c *LDAPClient) QueryDangerousACLs(ctx context.Context) ([]ACLEntry, error) {
	var results []ACLEntry
	targets := make([]string, 0, len(hvtSuffixes)+1)
	for _, sfx := range hvtSuffixes {
		targets = append(targets, sfx+","+c.opts.BaseDN())
	}
	targets = append(targets, c.opts.BaseDN()) // domain root for DCSync

	for _, dn := range targets {
		sr := ldap.NewSearchRequest(
			dn, ldap.ScopeBaseObject,
			ldap.NeverDerefAliases, 1, 0, false,
			"(objectClass=*)",
			[]string{"nTSecurityDescriptor"},
			nil, // SD_FLAGS control requires ber encoding; nTSecurityDescriptor returned for privileged binds
		)
		res, err := c.conn.Search(sr)
		if err != nil {
			continue
		}
		if len(res.Entries) == 0 {
			continue
		}
		raw := res.Entries[0].GetRawAttributeValue("nTSecurityDescriptor")
		if len(raw) > 0 {
			entries := parseSecurityDescriptor(dn, raw)
			results = append(results, entries...)
		}
	}
	return results, nil
}

// ── ADCS Queries ──────────────────────────────────────────────────────────────

// QueryADCS returns Certificate Authorities and certificate templates.
func (c *LDAPClient) QueryADCS(ctx context.Context) ([]CA, []CertTemplate, error) {
	configBase := "CN=Configuration," + c.opts.BaseDN()

	caEntries, err := c.SearchBase(ctx,
		"CN=Enrollment Services,CN=Public Key Services,CN=Services,"+configBase,
		"(objectClass=pKIEnrollmentService)",
		[]string{"cn", "dNSHostName", "distinguishedName"},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("ADCS CA query: %w", err)
	}
	cas := make([]CA, 0, len(caEntries))
	for _, e := range caEntries {
		cas = append(cas, CA{
			Name:        getAttributeValue(e, "cn"),
			DNSHostName: getAttributeValue(e, "dNSHostName"),
			DN:          e.DN,
		})
	}

	tmplEntries, err := c.SearchBase(ctx,
		"CN=Certificate Templates,CN=Public Key Services,CN=Services,"+configBase,
		"(objectClass=pKICertificateTemplate)",
		[]string{
			"cn", "displayName", "distinguishedName",
			"msPKI-Certificate-Name-Flag", "msPKI-Enrollment-Flag",
			"msPKI-RA-Signature", "pKIExtendedKeyUsage",
			"msPKI-Template-Schema-Version",
		},
	)
	if err != nil {
		return cas, nil, fmt.Errorf("ADCS template query: %w", err)
	}
	templates := make([]CertTemplate, 0, len(tmplEntries))
	for _, e := range tmplEntries {
		templates = append(templates, parseCertTemplate(e))
	}
	return cas, templates, nil
}

// QueryOUs returns all Organizational Units.
func (c *LDAPClient) QueryOUs(ctx context.Context) ([]OU, error) {
	entries, err := c.Search(ctx, "(objectClass=organizationalUnit)", []string{"ou", "distinguishedName", "objectGUID"})
	if err != nil {
		return nil, err
	}
	ous := make([]OU, 0, len(entries))
	for _, e := range entries {
		ous = append(ous, OU{
			Name: getAttributeValue(e, "ou"),
			DN:   e.DN,
			GUID: guidToStr(e.GetRawAttributeValue("objectGUID")),
		})
	}
	return ous, nil
}

// QueryGPOs returns all Group Policy Objects.
func (c *LDAPClient) QueryGPOs(ctx context.Context) ([]GPO, error) {
	configBase := "CN=Policies,CN=System," + c.opts.BaseDN()
	entries, err := c.SearchBase(ctx, configBase, "(objectClass=groupPolicyContainer)",
		[]string{"cn", "displayName", "distinguishedName", "gPCFileSysPath", "objectGUID"})
	if err != nil {
		return nil, err
	}
	gpos := make([]GPO, 0, len(entries))
	for _, e := range entries {
		gpos = append(gpos, GPO{
			Name:        getAttributeValue(e, "cn"),
			DisplayName: getAttributeValue(e, "displayName"),
			DN:          e.DN,
			GUID:        guidToStr(e.GetRawAttributeValue("objectGUID")),
			Path:        getAttributeValue(e, "gPCFileSysPath"),
		})
	}
	return gpos, nil
}

// QueryContainers returns common AD containers.
func (c *LDAPClient) QueryContainers(ctx context.Context) ([]Container, error) {
	entries, err := c.Search(ctx, "(objectClass=container)", []string{"cn", "distinguishedName", "objectGUID"})
	if err != nil {
		return nil, err
	}
	conts := make([]Container, 0, len(entries))
	for _, e := range entries {
		conts = append(conts, Container{
			Name: getAttributeValue(e, "cn"),
			DN:   e.DN,
			GUID: guidToStr(e.GetRawAttributeValue("objectGUID")),
		})
	}
	return conts, nil
}

// ── Parsers ───────────────────────────────────────────────────────────────────

func getAttributeValue(e *ldap.Entry, name string) string {
	for _, attr := range e.Attributes {
		if strings.EqualFold(attr.Name, name) {
			if len(attr.Values) > 0 {
				return attr.Values[0]
			}
		}
	}
	return ""
}

func getAttributeValues(e *ldap.Entry, name string) []string {
	for _, attr := range e.Attributes {
		if strings.EqualFold(attr.Name, name) {
			return attr.Values
		}
	}
	return nil
}

func parseUser(e *ldap.Entry) User {
	uac := uint32(entryInt(e, "userAccountControl"))
	return User{
		SAMAccountName:          getAttributeValue(e, "sAMAccountName"),
		UPN:                     getAttributeValue(e, "userPrincipalName"),
		DN:                      e.DN,
		Description:             getAttributeValue(e, "description"),
		UAC:                     uac,
		Enabled:                 uac&UACAccountDisable == 0,
		AdminCount:              getAttributeValue(e, "adminCount") == "1",
		NoKerbPreauth:           uac&UACDontReqPreauth != 0,
		UnconstrainedDelegation: uac&UACTrustedForDelegation != 0,
		PasswordNeverExpires:    uac&UACDontExpirePassword != 0,
		PasswordNotRequired:     uac&UACPasswordNotRequired != 0,
		SPNs:                    getAttributeValues(e, "servicePrincipalName"),
		MemberOf:                getAttributeValues(e, "memberOf"),
		ConstrainedDelegation:   getAttributeValues(e, "msDS-AllowedToDelegateTo"),
		LastLogon:               filetime(entryInt64(e, "lastLogonTimestamp")),
		PasswordLastSet:         filetime(entryInt64(e, "pwdLastSet")),
		BadPwdCount:             entryInt(e, "badPwdCount"),
		DisplayName:             getAttributeValue(e, "displayName"),
		Title:                   getAttributeValue(e, "title"),
		Department:              getAttributeValue(e, "department"),
		Mail:                    getAttributeValue(e, "mail"),
		SID:                     parseSID(e.GetRawAttributeValue("objectSid")),
	}
}

func parseComputer(e *ldap.Entry) Computer {
	uac := uint32(entryInt(e, "userAccountControl"))
	laps := getAttributeValue(e, "ms-Mcs-AdmPwd")
	return Computer{
		SAMAccountName:          getAttributeValue(e, "sAMAccountName"),
		DNSHostName:             getAttributeValue(e, "dNSHostName"),
		OperatingSystem:         getAttributeValue(e, "operatingSystem"),
		OSVersion:               getAttributeValue(e, "operatingSystemVersion"),
		UAC:                     uac,
		Enabled:                 uac&UACAccountDisable == 0,
		IsDC:                    uac&UACServerTrustAccount != 0,
		UnconstrainedDelegation: uac&UACTrustedForDelegation != 0 && uac&UACServerTrustAccount == 0,
		SPNs:                    getAttributeValues(e, "servicePrincipalName"),
		ConstrainedDelegation:   getAttributeValues(e, "msDS-AllowedToDelegateTo"),
		RBCD:                    getAttributeValue(e, "msDS-AllowedToActOnBehalfOfOtherIdentity"),
		LAPSEnabled:             laps != "",
		LAPSPassword:            laps,
		LastLogon:               filetime(entryInt64(e, "lastLogonTimestamp")),
		DisplayName:             getAttributeValue(e, "displayName"),
		SID:                     parseSID(e.GetRawAttributeValue("objectSid")),
	}
}

func parseGroup(e *ldap.Entry) Group {
	gt, _ := strconv.ParseInt(getAttributeValue(e, "groupType"), 10, 32)
	name := getAttributeValue(e, "sAMAccountName")
	if name == "" {
		name = getAttributeValue(e, "cn") // Fallback
	}
	return Group{
		SAMAccountName: name,
		DN:             e.DN,
		Description:    getAttributeValue(e, "description"),
		Members:        getAttributeValues(e, "member"),
		AdminCount:     getAttributeValue(e, "adminCount") == "1",
		GroupType:      int32(gt),
	}
}

func parseCertTemplate(e *ldap.Entry) CertTemplate {
	nameFlag := uint32(entryInt(e, "msPKI-Certificate-Name-Flag"))
	enrollFlag := uint32(entryInt(e, "msPKI-Enrollment-Flag"))
	raSignatures := entryInt(e, "msPKI-RA-Signature")
	ekus := getAttributeValues(e, "pKIExtendedKeyUsage")

	enrolleeSuppliesSAN := nameFlag&0x1 != 0
	requiresManagerApproval := enrollFlag&0x2 != 0
	anyPurpose, clientAuth, isEnrollmentAgent := false, false, false
	for _, eku := range ekus {
		switch eku {
		case "2.5.29.37.0":
			anyPurpose = true
		case "1.3.6.1.5.5.7.3.2":
			clientAuth = true
		case "1.3.6.1.4.1.311.20.2.1":
			isEnrollmentAgent = true
		}
	}
	schemaVer, _ := strconv.Atoi(getAttributeValue(e, "msPKI-Template-Schema-Version"))
	return CertTemplate{
		Name:                    getAttributeValue(e, "cn"),
		DN:                      e.DN,
		DisplayName:             getAttributeValue(e, "displayName"),
		SchemaVersion:           schemaVer,
		RequiresManagerApproval: requiresManagerApproval,
		EnrolleeSuppliesSAN:     enrolleeSuppliesSAN,
		AnyPurpose:              anyPurpose,
		IsEnrollmentAgent:       isEnrollmentAgent && raSignatures == 0,
		ClientAuth:              clientAuth,
		ExtendedKeyUsage:        ekus,
	}
}

// ── Windows Security Descriptor parser ───────────────────────────────────────

func parseSecurityDescriptor(objectDN string, raw []byte) []ACLEntry {
	if len(raw) < 20 {
		return nil
	}
	control := binary.LittleEndian.Uint16(raw[2:4])
	if control&0x0004 == 0 { // SE_DACL_PRESENT
		return nil
	}
	daclOffset := binary.LittleEndian.Uint32(raw[16:20])
	if int(daclOffset) >= len(raw)-8 {
		return nil
	}
	aceCount := int(binary.LittleEndian.Uint16(raw[daclOffset+4 : daclOffset+6]))
	pos := int(daclOffset) + 8

	var results []ACLEntry
	for i := 0; i < aceCount && pos < len(raw); i++ {
		if pos+4 > len(raw) {
			break
		}
		aceType := raw[pos]
		aceSize := int(binary.LittleEndian.Uint16(raw[pos+2 : pos+4]))
		if aceSize < 4 || pos+aceSize > len(raw) {
			break
		}
		aceData := raw[pos : pos+aceSize]
		pos += aceSize

		if aceType != 0x00 && aceType != 0x05 {
			continue
		}
		if len(aceData) < 8 {
			continue
		}
		accessMask := binary.LittleEndian.Uint32(aceData[4:8])

		var objectGUID string
		sidOffset := 8
		if aceType == 0x05 && len(aceData) >= 12 {
			flags := binary.LittleEndian.Uint32(aceData[8:12])
			sidOffset = 12
			if flags&0x1 != 0 && len(aceData) >= sidOffset+16 {
				objectGUID = guidToStr(aceData[sidOffset : sidOffset+16])
				sidOffset += 16
			}
			if flags&0x2 != 0 && len(aceData) >= sidOffset+16 {
				sidOffset += 16
			}
		}

		if !isDangerousACE(accessMask, objectGUID) {
			continue
		}
		results = append(results, ACLEntry{
			Object:      objectDN,
			Principal:   parseSID(aceData[sidOffset:]),
			Right:       rightName(accessMask, objectGUID),
			AceType:     "ALLOW",
			IsDangerous: true,
			ObjectGUID:  objectGUID,
		})
	}
	return results
}

func isDangerousACE(mask uint32, guid string) bool {
	if mask&maskGenericAll != 0 || mask&maskWriteDACL != 0 ||
		mask&maskWriteOwner != 0 || mask&maskGenericWrite != 0 {
		return true
	}
	if mask&maskAllExtRight != 0 {
		if _, ok := dcsyncGUIDs[guid]; ok {
			return true
		}
		if guid == "" {
			return true // all extended rights — includes DCSync, force password change
		}
	}
	return false
}

func rightName(mask uint32, guid string) string {
	switch {
	case mask&maskGenericAll != 0:
		return "GenericAll"
	case mask&maskWriteDACL != 0:
		return "WriteDACL"
	case mask&maskWriteOwner != 0:
		return "WriteOwner"
	case mask&maskGenericWrite != 0:
		return "GenericWrite"
	case mask&maskAllExtRight != 0:
		if name, ok := dcsyncGUIDs[guid]; ok {
			return "ExtendedRight(" + name + ")"
		}
		return "AllExtendedRights"
	}
	return fmt.Sprintf("Mask(0x%08x)", mask)
}

func parseSID(data []byte) string {
	if len(data) < 8 {
		return "UNKNOWN_SID"
	}
	rev := data[0]
	subCount := int(data[1])
	var auth uint64
	for i := 0; i < 6; i++ {
		auth = (auth << 8) | uint64(data[2+i])
	}
	if len(data) < 8+subCount*4 {
		return "INVALID_SID"
	}
	subs := make([]string, subCount)
	for i := 0; i < subCount; i++ {
		subs[i] = strconv.FormatUint(uint64(binary.LittleEndian.Uint32(data[8+i*4:12+i*4])), 10)
	}
	return fmt.Sprintf("S-%d-%d-%s", rev, auth, strings.Join(subs, "-"))
}

func guidToStr(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	return fmt.Sprintf("%08x%04x%04x%02x%02x%02x%02x%02x%02x%02x%02x",
		binary.LittleEndian.Uint32(b[0:4]),
		binary.LittleEndian.Uint16(b[4:6]),
		binary.LittleEndian.Uint16(b[6:8]),
		b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15],
	)
}

// ── Time / number helpers ─────────────────────────────────────────────────────

// filetime converts Windows FILETIME (100-ns intervals since 1601-01-01) to time.Time.
func filetime(t int64) time.Time {
	if t <= 0 {
		return time.Time{}
	}
	const epochDiff = 116444736000000000
	return time.Unix(0, (t-epochDiff)*100)
}

// intervalToDuration converts negative Windows interval to Go Duration.
func intervalToDuration(v int64) time.Duration {
	if v == 0 {
		return 0
	}
	if v < 0 {
		v = -v
	}
	return time.Duration(v * 100)
}

// ── RootDSE / Unauthenticated Helpers ────────────────────────────────────────

// DiscoverOSUnauthenticated attempts to get OS version without credentials.
func (c *LDAPClient) DiscoverOSUnauthenticated(ctx context.Context) (string, error) {
	// 1. Query RootDSE
	sr := ldap.NewSearchRequest(
		"", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
		"(objectClass=*)",
		[]string{"dnsHostName", "serverName", "ldapServiceName", "supportedLDAPVersion"},
		nil,
	)
	res, err := c.conn.Search(sr)
	if err != nil || len(res.Entries) == 0 {
		return "", fmt.Errorf("rootDSE query failed")
	}
	entry := res.Entries[0]

	// 2. Try to get serverName (DN of the server object)
	serverDN := entry.GetAttributeValue("serverName")
	if serverDN != "" {
		// Attempt to read the server object
		sr2 := ldap.NewSearchRequest(
			serverDN, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)", []string{"operatingSystem", "operatingSystemVersion"}, nil,
		)
		res2, err := c.conn.Search(sr2)
		if err == nil && len(res2.Entries) > 0 {
			os := res2.Entries[0].GetAttributeValue("operatingSystem")
			ver := res2.Entries[0].GetAttributeValue("operatingSystemVersion")
			if os != "" {
				if ver != "" {
					return fmt.Sprintf("%s (%s)", os, ver), nil
				}
				return os, nil
			}
		}
	}

	// 3. Fallback to ldapServiceName (common format: domain.local:server$@DOMAIN.LOCAL)
	svcName := entry.GetAttributeValue("ldapServiceName")
	if svcName != "" {
		return "Windows (via LDAP Service Name)", nil
	}

	return "Windows Server", nil
}

func entryInt(e *ldap.Entry, attr string) int {
	n, _ := strconv.Atoi(e.GetAttributeValue(attr))
	return n
}

func entryInt64(e *ldap.Entry, attr string) int64 {
	n, _ := strconv.ParseInt(e.GetAttributeValue(attr), 10, 64)
	return n
}
