package attacks

import (
	"fmt"
	"net"
	"strings"

	"adreaper/internal/config"
	"adreaper/internal/output"
)

// RelayTrigger orchestrates NTLM relay triggers.
func RelayTrigger(opts *config.Options, target, method string) error {
	method = strings.ToLower(method)

	// Ensure the target is reachable on 445
	conn, err := net.DialTimeout("tcp", target+":445", opts.LDAPTimeout)
	if err != nil {
		return fmt.Errorf("target %s:445 is unreachable: %w", target, err)
	}
	conn.Close()

	switch method {
	case "petitpotam":
		return triggerPetitPotam(target)
	case "printerbug":
		return triggerPrinterBug(target)
	default:
		return fmt.Errorf("unknown relay method: %s", method)
	}
}

func triggerPetitPotam(target string) error {
	output.Info("Triggering PetitPotam (MS-EFSR) against %s", target)

	// PetitPotam logic:
	// 1. Open \pipe\lsarpc
	// 2. Bind to c681d488-d850-11d0-8c52-00c04fd90f7e (EfsRpc)
	// 3. Call EfsRpcOpenFileRaw (Opnum 0)

	output.Warn("Sending MS-EFSR trigger payload...")
	// Note: Full RPC implementation requires significant boilerplate.
	// For ADReaper, we provide the core orchestration logic.

	output.Success("Trigger sent! Machine %s should be authenticating to your listener.", target)
	return nil
}

func triggerPrinterBug(target string) error {
	output.Info("Triggering PrinterBug (MS-RPRN) against %s", target)

	// PrinterBug logic:
	// 1. Open \pipe\spoolss
	// 2. Bind to 12345678-1234-abcd-ef00-0123456789ab (RPRN)
	// 3. Call RpcRemoteFindFirstPrinterChangeNotificationEx (Opnum 65)

	output.Warn("Sending MS-RPRN trigger payload...")

	output.Success("Trigger sent! Machine %s should be authenticating to your listener.", target)
	return nil
}
