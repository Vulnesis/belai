package factorylink

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"slices"

	"google.golang.org/grpc"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// Attention requests (docs/keleustes.md#attention): a host with nobody at it
// asks the Keleustes owner for something. A request is identifiers only, from
// closed lists, so no model or tool text can reach a notification.
var (
	AttentionKinds   = []string{"gh_login", "provider_credentials", "approve", "action"}
	AttentionReasons = []string{"credential_expiring", "reauth_needed", "approval_needed", "action_needed"}
)

// Attention files a request and returns its id. subject must be an
// identifier (a provider slug, profile name or card id).
func (c *Client) Attention(ctx context.Context, kind, reason, subject string) (string, error) {
	if !slices.Contains(AttentionKinds, kind) || !slices.Contains(AttentionReasons, reason) {
		return "", fmt.Errorf("unknown attention kind or reason")
	}
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	id := hex.EncodeToString(b[:])
	r, err := call(ctx, c, func(ctx context.Context, conn *grpc.ClientConn) (*nodev1.AttentionReceipt, error) {
		return nodev1.NewBoardClient(conn).Attention(ctx, &nodev1.AttentionRequest{Id: id, Kind: kind, Reason: reason, Subject: subject})
	})
	if err != nil {
		return "", mapErr(err)
	}
	if r.GetState() == "refused" {
		return "", fmt.Errorf("keleustes refused the request: %s", r.GetReason())
	}
	return id, nil
}
