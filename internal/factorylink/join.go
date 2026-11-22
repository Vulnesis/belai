package factorylink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/vulnetix/belai/internal/factorylink/nodev1"
)

// ErrPinMismatch reports a server whose key is not the one the token names.
var ErrPinMismatch = errors.New("server certificate does not match the join token's pin")

// pinnedTLS trusts exactly the server key whose SPKI SHA-256 is pin. The
// normal chain check is replaced by the pin; nothing else is accepted.
func pinnedTLS(pin []byte) *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		// The pin below is the whole verification.
		InsecureSkipVerify: true, //nolint:gosec // replaced by VerifyPeerCertificate
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrPinMismatch
			}
			leaf, err := x509.ParseCertificate(raw[0])
			if err != nil {
				return ErrPinMismatch
			}
			sum := sha256.Sum256(leaf.RawSubjectPublicKeyInfo)
			if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
				return ErrPinMismatch
			}
			return nil
		},
	}
}

// Join redeems tok, saves the resulting profile under home and makes it
// active. Addresses are tried in token order.
func Join(ctx context.Context, home string, tok *Token, host *nodev1.HostAdvert) (*Profile, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "belai node"},
	}, key)
	if err != nil {
		return nil, err
	}
	req := &nodev1.JoinRequest{
		TokenId: tok.TokenID,
		Secret:  tok.secretBytes(),
		CsrDer:  csr,
		Host:    host,
	}
	var lastErr error
	for _, addr := range tok.Addrs {
		resp, err := joinAt(ctx, addr, tok.pinBytes(), req)
		if err == nil {
			p := &Profile{
				ServerID:      resp.GetServerId(),
				ServerName:    resp.GetServerName(),
				NodeID:        resp.GetNodeId(),
				Addrs:         preferFirst(tok.Addrs, addr),
				TLSServerName: resp.GetTlsServerName(),
				JoinedAt:      time.Now().UTC(),
			}
			if p.ServerID != tok.ServerID {
				return nil, errors.New("server answered with a different server id than the token names")
			}
			if err := save(home, p, key, resp.GetClientCertDer(), resp.GetCaCertDer()); err != nil {
				return nil, fmt.Errorf("save keleustes profile: %w", err)
			}
			return p, nil
		}
		lastErr = err
		// A refusal is final: the server saw the token and said no.
		if st, ok := status.FromError(err); ok && (st.Code() == codes.PermissionDenied || st.Code() == codes.InvalidArgument) {
			return nil, errors.New(st.Message())
		}
		if errors.Is(err, ErrPinMismatch) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("could not reach Keleustes at %v: %w", tok.Addrs, lastErr)
}

func joinAt(ctx context.Context, addr string, pin []byte, req *nodev1.JoinRequest) (*nodev1.JoinResponse, error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(credentials.NewTLS(pinnedTLS(pin))))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := nodev1.NewNodeClient(conn).Join(ctx, req, grpc.WaitForReady(false))
	if err != nil && errors.Is(unwrapTransport(err), ErrPinMismatch) {
		return nil, ErrPinMismatch
	}
	return resp, err
}

// unwrapTransport maps a gRPC Unavailable caused by our pin check back to it.
func unwrapTransport(err error) error {
	if st, ok := status.FromError(err); ok && st.Code() == codes.Unavailable {
		if containsPinMismatch(st.Message()) {
			return ErrPinMismatch
		}
	}
	return err
}

func containsPinMismatch(msg string) bool {
	return strings.Contains(msg, ErrPinMismatch.Error())
}

func preferFirst(addrs []string, first string) []string {
	out := []string{first}
	for _, a := range addrs {
		if a != first {
			out = append(out, a)
		}
	}
	return out
}
