package factorylink

import (
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/vulnetix/belai/internal/credentials"
)

// Profile is one joined Keleustes server. It lives in
// <belai home>/factory/<serverId>/: profile.json, node.crt, ca.pem, and the
// node key in the OS keychain (account "keleustes-node:<serverId>") or, when
// there is no keychain, node.key with mode 0600.
type Profile struct {
	ServerID      string    `json:"serverId"`
	ServerName    string    `json:"serverName"`
	NodeID        string    `json:"nodeId"`
	Addrs         []string  `json:"addrs"`
	TLSServerName string    `json:"tlsServerName"`
	JoinedAt      time.Time `json:"joinedAt"`
	// KeyInFile is true when the key is in node.key rather than the keychain.
	KeyInFile bool `json:"keyInFile,omitempty"`
	// Revoked is set when the server said this node was revoked.
	Revoked string `json:"revoked,omitempty"`

	dir string
}

// ErrNoProfile reports that this host has not joined a Keleustes server.
var ErrNoProfile = errors.New("not connected to a Keleustes server")

// keychain is swapped in tests.
var keychain = func() credentials.Keychain { return credentials.NewKeyringBackend("belai") }

func factoryDir(home string) string { return filepath.Join(home, "factory") }

func keyAccount(serverID string) string { return "keleustes-node:" + serverID }

// Dir is the profile's directory.
func (p *Profile) Dir() string { return p.dir }

// Active loads the active profile from belai home.
func Active(home string) (*Profile, error) {
	id, err := os.ReadFile(filepath.Join(factoryDir(home), "active"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, err
	}
	return Load(home, strings.TrimSpace(string(id)))
}

// Load reads one profile by server id.
func Load(home, serverID string) (*Profile, error) {
	if !validID(serverID) {
		return nil, ErrNoProfile
	}
	dir := filepath.Join(factoryDir(home), serverID)
	data, err := os.ReadFile(filepath.Join(dir, "profile.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoProfile
	}
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("keleustes profile: %w", err)
	}
	p.dir = dir
	return &p, nil
}

// validID keeps a server id usable as one path element.
func validID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// save writes a new profile with its certificate material and makes it active.
func save(home string, p *Profile, key ed25519.PrivateKey, certDER, caDER []byte) error {
	if !validID(p.ServerID) {
		return fmt.Errorf("server id %q is not valid", p.ServerID)
	}
	dir := filepath.Join(factoryDir(home), p.ServerID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	p.dir = dir
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	kc := keychain()
	p.KeyInFile = true
	if kc.Available() {
		if err := kc.Set(keyAccount(p.ServerID), string(keyPEM)); err == nil {
			p.KeyInFile = false
			_ = os.Remove(filepath.Join(dir, "node.key"))
		}
	}
	if p.KeyInFile {
		if err := writeFile(filepath.Join(dir, "node.key"), keyPEM, 0o600); err != nil {
			return err
		}
	}
	if err := writeFile(filepath.Join(dir, "node.crt"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o644); err != nil {
		return err
	}
	if err := writeFile(filepath.Join(dir, "ca.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		return err
	}
	if err := p.write(); err != nil {
		return err
	}
	return writeFile(filepath.Join(factoryDir(home), "active"), []byte(p.ServerID+"\n"), 0o600)
}

func (p *Profile) write() error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(filepath.Join(p.dir, "profile.json"), append(data, '\n'), 0o600)
}

// MarkRevoked records that the server revoked this node.
func (p *Profile) MarkRevoked(reason string) error {
	if reason == "" {
		reason = "revoked"
	}
	p.Revoked = reason
	return p.write()
}

// Remove deletes the profile, its key and, if it was active, the pointer.
func Remove(home string, p *Profile) error {
	if p.dir == "" {
		return errors.New("profile has no directory")
	}
	if !p.KeyInFile {
		_ = keychain().Delete(keyAccount(p.ServerID))
	}
	if err := os.RemoveAll(p.dir); err != nil {
		return err
	}
	active := filepath.Join(factoryDir(home), "active")
	if id, err := os.ReadFile(active); err == nil && strings.TrimSpace(string(id)) == p.ServerID {
		return os.Remove(active)
	}
	return nil
}

// certificate loads the node's TLS client certificate and private key.
func (p *Profile) certificate() (tls.Certificate, error) {
	certPEM, err := os.ReadFile(filepath.Join(p.dir, "node.crt"))
	if err != nil {
		return tls.Certificate{}, err
	}
	var keyPEM []byte
	if p.KeyInFile {
		keyPEM, err = os.ReadFile(filepath.Join(p.dir, "node.key"))
	} else {
		var s string
		s, err = keychain().Get(keyAccount(p.ServerID))
		keyPEM = []byte(s)
	}
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("keleustes node key: %w", err)
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

func (p *Profile) caPool() (*x509.CertPool, error) {
	caPEM, err := os.ReadFile(filepath.Join(p.dir, "ca.pem"))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("keleustes ca.pem holds no certificate")
	}
	return pool, nil
}

// resumeCursor is the highest server frame seq applied, kept across restarts.
func (p *Profile) resumeCursor() uint64 {
	data, err := os.ReadFile(filepath.Join(p.dir, "cursor"))
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(data)), 10, 64)
	return n
}

func (p *Profile) setResumeCursor(n uint64) error {
	return writeFile(filepath.Join(p.dir, "cursor"), []byte(strconv.FormatUint(n, 10)+"\n"), 0o600)
}

// writeFile writes atomically (temp file + rename) with the given mode.
func writeFile(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}
