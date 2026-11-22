package noncegate

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// LoadSecret returns the master secret from the hex value of env (when set)
// or from file, creating file with 32 random bytes when it does not exist.
// Replicas that verify each other's nonces share the same file or variable.
// A file readable by group or others, or a symbolic link, is refused.
func LoadSecret(file, env string) ([]byte, error) {
	if env != "" {
		if v := strings.TrimSpace(os.Getenv(env)); v != "" {
			b, err := hex.DecodeString(v)
			if err != nil || len(b) < 32 {
				return nil, fmt.Errorf("%s must hold at least 64 hex characters", env)
			}
			return b, nil
		}
		if file == "" {
			return nil, fmt.Errorf("%s is not set", env)
		}
	}
	fi, err := os.Lstat(file)
	if errors.Is(err, fs.ErrNotExist) {
		return createSecret(file)
	}
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", file)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s is readable by group or others; chmod 600 it", file)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	b, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(b) < 32 {
		return nil, fmt.Errorf("%s must hold at least 64 hex characters", file)
	}
	return b, nil
}

func createSecret(file string) ([]byte, error) {
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return nil, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if _, err := f.WriteString(hex.EncodeToString(b) + "\n"); err != nil {
		f.Close()
		return nil, err
	}
	return b, f.Close()
}
