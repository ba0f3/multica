package daemon

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// caBundleSource is implemented by repocache.Cache. It is optional so test
// doubles of repoCacheBackend do not have to implement it; writeWorkerCABundle
// falls back to the extra file alone when the configured cache cannot supply a
// bundle.
type caBundleSource interface {
	CABundlePEM() ([]byte, error)
}

// extraCAActiveSource is implemented by repocache.Cache. It is optional so
// test doubles of repoCacheBackend do not have to implement it; when the cache
// cannot report active extra CAs, writeWorkerCABundle treats them as inactive.
type extraCAActiveSource interface {
	ExtraCACertsActive() bool
}

// writeWorkerCABundle writes the CA bundle a Docker worker must trust to
// <envRoot>/ca-bundle.pem and returns its host path. It combines the repo
// cache's bundle (the machine trust plus any server-provided CAs) with the
// valid CERTIFICATE blocks of extraPath, so git/curl/node/python in the worker
// trust both the host's existing Git trust and the extra CA.
//
// It returns "" when neither source produced a bundle. When no extra CA is
// configured at all — no extraPath and no active server CAs — it returns ""
// without writing anything, so the worker image's own /etc/ssl/certs system
// store stays in effect rather than being replaced by a mounted bundle. A
// configured extraPath that is missing, unreadable, or holds no valid
// certificate is an error: a bundle the operator asked for must never be
// silently dropped.
func (d *Daemon) writeWorkerCABundle(envRoot, extraPath string) (string, error) {
	if extraPath == "" && !d.extraCACertsActive() {
		return "", nil
	}

	var bundle bytes.Buffer
	if cache, ok := d.repoCache.(caBundleSource); ok {
		pem, err := cache.CABundlePEM()
		if err != nil {
			return "", fmt.Errorf("read repo cache CA bundle: %w", err)
		}
		bundle.Write(pem)
	}

	if extraPath != "" {
		extra, err := extraCACertsFromFile(extraPath)
		if err != nil {
			return "", err
		}
		if bundle.Len() > 0 && !bytes.HasSuffix(bundle.Bytes(), []byte("\n")) {
			bundle.WriteByte('\n')
		}
		bundle.Write(extra)
	}

	if bundle.Len() == 0 {
		return "", nil
	}

	path := filepath.Join(envRoot, "ca-bundle.pem")
	if err := writeCABundleAtomic(path, bundle.Bytes()); err != nil {
		return "", err
	}
	return path, nil
}

// extraCACertsFromFile returns the valid CERTIFICATE blocks of path. A missing
// or unreadable file, or content without a valid certificate, is an error.
func extraCACertsFromFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read CA bundle %s: %w", path, err)
	}
	var out bytes.Buffer
	rest := data
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			continue
		}
		if err := pem.Encode(&out, block); err != nil {
			return nil, fmt.Errorf("encode CA bundle %s: %w", path, err)
		}
	}
	if out.Len() == 0 {
		return nil, fmt.Errorf("CA bundle %s has no valid certificate", path)
	}
	return out.Bytes(), nil
}

// writeCABundleAtomic writes data to path atomically, mode 0644: the bundle is
// public certificate material mounted read-only into the worker.
func writeCABundleAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ca-bundle-*.pem")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o644); err != nil {
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
	return os.Rename(tmp.Name(), path)
}

// dockerTaskCABundleExists reports whether the configured extra CA bundle path
// is present on disk, for the startup log.
func dockerTaskCABundleExists(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// extraCACertsActive reports whether the repo cache currently has active
// server-provided extra CAs. A cache that does not implement the optional
// extraCAActiveSource is treated as having none.
func (d *Daemon) extraCACertsActive() bool {
	cache, ok := d.repoCache.(extraCAActiveSource)
	return ok && cache.ExtraCACertsActive()
}
