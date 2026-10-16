package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestKeyGenerationIsPrivateAndDoesNotOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "release.key")
	if err := generateKey(path); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	for _, name := range []string{path, path + ".pub"} {
		st, err := os.Stat(name)
		if err != nil || st.Mode().Perm() != 0600 {
			t.Fatal("Key file is not private", name, err)
		}
	}
	if generateKey(path) == nil {
		t.Fatal("Existing key was overwritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("Existing key changed")
	}
}

func TestChecksumSignatureCoversEveryPlatform(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()
	var checksums bytes.Buffer
	for _, platform := range []string{"linux-amd64", "linux-arm64", "linux-armv7", "darwin-arm64", "darwin-amd64"} {
		digest := sha256.Sum256([]byte(platform))
		fmt.Fprintf(&checksums, "%x  shellport-v1.2.3-%s.tar.gz\n", digest, platform)
	}
	file := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(file, checksums.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := signChecksums(file, dir, base64.StdEncoding.EncodeToString(key)); err != nil {
		t.Fatal(err)
	}
	sig, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if !ed25519.Verify(pub, checksums.Bytes(), sig) {
		t.Fatal("Every-platform checksum signature rejected")
	}
	changed := append([]byte{}, checksums.Bytes()...)
	changed[0] ^= 1
	if ed25519.Verify(pub, changed, sig) {
		t.Fatal("Changed download checksum accepted")
	}
	public, _ := os.ReadFile(filepath.Join(dir, "shellport-release-key.pem"))
	block, _ := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" {
		t.Fatal("No standard public verification key")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil || !bytes.Equal(parsed.(ed25519.PublicKey), pub) {
		t.Fatal("Published verification key differs", err)
	}
}

func TestChecksumSigningRejectsInvalidKeysWithoutOutput(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key[len(key)-1] ^= 1 // A valid seed with a mismatched public half must be refused.
	for _, encoded := range []string{"", "invalid-key", base64.StdEncoding.EncodeToString(key[:32]), base64.StdEncoding.EncodeToString(key)} {
		dir := t.TempDir()
		file := filepath.Join(dir, "SHA256SUMS")
		if err := os.WriteFile(file, []byte("checksum  archive.tar.gz\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if signChecksums(file, dir, encoded) == nil {
			t.Fatal("Invalid signing key accepted")
		}
		for _, name := range []string{"SHA256SUMS.sig", "shellport-release-key.pem"} {
			if _, err := os.Stat(filepath.Join(dir, name)); !os.IsNotExist(err) {
				t.Fatal("Rejected key produced release output", name, err)
			}
		}
	}
}

func TestChecksumSigningDoesNotOverwriteSignature(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "SHA256SUMS")
	if err := os.WriteFile(file, []byte("checksum  archive.tar.gz\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.StdEncoding.EncodeToString(key)
	if err := signChecksums(file, dir, encoded); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("different checksum  archive.tar.gz\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if signChecksums(file, dir, encoded) == nil {
		t.Fatal("Existing signature was overwritten")
	}
	after, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS.sig"))
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("Existing signature changed", err)
	}
}
