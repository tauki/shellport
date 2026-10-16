// Sign release checksums covering every platform; never upload.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	keygen := flag.String("keygen", "", "Create a new private signing key and .pub file at this path")
	output := flag.String("output", "", "Existing staging directory")
	checksums := flag.String("checksums", "", "Sign a release SHA256SUMS file covering every platform")
	flag.Parse()
	var err error
	if flag.NArg() != 0 {
		err = errors.New("unexpected arguments")
	} else if *keygen != "" && *checksums == "" && *output == "" {
		err = generateKey(*keygen)
	} else if *keygen == "" && *checksums != "" && *output != "" {
		err = signChecksums(*checksums, *output, os.Getenv("SHELLPORT_RELEASE_SIGNING_KEY"))
	} else {
		err = errors.New("use --keygen PATH, or --checksums FILE --output DIRECTORY")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Shellport release:", err)
		os.Exit(1)
	}
}

func writeNew(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	return closeErr
}

func generateKey(path string) error {
	if _, err := os.Lstat(path + ".pub"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("public key output already exists or cannot be inspected")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	if err = writeNew(path, []byte(base64.StdEncoding.EncodeToString(key)+"\n")); err != nil {
		return err
	}
	if err = writeNew(path+".pub", []byte(base64.StdEncoding.EncodeToString(pub)+"\n")); err != nil {
		return err
	}
	fmt.Println("Created a private signing key and its public verification key. No key was printed.")
	return nil
}

func signingKey(encodedKey string) (ed25519.PrivateKey, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encodedKey))
	if err != nil || len(key) != ed25519.PrivateKeySize || !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
		return nil, errors.New("SHELLPORT_RELEASE_SIGNING_KEY must contain a valid base64 Ed25519 private key")
	}
	return ed25519.PrivateKey(key), nil
}

func signChecksums(checksums, output, encodedKey string) error {
	key, err := signingKey(encodedKey)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(checksums)
	if err != nil {
		return err
	}
	if len(data) == 0 || len(data) > 1<<20 {
		return errors.New("checksum file must be nonempty and bounded")
	}
	public, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return err
	}
	if err = writeNew(filepath.Join(output, "SHA256SUMS.sig"), ed25519.Sign(key, data)); err != nil {
		return err
	}
	return writeNew(filepath.Join(output, "shellport-release-key.pem"), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}))
}
