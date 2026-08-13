package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/canopy-network/canopy/lib"
	"github.com/canopy-network/canopy/lib/crypto"
	"github.com/canopy-network/canopy/lib/crypto/signer"
)

func TestSignSendAndInspect(t *testing.T) {
	directory := t.TempDir()
	password := "test-password"
	key, err := crypto.NewBLS12381PrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	keystore := crypto.NewKeystoreInMemory()
	address, err := keystore.ImportRaw(key.Bytes(), password, crypto.ImportRawOpts{Nickname: "withdrawal"})
	if err != nil {
		t.Fatal(err)
	}
	if err = keystore.SaveToFile(directory); err != nil {
		t.Fatal(err)
	}
	request := signer.SendRequest{
		Recipient:     "502c0b3d6ccd1c6f164aa5536b2ba2cb9e80c711",
		AmountUCNPY:   1_000_000,
		FeeUCNPY:      10_000,
		CreatedHeight: 2_044_370,
		NetworkID:     1,
		ChainID:       1,
		Time:          1_786_569_463_230_678,
	}
	requestJSON, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(directory, "request.json")
	if err = os.WriteFile(requestPath, requestJSON, 0600); err != nil {
		t.Fatal(err)
	}
	inputReader, inputWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = inputWriter.WriteString(password + "\n"); err != nil {
		t.Fatal(err)
	}
	_ = inputWriter.Close()
	defer func() { _ = inputReader.Close() }()
	var signedJSON, errorOutput bytes.Buffer
	if err = run([]string{
		"sign-send", "--keystore-dir", directory, "--key", "withdrawal", requestPath,
	}, inputReader, &signedJSON, &errorOutput); err != nil {
		t.Fatalf("sign: %v; stderr: %s", err, errorOutput.String())
	}
	transaction := new(lib.Transaction)
	if err = json.Unmarshal(signedJSON.Bytes(), transaction); err != nil {
		t.Fatal(err)
	}
	details, err := signer.Inspect(transaction)
	if err != nil {
		t.Fatal(err)
	}
	if details.Sender != address || details.AmountUCNPY != request.AmountUCNPY {
		t.Fatalf("unexpected signed details: %+v", details)
	}

	signedPath := filepath.Join(directory, "signed.json")
	if err = os.WriteFile(signedPath, signedJSON.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	var inspectedJSON bytes.Buffer
	if err = run([]string{"inspect", signedPath}, inputReader, &inspectedJSON, &errorOutput); err != nil {
		t.Fatal(err)
	}
	inspected := new(signer.Details)
	if err = json.Unmarshal(inspectedJSON.Bytes(), inspected); err != nil {
		t.Fatal(err)
	}
	if *inspected != *details {
		t.Fatalf("inspect mismatch: got %+v want %+v", inspected, details)
	}
}

func TestSignSendRejectsUnknownRequestField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, []byte(`{"unknown":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	input, output, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = output.Close()
	defer func() { _ = input.Close() }()
	if err = run([]string{"sign-send", "--keystore-dir", t.TempDir(), "--key", "key", path}, input, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected request decoding error")
	}
}
