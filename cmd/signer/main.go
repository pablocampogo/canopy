// signer is an offline command for signing and inspecting native Canopy
// sends. It intentionally contains no networking code.
package main

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/canopy-network/canopy/lib"
	"github.com/canopy-network/canopy/lib/crypto"
	"github.com/canopy-network/canopy/lib/crypto/signer"
	"golang.org/x/term"
)

const maxInputBytes = 1 << 20

// main() executes the offline signer command
func main() {
	// run the command and print any returned error
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "signer: %v\n", err)
		os.Exit(1)
	}
}

// run() routes the command-line arguments to the selected signer command
func run(args []string, stdin *os.File, stdout, stderr io.Writer) error {
	// print usage when no command was provided
	if len(args) == 0 {
		return usage(stderr)
	}
	// execute the selected command
	switch args[0] {
	case "sign-send":
		return signSend(args[1:], stdin, stdout, stderr)
	case "prepare-send":
		return prepareSend(args[1:], stdout, stderr)
	case "finalize-send":
		return finalizeSend(args[1:], stdout, stderr)
	case "inspect":
		return inspect(args[1:], stdout)
	case "help", "-h", "--help":
		return usage(stderr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

// usage() prints the signer command usage
func usage(w io.Writer) error {
	_, _ = fmt.Fprintln(w, `Usage:
  signer sign-send --keystore-dir DIR --key ADDRESS_OR_NICKNAME REQUEST.json
  signer prepare-send --public-key HEX [--payload-file FILE] REQUEST.json
  signer finalize-send --signature-file FILE [--signature-format raw|der] [--signature-encoding raw|hex|base64] PREPARED.json
  signer inspect SIGNED.json

sign-send reads the keystore password from a terminal without echo, or from
standard input when piped. prepare-send and finalize-send keep private keys in
an external HSM. Signed /v1/tx JSON is written to standard output.`)
	return nil
}

// prepareSend constructs a canonical native send and writes a portable HSM request.
func prepareSend(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("prepare-send", flag.ContinueOnError)
	flags.SetOutput(stderr)
	publicKeyHex := flags.String("public-key", "", "hex-encoded signing public key")
	payloadFile := flags.String("payload-file", "", "optional file for the raw HSM signing payload")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *publicKeyHex == "" || flags.NArg() != 1 {
		return fmt.Errorf("prepare-send requires --public-key and one request file")
	}
	publicKey, err := crypto.NewPublicKeyFromString(strings.TrimPrefix(*publicKeyHex, "0x"))
	if err != nil {
		return fmt.Errorf("decode public key: %w", err)
	}
	request := new(signer.SendRequest)
	if err = decodeFile(flags.Arg(0), request); err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	prepared, err := signer.PrepareSend(*request, publicKey)
	if err != nil {
		return err
	}
	if *payloadFile != "" {
		payload, decodeErr := hex.DecodeString(prepared.SigningPayload)
		if decodeErr != nil {
			return fmt.Errorf("decode signing payload: %w", decodeErr)
		}
		if writeErr := os.WriteFile(*payloadFile, payload, 0600); writeErr != nil {
			return fmt.Errorf("write signing payload: %w", writeErr)
		}
	}
	return writeJSON(stdout, prepared)
}

// finalizeSend attaches and verifies a signature produced by an external HSM.
func finalizeSend(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("finalize-send", flag.ContinueOnError)
	flags.SetOutput(stderr)
	signatureFile := flags.String("signature-file", "", "file containing the HSM signature")
	signatureFormat := flags.String("signature-format", signer.SignatureFormatRaw, "signature format: raw or der")
	signatureEncoding := flags.String("signature-encoding", "hex", "signature file encoding: raw, hex, or base64")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *signatureFile == "" || flags.NArg() != 1 {
		return fmt.Errorf("finalize-send requires --signature-file and one prepared request file")
	}
	prepared := new(signer.PreparedSend)
	if err := decodeFile(flags.Arg(0), prepared); err != nil {
		return fmt.Errorf("read prepared request: %w", err)
	}
	signature, err := readSignature(*signatureFile, *signatureEncoding)
	if err != nil {
		return err
	}
	transaction, err := signer.FinalizeSend(prepared, signature, *signatureFormat)
	if err != nil {
		return err
	}
	return writeJSON(stdout, transaction)
}

// readSignature reads a size-limited HSM signature file in a common encoding.
func readSignature(path, encoding string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	defer func() { _ = file.Close() }()
	encoded, err := io.ReadAll(io.LimitReader(file, maxInputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read signature: %w", err)
	}
	if len(encoded) > maxInputBytes {
		return nil, fmt.Errorf("signature exceeds %d bytes", maxInputBytes)
	}
	switch encoding {
	case "raw":
		return encoded, nil
	case "hex":
		decoded, decodeErr := hex.DecodeString(strings.TrimSpace(string(encoded)))
		if decodeErr != nil {
			return nil, fmt.Errorf("decode hex signature: %w", decodeErr)
		}
		return decoded, nil
	case "base64":
		decoded, decodeErr := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encoded)))
		if decodeErr != nil {
			return nil, fmt.Errorf("decode base64 signature: %w", decodeErr)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("unsupported signature encoding %q", encoding)
	}
}

// signSend() parses a send request, unlocks its key, and writes the signed transaction
func signSend(args []string, stdin *os.File, stdout, stderr io.Writer) error {
	// define and parse the sign-send flags
	flags := flag.NewFlagSet("sign-send", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keystoreDir := flags.String("keystore-dir", "", "directory containing keystore.json")
	keySelector := flags.String("key", "", "key address or nickname")
	if err := flags.Parse(args); err != nil {
		return err
	}
	// validate the required flags and request file
	if *keystoreDir == "" || *keySelector == "" || flags.NArg() != 1 {
		return fmt.Errorf("sign-send requires --keystore-dir, --key, and one request file")
	}
	// decode the send request
	request := new(signer.SendRequest)
	if err := decodeFile(flags.Arg(0), request); err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	// read the keystore password without echo when using a terminal
	password, err := readPassword(stdin, stderr)
	if err != nil {
		return err
	}
	// load the keystore from disk
	keystore, err := crypto.NewKeystoreFromFile(*keystoreDir)
	if err != nil {
		return fmt.Errorf("read keystore: %w", err)
	}
	// select the key by nickname unless the selector is a valid address
	options := crypto.GetKeyGroupOpts{Nickname: *keySelector}
	if address, addressErr := crypto.NewAddressFromString(*keySelector); addressErr == nil && len(address.Bytes()) == crypto.AddressSize {
		options = crypto.GetKeyGroupOpts{Address: address.Bytes()}
	}
	// unlock the selected key
	key, err := keystore.GetKeyGroup(password, options)
	if err != nil {
		return fmt.Errorf("unlock key: %w", err)
	}
	// build and sign the native send
	transaction, err := signer.SignSend(*request, key.PrivateKey)
	if err != nil {
		return err
	}
	// write the signed transaction as JSON
	return writeJSON(stdout, transaction)
}

// inspect() verifies a signed transaction and writes its auditable details
func inspect(args []string, stdout io.Writer) error {
	// parse the inspect arguments without writing flag errors to stdout
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return err
	}
	// validate the required signed transaction file
	if flags.NArg() != 1 {
		return fmt.Errorf("inspect requires one signed transaction file")
	}
	// decode the signed transaction
	transaction := new(lib.Transaction)
	if err := decodeFile(flags.Arg(0), transaction); err != nil {
		return fmt.Errorf("read transaction: %w", err)
	}
	// verify and inspect the transaction
	details, err := signer.Inspect(transaction)
	if err != nil {
		return err
	}
	// write the verified details as JSON
	return writeJSON(stdout, details)
}

// decodeFile() decodes exactly one size-limited JSON value from a file
func decodeFile(path string, destination any) error {
	// open the source file
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	// ensure the source file is closed before returning
	defer func() { _ = file.Close() }()
	// decode the size-limited JSON and reject unknown fields
	decoder := json.NewDecoder(io.LimitReader(file, maxInputBytes))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(destination); err != nil {
		return err
	}
	// reject any additional JSON values after the first value
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("file must contain exactly one JSON value")
	}
	return nil
}

// readPassword() reads a password from a terminal or piped standard input
func readPassword(input *os.File, prompt io.Writer) (string, error) {
	// read from the terminal without echo when one is attached
	if term.IsTerminal(int(input.Fd())) {
		_, _ = fmt.Fprint(prompt, "Keystore password: ")
		password, err := term.ReadPassword(int(input.Fd()))
		_, _ = fmt.Fprintln(prompt)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		// reject empty terminal passwords
		if len(password) == 0 {
			return "", fmt.Errorf("password cannot be empty")
		}
		return string(password), nil
	}
	// limit a piped password to 4096 bytes plus one byte for overflow detection
	reader := bufio.NewReader(io.LimitReader(input, 4097))
	password, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	// reject a piped password that exceeds the size limit
	if len(password) > 4096 {
		return "", fmt.Errorf("password exceeds 4096 bytes")
	}
	// remove one trailing line ending from the piped password
	value := strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r")
	// reject empty piped passwords
	if value == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return value, nil
}

// writeJSON() writes an indented JSON value to the destination
func writeJSON(output io.Writer, value any) error {
	// configure and execute the JSON encoder
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
