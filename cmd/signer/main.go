// signer is an offline command for signing and inspecting native Canopy
// sends. It intentionally contains no networking code.
package main

import (
	"bufio"
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

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "signer: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usage(stderr)
	}
	switch args[0] {
	case "sign-send":
		return signSend(args[1:], stdin, stdout, stderr)
	case "inspect":
		return inspect(args[1:], stdout)
	case "help", "-h", "--help":
		return usage(stderr)
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage(w io.Writer) error {
	_, _ = fmt.Fprintln(w, `Usage:
  signer sign-send --keystore-dir DIR --key ADDRESS_OR_NICKNAME REQUEST.json
  signer inspect SIGNED.json

sign-send reads the keystore password from a terminal without echo, or from
standard input when piped. The signed /v1/tx JSON is written to standard output.`)
	return nil
}

func signSend(args []string, stdin *os.File, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("sign-send", flag.ContinueOnError)
	flags.SetOutput(stderr)
	keystoreDir := flags.String("keystore-dir", "", "directory containing keystore.json")
	keySelector := flags.String("key", "", "key address or nickname")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *keystoreDir == "" || *keySelector == "" || flags.NArg() != 1 {
		return fmt.Errorf("sign-send requires --keystore-dir, --key, and one request file")
	}
	request := new(signer.SendRequest)
	if err := decodeFile(flags.Arg(0), request); err != nil {
		return fmt.Errorf("read request: %w", err)
	}
	password, err := readPassword(stdin, stderr)
	if err != nil {
		return err
	}
	keystore, err := crypto.NewKeystoreFromFile(*keystoreDir)
	if err != nil {
		return fmt.Errorf("read keystore: %w", err)
	}
	options := crypto.GetKeyGroupOpts{Nickname: *keySelector}
	if address, addressErr := crypto.NewAddressFromString(*keySelector); addressErr == nil && len(address.Bytes()) == crypto.AddressSize {
		options = crypto.GetKeyGroupOpts{Address: address.Bytes()}
	}
	key, err := keystore.GetKeyGroup(password, options)
	if err != nil {
		return fmt.Errorf("unlock key: %w", err)
	}
	transaction, err := signer.SignSend(*request, key.PrivateKey)
	if err != nil {
		return err
	}
	return writeJSON(stdout, transaction)
}

func inspect(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("inspect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("inspect requires one signed transaction file")
	}
	transaction := new(lib.Transaction)
	if err := decodeFile(flags.Arg(0), transaction); err != nil {
		return fmt.Errorf("read transaction: %w", err)
	}
	details, err := signer.Inspect(transaction)
	if err != nil {
		return err
	}
	return writeJSON(stdout, details)
}

func decodeFile(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()
	decoder := json.NewDecoder(io.LimitReader(file, maxInputBytes))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(destination); err != nil {
		return err
	}
	var trailing any
	if err = decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return fmt.Errorf("file must contain exactly one JSON value")
	}
	return nil
}

func readPassword(input *os.File, prompt io.Writer) (string, error) {
	if term.IsTerminal(int(input.Fd())) {
		_, _ = fmt.Fprint(prompt, "Keystore password: ")
		password, err := term.ReadPassword(int(input.Fd()))
		_, _ = fmt.Fprintln(prompt)
		if err != nil {
			return "", fmt.Errorf("read password: %w", err)
		}
		if len(password) == 0 {
			return "", fmt.Errorf("password cannot be empty")
		}
		return string(password), nil
	}
	reader := bufio.NewReader(io.LimitReader(input, 4097))
	password, err := io.ReadAll(reader)
	if err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}
	if len(password) > 4096 {
		return "", fmt.Errorf("password exceeds 4096 bytes")
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(password), "\n"), "\r")
	if value == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return value, nil
}

func writeJSON(output io.Writer, value any) error {
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}
