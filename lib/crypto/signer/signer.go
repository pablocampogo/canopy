// Package signer builds, signs, and verifies native Canopy send transactions.
//
// The package performs no network or filesystem access. Callers are responsible
// for obtaining a recent height and the current send fee before moving a request
// into an offline signing environment.
package signer

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/canopy-network/canopy/fsm"
	"github.com/canopy-network/canopy/lib"
	"github.com/canopy-network/canopy/lib/crypto"
	ethCrypto "github.com/ethereum/go-ethereum/crypto"
)

const (
	// PreparedSendVersion identifies the stable external-signing interchange format.
	PreparedSendVersion = "canopy-hsm-v1"

	KeyTypeEd25519      = "ed25519"
	KeyTypeSecp256k1    = "secp256k1"
	KeyTypeEthSecp256k1 = "eth-secp256k1"

	SigningPayloadMessage = "message"
	SigningPayloadDigest  = "digest"

	HashNone   = "none"
	HashSHA256 = "sha256"

	SignatureFormatRaw = "raw"
	SignatureFormatDER = "der"
)

// SendRequest contains every operator-controlled field of a native send
// AmountUCNPY and FeeUCNPY are integer micro-CNPY values. Time is a required
// Unix-microsecond value that must remain stable for every retry.
//
// Integer fields are JSON strings so values retain full uint64 precision in
// every language that invokes the command-line signer.
type SendRequest struct {
	Recipient     string `json:"recipient"`            // recipient address in hexadecimal format
	AmountUCNPY   uint64 `json:"amountUCNPY,string"`   // amount to send in micro-CNPY
	FeeUCNPY      uint64 `json:"feeUCNPY,string"`      // transaction fee in micro-CNPY
	CreatedHeight uint64 `json:"createdHeight,string"` // recent chain height used to create the transaction
	NetworkID     uint64 `json:"networkID,string"`     // destination network identifier
	ChainID       uint64 `json:"chainID,string"`       // destination chain identifier
	Memo          string `json:"memo,omitempty"`       // optional transaction memo
	Time          uint64 `json:"time,string"`          // transaction time in Unix microseconds
}

// Details is an auditable summary derived from a verified signed transaction
type Details struct {
	TransactionHash string `json:"transactionHash"`      // hash of the signed transaction in hexadecimal format
	Sender          string `json:"sender"`               // address derived from the signing public key
	Recipient       string `json:"recipient"`            // recipient address in hexadecimal format
	AmountUCNPY     uint64 `json:"amountUCNPY,string"`   // amount sent in micro-CNPY
	FeeUCNPY        uint64 `json:"feeUCNPY,string"`      // transaction fee in micro-CNPY
	CreatedHeight   uint64 `json:"createdHeight,string"` // chain height used to create the transaction
	NetworkID       uint64 `json:"networkID,string"`     // destination network identifier
	ChainID         uint64 `json:"chainID,string"`       // destination chain identifier
	Memo            string `json:"memo,omitempty"`       // optional transaction memo
	Time            uint64 `json:"time,string"`          // transaction time in Unix microseconds
}

// PreparedSend is a portable external-signing request. SigningPayload is the
// exact hex-encoded byte string an HSM must sign. For Ed25519 it is the raw
// canonical protobuf message. For secp256k1 it is the SHA-256 digest of that
// message. Transaction and SignBytes are included for auditability and are
// recomputed and compared by FinalizeSend before a signature is accepted.
type PreparedSend struct {
	Version            string           `json:"version"`
	KeyType            string           `json:"keyType"`
	PublicKey          string           `json:"publicKey"`
	SignBytes          string           `json:"signBytes"`
	SigningPayload     string           `json:"signingPayload"`
	SigningPayloadType string           `json:"signingPayloadType"`
	Hash               string           `json:"hash"`
	Transaction        *lib.Transaction `json:"transaction"`
}

type signingProfile struct {
	keyType     string
	payloadType string
	hash        string
}

// BuildSend() constructs an unsigned native send using Canopy's canonical
// protobuf types. It does not check the governance-controlled minimum fee or
// whether CreatedHeight is recent; those checks require current chain state.
func BuildSend(request SendRequest, publicKey crypto.PublicKeyI) (*lib.Transaction, error) {
	// validate the public key
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	// validate the created height
	if request.CreatedHeight == 0 {
		return nil, fmt.Errorf("createdHeight must be greater than zero")
	}
	// validate the network identifier
	if request.NetworkID == 0 {
		return nil, fmt.Errorf("networkID must be greater than zero")
	}
	// validate the chain identifier
	if request.ChainID == 0 {
		return nil, fmt.Errorf("chainID must be greater than zero")
	}
	// validate the transaction time
	if request.Time == 0 {
		return nil, fmt.Errorf("time must be greater than zero")
	}
	// enforce the maximum memo length
	if len(request.Memo) > 200 {
		return nil, fmt.Errorf("memo exceeds 200 bytes")
	}
	// prevent native sends from using reserved Ethereum memo prefixes
	if lib.IsRLPMemo(request.Memo) {
		return nil, fmt.Errorf("memo %q is reserved for Ethereum transactions", request.Memo)
	}
	// decode and validate the recipient address
	recipient, err := crypto.NewAddressFromString(request.Recipient)
	if err != nil || len(recipient.Bytes()) != crypto.AddressSize {
		return nil, fmt.Errorf("recipient must be exactly 40 hexadecimal characters")
	}
	// create and validate the canonical send message
	message := &fsm.MessageSend{
		FromAddress: publicKey.Address().Bytes(),
		ToAddress:   recipient.Bytes(),
		Amount:      request.AmountUCNPY,
	}
	if checkErr := message.Check(); checkErr != nil {
		return nil, checkErr
	}
	// wrap the send message in its protobuf Any container
	anyMessage, anyErr := lib.NewAny(message)
	if anyErr != nil {
		return nil, anyErr
	}
	// assemble and return the unsigned transaction
	return &lib.Transaction{
		MessageType:   fsm.MessageSendName,
		Msg:           anyMessage,
		CreatedHeight: request.CreatedHeight,
		Time:          request.Time,
		Fee:           request.FeeUCNPY,
		Memo:          request.Memo,
		NetworkId:     request.NetworkID,
		ChainId:       request.ChainID,
	}, nil
}

// SignSend() builds and signs a native send, then verifies the resulting
// signature and signed fields before returning it.
func SignSend(request SendRequest, privateKey crypto.PrivateKeyI) (*lib.Transaction, error) {
	// validate the private key
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	// retrieve and validate the paired public key
	publicKey := privateKey.PublicKey()
	if publicKey == nil {
		return nil, fmt.Errorf("private key public key is nil")
	}
	// build the unsigned send transaction
	transaction, err := BuildSend(request, publicKey)
	if err != nil {
		return nil, err
	}
	// create the canonical transaction sign bytes
	signBytes, signErr := transaction.GetSignBytes()
	if signErr != nil {
		return nil, signErr
	}
	// sign the transaction and ensure the signer returned a signature
	signature := privateKey.Sign(signBytes)
	if len(signature) == 0 {
		return nil, fmt.Errorf("signer returned an empty signature")
	}
	// attach the public key and signature to the transaction
	transaction.Signature = &lib.Signature{
		PublicKey: publicKey.Bytes(),
		Signature: signature,
	}
	// verify the complete transaction before returning it
	if _, err = Inspect(transaction); err != nil {
		return nil, fmt.Errorf("verify signed transaction: %w", err)
	}
	return transaction, nil
}

// PrepareSend constructs a native send and exposes the exact payload required
// by an external signer. It supports the key types commonly available from
// custody systems and HSMs: Ed25519, compressed secp256k1, and Ethereum-style
// uncompressed secp256k1.
func PrepareSend(request SendRequest, publicKey crypto.PublicKeyI) (*PreparedSend, error) {
	transaction, err := BuildSend(request, publicKey)
	if err != nil {
		return nil, err
	}
	profile, err := profileForPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	signBytes, signErr := transaction.GetSignBytes()
	if signErr != nil {
		return nil, signErr
	}
	payload := signingPayload(profile, signBytes)
	return &PreparedSend{
		Version:            PreparedSendVersion,
		KeyType:            profile.keyType,
		PublicKey:          hex.EncodeToString(publicKey.Bytes()),
		SignBytes:          hex.EncodeToString(signBytes),
		SigningPayload:     hex.EncodeToString(payload),
		SigningPayloadType: profile.payloadType,
		Hash:               profile.hash,
		Transaction:        transaction,
	}, nil
}

// FinalizeSend validates a prepared request, canonicalizes a raw or ASN.1 DER
// HSM signature, attaches it to the transaction, and verifies the completed
// transaction. DER is valid only for secp256k1. Raw Ed25519 signatures are
// passed through unchanged; raw secp256k1 signatures are normalized to low-S.
func FinalizeSend(prepared *PreparedSend, signature []byte, format string) (*lib.Transaction, error) {
	transaction, publicKey, profile, err := validatePreparedSend(prepared)
	if err != nil {
		return nil, err
	}
	canonicalSignature, err := canonicalizeSignature(publicKey, signature, format)
	if err != nil {
		return nil, err
	}
	transaction.Signature = &lib.Signature{
		PublicKey: publicKey.Bytes(),
		Signature: canonicalSignature,
	}
	if _, err = Inspect(transaction); err != nil {
		return nil, fmt.Errorf("verify external signature for %s: %w", profile.keyType, err)
	}
	return transaction, nil
}

func validatePreparedSend(prepared *PreparedSend) (*lib.Transaction, crypto.PublicKeyI, signingProfile, error) {
	if prepared == nil {
		return nil, nil, signingProfile{}, fmt.Errorf("prepared send is nil")
	}
	if prepared.Version != PreparedSendVersion {
		return nil, nil, signingProfile{}, fmt.Errorf("unsupported prepared send version %q", prepared.Version)
	}
	publicKeyBytes, err := hex.DecodeString(prepared.PublicKey)
	if err != nil {
		return nil, nil, signingProfile{}, fmt.Errorf("decode public key: %w", err)
	}
	publicKey, err := crypto.NewPublicKeyFromBytes(publicKeyBytes)
	if err != nil {
		return nil, nil, signingProfile{}, fmt.Errorf("decode public key: %w", err)
	}
	if !bytes.Equal(publicKey.Bytes(), publicKeyBytes) {
		return nil, nil, signingProfile{}, fmt.Errorf("public key is not canonical")
	}
	profile, err := profileForPublicKey(publicKey)
	if err != nil {
		return nil, nil, signingProfile{}, err
	}
	if prepared.KeyType != profile.keyType || prepared.SigningPayloadType != profile.payloadType || prepared.Hash != profile.hash {
		return nil, nil, signingProfile{}, fmt.Errorf("prepared signing profile does not match public key")
	}
	request, err := requestFromUnsignedTransaction(prepared.Transaction, publicKey)
	if err != nil {
		return nil, nil, signingProfile{}, err
	}
	transaction, err := BuildSend(request, publicKey)
	if err != nil {
		return nil, nil, signingProfile{}, err
	}
	signBytes, signErr := transaction.GetSignBytes()
	if signErr != nil {
		return nil, nil, signingProfile{}, signErr
	}
	if err = compareHexField("signBytes", prepared.SignBytes, signBytes); err != nil {
		return nil, nil, signingProfile{}, err
	}
	if err = compareHexField("signingPayload", prepared.SigningPayload, signingPayload(profile, signBytes)); err != nil {
		return nil, nil, signingProfile{}, err
	}
	return transaction, publicKey, profile, nil
}

func requestFromUnsignedTransaction(transaction *lib.Transaction, publicKey crypto.PublicKeyI) (SendRequest, error) {
	if transaction == nil {
		return SendRequest{}, fmt.Errorf("prepared transaction is nil")
	}
	if transaction.Signature != nil {
		return SendRequest{}, fmt.Errorf("prepared transaction must not contain a signature")
	}
	if transaction.MessageType != fsm.MessageSendName {
		return SendRequest{}, fmt.Errorf("transaction type must be %q", fsm.MessageSendName)
	}
	message, err := lib.FromAny(transaction.Msg)
	if err != nil {
		return SendRequest{}, err
	}
	send, ok := message.(*fsm.MessageSend)
	if !ok {
		return SendRequest{}, fmt.Errorf("transaction payload is not a native send")
	}
	if !bytes.Equal(send.FromAddress, publicKey.Address().Bytes()) {
		return SendRequest{}, fmt.Errorf("sender does not match signing public key")
	}
	if send.VestingStartHeight != 0 || send.VestingCliffHeight != 0 || send.VestingEndHeight != 0 {
		return SendRequest{}, fmt.Errorf("external signer supports liquid sends only")
	}
	if transaction.Nonce != 0 {
		return SendRequest{}, fmt.Errorf("native send nonce must be zero")
	}
	return SendRequest{
		Recipient:     hex.EncodeToString(send.ToAddress),
		AmountUCNPY:   send.Amount,
		FeeUCNPY:      transaction.Fee,
		CreatedHeight: transaction.CreatedHeight,
		NetworkID:     transaction.NetworkId,
		ChainID:       transaction.ChainId,
		Memo:          transaction.Memo,
		Time:          transaction.Time,
	}, nil
}

func profileForPublicKey(publicKey crypto.PublicKeyI) (signingProfile, error) {
	switch publicKey.(type) {
	case *crypto.ED25519PublicKey:
		return signingProfile{KeyTypeEd25519, SigningPayloadMessage, HashNone}, nil
	case *crypto.SECP256K1PublicKey:
		return signingProfile{KeyTypeSecp256k1, SigningPayloadDigest, HashSHA256}, nil
	case *crypto.ETHSECP256K1PublicKey:
		return signingProfile{KeyTypeEthSecp256k1, SigningPayloadDigest, HashSHA256}, nil
	default:
		return signingProfile{}, fmt.Errorf("external signing does not support public key type %T", publicKey)
	}
}

func signingPayload(profile signingProfile, signBytes []byte) []byte {
	if profile.hash == HashSHA256 {
		return crypto.Hash(signBytes)
	}
	return bytes.Clone(signBytes)
}

func compareHexField(name, encoded string, expected []byte) error {
	decoded, err := hex.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode %s: %w", name, err)
	}
	if !bytes.Equal(decoded, expected) {
		return fmt.Errorf("prepared %s does not match transaction", name)
	}
	return nil
}

func canonicalizeSignature(publicKey crypto.PublicKeyI, signature []byte, format string) ([]byte, error) {
	switch publicKey.(type) {
	case *crypto.ED25519PublicKey:
		if format != SignatureFormatRaw {
			return nil, fmt.Errorf("Ed25519 signatures require raw format")
		}
		if len(signature) != crypto.Ed25519SignatureSize {
			return nil, fmt.Errorf("Ed25519 signature must be %d bytes", crypto.Ed25519SignatureSize)
		}
		return bytes.Clone(signature), nil
	case *crypto.SECP256K1PublicKey, *crypto.ETHSECP256K1PublicKey:
		return canonicalizeSecp256k1Signature(signature, format)
	default:
		return nil, fmt.Errorf("external signing does not support public key type %T", publicKey)
	}
}

func canonicalizeSecp256k1Signature(signature []byte, format string) ([]byte, error) {
	var r, s *big.Int
	switch format {
	case SignatureFormatRaw:
		if len(signature) != crypto.SECP256K1SignatureSize {
			return nil, fmt.Errorf("raw secp256k1 signature must be %d bytes", crypto.SECP256K1SignatureSize)
		}
		r = new(big.Int).SetBytes(signature[:32])
		s = new(big.Int).SetBytes(signature[32:])
	case SignatureFormatDER:
		if len(signature) < 8 || len(signature) > 72 {
			return nil, fmt.Errorf("DER secp256k1 signature must be between 8 and 72 bytes")
		}
		parsed := new(struct{ R, S *big.Int })
		rest, err := asn1.Unmarshal(signature, parsed)
		if err != nil || len(rest) != 0 || parsed.R == nil || parsed.S == nil {
			return nil, fmt.Errorf("invalid DER secp256k1 signature")
		}
		r, s = parsed.R, parsed.S
	default:
		return nil, fmt.Errorf("unsupported signature format %q", format)
	}
	order := ethCrypto.S256().Params().N
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(order) >= 0 || s.Cmp(order) >= 0 {
		return nil, fmt.Errorf("secp256k1 signature values are out of range")
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(order), 1)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(order, s)
	}
	canonical := make([]byte, crypto.SECP256K1SignatureSize)
	r.FillBytes(canonical[:32])
	s.FillBytes(canonical[32:])
	return canonical, nil
}

// Inspect() verifies a signed native send and returns the exact fields covered by
// its signature. Verification is stateless: final fee and height acceptance
// remain the responsibility of a synchronized Canopy node.
func Inspect(transaction *lib.Transaction) (*Details, error) {
	// validate the transaction reference
	if transaction == nil {
		return nil, fmt.Errorf("transaction is nil")
	}
	// execute the stateless transaction validation
	if err := transaction.CheckBasic(); err != nil {
		return nil, err
	}
	// ensure the transaction declares a native send
	if transaction.MessageType != fsm.MessageSendName {
		return nil, fmt.Errorf("transaction type must be %q", fsm.MessageSendName)
	}
	// decode the wrapped transaction message
	message, messageErr := lib.FromAny(transaction.Msg)
	if messageErr != nil {
		return nil, messageErr
	}
	// ensure the decoded payload is a native send
	send, ok := message.(*fsm.MessageSend)
	if !ok {
		return nil, fmt.Errorf("transaction payload is not a native send")
	}
	// validate the native send message
	if checkErr := send.Check(); checkErr != nil {
		return nil, checkErr
	}
	// decode the signing public key
	publicKey, err := crypto.NewPublicKeyFromBytes(transaction.Signature.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	// ensure the message sender matches the signing key
	if !bytes.Equal(send.FromAddress, publicKey.Address().Bytes()) {
		return nil, fmt.Errorf("sender does not match signing public key")
	}
	// recreate the canonical transaction sign bytes
	signBytes, signErr := transaction.GetSignBytes()
	if signErr != nil {
		return nil, signErr
	}
	// verify the transaction signature
	if !publicKey.VerifyBytes(signBytes, transaction.Signature.Signature) {
		return nil, fmt.Errorf("invalid transaction signature")
	}
	// calculate the verified transaction hash
	hash, hashErr := transaction.GetHash()
	if hashErr != nil {
		return nil, hashErr
	}
	// return the human-readable signed fields
	return &Details{
		TransactionHash: hex.EncodeToString(hash),
		Sender:          publicKey.Address().String(),
		Recipient:       hex.EncodeToString(send.ToAddress),
		AmountUCNPY:     send.Amount,
		FeeUCNPY:        transaction.Fee,
		CreatedHeight:   transaction.CreatedHeight,
		NetworkID:       transaction.NetworkId,
		ChainID:         transaction.ChainId,
		Memo:            transaction.Memo,
		Time:            transaction.Time,
	}, nil
}
