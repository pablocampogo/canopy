// Package signer builds, signs, and verifies native Canopy send transactions.
//
// The package performs no network or filesystem access. Callers are responsible
// for obtaining a recent height and the current send fee before moving a request
// into an offline signing environment.
package signer

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/canopy-network/canopy/fsm"
	"github.com/canopy-network/canopy/lib"
	"github.com/canopy-network/canopy/lib/crypto"
)

// SendRequest contains every operator-controlled field of a native send.
// AmountUCNPY and FeeUCNPY are integer micro-CNPY values. Time is a required
// Unix-microsecond value that must remain stable for every retry.
//
// Integer fields are JSON strings so values retain full uint64 precision in
// every language that invokes the command-line signer.
type SendRequest struct {
	Recipient     string `json:"recipient"`
	AmountUCNPY   uint64 `json:"amountUCNPY,string"`
	FeeUCNPY      uint64 `json:"feeUCNPY,string"`
	CreatedHeight uint64 `json:"createdHeight,string"`
	NetworkID     uint64 `json:"networkID,string"`
	ChainID       uint64 `json:"chainID,string"`
	Memo          string `json:"memo,omitempty"`
	Time          uint64 `json:"time,string"`
}

// Details is an auditable summary derived from a verified signed transaction.
type Details struct {
	TransactionHash string `json:"transactionHash"`
	Sender          string `json:"sender"`
	Recipient       string `json:"recipient"`
	AmountUCNPY     uint64 `json:"amountUCNPY,string"`
	FeeUCNPY        uint64 `json:"feeUCNPY,string"`
	CreatedHeight   uint64 `json:"createdHeight,string"`
	NetworkID       uint64 `json:"networkID,string"`
	ChainID         uint64 `json:"chainID,string"`
	Memo            string `json:"memo,omitempty"`
	Time            uint64 `json:"time,string"`
}

// BuildSend constructs an unsigned native send using Canopy's canonical
// protobuf types. It does not check the governance-controlled minimum fee or
// whether CreatedHeight is recent; those checks require current chain state.
func BuildSend(request SendRequest, publicKey crypto.PublicKeyI) (*lib.Transaction, error) {
	if publicKey == nil {
		return nil, fmt.Errorf("public key is nil")
	}
	if request.CreatedHeight == 0 {
		return nil, fmt.Errorf("createdHeight must be greater than zero")
	}
	if request.NetworkID == 0 {
		return nil, fmt.Errorf("networkID must be greater than zero")
	}
	if request.ChainID == 0 {
		return nil, fmt.Errorf("chainID must be greater than zero")
	}
	if request.Time == 0 {
		return nil, fmt.Errorf("time must be greater than zero")
	}
	if len(request.Memo) > 200 {
		return nil, fmt.Errorf("memo exceeds 200 bytes")
	}
	if lib.IsRLPMemo(request.Memo) {
		return nil, fmt.Errorf("memo %q is reserved for Ethereum transactions", request.Memo)
	}
	recipient, err := crypto.NewAddressFromString(request.Recipient)
	if err != nil || len(recipient.Bytes()) != crypto.AddressSize {
		return nil, fmt.Errorf("recipient must be exactly 40 hexadecimal characters")
	}
	message := &fsm.MessageSend{
		FromAddress: publicKey.Address().Bytes(),
		ToAddress:   recipient.Bytes(),
		Amount:      request.AmountUCNPY,
	}
	if checkErr := message.Check(); checkErr != nil {
		return nil, checkErr
	}
	anyMessage, anyErr := lib.NewAny(message)
	if anyErr != nil {
		return nil, anyErr
	}
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

// SignSend builds and signs a native send, then verifies the resulting
// signature and signed fields before returning it.
func SignSend(request SendRequest, privateKey crypto.PrivateKeyI) (*lib.Transaction, error) {
	if privateKey == nil {
		return nil, fmt.Errorf("private key is nil")
	}
	publicKey := privateKey.PublicKey()
	if publicKey == nil {
		return nil, fmt.Errorf("private key public key is nil")
	}
	transaction, err := BuildSend(request, publicKey)
	if err != nil {
		return nil, err
	}
	signBytes, signErr := transaction.GetSignBytes()
	if signErr != nil {
		return nil, signErr
	}
	signature := privateKey.Sign(signBytes)
	if len(signature) == 0 {
		return nil, fmt.Errorf("signer returned an empty signature")
	}
	transaction.Signature = &lib.Signature{
		PublicKey: publicKey.Bytes(),
		Signature: signature,
	}
	if _, err = Inspect(transaction); err != nil {
		return nil, fmt.Errorf("verify signed transaction: %w", err)
	}
	return transaction, nil
}

// Inspect verifies a signed native send and returns the exact fields covered by
// its signature. Verification is stateless: final fee and height acceptance
// remain the responsibility of a synchronized Canopy node.
func Inspect(transaction *lib.Transaction) (*Details, error) {
	if transaction == nil {
		return nil, fmt.Errorf("transaction is nil")
	}
	if err := transaction.CheckBasic(); err != nil {
		return nil, err
	}
	if transaction.MessageType != fsm.MessageSendName {
		return nil, fmt.Errorf("transaction type must be %q", fsm.MessageSendName)
	}
	message, messageErr := lib.FromAny(transaction.Msg)
	if messageErr != nil {
		return nil, messageErr
	}
	send, ok := message.(*fsm.MessageSend)
	if !ok {
		return nil, fmt.Errorf("transaction payload is not a native send")
	}
	if checkErr := send.Check(); checkErr != nil {
		return nil, checkErr
	}
	publicKey, err := crypto.NewPublicKeyFromBytes(transaction.Signature.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if !bytes.Equal(send.FromAddress, publicKey.Address().Bytes()) {
		return nil, fmt.Errorf("sender does not match signing public key")
	}
	signBytes, signErr := transaction.GetSignBytes()
	if signErr != nil {
		return nil, signErr
	}
	if !publicKey.VerifyBytes(signBytes, transaction.Signature.Signature) {
		return nil, fmt.Errorf("invalid transaction signature")
	}
	hash, hashErr := transaction.GetHash()
	if hashErr != nil {
		return nil, hashErr
	}
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
