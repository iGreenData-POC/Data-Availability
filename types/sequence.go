package types

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/0xPolygon/cdk-data-availability/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	solsha3 "github.com/miguelmota/go-solidity-sha3"
)

const (
	signatureLen = 65
)

// Sequence represents the data that the sequencer will send to L1
// and other metadata needed to build the accumulated input hash aka accInputHash
type Sequence []ArgBytes

type MessagePayload struct {
	Data string `json:"data"`
}

// HashToSign returns the accumulated input hash of the sequence.
// Note that this is equivalent to what happens on the smart contract
func (s *Sequence) HashToSign() []byte {
	currentHash := common.Hash{}.Bytes()
	for _, batchData := range ([]ArgBytes)(*s) {
		types := []string{
			"bytes32",
			"bytes32",
		}
		values := []interface{}{
			currentHash,
			crypto.Keccak256(batchData),
		}
		currentHash = solsha3.SoliditySHA3(types, values)
	}
	return currentHash
}

func sendRequestsToAdaptor(ctx context.Context, url string, payload MessagePayload) ([]byte, error) {
	client := &http.Client{
		Timeout: time.Second * 10, // Set a timeout for the request
	}

	// Marshal the payload into JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	// Create the POST request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json") // Set header to application/json

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return responseBody, nil
}

// Sign returns a signed sequence by the private key.
// Note that what's being signed is the accumulated input hash
func (s *Sequence) Sign(privateKey *ecdsa.PrivateKey) (*SignedSequence, error) {
	log.Infof("Inside sequence.go Sign function!")
	hashToSign := s.HashToSign()

	payload := MessagePayload{
		Data: hex.EncodeToString(hashToSign),
	}
	log.Infof("Created message payload!")
	//add
	sig, err := sendRequestsToAdaptor(context.Background(), "http://34.136.253.25:3000/v1/sign-message", payload)
	if err != nil {
		log.Infof("Failed to send message request to adaptor")
		return nil, err
	}
	log.Infof("Send message request to adaptor!", sig)
	/*sig, err := crypto.Sign(hashToSign, privateKey)
	if err != nil {
		return nil, err
	}*/

	rBytes := sig[:32]
	sBytes := sig[32:64]
	vByte := sig[64]

	if strings.ToUpper(common.Bytes2Hex(sBytes)) > "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" {
		magicNumber := common.Hex2Bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
		sBig := big.NewInt(0).SetBytes(sBytes)
		magicBig := big.NewInt(0).SetBytes(magicNumber)
		s1 := magicBig.Sub(magicBig, sBig)
		sBytes = s1.Bytes()
		if vByte == 0 {
			vByte = 1
		} else {
			vByte = 0
		}
	}
	vByte += 27

	actualSignature := []byte{}
	actualSignature = append(actualSignature, rBytes...)
	actualSignature = append(actualSignature, sBytes...)
	actualSignature = append(actualSignature, vByte)

	return &SignedSequence{
		Sequence:  *s,
		Signature: actualSignature,
	}, nil
}

// OffChainData returns the data that needs to be stored off chain from a given sequence
func (s *Sequence) OffChainData() []OffChainData {
	od := []OffChainData{}
	for _, batchData := range ([]ArgBytes)(*s) {
		od = append(od, OffChainData{
			Key:   crypto.Keccak256Hash(batchData),
			Value: batchData,
		})
	}
	return od
}

// SignedSequence is a sequence but signed
type SignedSequence struct {
	Sequence  Sequence `json:"sequence"`
	Signature ArgBytes `json:"signature"`
}

// Signer returns the address of the signer
// must be changed to use ecrecover as per the fireblocks signing
func (s *SignedSequence) Signer() (common.Address, error) {
	if len(s.Signature) != signatureLen {
		log.Infof("Invalid signature for sequence from sequencer!")
		return common.Address{}, errors.New("invalid signature")
	}
	log.Infof("The received signature from sequence sender", hex.EncodeToString(s.Signature))

	// mySig := make([]byte, 65)
	// copy(mySig, sig)
	// mySig[64] -= 27
	marshelledSig, err := s.Signature.MarshalText()
	if err != nil {
		log.Infof("error marshalling============", err)
	}

	sig := make([]byte, 65)
	copy(sig, marshelledSig)
	sig[64] -= 27

	//double hash as per Fireblocks

	/////
	firstHash := s.Sequence.HashToSign()
	log.Infof("Creating firstHash in DAC============>", firstHash)

	message := hex.EncodeToString(firstHash)
	log.Infof("Hex encoding firstHash= in DAC==========>", message)

	wrappedMessage := "\x19Ethereum Signed Message in DAC:\n" +
		string(rune(len(message))) +
		message

	// Calculate the hash of the wrapped message
	hash := sha256.Sum256([]byte(wrappedMessage))

	// Calculate the hash of the hash
	contentHash := sha256.Sum256(hash[:])

	// mySig := make([]byte, 65)
	// copy(mySig, sig)
	// mySig[64] -= 27

	log.Infof("REcovetring key in DAC ====================")
	pubKey, err := crypto.SigToPub(contentHash[:], sig)
	if err != nil {
		log.Infof("error converting to public key", err)
		return common.Address{}, err
	}
	val := crypto.PubkeyToAddress(*pubKey)
	log.Infof("recovered address  in DAC is:", val.String())
	/////

	// log.Infof("Creating firstHash")
	// firstHash := s.Sequence.HashToSign()

	// log.Infof("Hex encoding firstHash")
	// message := hex.EncodeToString(firstHash)
	// log.Infof("Hex encoded firstHash is:", message)

	// log.Infof("Creating wrapped message")
	// wrappedMessage := "\x19Ethereum Signed Message:\n" +
	// 	string(rune(len(message))) +
	// 	message

	// log.Infof("Creating SHA256 hash of wrapped message")
	// Calculate the hash of the wrapped message
	// hash := sha256.Sum256([]byte(wrappedMessage))

	// log.Infof("Creating hash of hash of SHA256")
	// Calculate the hash of the hash
	// contentHash := sha256.Sum256(hash[:])

	// log.Infof("Recovering public key")
	// pubKey, err := crypto.SigToPub(contentHash[:], sig)
	// if err != nil {
	// 	log.Infof("error converting to public key", err)
	// 	return common.Address{}, err
	// }

	return crypto.PubkeyToAddress(*pubKey), nil
}
