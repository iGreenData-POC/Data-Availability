package types

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
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

type FireblocksAdaptorResponse struct {
	Status string `json:"status"`
	Data   struct {
		FinalSignature string `json:"finalSignature"`
	} `json:"data"`
	Error struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	} `json:"error"`
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

func sendRequestsToAdaptor(ctx context.Context, url string, payload MessagePayload) (string, error) {
	client := &http.Client{
		Timeout: time.Second * 60, // Set a timeout for the request
	}

	// Marshal the payload into JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Create the POST request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json") // Set header to application/json

	// Send the request
	resp, err := client.Do(req)

	if err != nil {
		fmt.Println("Send request to adaptor error ::::", err)
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	// Unmarshal the response into a struct
	var fireblocksAdaptorResponse FireblocksAdaptorResponse
	if err := json.Unmarshal(responseBody, &fireblocksAdaptorResponse); err != nil {
		return "", err
	}

	var finalSignature string
	if fireblocksAdaptorResponse.Status == "SUCCESS" {
		// Extract the finalSignature
		finalSignature = fireblocksAdaptorResponse.Data.FinalSignature
	} else {
		err := errors.New(fireblocksAdaptorResponse.Error.Message + " : " + fireblocksAdaptorResponse.Error.Code)
		return "", err
	}
	return finalSignature, nil
}

// Sign returns a signed sequence by the private key.
// Note that what's being signed is the accumulated input hash
func (s *Sequence) Sign(privateKey *ecdsa.PrivateKey, fireblocksFeatureEnabled bool, rawSigningAdaptorUrl string) (*SignedSequence, error) {
	hashToSign := s.HashToSign()
	sig, err := crypto.Sign(hashToSign, privateKey)
	if err != nil {
		return nil, err
	}

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

func signWithAdaptor(hashToSign []byte, rawSigningAdaptorUrl string) ([]byte, error) {
	payload := MessagePayload{
		Data: hex.EncodeToString(hashToSign),
	}
	signature, err := sendRequestsToAdaptor(context.Background(), rawSigningAdaptorUrl, payload)
	if err != nil {
		return nil, err
	}

	trimmedSignature := signature[2:]
	sig, err := hex.DecodeString(trimmedSignature)
	if err != nil {
		return nil, err
	}

	log.Infof("Trimmed and decoded signature from adaptor: %x", sig)
	return sig, nil
}

func signWithPrivateKey(hashToSign []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	sig, err := crypto.Sign(hashToSign, privateKey)
	if err != nil {
		return nil, err
	}
	return sig, nil
}

func processSignature(sig []byte, fireblocksFeatureEnabled bool) ([]byte, error) {
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

	log.Infof("Processed signature: %x", actualSignature)
	return actualSignature, nil
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
func (s *SignedSequence) Signer(fireblocksFeatureEnabled bool) (common.Address, error) {
	if len(s.Signature) != signatureLen {
		return common.Address{}, errors.New("invalid signature")
	}

	sig := make([]byte, signatureLen)
	copy(sig, s.Signature)
	sig[64] -= 27

	if fireblocksFeatureEnabled {
		log.Infof("The received signature from sequence sender", hex.EncodeToString(s.Signature))

		// Double hash as per Fireblocks
		firstHash := s.Sequence.HashToSign()
		message := hex.EncodeToString(firstHash)
		wrappedMessage := "\x19Ethereum Signed Message:\n" + string(rune(len(message))) + message

		// Calculate the hash of the wrapped message
		hash := sha256.Sum256([]byte(wrappedMessage))
		// Calculate the hash of the hash
		contentHash := sha256.Sum256(hash[:])

		pubKey, err := crypto.SigToPub(contentHash[:], sig)
		if err != nil {
			log.Infof("Error converting to public key", err)
			return common.Address{}, err
		}
		val := crypto.PubkeyToAddress(*pubKey)
		log.Infof("Recovered address in DAC is:", val.String())

		return crypto.PubkeyToAddress(*pubKey), nil
	} else {
		pubKey, err := crypto.SigToPub(s.Sequence.HashToSign(), sig)
		if err != nil {
			return common.Address{}, err
		}
		return crypto.PubkeyToAddress(*pubKey), nil
	}
}
