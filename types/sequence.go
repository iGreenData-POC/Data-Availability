package types

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/0xPolygon/cdk-data-availability/log"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	solsha3 "github.com/miguelmota/go-solidity-sha3"
	"io/ioutil"
	"net/http"
	"time"
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
func sendRequestsToAdaptor(ctx context.Context, url string, payload MessagePayload) (string, error) {
	client := &http.Client{
		Timeout: time.Second * 60, // Set a timeout for the request
	}

	// Marshal the payload into JSON
	jsonData, err := json.Marshal(payload)
	log.Infof("Send request to adaptor jsonData 00000==========>", jsonData)
	if err != nil {
		return "", err
	}

	// Create the POST request
	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json") // Set header to application/json
	log.Infof("Send request to adaptor req 11111==========>", req)

	// Send the request
	resp, err := client.Do(req)
	log.Infof("Send request to adaptor resp 22222==========>", resp)
	if err != nil {
		fmt.Println("Send request to adaptor error ::::", err)
		log.Infof("Send request to adaptor error 333333==========>", err)
		return "", err
	}
	defer resp.Body.Close()

	// Read the response body
	responseBody, err := ioutil.ReadAll(resp.Body)
	log.Infof("Send request to adaptor responseBody 4444==========>", responseBody)
	log.Infof("Send request to adaptor string(responseBody)5555==========>", string(responseBody))
	if err != nil {
		return "", err
	}
	return string(responseBody), nil
}

// Sign returns a signed sequence by the private key.
// Note that what's being signed is the accumulated input hash
func (s *Sequence) Sign() (*SignedSequence, error) {
	log.Infof("Inside sequence.go Sign function!")

	hashToSign := s.HashToSign()
	log.Infof("Creating hashToSign==========>", hashToSign)

	payload := MessagePayload{
		Data: hex.EncodeToString(hashToSign),
	}
	log.Infof("Hex encoding hashToSign===========>", hex.EncodeToString(hashToSign))
	log.Infof("Created message payload!")
	//add
	signature, err := sendRequestsToAdaptor(context.Background(), "http://34.136.253.25:3000/v1/sign-message", payload)
	if err != nil {
		log.Infof("Failed to send message request to adaptor")
		return nil, err
	}
	log.Infof("Signature message from adaptor!", signature)
	/*sig, err := crypto.Sign(hashToSign, privateKey)
	if err != nil {
		return nil, err
	}*/
	trimmedSignature := signature[2:]
	log.Infof("TrimmedSignature message from adaptor!", trimmedSignature)

	sig, err := hex.DecodeString(trimmedSignature)
	if err != nil {
		log.Infof("Failed to decode signature!", err)
	}
	log.Infof("The Decoded signature is:", sig)

	///////

	firstHash := s.HashToSign()
	log.Infof("Creating firstHash============>", firstHash)

	message := hex.EncodeToString(firstHash)
	log.Infof("Hex encoding firstHash===========>", message)

	wrappedMessage := "\x19Ethereum Signed Message:\n" +
		string(rune(len(message))) +
		message

	// Calculate the hash of the wrapped message
	hash := sha256.Sum256([]byte(wrappedMessage))

	// Calculate the hash of the hash
	contentHash := sha256.Sum256(hash[:])

	mySig := make([]byte, 65)
	copy(mySig, sig)
	mySig[64] -= 27

	pubKey, err := crypto.SigToPub(contentHash[:], mySig)
	if err != nil {
		fmt.Println("error recovering pub key", err)
	}
	val := crypto.PubkeyToAddress(*pubKey)

	fmt.Println("recovered address is:", val.String())
	rBytes := sig[:32]
	log.Infof("The Decoded r value is:", string(rBytes))
	sBytes := sig[32:64]
	log.Infof("The Decoded s value is:", string(sBytes))
	vByte := sig[64]
	log.Infof("The Decoded v value is:", string(vByte))

	// if strings.ToUpper(common.Bytes2Hex(sBytes)) > "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0" {
	// 	log.Infof("Inside  strings.ToUpper(common.Bytes2Hex(sBytes))message from adaptor!")
	// 	magicNumber := common.Hex2Bytes("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")
	// 	sBig := big.NewInt(0).SetBytes(sBytes)
	// 	magicBig := big.NewInt(0).SetBytes(magicNumber)
	// 	s1 := magicBig.Sub(magicBig, sBig)
	// 	sBytes = s1.Bytes()
	// 	if vByte == 0 {
	// 		vByte = 1
	// 	} else {
	// 		vByte = 0
	// 	}
	// }
	// // vByte += 27

	actualSignature := []byte{}
	actualSignature = append(actualSignature, rBytes...)
	actualSignature = append(actualSignature, sBytes...)
	actualSignature = append(actualSignature, vByte)
	log.Infof("The Decoded v value is hex.EncodeToString(sig):", hex.EncodeToString(sig))
	log.Infof("The Decoded v value is hex.EncodeToString(actualSignature):", hex.EncodeToString(actualSignature))

	// log.Infof("ActualSignature message from adaptor!", actualSignature)

	// test := &SignedSequence{
	// 	Sequence:  *s,
	// 	Signature: actualSignature,
	// }

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
	/*marshalledSig, err := s.Signature.MarshalText()
	if err != nil {
		log.Infof("error", err)
	}*/

	sig := make([]byte, 65)
	copy(sig, s.Signature)
	sig[64] -= 27

	//double hash as per Fireblocks

	/////
	firstHash := s.Sequence.HashToSign()
	log.Infof("Creating firstHash in DAC============>", firstHash)

	message := hex.EncodeToString(firstHash)
	log.Infof("Hex encoding firstHash= in DAC==========>", message)

	wrappedMessage := "\x19Ethereum Signed Message:\n" +
		string(rune(len(message))) +
		message

	// Calculate the hash of the wrapped message
	hash := sha256.Sum256([]byte(wrappedMessage))

	// Calculate the hash of the hash
	contentHash := sha256.Sum256(hash[:])

	// mySig := make([]byte, 65)
	// copy(mySig, sig)
	// mySig[64] -= 27

	log.Infof("Recovering key in DAC ====================")
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
