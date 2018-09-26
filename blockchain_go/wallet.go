package core

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"log"

	"golang.org/x/crypto/ripemd160"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts"
	"math/big"
	"encoding/hex"
)

const version = byte(0x00)
const addressChecksumLen = 4

// Wallet stores private and public keys
type Wallet struct {
	PrivateKey ecdsa.PrivateKey
	PublicKey  []byte
}

// NewWallet creates and returns a Wallet
func NewWallet() *Wallet {
	private, public := newKeyPair()
	wallet := Wallet{private, public}

	return &wallet
}

// GetAddress returns wallet address
func (w Wallet) GetAddress() []byte {
	pubKeyHash := HashPubKey(w.PublicKey)

	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	address := Base58Encode(fullPayload)

	return address
}

// GetAddressFromPubkeyHash get Base58Encode from public key hashes
func GetAddressFromPubkeyHash(pubKeyHash []byte) []byte {

	versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	address := Base58Encode(fullPayload)

	return address
}

// GetAddressFromPubkeyHash get Base58Encode from public key hashes
func Base58ToPubkeyHash(address []byte) []byte {

	pubKeyHash := Base58Decode([]byte(address))
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]

	return pubKeyHash
}

// HashPubKey hashes public key
func HashPubKey(pubKey []byte) []byte {
	publicSHA256 := sha256.Sum256(pubKey)

	RIPEMD160Hasher := ripemd160.New()
	_, err := RIPEMD160Hasher.Write(publicSHA256[:])
	if err != nil {
		log.Panic(err)
	}
	publicRIPEMD160 := RIPEMD160Hasher.Sum(nil)

	return publicRIPEMD160
}

// ValidateAddress check if address if valid
func ValidateAddress(address string) bool {
	pubKeyHash := Base58Decode([]byte(address))
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))

	return bytes.Compare(actualChecksum, targetChecksum) == 0
}

// Checksum generates a checksum for a public key
func checksum(payload []byte) []byte {
	firstSHA := sha256.Sum256(payload)
	secondSHA := sha256.Sum256(firstSHA[:])

	return secondSHA[:addressChecksumLen]
}

func newKeyPair() (ecdsa.PrivateKey, []byte) {
	//curve := elliptic.P256()
	//private, err := ecdsa.GenerateKey(curve, rand.Reader)
	private, err := crypto.GenerateKey()
	if err != nil {
		log.Panic(err)
	}
	pubKey := append(private.PublicKey.X.Bytes(), private.PublicKey.Y.Bytes()...)

	return *private, pubKey
}

func (w Wallet)ToCommonAddress()common.Address{
	address := HashPubKey(w.PublicKey)
	return common.BytesToAddress(address)
}

func Base58ToCommonAddress(key []byte)common.Address{
	address := Base58ToPubkeyHash(key)
	return common.BytesToAddress(address)
}

func CommonAddressToBase58(address *common.Address)string{
	return string(GetAddressFromPubkeyHash(address.Bytes()))
}

func (w Wallet) SignTxWithPassphrase(account accounts.Account,passwd string,tx *Transaction,chainID *big.Int,nodeID string,bcc *Blockchain)(*Transaction,error){
	var bc *Blockchain
	if(bcc != nil){
		bc = bcc
	}else{
		bc = NewBlockchain(nodeID)
	}
	prevTXs := make(map[string]Transaction)

	for _, vin := range tx.Vin {
		prevTX, err := bc.FindTransaction(vin.Txid)
		if err != nil {
			return nil,err
		}
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}
	if(bcc == nil) {
		bc.Db.Close()
	}

	tx.Sign(w.PrivateKey, prevTXs)
	return tx,nil
	//uTXOSet.Blockchain.SignTransaction(&tx, w.PrivateKey)
}