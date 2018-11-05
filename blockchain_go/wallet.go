package core

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"log"

	"golang.org/x/crypto/ripemd160"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/accounts"
	"math/big"
	"encoding/hex"
	"fmt"
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
	pubKeyHash := HashPubKey256T(w.PublicKey)

	/*versionedPayload := append([]byte{version}, pubKeyHash...)
	checksum := checksum(versionedPayload)

	fullPayload := append(versionedPayload, checksum...)
	address := Base58Encode(fullPayload)*/

	return pubKeyHash
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

// HashPubKey hashes public key
func HashPubKey256T(pubKey []byte) []byte {
	//pubBytes := crypto.FromECDSAPub(&pubKey) //将pubkey转换为字节序列
	var addr common.Address
	copy(addr[:], crypto.Keccak256(pubKey[0:])[12:])
	return addr.Bytes()
}


// ValidateAddress check if address if valid
func ValidateAddress(address string) bool {
	/*pubKeyHash := Base58Decode([]byte(address))
	actualChecksum := pubKeyHash[len(pubKeyHash)-addressChecksumLen:]
	version := pubKeyHash[0]
	pubKeyHash = pubKeyHash[1 : len(pubKeyHash)-addressChecksumLen]
	targetChecksum := checksum(append([]byte{version}, pubKeyHash...))

	return bytes.Compare(actualChecksum, targetChecksum) == 0*/
	var addr string
	if len(address) >= 2 && address[:2] == "0x" {
		addr = address[2:]
	}
	_,err := hex.DecodeString(addr)
	if err!=nil{
		return false
	}
	if len(address) != 42{
		return false
	}
	return true
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
	address := HashPubKey256T(w.PublicKey)
	return common.BytesToAddress(address)
}

func Base58ToCommonAddress(key []byte)common.Address{
	address := Base58ToPubkeyHash(key)
	return common.BytesToAddress(address)
}

func PubkeyHashToCommonAddress(key []byte)common.Address{
	return common.BytesToAddress(key)
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
		defer bc.Db.Close()
	}
	prevTXs := make(map[string]Transaction)

	for _, vin := range tx.Vin {
		prevTX, err := bc.FindTransaction(vin.Txid)
		if err != nil {
			return nil,err
		}
		prevTXs[hex.EncodeToString(prevTX.ID)] = prevTX
	}
	/*if(bcc == nil) {
		bc.Db.Close()
	}*/

	var err error
	// Depending on the presence of the chain ID, sign with EIP155 or homestead
	if chainID != nil {
		tx.Sign(w.PrivateKey, prevTXs,NewEIP155Signer(chainID))
		tx,err = SignTx(tx, NewEIP155Signer(chainID), &w.PrivateKey)
	}else{
		tx.Sign(w.PrivateKey, prevTXs,HomesteadSigner{})
		tx,err = SignTx(tx, HomesteadSigner{}, &w.PrivateKey)
	}
	fmt.Printf("===af SignTxWithPassphrase tx %x %s \n",tx.ID,err)
	return tx,err
	//uTXOSet.Blockchain.SignTransaction(&tx, w.PrivateKey)
}