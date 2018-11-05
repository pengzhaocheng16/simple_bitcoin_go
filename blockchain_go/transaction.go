package core

import (
	"bytes"
	"errors"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"strings"
	"encoding/gob"
	"encoding/hex"
	"fmt"
	"log"
	"time"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/common"
	"sync/atomic"
	"github.com/ethereum/go-ethereum/rlp"
	."../boltqueue"
	."./state"
	"github.com/btcsuite/btcutil"
)

const subsidy = 50
// The size of a SHA256 checksum in bytes.
const Size = 32
//go:generate gencodec -type txdata -field-override txdataMarshaling -out gen_tx_json.go

var (
	ErrInvalidSig = errors.New("invalid transaction v, r, s values")
)

// Transaction represents a Bitcoin transaction
type Transaction struct {
	ID   []byte
	Vin  []TXInput
	Vout []TXOutput
	Timestamp *big.Int
	size atomic.Value
	Data txdata
	from atomic.Value
}
type writeCounter common.StorageSize

type txdata struct {
	AccountNonce uint64          `json:"nonce"    gencodec:"required"`
	Price        *big.Int        `json:"gasPrice" gencodec:"required"`//
	GasLimit     uint64          `json:"gas"      gencodec:"required"`//
	Recipient    *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int        `json:"value"    gencodec:"required"`
	Payload      []byte          `json:"input"    gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	// This is only used when marshaling to JSON.
	Hash *common.Hash `json:"hash" rlp:"-"`
}

func Txdata()txdata{
	return txdata{}
}

func (tx Transaction)Nonce()uint64{
	return tx.Data.AccountNonce
}

func (tx Transaction)To()*common.Address{
	return tx.Data.Recipient
}

func (tx Transaction)From(signer Signer)common.Address{
	addr, _ := signer.Sender(&tx)
	return addr
}

func (tx Transaction)Value()*big.Int{
	return big.NewInt(int64(tx.Vout[0].Value))
	//return tx.Data.Amount
}

func (tx Transaction)Cost()*big.Int{
	return big.NewInt(0)
}

func (tx Transaction)Gas()*big.Int{
	return big.NewInt(0)
}

func (c *writeCounter) Write(b []byte) (int, error) {
	*c += writeCounter(len(b))
	return len(b), nil
}

// IsCoinbase checks whether the transaction is coinbase
func (tx Transaction) IsCoinbase() bool {
	return len(tx.Vin) == 1 && len(tx.Vin[0].Txid) == 0 && tx.Vin[0].Vout.Int64() == 0
}

// ChainId returns which chain id this transaction was signed for (if at all)
func (tx *Transaction) ChainId() *big.Int {
	return deriveChainId(tx.Data.V)
}
// Protected returns whether the transaction is protected from replay protection.
func (tx *Transaction) Protected() bool {
	return isProtectedV(tx.Data.V)
}

func isProtectedV(V *big.Int) bool {
	if V.BitLen() <= 8 {
		v := V.Uint64()
		return v != 27 && v != 28
	}
	// anything not 27 or 28 are considered unprotected
	return true
}

// Serialize returns a serialized Transaction
func (tx Transaction) Serialize() []byte {
	var encoded bytes.Buffer

	enc := gob.NewEncoder(&encoded)
	err := enc.Encode(tx)
	if err != nil {
		log.Panic(err)
	}

	return encoded.Bytes()
}

// Hash returns the hash of the Transaction
// before sign
func (tx *Transaction) Hash() []byte {
	if(tx.ID != nil){
		return tx.ID
	}
	var hash [32]byte

	txCopy := *tx
	txCopy.ID = nil
	txCopy.Data.V = big.NewInt(0)
	txCopy.Data.R = nil
	txCopy.Data.S = nil

	//hash = sha256.Sum256(txCopy.Serialize())
	hash = tx.RLPHash()

	return hash[:]
}
// Hash returns the hash of the Transaction
// before sign
func (tx *Transaction) HashSign() []byte {
	if(tx.ID != nil){
		return tx.ID
	}
	var hash [32]byte

	txCopy := *tx
	txCopy.ID = nil

	//hash = sha256.Sum256(txCopy.Serialize())
	hash = txCopy.RLPHash()

	return hash[:]
}

// Hash returns the hash of the Transaction
func (tx *Transaction) CommonHash() common.Hash {
	var hash common.Hash
	hash = common.BytesToHash(tx.Hash())
	return hash
}

type TransactionCopy struct {
	ID   []byte
	Vin  []byte
	Vout []byte
	Timestamp *big.Int
	//size atomic.Value
	Data []byte
	//from atomic.Value
}

type txdataCopy struct {
	AccountNonce uint64          `json:"nonce"    gencodec:"required"`
	Price        *big.Int        `json:"gasPrice" gencodec:"required"`
	GasLimit     uint64          `json:"gas"      gencodec:"required"`
	Recipient    *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int        `json:"value"    gencodec:"required"`
	Payload      []byte          `json:"input"    gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}
// Hash returns the hash of the Transaction
func (tx *Transaction) RLPHash() [Size]byte {
	var hash [32]byte

	txCopy := *tx
	//txCopy.ID = []byte{}
	txCopy.ID = nil
	//txCopy.data = txdata{}
	//size := tx.size.Load().(common.StorageSize)
	//tx.size.Store(big.NewFloat(float64(size)))

	var err error
	var copy =  TransactionCopy{}
	copy.ID = nil

	var txinputs = [][]byte{}
	for _,input := range txCopy.Vin{
		/*log.Println("---encoded target input.Txid:",input.Txid)
		log.Println("---encoded target input.Vout:",input.Vout)
		log.Println("---encoded target input.Signature:",input.Signature)
		log.Println("---encoded target input.PubKey:",input.PubKey)*/
		vin,err := rlp.EncodeToBytes(input)
		if(err!=nil){
			log.Fatal(err)
		}
		txinputs = append(txinputs,vin)
	}
	copy.Vin,err = rlp.EncodeToBytes(txinputs)
	if(err!=nil){
		log.Fatal(err)
	}
	//log.Println("---encoded bytes RLP copy.Vin:",copy.Vin)
	var txoutputs = [][]byte{}
	for _,output := range txCopy.Vout {
		vout, err := rlp.EncodeToBytes(output)
		if (err != nil) {
			log.Fatal(err)
		}
		txoutputs = append(txoutputs, vout)
	}
	copy.Vout,err = rlp.EncodeToBytes(txoutputs)
	if(err!=nil){
		log.Fatal(err)
	}
	//log.Println("---encoded bytes RLP copy.Vout:",copy.Vout)
	copy.Timestamp = txCopy.Timestamp
	//log.Println("---encoded bytes RLP copy.Timestamp:",copy.Timestamp)
	txdataCopy := txdataCopy{}
	txdataCopy.AccountNonce = txCopy.Data.AccountNonce
	txdataCopy.Price = txCopy.Data.Price
	txdataCopy.GasLimit = txCopy.Data.GasLimit
	txdataCopy.Recipient = txCopy.Data.Recipient
	txdataCopy.Amount = txCopy.Data.Amount
	txdataCopy.Payload = txCopy.Data.Payload
	txdataCopy.V = txCopy.Data.V
	txdataCopy.R = txCopy.Data.R
	txdataCopy.S = txCopy.Data.S
	copy.Data,err = rlp.EncodeToBytes(txdataCopy)
	if(err!=nil){
		log.Fatal(err)
	}
	//log.Println("---encoded bytes RLP copy.Data:",copy.Data)

	txBytes,err1 := rlp.EncodeToBytes(copy)
	if(err1!=nil){
		log.Fatal(err1)
	}
	//log.Println("---encoded bytes RLP txBytes:",txBytes)
	hash = sha256.Sum256(txBytes)

	return hash
}

// Hash returns the hash of the Transaction
func (tx *Transaction) HashCommon() common.Hash {
	var hash []byte
	hash = tx.Hash()

	return common.BytesToHash(hash)
}

func (tx *Transaction) RawSignatureValues()( *big.Int, *big.Int, *big.Int) {

	return tx.Data.V,tx.Data.R,tx.Data.S
}

// Sign signs each input of a Transaction
func (tx *Transaction) Sign(privKey ecdsa.PrivateKey, prevTXs map[string]Transaction,s Signer) {
	if tx.IsCoinbase() {
		return
	}

	for _, vin := range tx.Vin {
		if prevTXs[hex.EncodeToString(vin.Txid)].ID == nil {
			log.Panic("ERROR: Previous transaction is not correct")
		}
	}

	txCopy := tx.TrimmedCopy(false)

	for inID, vin := range txCopy.Vin {
		prevTx := prevTXs[hex.EncodeToString(vin.Txid)]
		txCopy.Vin[inID].Signature = nil
		txCopy.Vin[inID].PubKey = prevTx.Vout[vin.Vout.Int64()].PubKeyHash

		//dataToSign := fmt.Sprintf("%x", txCopy.RLPHash())
		dataToSign := txCopy.RLPHash()
		var dataToSignin = dataToSign[:]

		//r, s, err := ecdsa.Sign(rand.Reader, &privKey, []byte(dataToSign))
		//recovery value at bytes[64]
		var sig,err = crypto.Sign([]byte(dataToSignin), &privKey)
		if err != nil {
			log.Panic(err)
		}
		/*r, s, _, err1 := s.SignatureValues(tx, sig)
		if err1 != nil {
			log.Panic(err1)
		}
		signature := append(r.Bytes(), s.Bytes()...)
		*/
		signature :=sig

		tx.Vin[inID].Signature = signature
		txCopy.Vin[inID].PubKey = nil
	}

}


// InitFrom requires a signer to derive the sender.
//
func (tx *Transaction) InitFrom(s Signer) (*Transaction, error) {

	var err error
	_, err = Sender(s, tx)
	return tx, err
}

// WithSignature returns a new transaction with the given signature.
// This signature needs to be formatted as described in the yellow paper (v+27).
func (tx *Transaction) WithSignature(signer Signer, sig []byte) (*Transaction, error) {
	r, s, v, err := signer.SignatureValues(tx, sig)
	if err != nil {
		return nil, err
	}
	cpy := &Transaction{ID:tx.ID,Vin:tx.Vin,Vout:tx.Vout,Timestamp:tx.Timestamp,Data: tx.Data}
	cpy.Data.R, cpy.Data.S, cpy.Data.V = r, s, v
	return cpy, nil
}

// String returns a human-readable representation of a transaction
func (tx Transaction) String() string {
	var lines []string

	lines = append(lines, fmt.Sprintf("--- Transaction %x:", tx.ID))
	for i, input := range tx.Vin {

		lines = append(lines, fmt.Sprintf("     Input %d:", i))
		lines = append(lines, fmt.Sprintf("       TXID:      %x", input.Txid))
		lines = append(lines, fmt.Sprintf("       Out:       %d", input.Vout))
		lines = append(lines, fmt.Sprintf("       Signature: %x", input.Signature))
		lines = append(lines, fmt.Sprintf("       PubKey:    %x", input.PubKey))
	}

	for i, output := range tx.Vout {
		lines = append(lines, fmt.Sprintf("     Output %d:", i))
		lines = append(lines, fmt.Sprintf("       Value:  %d", output.Value))
		lines = append(lines, fmt.Sprintf("       Script: %x", output.PubKeyHash))
	}
	if &tx.Data!=nil {
		lines = append(lines, fmt.Sprintf("     AccountNonce  %d:", tx.Data.AccountNonce))
		lines = append(lines, fmt.Sprintf("       GashLimit:%d", tx.Data.GasLimit))
		lines = append(lines, fmt.Sprintf("       Price:    %d", tx.Data.Price))
		lines = append(lines, fmt.Sprintf("       s:        %x", tx.Data.S))
		lines = append(lines, fmt.Sprintf("       v:        %x", tx.Data.V))
		lines = append(lines, fmt.Sprintf("       r:        %x", tx.Data.R))
		lines = append(lines, fmt.Sprintf("       value:    %d", tx.Data.Amount))
		lines = append(lines, fmt.Sprintf("       Payload:  %x", tx.Data.Payload))
		lines = append(lines, fmt.Sprintf("       Hash:     %x", tx.Data.Hash))
	}
	    lines = append(lines, fmt.Sprintf("       Timestamp:%d", tx.Timestamp))

	return strings.Join(lines, "\n")
}

// TrimmedCopy creates a trimmed copy of Transaction to be used in signing
func (tx *Transaction) TrimmedCopy(noData bool) Transaction {
	var inputs []TXInput
	var outputs []TXOutput

	for _, vin := range tx.Vin {
		inputs = append(inputs, TXInput{vin.Txid, vin.Vout, nil, nil})
	}

	for _, vout := range tx.Vout {
		outputs = append(outputs, TXOutput{vout.Value, vout.PubKeyHash})
	}

	var v = atomic.Value{}
	v.Store(common.StorageSize(0))
	var froma = atomic.Value{}
	froma.Store(common.Address{})


	txCopy := Transaction{nil, inputs, outputs,
	tx.Timestamp,tx.size,tx.Data,froma}
	tx.SetSize(uint64(len(tx.Serialize())))

	if noData {
		txCopy.Data.V = big.NewInt(0)
		txCopy.Data.R = nil
		txCopy.Data.S = nil
	}
	//txCopy.size.Store(tx.Size())


	return txCopy
}

// Verify verifies signatures of Transaction inputs
func (tx *Transaction) Verify(prevTXs map[string]Transaction) bool {
	if tx.IsCoinbase() {
		return true
	}

	for _, vin := range tx.Vin {
		if prevTXs[hex.EncodeToString(vin.Txid)].ID == nil {
			log.Fatalln("ERROR: Previous transaction is not correct")
		}
	}

	txCopy := tx.TrimmedCopy(true)

	dec := &tx.Data
	var V byte
	//var v uint64
	var signer Signer
	signer = HomesteadSigner{}
	if isProtectedV(dec.V) {
		chainID := deriveChainId(dec.V).Uint64()
		V = byte(dec.V.Uint64() - 35 - 2*chainID)
		//v = 2*chainID + 35
		signer = NewEIP155Signer(big.NewInt(int64(chainID)))
	} else {
		V = byte(dec.V.Uint64() - 27)
		//v = 27
	}

		var sig = []byte{}
		//log.Println("INFO:  data len(dec.R.Bytes()):",len(dec.R.Bytes()))
		sig = append(sig,dec.R.Bytes()...)
		sig = append(sig,dec.S.Bytes()...)
		sig = append(sig,V)
		//sig = append(sig,dec.V.Bytes()...)
		//log.Println("INFO:  data len(sig):",len(sig))

		//var rlphash = txCopy.RLPHash()
		var rlphash = signer.Hash(tx)
		//log.Println("---encoded  rlphash:",rlphash)
		var dataToVerify = rlphash[:]
		rawPubKey,err1 := crypto.Ecrecover(dataToVerify,sig)
		//log.Println("INFO:  data len(rawPubKey) Ecrecover:",rawPubKey)
		if err1!=nil {
			log.Panic(err1)
		}
		rawPubKey1 := tx.Vin[0].PubKey
		var pubkey = []byte{}
		pubkey = append(pubkey,rawPubKey[0:1]...)
		pubkey = append(pubkey,rawPubKey1...)
		//log.Println("INFO:  data len(rawPubKey):",rawPubKey1)

		//if !crypto.ValidateSignatureValues(V, dec.R, dec.S, false) {
		//	//return ErrInvalidSig
		//	log.Panic("ERROR: Signature is not correct data")
		//	return false
		//}
		if !crypto.VerifySignature(pubkey,dataToVerify,sig[0:64]) {
			//return ErrInvalidSig
			log.Panic("ERROR: Signature is not correct data")
			return false
		}

	curve := crypto.S256()

	for inID, vin := range tx.Vin {
		prevTx := prevTXs[hex.EncodeToString(vin.Txid)]
		txCopy.Vin[inID].Signature = nil
		txCopy.Vin[inID].PubKey = prevTx.Vout[vin.Vout.Int64()].PubKeyHash

		/*r := big.Int{}
		s := big.Int{}
		sigLen := len(vin.Signature)
		r.SetBytes(vin.Signature[:(sigLen / 2)])
		s.SetBytes(vin.Signature[(sigLen / 2):])*/

		x := big.Int{}
		y := big.Int{}
		keyLen := len(vin.PubKey)
		x.SetBytes(vin.PubKey[:(keyLen / 2)])
		y.SetBytes(vin.PubKey[(keyLen / 2):])

		r, s, _, err := signer.SignatureValues(tx, vin.Signature)
		if err != nil {
			log.Panic(err)
		}

		//dataToVerify := fmt.Sprintf("%x", txCopy.RLPHash())
		var rlphash = txCopy.RLPHash()
		var dataToVerify = rlphash[:]
		log.Println("---encoded bytes dataToVerify:",dataToVerify)
		rawPubKey := ecdsa.PublicKey{curve, &x, &y}
		if ecdsa.Verify(&rawPubKey, []byte(dataToVerify), r, s) == false {
			log.Fatalln("ERROR: Signature is not correct")
			return false
		}
		/*if !crypto.ValidateSignatureValues(v.Bytes()[0], r, s, false) {
			//return ErrInvalidSig
			log.Panic("ERROR: SignatureValues is not correct")
			return false
		}*/
		//crypto.PubkeyToAddress()
		/*if !crypto.VerifySignature(vin.PubKey,dataToVerify,vin.Signature) {
			//return ErrInvalidSig
			log.Panic("ERROR: Signature is not correct")
			return false
		}*/

		txCopy.Vin[inID].PubKey = nil
	}

	return true
}

// NewCoinbaseTX creates a new coinbase transaction
func NewCoinbaseTX(nonce uint64,to common.Address, data,nodeID string) *Transaction {
	if data == "" {
		randData := make([]byte, subsidy)
		_, err := rand.Read(randData)
		if err != nil {
			log.Panic(err)
		}

		data = fmt.Sprintf("%x", randData)
	}

	txin := TXInput{[]byte{}, big.NewInt(0), nil, []byte(data)}

	// Convert the amount to honey.
	honey, err := btcutil.NewAmount(subsidy)
	if err != nil {
		context := "Failed to convert amount"
		log.Println(errors.New(err.Error()+context))
		return nil
	}
	txout := NewTXOutput(uint64(honey), to.Bytes())

	//prepare tx data
	//var toa = Base58ToCommonAddress([]byte(to))
	//coinbase tx no from address

	d := txdata{
		AccountNonce: nonce,
		Recipient:    &to,
		Payload:     make([]byte, 0) ,
		Amount:       new(big.Int),
		//GasLimit:     gasLimit,
		//Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	d.Amount.Set(big.NewInt(subsidy))

	var v = atomic.Value{}
	v.Store(common.StorageSize(0))
	var froma = atomic.Value{}
	froma.Store(common.Address{})
	tx := Transaction{nil, []TXInput{txin}, []TXOutput{*txout},
	big.NewInt(time.Now().Unix()),v,d,froma}
	tx.ID = tx.Hash()
	//tx.SetSize(uint64(len(tx.Serialize())))
	tx.Size()

	return &tx
}

// NewUTXOTransaction creates a new transaction
// sign transaction
func NewUTXOTransaction(nonce uint64,wallet *Wallet, to common.Address, amount *float64,data []byte, UTXOSet *UTXOSet,nodeID string) *Transaction {
	pubKeyHash := HashPubKey256T(wallet.PublicKey)
	var inputs []TXInput
	var outputs []TXOutput

	// Convert the amount to honey.
	honey, err := btcutil.NewAmount(*amount)
	if err != nil {
		context := "Failed to convert amount"
		log.Println(errors.New(err.Error()+context))
		return nil
	}
	acc, validOutputs,extraOutputs := UTXOSet.FindSpendableOutputs(pubKeyHash, uint64(honey),false,nil,nil)

	if acc < uint64(honey) {
		log.Panic("ERROR: Not enough funds")
	}

	// Build a list of inputs
	for txid, outs := range validOutputs {
		txID, err := hex.DecodeString(txid)
		if err != nil {
			log.Panic(err)
		}
		for _, out := range outs {
			input := TXInput{txID, big.NewInt(int64(out)), nil, wallet.PublicKey}
			inputs = append(inputs, input)
		}
	}

	// Build a list of outputs
	//from := fmt.Sprintf("%s", wallet.GetAddress())
	from := wallet.GetAddress()
	outputs = append(outputs, *NewTXOutput(uint64(honey), to.Bytes()))
	if acc > uint64(honey) {
		outputs = append(outputs, *NewTXOutput(uint64(acc-uint64(honey)), from)) // a change
	}
	for _,txouts := range extraOutputs{
		outputs = append(outputs,txouts...)
	}

	//prepare tx data
	/*address := common.BytesToAddress(pubKeyHash).String()
	var wt = new(WalletTransactions)
	wt.InitDB(nodeID,address)
	nonce,err := wt.GetTransactionNonce(address)
	wt.DB.Close()
	if(err!=nil){
		log.Panic(err)
	}*/
	//var toa = Base58ToCommonAddress([]byte(to))
	d := txdata{
		AccountNonce: nonce,
		Recipient:    &to,
		Payload:      data,
		Amount:       new(big.Int),
		//GasLimit:     gasLimit,
		//Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	if uint64(honey) != 0 {
		d.Amount.Set(big.NewInt(int64(honey)))
	}

	//sign transaction
	var v = atomic.Value{}
	v.Store(common.StorageSize(0))
	var froma = atomic.Value{}
	froma.Store(common.Address{})
	tx := Transaction{nil, inputs, outputs,
	big.NewInt(time.Now().Unix()),v,d,froma}
	tx.ID = tx.Hash()
	//tx.SetSize(uint64(len(tx.Serialize())))
	tx.Size()
	//UTXOSet.Blockchain.SignTransaction(&tx, wallet.PrivateKey)
	account := accounts.Account{Address: wallet.ToCommonAddress()}
	wallet.SignTxWithPassphrase(account,"",&tx,nil,nodeID,UTXOSet.Blockchain)

	return &tx
}

// DeserializeTransaction deserializes a transaction
func DeserializeTransaction(data []byte) Transaction {
	var transaction Transaction

	decoder := gob.NewDecoder(bytes.NewReader(data))
	err := decoder.Decode(&transaction)
	if err != nil {
		log.Panic(err)
	}

	return transaction
}

func VeryfyFromToAddress(tx *Transaction) bool{
	if tx.IsCoinbase() {
		return true
	}
	if len(tx.Vout)>0 {
		for _, txin := range tx.Vin {
			if hex.EncodeToString(txin.PubKey) == hex.EncodeToString(tx.Vout[0].PubKeyHash) {
				//log.Panic("ERROR: Wallet from equal Wallet to is not valid")
				return false
			}
		}
	}
	return true
}
/*
// EncodeRLP implements rlp.Encoder
func (tx *Transaction) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, &tx)
}


// DecodeRLP implements rlp.Decoder
func (tx *Transaction) DecodeRLP(s *rlp.Stream) error {
	_, size, _ := s.Kind()
	err := s.Decode(&tx)
	if err == nil {
		tx.size.Store(common.StorageSize(rlp.ListSize(size)))
	}
	return err
}
*/

// Size returns the true RLP encoded storage size of the transaction, either by
// encoding and returning it, or returning a previsouly cached value.
func (tx *Transaction) Size() common.StorageSize {
	if size := tx.size.Load(); size != nil && size != common.StorageSize(0) {
		return size.(common.StorageSize)
	}
	c := writeCounter(0)
	txserial := tx.Serialize();
	rlp.Encode(&c, &txserial)
	tx.size.Store(common.StorageSize(c))
	return common.StorageSize(c)
}

func (tx *Transaction) SetSize(c uint64) common.StorageSize {
	tx.size.Store(common.StorageSize(c))
	return  common.StorageSize(c)
}

func PendingIn(chainId string,tx *Transaction){
	//queueFile := fmt.Sprintf("%x_tx.db", wallet.GetAddress())
	queueFile := GenWalletStateDbName(chainId)
	//fmt.Printf("===af GenWalletStateDbName  \n")
	if DbExists(dbFile) {
		fmt.Println("wallet transaction file already exists.PendingIn")
		//os.Exit(1)
	}
	//fmt.Printf("===bf NewPQueue  \n")
	txPQueue, err := NewPQueue(queueFile)
	if err != nil {
		log.Panic("create queue error",err)
	}
	//defer txPQueue.Close()
	//defer os.Remove(queueFile)
	//fmt.Printf("===bf SetMsg  \n")
	txPQueue.SetMsg(2,tx.ID,tx.ID)
	txPQueue.SetMsg(3,tx.ID,tx.Serialize())
	for _,vin := range tx.Vin{
		//fmt.Printf("===in SetMsg  \n")
		eqerr := txPQueue.SetMsg(1, vin.Txid,tx.ID)
		if eqerr != nil {
			log.Panic("Enqueue error",eqerr)
		}
	}
	//fmt.Printf("===af SetMsg  \n")
	txPQueue.Close()
}

func RemovePendingIn(chainId string,tx *Transaction){
	//queueFile := fmt.Sprintf("%x_tx.db", wallet.GetAddress())
	queueFile := GenWalletStateDbName(chainId)
	//fmt.Printf("===af GenWalletStateDbName  \n")
	if DbExists(dbFile) {
		fmt.Println("wallet transaction file already exists.PendingIn")
		//os.Exit(1)
	}
	//fmt.Printf("===bf NewPQueue  \n")
	txPQueue, err := NewPQueue(queueFile)
	if err != nil {
		log.Panic("create queue error",err)
	}
	//defer txPQueue.Close()
	//defer os.Remove(queueFile)
	//fmt.Printf("===bf SetMsg  \n")
	txPQueue.DeleteMsg(2,tx.ID)
	txPQueue.DeleteMsg(3,tx.ID)
	for _,vin := range tx.Vin{
		//fmt.Printf("===in SetMsg  \n")
		eqerr := txPQueue.DeleteMsg(1, vin.Txid)
		if eqerr != nil {
			log.Panic("Enqueue error",eqerr)
		}
	}
	//fmt.Printf("===af SetMsg  \n")
	txPQueue.Close()
}

func HasDoubleSpent(txs []*Transaction)bool{
	var txmap  = make(map[string][]byte,0);
	for _,tx := range txs {
		for _,vin := range tx.Vin {
			if txmap[hex.EncodeToString(vin.Txid)] != nil{
				return true
			}
		}
		for _,vin := range tx.Vin {
			txmap[hex.EncodeToString(vin.Txid)] = vin.Txid
		}
	}
	return false
}

func VerifyTx(tx Transaction,bc *Blockchain,preHash *common.Hash)(bool){
	if &tx == nil {
		fmt.Println("transaction %x is nil:",&tx.ID)
		return false
	}
	// ignore transaction if it's not valid
	// 1 have received longest chain among knownodes(full nodes)
	// 2 transaction have valid sign accounding to owner's pubkey by VerifyTransaction()
	// 3 utxo amount >= transaction output amount
	// 4 transaction from address not equal to address
	var valid1 = true
	var valid2 = true
	var valid3 = true
	//verify signatures
	//TODO check transaction data signature
	if !bc.VerifyTransaction(&tx) {
		//log.Panic("ERROR: Invalid transaction:sign")
		valid1 = false
	}

	UTXOSet := UTXOSet{bc}
	var result = UTXOSet.IsUTXOAmountValid(&tx,preHash)
	if(tx.IsCoinbase()==false&&!result){
		//log.Panic("ERROR: Invalid transaction:amount")
		valid2 = false
	}
	valid3 = VeryfyFromToAddress(&tx)
	fmt.Printf("valid1  %s\n", valid1)
	fmt.Printf("valid2  %s\n", valid2)
	fmt.Printf("valid3  %s\n", valid3)

	if(valid1 && valid2 && valid3){
		return true
	}else{
		return false
	}
}

// Transactions is a Transaction slice type for basic sorting.
type Transactions []*Transaction
// Len returns the length of s.
func (s Transactions) Len() int { return len(s) }
// Swap swaps the i'th and the j'th element in s.
func (s Transactions) Swap(i, j int) { s[i], s[j] = s[j], s[i] }
// GetRlp implements Rlpable and returns the i'th element of s in rlp.
func (s Transactions) GetRlp(i int) []byte {
	enc, _ := rlp.EncodeToBytes(s[i])
	return enc
}
// TxDifference returns a new set t which is the difference between a to b.
func TxDifference(a, b Transactions) (keep Transactions) {
	keep = make(Transactions, 0, len(a))

	remove := make(map[common.Hash]struct{})
	for _, tx := range b {
		remove[common.BytesToHash(tx.Hash())] = struct{}{}
	}

	for _, tx := range a {
		if _, ok := remove[common.BytesToHash(tx.Hash())]; !ok {
			keep = append(keep, tx)
		}
	}

	return keep
}
// TxByNonce implements the sort interface to allow sorting a list of transactions
// by their nonces. This is usually only useful for sorting transactions from a
// single account, otherwise a nonce comparison doesn't make much sense.
type TxByNonce Transactions

func (s TxByNonce) Len() int           { return len(s) }
func (s TxByNonce) Less(i, j int) bool { return s[i].Data.AccountNonce < s[j].Data.AccountNonce }
func (s TxByNonce) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }

/**
	new transaction to sign
 */
func NewTransactionAmountFloat(wallet Wallet,nonce uint64,to *common.Address,amount float64,input []byte,nodeID string)*Transaction {
	// Ensure amount is in the valid range for monetary amounts.
	if amount < 0.00000001 || amount > btcutil.MaxSatoshi {
		log.Println(errors.New("Invalid amount"))
		return nil
	}

	// Convert the amount to honey.
	honey, err := btcutil.NewAmount(amount)
	if err != nil {
		context := "Failed to convert amount"
		log.Println(errors.New(err.Error()+context))
		return nil
	}
	return NewTransaction(wallet,nonce,to,int64(honey),input,nodeID)
}

/**
new transaction to sign
*/
func NewTransaction(wallet Wallet,nonce uint64,to *common.Address,honey int64,input []byte,nodeID string)*Transaction{

	var bc = NewBlockchain(nodeID)
	uTXOSet := UTXOSet{bc}

	pubKeyHash := HashPubKey256T(wallet.PublicKey)
	var inputs []TXInput
	var outputs []TXOutput

	acc, validOutputs,extraOutputs := uTXOSet.FindSpendableOutputs(pubKeyHash,uint64(honey),false,nil,nil)
	bc.Db.Close()

	if acc < uint64(honey) {
		log.Panic("ERROR: Not enough funds")
	}

	// Build a list of inputs
	for txid, outs := range validOutputs {
		txID, err := hex.DecodeString(txid)
		if err != nil {
			log.Panic(err)
		}
		for _, out := range outs {
			input := TXInput{txID, big.NewInt(int64(out)), nil, wallet.PublicKey}
			inputs = append(inputs, input)
		}
	}

	// Build a list of outputs
	//from := fmt.Sprintf("%s", wallet.GetAddress())
	from := wallet.GetAddress()
	//outputs = append(outputs, *NewTXOutput(uint64(honey), CommonAddressToBase58(to)))
	outputs = append(outputs, *NewTXOutput(uint64(honey), to.Bytes()))
	if acc > uint64(honey) {
		outputs = append(outputs, *NewTXOutput(acc-uint64(honey), from)) // a change
	}
	for _,txouts := range extraOutputs{
		outputs = append(outputs,txouts...)
	}

	d := txdata{
		AccountNonce: nonce,
		Recipient:    to ,
		Payload:      input,
		Amount:       big.NewInt(int64(honey)),
		//GasLimit:     gasLimit,
		//Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}

	//build a transaction
	var v = atomic.Value{}
	v.Store(common.StorageSize(0))
	var froma = atomic.Value{}
	//froma.Store(PubkeyHashToCommonAddress(pubKeyHash))
	//froma.Store(nil)
	froma.Store(common.Address{})
	tx := Transaction{nil, inputs, outputs,
	big.NewInt(time.Now().Unix()),v,d,froma}
	tx.ID = tx.Hash()
	//tx.SetSize(uint64(len(tx.Serialize())))
	tx.Size()

	fmt.Printf("===after build transaction %x \n", tx.ID)

	return &tx
}

/**
	new transaction from singed transaction field
 */
 /*
func NewTransactionSigned(from *common.Address,nonce uint64,to *common.Address,amount *big.Int,input []byte,nodeID string)*Transaction{
	var bc = NewBlockchain(nodeID)
	uTXOSet := UTXOSet{bc}

	//pubKeyHash := HashPubKey(wallet.PublicKey)
	pubkey, err := secp256k1.RecoverPubkey(hash, sig)
	var inputs []TXInput
	var outputs []TXOutput

	acc, validOutputs := uTXOSet.FindSpendableOutputs(pubKeyHash, amount,false,nil,nil)
	bc.Db.Close()

	if acc < amount.Uint64() {
		log.Panic("ERROR: Not enough funds")
	}

	// Build a list of inputs
	for txid, outs := range validOutputs {
		txID, err := hex.DecodeString(txid)
		if err != nil {
			log.Panic(err)
		}
		for _, out := range outs {
			input := TXInput{txID, out, nil, wallet.PublicKey}
			inputs = append(inputs, input)
		}
	}

	// Build a list of outputs
	from := fmt.Sprintf("%s", wallet.GetAddress())
	outputs = append(outputs, *NewTXOutput(amount, CommonAddressToBase58(to)))
	if acc > amount.Uint64() {
		outputs = append(outputs, *NewTXOutput(big.NewInt(int64(acc-amount.Uint64())), from)) // a change
	}

	d := txdata{
		AccountNonce: nonce,
		Recipient:    to ,
		Payload:      input,
		Amount:       amount,
		//GasLimit:     gasLimit,
		//Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}

	//build a transaction
	var v = atomic.Value{}
	v.Store(common.StorageSize(0))
	tx := Transaction{nil, inputs, outputs, time.Now().Unix(),v,d}
	tx.ID = tx.Hash()
	tx.SetSize(uint64(len(tx.Serialize())))
	//uTXOSet.Blockchain.SignTransaction(&tx, wallet.PrivateKey)

	fmt.Printf("===after build transaction %x \n", tx.ID)

	return &tx
}
 */
