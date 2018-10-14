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
)

const subsidy = 50
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

func (tx Transaction)Nonce()uint64{
	return tx.Data.AccountNonce
}

func (tx Transaction)To()*common.Address{
	return tx.Data.Recipient
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
	return len(tx.Vin) == 1 && len(tx.Vin[0].Txid) == 0 && tx.Vin[0].Vout.Int64() == -1
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
func (tx *Transaction) Hash() []byte {
	var hash [32]byte

	txCopy := *tx
	txCopy.ID = []byte{}

	hash = sha256.Sum256(txCopy.Serialize())

	return hash[:]
}

// Hash returns the hash of the Transaction
func (tx *Transaction) CommonHash() common.Hash {
	var hash common.Hash
	hash = common.BytesToHash(tx.Hash())
	return hash
}


// Hash returns the hash of the Transaction
func (tx *Transaction) RLPHash() []byte {
	var hash [32]byte

	txCopy := *tx
	//txCopy.ID = []byte{}
	txCopy.ID = nil
	//txCopy.data = txdata{}
	//size := tx.size.Load().(common.StorageSize)
	//tx.size.Store(big.NewFloat(float64(size)))

	txBytes,err := rlp.EncodeToBytes(txCopy)
	if(err!=nil){
		log.Panic(err)
	}
	hash = sha256.Sum256(txBytes)

	return hash[:]
}

// Hash returns the hash of the Transaction
func (tx *Transaction) HashCommon() common.Hash {
	var hash []byte
	hash = tx.Hash()

	return common.BytesToHash(hash)
}

// Sign signs each input of a Transaction
func (tx *Transaction) Sign(privKey ecdsa.PrivateKey, prevTXs map[string]Transaction) {
	if tx.IsCoinbase() {
		return
	}

	for _, vin := range tx.Vin {
		if prevTXs[hex.EncodeToString(vin.Txid)].ID == nil {
			log.Panic("ERROR: Previous transaction is not correct")
		}
	}

	txCopy := tx.TrimmedCopy()

	for inID, vin := range txCopy.Vin {
		prevTx := prevTXs[hex.EncodeToString(vin.Txid)]
		txCopy.Vin[inID].Signature = nil
		txCopy.Vin[inID].PubKey = prevTx.Vout[vin.Vout.Int64()].PubKeyHash

		dataToSign := fmt.Sprintf("%x\n", txCopy.RLPHash())

		r, s, err := ecdsa.Sign(rand.Reader, &privKey, []byte(dataToSign))
		if err != nil {
			log.Panic(err)
		}
		signature := append(r.Bytes(), s.Bytes()...)

		tx.Vin[inID].Signature = signature
		txCopy.Vin[inID].PubKey = nil
	}

}


// AsMessage returns the transaction as a core.Message.
//
// AsMessage requires a signer to derive the sender.
//
// XXX Rename message to something less arbitrary?
func (tx *Transaction) AsMessage(s Signer) (*Transaction, error) {

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
	    lines = append(lines, fmt.Sprintf("       Timestamp: %d", tx.Timestamp))

	return strings.Join(lines, "\n")
}

// TrimmedCopy creates a trimmed copy of Transaction to be used in signing
func (tx *Transaction) TrimmedCopy() Transaction {
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
	txCopy := Transaction{tx.ID, inputs, outputs,
	tx.Timestamp,tx.size,tx.Data,froma}
	tx.SetSize(uint64(len(tx.Serialize())))
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
			log.Panic("ERROR: Previous transaction is not correct")
		}
	}

	txCopy := tx.TrimmedCopy()
	curve := crypto.S256()

	for inID, vin := range tx.Vin {
		prevTx := prevTXs[hex.EncodeToString(vin.Txid)]
		txCopy.Vin[inID].Signature = nil
		txCopy.Vin[inID].PubKey = prevTx.Vout[vin.Vout.Int64()].PubKeyHash

		r := big.Int{}
		s := big.Int{}
		sigLen := len(vin.Signature)
		r.SetBytes(vin.Signature[:(sigLen / 2)])
		s.SetBytes(vin.Signature[(sigLen / 2):])

		x := big.Int{}
		y := big.Int{}
		keyLen := len(vin.PubKey)
		x.SetBytes(vin.PubKey[:(keyLen / 2)])
		y.SetBytes(vin.PubKey[(keyLen / 2):])

		dataToVerify := fmt.Sprintf("%x\n", txCopy.RLPHash())

		rawPubKey := ecdsa.PublicKey{curve, &x, &y}
		if ecdsa.Verify(&rawPubKey, []byte(dataToVerify), &r, &s) == false {
			return false
		}
		txCopy.Vin[inID].PubKey = nil
	}

	return true
}

// NewCoinbaseTX creates a new coinbase transaction
func NewCoinbaseTX(to, data,nodeID string) *Transaction {
	if data == "" {
		randData := make([]byte, subsidy)
		_, err := rand.Read(randData)
		if err != nil {
			log.Panic(err)
		}

		data = fmt.Sprintf("%x", randData)
	}

	txin := TXInput{[]byte{}, big.NewInt(-1), nil, []byte(data)}
	txout := NewTXOutput(big.NewInt(subsidy), to)

	//prepare tx data
	var toa = Base58ToCommonAddress([]byte(to))
	//coinbase tx no from address
	address := toa.String()
	var wt = new(WalletTransactions)
	wt.InitDB(nodeID,address)
	nonce,err := wt.GetTransactionNonce(address)
	wt.DB.Close()
	if(err!=nil){
		log.Panic(err)
	}
	d := txdata{
		AccountNonce: nonce,
		Recipient:    &toa,
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
func NewUTXOTransaction(wallet *Wallet, to string, amount *big.Int,data []byte, UTXOSet *UTXOSet,nodeID string) *Transaction {
	pubKeyHash := HashPubKey(wallet.PublicKey)
	var inputs []TXInput
	var outputs []TXOutput

	acc, validOutputs,extraOutputs := UTXOSet.FindSpendableOutputs(pubKeyHash, amount,false,nil,nil)

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
			input := TXInput{txID, big.NewInt(int64(out)), nil, wallet.PublicKey}
			inputs = append(inputs, input)
		}
	}

	// Build a list of outputs
	from := fmt.Sprintf("%s", wallet.GetAddress())
	outputs = append(outputs, *NewTXOutput(amount, to))
	if acc > amount.Uint64() {
		outputs = append(outputs, *NewTXOutput(big.NewInt(int64(acc-amount.Uint64())), from)) // a change
	}
	for _,txouts := range extraOutputs{
		outputs = append(outputs,txouts...)
	}

	//prepare tx data
	address := common.BytesToAddress(pubKeyHash).String()
	var wt = new(WalletTransactions)
	wt.InitDB(nodeID,address)
	nonce,err := wt.GetTransactionNonce(address)
	wt.DB.Close()
	if(err!=nil){
		log.Panic(err)
	}
	var toa = Base58ToCommonAddress([]byte(to))
	d := txdata{
		AccountNonce: nonce,
		Recipient:    &toa,
		Payload:      data,
		Amount:       new(big.Int),
		//GasLimit:     gasLimit,
		//Price:        new(big.Int),
		V:            new(big.Int),
		R:            new(big.Int),
		S:            new(big.Int),
	}
	if amount.Uint64() != 0 {
		d.Amount.Set(amount)
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
	if dbExists(dbFile) {
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

func VerifyTx(tx Transaction,bc *Blockchain)bool{
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
	if(tx.IsCoinbase()==false&&!UTXOSet.IsUTXOAmountValid(&tx,nil)){
		//log.Panic("ERROR: Invalid transaction:amount")
		valid2 = false
	}
	valid3 = VeryfyFromToAddress(&tx)
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
func NewTransaction(wallet Wallet,nonce uint64,to *common.Address,amount *big.Int,input []byte,nodeID string)*Transaction{
	var bc = NewBlockchain(nodeID)
	uTXOSet := UTXOSet{bc}

	pubKeyHash := HashPubKey(wallet.PublicKey)
	var inputs []TXInput
	var outputs []TXOutput

	acc, validOutputs,extraOutputs := uTXOSet.FindSpendableOutputs(pubKeyHash, amount,false,nil,nil)
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
			input := TXInput{txID, big.NewInt(int64(out)), nil, wallet.PublicKey}
			inputs = append(inputs, input)
		}
	}

	// Build a list of outputs
	from := fmt.Sprintf("%s", wallet.GetAddress())
	outputs = append(outputs, *NewTXOutput(amount, CommonAddressToBase58(to)))
	if acc > amount.Uint64() {
		outputs = append(outputs, *NewTXOutput(big.NewInt(int64(acc-amount.Uint64())), from)) // a change
	}
	for _,txouts := range extraOutputs{
		outputs = append(outputs,txouts...)
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
