package boltqueue

import (
	"encoding/binary"
	"errors"
	"fmt"
	"bytes"
	"log"

	"github.com/boltdb/bolt"
)

// TODO: Interfacification of messages

var foundItem = errors.New("item found")

// aKey singleton for assigning keys to messages
var aKey = new(atomicKey)

// PQueue is a priority queue backed by a Bolt database on disk
type PQueue struct {
	conn *bolt.DB
}

// NewPQueue loads or creates a new PQueue with the given filename
func NewPQueue(filename string) (*PQueue, error) {
	db, err := bolt.Open(filename, 0600, nil)
	if err != nil {
		return nil, err
	}
	return &PQueue{db}, nil
}

func (b *PQueue) enqueueMessage(priority int, key []byte, message *Message) error {
	if priority < 0 || priority > 255 {
		return fmt.Errorf("Invalid priority %d on Enqueue", priority)
	}
	p := make([]byte, 1)
	p[0] = byte(uint8(priority))
	return b.conn.Update(func(tx *bolt.Tx) error {
		// Get bucket for this priority level
		pb, err := tx.CreateBucketIfNotExists(p)
		if err != nil {
			return err
		}
		err = pb.Put(key, message.value)
		if err != nil {
			return err
		}
		return nil
	})
}

// Enqueue adds a message to the queue
func (b *PQueue) Enqueue(priority int, message *Message) error {
	k := make([]byte, 8)
	binary.BigEndian.PutUint64(k, aKey.Get())
	return b.enqueueMessage(priority, k, message)
}

// Requeue adds a message back into the queue, keeping its precedence.
// If added at the same priority, it should be among the first to dequeue.
// If added at a different priority, it will dequeue before newer messages
// of that priority.
func (b *PQueue) Requeue(priority int, message *Message) error {
	if message.key == nil {
		return fmt.Errorf("Cannot requeue new message")
	}
	return b.enqueueMessage(priority, message.key, message)
}

// Dequeue removes the oldest, highest priority message from the queue and
// returns it
func (b *PQueue) Dequeue() (*Message, error) {
	var m *Message
	err := b.conn.Update(func(tx *bolt.Tx) error {
		err := tx.ForEach(func(bname []byte, bucket *bolt.Bucket) error {
			if bucket.Stats().KeyN == 0 { //empty bucket
				return nil
			}
			cur := bucket.Cursor()
			k, v := cur.First() //Should not be empty by definition
			priority, _ := binary.Uvarint(bname)
			m = &Message{priority: int(priority), key: cloneBytes(k), value: cloneBytes(v)}

			// Remove message
			if err := cur.Delete(); err != nil {
				return err
			}
			return foundItem //to stop the iteration
		})
		if err != nil && err != foundItem {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return m, nil
}

// Size returns the number of entries of a given priority from 1 to 5
func (b *PQueue) Size(priority int) (int, error) {
	if priority < 0 || priority > 255 {
		return 0, fmt.Errorf("Invalid priority %d for Size()", priority)
	}
	tx, err := b.conn.Begin(false)
	if err != nil {
		return 0, err
	}
	bucket := tx.Bucket([]byte{byte(uint8(priority))})
	if bucket == nil {
		return 0, nil
	}
	count := bucket.Stats().KeyN
	tx.Rollback()
	return count, nil
}

// Close closes the queue and releases all resources
func (b *PQueue) Close() error {
	err := b.conn.Close()
	if err != nil {
		return err
	}
	return nil
}

// taken from boltDB. Avoids corruption when re-queueing
func cloneBytes(v []byte) []byte {
	var clone = make([]byte, len(v))
	copy(clone, v)
	return clone
}

func (b *PQueue)IsExist(priority int, value []byte)bool{
	//var m *Message
	var result bool = false
	err := b.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte{byte(uint8(priority))})
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			//m = &Message{priority: int(priority), key: cloneBytes(k), value: cloneBytes(v)}
			if(bytes.Equal(v,value)){
				result = true
				break
			}
		}
		/*txIdBytes := b.Get(key)
		if(txIdBytes != nil){
			result = true
		}*/

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return result
}


func (b *PQueue)IsKeyExist(priority int, key []byte)bool{
	var result bool = false
	err := b.conn.Update(func(tx *bolt.Tx) error {
		bu,err := tx.CreateBucketIfNotExists([]byte{byte(uint8(priority))})
		if err != nil {
			return err
		}
		txIdBytes := bu.Get(key)
		if(txIdBytes != nil){
			result = true
		}

		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return result
}

func (b *PQueue)GetMsgBykey(priority int, txId []byte)*Message{
	var m *Message = nil
	err := b.conn.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte{byte(uint8(priority))})
		if err != nil {
			return err
		}
		//b := tx.Bucket([]byte{byte(uint8(priority))})
		txBytes := b.Get(txId)
		m = &Message{priority: int(priority), key: cloneBytes(txId), value: cloneBytes(txBytes)}

		//fmt.Printf("txBytes: ", txBytes)
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return m
}

func (b *PQueue)GetMsgEqual(priority int, value []byte)*Message{
	var m *Message = nil
	err := b.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte{byte(uint8(priority))})
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			m = &Message{priority: int(priority), key: cloneBytes(k), value: cloneBytes(v)}
			value = value
			mvalue := m.value
			if(bytes.Equal(mvalue,value)){
				break
			}
		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return m
}



func (b *PQueue)SetMsg(priority int, txId []byte,value []byte) error{
	return b.conn.Update(func(tx *bolt.Tx) error {
		//bu := tx.Bucket([]byte{byte(uint8(priority))})
		bn := []byte{byte(uint8(priority))}
		bu,err := tx.CreateBucketIfNotExists(bn)
		if err != nil {
			return err
		}
		return bu.Put(txId, value)
	})
}


func (b *PQueue)DeleteMsg(priority int, txId []byte)error{
	return b.conn.Update(func(tx *bolt.Tx) error {
		//bu := tx.Bucket([]byte{byte(uint8(priority))})
		bn := []byte{byte(uint8(priority))}
		bu,err := tx.CreateBucketIfNotExists(bn)
		if err != nil {
			return err
		}
		bu.Delete(txId)
		return nil
	})
}

func (b *PQueue) Put(priority int,key []byte ,message Message)error{
	p := make([]byte, 1)
	p[0] = byte(uint8(priority))
	return b.conn.Update(func(tx *bolt.Tx) error {
		// Get bucket for this priority level
		pb, err := tx.CreateBucketIfNotExists(p)
		if err != nil {
			return err
		}
		err1 := pb.Put(key, message.value)
		if err1 != nil {
			return err1
		}
		return nil
	})
}


func (b *PQueue) Get(priority int,key []byte)*Message{
	p := make([]byte, 1)
	p[0] = byte(uint8(priority))
	var msg *Message
	err := b.conn.Update(func(tx *bolt.Tx) error {
		// Get bucket for this priority level
		pb, err := tx.CreateBucketIfNotExists(p)
		if err != nil {
			return err
		}

		m := pb.Get(key)
		msg = &Message{priority: int(priority), key: cloneBytes(key), value: cloneBytes(m)}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return msg
}


func (b *PQueue)GetAll(priority int)[]*Message{
	var mv = []*Message{}
	err := b.conn.View(func(tx *bolt.Tx) error {
		b := tx.Bucket([]byte{byte(uint8(priority))})
		c := b.Cursor()

		for k, v := c.First(); k != nil; k, v = c.Next() {
			msg := &Message{priority: int(priority), key: cloneBytes(k), value: cloneBytes(v)}
			mv = append(mv,msg)

		}
		return nil
	})
	if err != nil {
		log.Panic(err)
	}
	return mv
}
