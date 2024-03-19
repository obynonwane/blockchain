package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
)

// declare constants
const (
	privKeyLen = 64
	pubKeyLen  = 32
	seedLen    = 32
)

type PrivateKey struct {
	key ed25519.PrivateKey
}

// generate private key
func GeneratePrivateKey() *PrivateKey {

	//make me a empty seed of byte of length of seedLen
	seed := make([]byte, seedLen)

	//read from io reader untill buffer is full i.e populates the empty byte of seed above while panic if error exist
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		panic(err)
	}

	//return the generated private key
	return &PrivateKey{
		key: ed25519.NewKeyFromSeed(seed),
	}
}

func (p *PrivateKey) Bytes() []byte {
	return p.key
}

func (p *PrivateKey) Sign(msg []byte) *Signature {
	return &Signature{
		value: ed25519.Sign(p.key, msg),
	}
}

func (p *PrivateKey) Public() *PublicKey {
	//make me a byte of length pubKeyLen
	b := make([]byte, pubKeyLen)

	//copy the bytes in p.key starting from index 32 into byte slice b
	copy(b, p.key[32:])

	//return the generated public key
	return &PublicKey{
		key: b,
	}
}

type PublicKey struct {
	key ed25519.PublicKey
}

// returns public key byte
func (p *PublicKey) Bytes() []byte {
	return p.key
}

// signature struct
type Signature struct {
	value []byte
}

// verify signature
func (s *Signature) Verify(pubKey *PublicKey, msg []byte) bool {
	return ed25519.Verify(pubKey.key, msg, s.value)
}
