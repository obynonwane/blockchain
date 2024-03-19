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
	Key ed25519.PrivateKey
}

func (p *PrivateKey) GeneratePrivateKey() *PrivateKey {

	//make me a empty seed of byte of length of seedLen
	seed := make([]byte, seedLen)

	//populate the empty byte of seed above while panic if error exist
	_, err := io.ReadFull(rand.Reader, seed)
	if err != nil {
		panic(err)
	}

	//return the generated private key
	return &PrivateKey{
		Key: ed25519.NewKeyFromSeed(seed),
	}
}

func (p *PrivateKey) Bytes() []byte {
	return p.Key
}

func (p *PrivateKey) Sign(msg []byte) []byte {
	return ed25519.Sign(p.Key, msg)
}

func (p *PublicKey) Public() *PublicKey {
	//make me a byte of length pubKeyLen
	b := make([]byte, pubKeyLen)

	//copy the bytes in p.key starting from index 32 into byte slice b
	copy(b, p.Key[32:])

	//return the generated public key
	return &PublicKey{
		Key: b,
	}
}

type PublicKey struct {
	Key ed25519.PublicKey
}
