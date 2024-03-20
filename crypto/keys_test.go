package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGeneratePrivateKey(t *testing.T) {
	privKey := GeneratePrivateKey()
	assert.Equal(t, len(privKey.Bytes()), privKeyLen)

	pubKey := privKey.Public()
	assert.Equal(t, len(pubKey.Bytes()), pubKeyLen)
}

func TestPrivateKeySign(t *testing.T) {
	//generate private key
	privKey := GeneratePrivateKey() //generate private key
	pubKey := privKey.Public()      //generate public key
	msg := []byte("foo bar baz")    //create a message

	sig := privKey.Sign(msg)                //sign the message
	assert.True(t, sig.Verify(pubKey, msg)) //verify the message signed
}
