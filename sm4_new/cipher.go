/*
 * Package sm4 implements the Chinese SM4 Digest Algorithm,
 * according to "go/src/crypto/aes"
 * author: weizhang <d5c5ceb0@gmail.com>
 * 2017.02.24
 */

package sm4

import (
	"crypto/cipher"
	"strconv"
	"fmt"
	"encoding/pem"
	"os"
	"crypto/x509"
	"errors"
	"crypto/rand"
)

// The SM4 block size in bytes.
const BlockSize = 16

type KeySizeError int

func (k KeySizeError) Error() string {
	return "sm4: invalid key size " + strconv.Itoa(int(k))
}

// sm4Cipher is an instance of SM4 encryption.
type sm4Cipher struct {
	subkeys [32]uint32
}

// NewCipher creates and returns a new cipher.Block.
func NewCipher(key []byte) (cipher.Block, error) {
	fmt.Println("--------------welcome crypto sm4 NewCipher------------")
	if len(key) != 16 {
		return nil, KeySizeError(len(key))
	}

	c := new(sm4Cipher)
	c.generateSubkeys(key)
	return c, nil
}

func (c *sm4Cipher) BlockSize() int {
	fmt.Println("--------------welcome crypto sm4 BlockSize------------")
	return BlockSize
	}

func (c *sm4Cipher) Encrypt(dst, src []byte) {
	fmt.Println("--------------welcome crypto sm4 Encrypt------------")
	encryptBlock(c.subkeys[:], dst, src)
	}

func (c *sm4Cipher) Decrypt(dst, src []byte) {
	fmt.Println("--------------welcome crypto sm4 Decrypt------------")
	decryptBlock(c.subkeys[:], dst, src)
	}

	////////////////////
type SM4Key []byte

func WriteKeytoMem(key SM4Key, pwd []byte) ([]byte, error) {
	if pwd != nil {
		block, err := x509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, x509.PEMCipherAES256)
		if err != nil {
			return nil, err
		}
		return pem.EncodeToMemory(block), nil
	} else {
		block := &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
		return pem.EncodeToMemory(block), nil
	}
}

func WriteKeyToPem(FileName string, key SM4Key, pwd []byte) (bool, error) {
	var block *pem.Block

	if pwd != nil {
		var err error
		block, err = x509.EncryptPEMBlock(rand.Reader,
			"SM4 ENCRYPTED KEY", key, pwd, x509.PEMCipherAES256)
		if err != nil {
			return false, err
		}
	} else {
		block = &pem.Block{
			Type:  "SM4 KEY",
			Bytes: key,
		}
	}
	file, err := os.Create(FileName)
	if err != nil {
		return false, err
	}
	defer file.Close()
	err = pem.Encode(file, block)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func ReadKeyFromMem(data []byte, pwd []byte) (SM4Key, error) {
	block, _ := pem.Decode(data)
	if x509.IsEncryptedPEMBlock(block) {
		if block.Type != "SM4 ENCRYPTED KEY" {
			return nil, errors.New("SM4: unknown type")
		}
		if pwd == nil {
			return nil, errors.New("SM4: need passwd")
		}
		data, err := x509.DecryptPEMBlock(block, pwd)
		if err != nil {
			return nil, err
		}
		return data, nil
	}
	if block.Type != "SM4 KEY" {
		return nil, errors.New("SM4: unknown type")
	}
	return block.Bytes, nil
}
