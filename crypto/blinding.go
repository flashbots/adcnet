package crypto

import (
	"crypto/aes"
	"crypto/sha3"
	"encoding/binary"
	"math/big"
	"math/bits"
)

// DeriveBlindingVector generates field element blinding factors from shared secrets.
// Used for auction IBLT blinding where field arithmetic is required.
func DeriveBlindingVector(sharedSecrets []SharedKey, round uint32, nEls int32, fieldOrder *big.Int) []*big.Int {
	bytesPerElement := (fieldOrder.BitLen() + 7) / 8
	bytesTotal := int(nEls) * bytesPerElement

	srcBytesBuf := make([]byte, bytesTotal)
	dstBytesBuf := make([]byte, bytesTotal)

	res := make([]*big.Int, nEls)
	for i := range res {
		res[i] = new(big.Int)
	}

	roundKeyBuf := make([]byte, 4+len(sharedSecrets[0]))
	binary.BigEndian.PutUint32(roundKeyBuf[:4], round)

	workingEl := big.NewInt(0)
	words := make([]big.Word, bytesPerElement*8/bits.UintSize)

	for _, sharedSecret := range sharedSecrets {
		copy(roundKeyBuf[4:], sharedSecret)
		roundSharedKey := sha3.Sum256(roundKeyBuf)

		block, err := aes.NewCipher(roundSharedKey[:16])
		if err != nil {
			panic(err.Error())
		}

		block.Encrypt(dstBytesBuf, srcBytesBuf)

		for i := 0; i < int(nEls); i++ {
			for word := 0; word < len(words); word++ {
				words[word] = big.Word(binary.LittleEndian.Uint64(dstBytesBuf[i*bytesPerElement+word*bits.UintSize/8 : i*bytesPerElement+(word+1)*bits.UintSize/8]))
			}

			workingEl.SetBits(words)
			FieldAddInplace(res[i], workingEl, fieldOrder)
		}
	}

	return res
}

// DeriveXorBlindingVector generates XOR blinding bytes from shared secrets.
// Used for message vector blinding where XOR-based privacy is sufficient.
func DeriveXorBlindingVector(sharedSecrets []SharedKey, round uint32, nBytes int) []byte {
	if nBytes == 0 {
		return []byte{}
	}

	res := make([]byte, nBytes)
	roundKeyBuf := make([]byte, 4+len(sharedSecrets[0]))
	binary.BigEndian.PutUint32(roundKeyBuf[:4], round)

	for _, sharedSecret := range sharedSecrets {
		copy(roundKeyBuf[4:], sharedSecret)
		roundSharedKey := sha3.Sum256(roundKeyBuf)

		block, err := aes.NewCipher(roundSharedKey[:16])
		if err != nil {
			panic(err.Error())
		}

		// Encrypt in CTR mode or use each block index as input
		var counter [aes.BlockSize]byte
		var cipherBlock [aes.BlockSize]byte
		for i := 0; i < nBytes; i += aes.BlockSize {
			binary.BigEndian.PutUint64(counter[8:], uint64(i/aes.BlockSize))
			block.Encrypt(cipherBlock[:], counter[:])
			end := min(i+aes.BlockSize, nBytes)
			XorInplace(res[i:end], cipherBlock[:end-i])
		}
	}

	return res
}
