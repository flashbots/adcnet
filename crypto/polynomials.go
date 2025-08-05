package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"math/big"
	"math/bits"
)

// xses are within (0, ~10]
func LagrangeCoeffs(xs []*big.Int, field *big.Int) []*big.Int {
	// Optimize! right now O(n^2), can be O(n)
	// prefixMul := make([]big.Int, len(xs)) // multiplication of all prefixes (prefixMul[i] = MUL j=0 until j=i xs[i] - x[j]
	// postfixMul := make([]big.Int, len(xs))

	res := make([]*big.Int, len(xs))

	for i := 0; i < len(xs); i++ {
		lhs := big.NewInt(1)
		rhs := big.NewInt(1)
		for j := 0; j < len(xs); j++ {
			if i == j {
				continue
			}

			lhs.Mul(lhs, xs[j])
			lhs.Neg(lhs)

			el := new(big.Int).Set(xs[i])
			el.Sub(el, xs[j])
			el.ModInverse(el, field)
			rhs.Mul(rhs, el)
		}

		res[i] = new(big.Int).Set(lhs)
		res[i].Mul(res[i], rhs)
		res[i].Mod(res[i], field)
	}

	return res
}

// Reuse the coefficients!
// This is plenty fast compared to (un)blinding vectors.
func LagrangeInterpolation(xs []*big.Int, ys []*big.Int, lCoeffs []*big.Int, field *big.Int) *big.Int {
	if lCoeffs == nil {
		lCoeffs = LagrangeCoeffs(xs, field)
	}

	res := new(big.Int)
	el := new(big.Int)
	for i := 0; i < len(xs); i++ {
		el.Set(ys[i])
		el.Mul(el, lCoeffs[i])
		res.Add(res, el)
		res.Mod(res, field)
		for res.Sign() < 0 {
			res.Add(res, field)
		}
	}
	return res
}

// RandomPolynomialEvals generates a random polynomial of given degree that evaluates
// to evalAtZero at x=0, and returns its evaluations at the given x values.
func RandomPolynomialEvals(deg int, xs []*big.Int, evalAtZero *big.Int, maxValue *big.Int) []*big.Int {
	if len(xs) == 0 {
		return nil
	}

	ys := make([]*big.Int, len(xs))
	as := make([]*big.Int, deg+1)

	// Set a[0] = evalAtZero to ensure f(0) = evalAtZero
	as[0] = new(big.Int).Set(evalAtZero)

	// Generate random coefficients for a[1] through a[deg]
	for i := 1; i <= deg; i++ {
		as[i], _ = rand.Int(rand.Reader, maxValue)
	}

	// Evaluate polynomial at each x
	for i := range xs {
		ys[i] = new(big.Int).SetInt64(0)
		xPower := big.NewInt(1)

		// Can be optimized a bit
		// Compute a[0] + a[1]*x + a[2]*x^2 + ... + a[deg]*x^deg
		for j := 0; j <= deg; j++ {
			term := new(big.Int).Mul(as[j], xPower)
			ys[i].Add(ys[i], term)
			ys[i].Mod(ys[i], maxValue)
			xPower.Mul(xPower, xs[i]) // Assuming this stays in the field
		}
	}

	return ys
}

type BlindingVectorStuff struct {
	srcBytesBuf []byte
	dstBytesBuf []byte
	res         []*big.Int
}

// DeriveBlindingVector deterministically generates a vector of blinding elements from shared secrets for the given round.
func DeriveBlindingVector(sharedSecrets []SharedKey, round uint32, nEls int32, fieldOrder *big.Int) []*big.Int {
	bytesPerElement := (fieldOrder.BitLen() + 7) / 8
	bytesTotal := int(nEls) * bytesPerElement

	srcBytesBuf := make([]byte, bytesTotal)
	dstBytesBuf := make([]byte, bytesTotal)

	res := make([]*big.Int, nEls)

	for i := range res {
		res[i] = new(big.Int)
	}

	// Assumes all shared secrets are the same length
	roundKeyBuf := make([]byte, 4+len(sharedSecrets[0]))
	binary.BigEndian.PutUint32(roundKeyBuf[:4], uint32(round))

	workingEl := big.NewInt(0)

	words := make([]big.Word, bytesPerElement*8/bits.UintSize)

	for _, sharedSecret := range sharedSecrets {
		copy(roundKeyBuf[4:], sharedSecret)
		roundSharedKey := sha3.Sum256(roundKeyBuf)

		// 128 bit AES
		block, err := aes.NewCipher(roundSharedKey[:16])
		if err != nil {
			panic(err.Error())
		}

		block.Encrypt(dstBytesBuf, srcBytesBuf)

		for i := 0; i < int(nEls); i++ {
			// Note: setting via bits (words) is much faster than via bytes
			for word := 0; word < len(words); word++ {
				words[word] = big.Word(binary.LittleEndian.Uint64(dstBytesBuf[i*bytesPerElement+word*bits.UintSize/8 : i*bytesPerElement+(word+1)*bits.UintSize/8]))
			}

			workingEl.SetBits(words)
			FieldAddInplace(res[i], workingEl, fieldOrder)
		}
	}

	return res
}
