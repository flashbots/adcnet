package crypto

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha3"
	"encoding/binary"
	"math/big"
)

// NevilleInterpolation performs polynomial interpolation using Neville's algorithm.
// Given points (xs[i], ys[i]), it computes the value of the interpolating polynomial at x.
// The result is computed modulo fieldOrder for finite field arithmetic.
func NevilleInterpolation(xs []*big.Int, ys []*big.Int, x *big.Int, fieldOrder *big.Int) *big.Int {
	// tmps
	ik := new(big.Rat)
	dm := new(big.Int)
	bigOne := big.NewInt(1)

	ps := make([]big.Rat, len(xs))
	for i := range ps {
		ps[i].SetFrac(ys[i], bigOne)
	}

	for k := 1; k < len(ys); k++ {
		for i := 0; i < len(ys)-k; i++ {
			ik.SetFrac(x, bigOne)
			ik.Num().Sub(ik.Num(), xs[i+k])
			ik.Mul(ik, &ps[i])

			// ps[i] is no longer needed, reuse the memory
			ps[i].SetFrac(xs[i], bigOne)
			ps[i].Num().Sub(ps[i].Num(), x)
			ps[i].Mul(&ps[i], &ps[i+1])

			ps[i].Add(&ps[i], ik)

			// Note: xs[i]-xs[i+k] sometimes is known (-k)
			ps[i].Denom().Mul(ps[i].Denom(), dm.Sub(xs[i], xs[i+k]))
		}
	}

	// Convert rational result to field element: (num * denom^-1) mod fieldOrder
	result := new(big.Int).Set(ps[0].Num())
	denomInv := new(big.Int).ModInverse(ps[0].Denom(), fieldOrder)
	if denomInv != nil {
		result.Mul(result, denomInv)
		result.Mod(result, fieldOrder)
	}
	return result
}

// DeriveBlindingVector deterministically generates a vector of blinding elements from shared secrets for the given round.
func DeriveBlindingVector(sharedSecrets []SharedKey, round uint32, nEls int32, fieldOrder *big.Int) []*big.Int {
	bytesPerElement := (fieldOrder.BitLen() + 7) / 8
	srcBytesBuf := make([]byte, int(nEls)*bytesPerElement)
	dstBytesBuf := make([]byte, int(nEls)*bytesPerElement)
	elBuf := make([]big.Int, nEls)
	res := make([]*big.Int, nEls)
	for i := range res {
		res[i] = &elBuf[i]
	}

	// Assumes all shared secrets are the same length
	roundKeyBuf := make([]byte, 4+len(sharedSecrets[0]))
	binary.BigEndian.PutUint32(roundKeyBuf[:4], uint32(round))

	workingEl := big.NewInt(0)

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
			workingEl.SetBytes(dstBytesBuf[i*bytesPerElement : (i+1)*bytesPerElement])
			FieldAddInplace(res[i], workingEl, fieldOrder)
		}
	}

	return res
}

// RandomPolynomialEvals generates a random polynomial of given degree that evaluates
// to evalAtZero at x=0, and returns its evaluations at the given x values.
func RandomPolynomialEvals(deg int, xs []*big.Int, evalAtZero *big.Int, fieldOrder *big.Int) []*big.Int {
	ys := make([]*big.Int, len(xs))
	as := make([]*big.Int, deg+1)

	// Set a[0] = evalAtZero to ensure f(0) = evalAtZero
	as[0] = new(big.Int).Set(evalAtZero)

	// Generate random coefficients for a[1] through a[deg]
	for i := 1; i <= deg; i++ {
		as[i], _ = rand.Int(rand.Reader, fieldOrder)
	}

	// Evaluate polynomial at each x
	for i := range xs {
		ys[i] = new(big.Int).SetInt64(0)
		xPower := big.NewInt(1)

		// Compute a[0] + a[1]*x + a[2]*x^2 + ... + a[deg]*x^deg
		for j := 0; j <= deg; j++ {
			term := new(big.Int).Mul(as[j], xPower)
			ys[i].Add(ys[i], term)
			xPower.Mul(xPower, xs[i])
		}

		// Apply modulo if needed
		ys[i].Mod(ys[i], fieldOrder)
	}

	return ys
}
