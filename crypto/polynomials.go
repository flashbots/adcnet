package crypto

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
)

// Not very optimal, but does not do excessive allocations
func NevilleInterpolation(xs []*big.Int, ys []*big.Int, x *big.Int) *big.Int {
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
	
	return bigOne.Div(ps[0].Num(), ps[0].Denom())
}

func SharedSecretsGenerator(sharedSecrets []SharedKey, round *big.Int, fieldOrder *big.Int) *big.Int {
	el := new(big.Int)
	secretElementGenerator := new(big.Int).Set(prfSeed)
	for _, sse := range sharedSecrets {
		// Probably insecure
		el.SetBytes(sse)
		el.Add(el, round)
		el.Mul(el, prfSeed)
		el.Mod(el, fieldOrder)
		secretElementGenerator.Add(secretElementGenerator, el)
		secretElementGenerator.Mod(secretElementGenerator, fieldOrder)
	}
	return secretElementGenerator
}

func DeriveBlindingVector(sharedSecrets []SharedKey, round uint32, nEls int32, fieldOrder *big.Int) []*big.Int {
	buf := make([]big.Int, nEls)
	res := make([]*big.Int, nEls)
	for i := range res {
		res[i] = &buf[i]
	}

	bigRound := big.NewInt(int64(round))

	secretElementGenerator := SharedSecretsGenerator(sharedSecrets, bigRound, fieldOrder)
	// Note: we can chunk and parallelize. Be careful with the generator though.
	DeriveBlindingVectorInplace(res, secretElementGenerator, bigRound, 0, len(res), fieldOrder)
	return res
}

func DeriveBlindingVectorInplace(res []*big.Int, secretElementGenerator *big.Int, round *big.Int, start int, end int, fieldOrder *big.Int) {
	nonceBuf := make([]byte, 8)
	binary.BigEndian.PutUint32(nonceBuf, uint32(round.Int64()))
	nonce := new(big.Int)
	el := new(big.Int).Exp(secretElementGenerator, big.NewInt(int64(start)), fieldOrder)

	for i := start; i < end; i++ {
		binary.BigEndian.PutUint32(nonceBuf[4:], uint32(i)) 
		nonce.SetBytes(nonceBuf)
		res[i].Mul(res[i], nonce.Mod(nonce, nonce.Mul(nonce, prfSeed)))
		res[i].Mod(res[i], fieldOrder)
		el.Mul(el, secretElementGenerator)
		el.Mod(el, fieldOrder)
	}
}

// RandomPolynomialEvals generates a random polynomial of given degree that evaluates
// to evalAtZero at x=0, and returns its evaluations at the given x values
func RandomPolynomialEvals(deg int, xs []*big.Int, evalAtZero *big.Int) []*big.Int {
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

