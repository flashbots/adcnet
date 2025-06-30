package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"math/big"
)

var fieldOrder *big.Int
var MessageFieldOrder *big.Int
var AuctionFieldOrder *big.Int
var prfSeed *big.Int

func init() {
	// 513 bits so that we can encode 512 bits of data in a chunk
	fieldOrder, _ = big.NewInt(0).SetString("23551861483160902848625974283278945001376208178765538238759867299042020937974421928051251754596306387970642948144090145836318438166833376091610669188604919", 10)
	MessageFieldOrder = fieldOrder
	// 127 bits
	AuctionFieldOrder, _ = big.NewInt(0).SetString("141504642401084501264176625615135659301", 10)
	prfSeed, _ = big.NewInt(0).SetString("21384347777672109934322149984740494809390049493978212797410708129763158788480720729944469031881574875043683705480707297038846484696174296250022771335208983", 10)
}

func VectorProductInplace(ls []*big.Int, rs []*big.Int, op func(*big.Int, *big.Int) *big.Int)  {
	for i := range ls {
		ls[i] = op(ls[i], rs[i])
	}
}

// TODO: bench & optimize
func FieldAdd(l *big.Int, r *big.Int, fieldOrder *big.Int) *big.Int {
	sum := big.NewInt(0).Add(l, r)
	for sum.Cmp(fieldOrder) > 1 {
		sum = sum.Sub(sum, fieldOrder)
	}
	for sum.Sign() < 0 {
		sum = sum.Add(sum, fieldOrder)
	}
	return sum
}

// TODO: bench & optimize
func FieldSub(l *big.Int, r *big.Int, fieldOrder *big.Int) *big.Int {
	sub := big.NewInt(0).Sub(l, r)
	sub = sub.Add(sub, fieldOrder)
	for sub.Cmp(fieldOrder) > 1 {
		sub = sub.Sub(sub, fieldOrder)
	}
	for sub.Sign() < 0 {
		sub = sub.Add(sub, fieldOrder)
	}
	return sub
}

// all K_T (or i-th K_T local share)
func GenerateSharedSecrets(n, t int) []*big.Int {
	// Generate a random field element for J: each order-t subset of order-n set (|J| = n choose t)
	// Each of those should be shared with all servers *NOT* in T
	// Alternative wording: shares should be distributed among n-t max subsets
	order_j := big.NewInt(0).Binomial(int64(n), int64(t)).Uint64()
	k_ts := make([]*big.Int, order_j)
	for i := uint64(0); i < order_j; i++ {
		rs, err := rand.Int(rand.Reader, big.NewInt(0).Exp(big.NewInt(2), big.NewInt(512), fieldOrder))
		if err != nil {
			panic(err.Error())
		}
		k_ts[i] = rs
	}

	return k_ts
}

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

func EvaluateF(sizeT int, K_Ts []*big.Int, round *big.Int) *big.Int {
	xs := make([]*big.Int, sizeT+1)
	ys := make([]*big.Int, sizeT+1)
	for i := range xs {
		xs[i] = big.NewInt(int64(i))
		ys[i] = big.NewInt(0)
	}

	sum := big.NewInt(0)
	for t := range K_Ts {
		ys[0].Set(K_Ts[t])
		sum = sum.Add(sum, NevilleInterpolation(xs, ys, round))
	}

	return sum
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
	if len(res) < 1000 {
		DeriveBlindingVectorInplace(res, secretElementGenerator, bigRound, 0, len(res), fieldOrder)
	} else {
		// crude chunking
		chunkSize := 1000
		nChunks := len(res)/chunkSize
		doneCh := make(chan struct{}, nChunks)
		for i := 0; i < len(res); i+=chunkSize {
		go func(i int) {
			DeriveBlindingVectorInplace(res, secretElementGenerator, bigRound, i, min(i+chunkSize, len(res)), fieldOrder)
			doneCh <- struct{}{}
		}(i)
		}
		for i := 0; i < nChunks; i++ {
			<-doneCh
		}
	}
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
		el.Add(el, nonce)
		el.Mul(el, secretElementGenerator)
		el.Mod(el, fieldOrder)
	}
}

func DeriveElement(key SharedKey, nonce *big.Int, fieldOrder *big.Int) *big.Int {
	el := new(big.Int)
	shasum := sha256.Sum256(append([]byte("element-derivation"), key.Bytes()...))
	el.Mul(el.SetBytes(shasum[:]), nonce)
	return el.Mod(el, fieldOrder)
}

// Generate K_T for all T in J s.t. T is all order-t subsets of all servers
// All servers NOT in T receive K_T (initial bootstrap - exchange secrets pairwise and xor or sth)
// |J| local secrets
// f_i s.t. f_i(x) = 0 for all x != 0, and f_i(0) = K_T
// K is the reconstructed t+1-of-n of K_T (xor or similar)
// clients encrypt to K (field addition)
// the above is for all slots for all rounds (each slot gets its own K_Ts and therefore K)


// Alternative: single zero-secret-sharing & generate field elements from that (or even just a shared key and do a PRF?)
// This is not supposed to work but I still don't quite get why. The encryption pads are not polynomials any more, but every client
// can generate them just fine, and t-of-n servers can as well.
// Note that we have two points we can communicate: schedule publish message (servers can send messages between each other, and 
// all clients can see the result), and the client publish message where every clinet can include something.
// Something as simple as shamirs secret sharing could work maybe?

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

