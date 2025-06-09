package crypto

import (
	"crypto/rand"
	"math/big"
)

var fieldOrder *big.Int

func init() {
	// TODO: generate a safer prime
	fieldOrder, _ = big.NewInt(0).SetString("12851828943861996687544933131329664243648161964035225777803182764218598103230414747362157598163698323127827349923527614031893870136367647463777553788359217", 10)
}

func FieldAdd(l *big.Int, r *big.Int) *big.Int {
	sum := big.NewInt(0).Add(l, r)
	// Note: we can do a much faster mod with at most 2 subtractions here
	return sum.Mod(sum, fieldOrder)
}

func FieldSub(l *big.Int, r *big.Int) *big.Int {
	// Should this be ((l + fieldOrder) - r) % fieldOrder? l-r
	// Or maybe distinguish betwen l>r and r>l? Then it's clear what to do.
	sub := big.NewInt(0).Sub(l, r)
	// Note: we can do a much faster mod with at most 2 subtractions here
	sub = sub.Add(sub, fieldOrder)
	return sub.Mod(sub, fieldOrder)
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
	ps := make([]big.Rat, len(xs))

	// tmps
	ik := new(big.Rat)
	dm := new(big.Int)
	bigOne := big.NewInt(1)

	for k := range ys {
		for i := 0; i < len(ys)-k; i++ {
			if k == 0 {
				ps[i].SetFrac(ys[i], bigOne)
			} else {
				ik.SetFrac(x, bigOne)
				ik.Num().Sub(ik.Num(), xs[i+k])
				ik.Mul(ik, &ps[i])

				// ps[i] is no longer needed, reuse the memory
				ps[i].SetFrac(xs[i], bigOne)
				ps[i].Num().Sub(ps[i].Num(), x)
				ps[i].Mul(&ps[i], &ps[i+1])

				ps[i].Add(&ps[i], ik)

				ps[i].Denom().Mul(ps[i].Denom(), dm.Sub(xs[i], xs[i+k]))
			}
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
