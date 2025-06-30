package crypto

import (
	"fmt"
	"maps"
	"math/big"
	"crypto/rand"
	unsafe_rand "math/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/require"
)

type Server struct {
	Shares map[string]*big.Int
}

func TestInterpolation(t *testing.T) {
	// 7x^3 + 3x^2 - 12x + 7
	xs := []*big.Int{
		big.NewInt(-1),
		big.NewInt(0),
		big.NewInt(2),
		big.NewInt(5),
	}

	ys := []*big.Int{
		big.NewInt(15),
		big.NewInt(7),
		big.NewInt(51),
		big.NewInt(897),
	}

	res := NevilleInterpolation(xs, ys, big.NewInt(-2))
	require.Equal(t, res.Int64(), int64(-13))
}

func TestBigInterpolation(t *testing.T) {
	xs := make([]*big.Int, 4)
	ys := make([]*big.Int, 4)
	for i := range xs {
		xs[i] = big.NewInt(int64(i))
		ys[i] = big.NewInt(0)
	}

	// random point
	ys[0].SetString("3400971016232485726551449299057556896915868662226607376649412587336645327403735602289735985867921794946846307425314353924927376609169908691446758184083445", 10)

	res := NevilleInterpolation(xs, ys, big.NewInt(10))
	require.Equal(t, int64(7801733792841892764), res.Int64())
}

func TestThresholdSecretSharing(t *testing.T) {
	// 5 participants, 3-of-5
	rs := unsafe_rand.New(unsafe_rand.NewSource(0))

	servers := make([]Server, 5)

	// Share distribution: abusing the fact that 3-of-5 simply excludes all pairs
	for i := 0; i < len(servers); i++ {
		for j := 0; j < len(servers); j++ {
			if i == j {
				continue
			}

			// (i, j) is all pairs

			share := big.NewInt(0).Rand(rs, fieldOrder)
			for s := range servers {
				// exclude ith and jth servers (3 have the share, 2 do not)
				if s != i && s != j {
					if servers[s].Shares == nil {
						servers[s].Shares = make(map[string]*big.Int)
					}
					servers[s].Shares[fmt.Sprintf("%d%d", i, j)] = big.NewInt(0).Set(share)
				}
			}
		}
	}

	round := big.NewInt(10)

	// Make sure that the two triples contain all the same shares
	allShares0 := make(map[string]*big.Int)
	maps.Insert(allShares0, maps.All(servers[0].Shares))
	maps.Insert(allShares0, maps.All(servers[1].Shares))
	maps.Insert(allShares0, maps.All(servers[2].Shares))

	allShares1 := make(map[string]*big.Int)
	maps.Insert(allShares1, maps.All(servers[2].Shares))
	maps.Insert(allShares1, maps.All(servers[3].Shares))
	maps.Insert(allShares1, maps.All(servers[4].Shares))

	require.Zero(t, EvaluateF(2, slices.Collect(maps.Values(allShares0)), round).Cmp(EvaluateF(2, slices.Collect(maps.Values(allShares1)), round)))

	// Now the tricky bit: compose the shared secret from evaluations of specific servers
	// F(x) = sum (T from J) F_T(x)
	// Note that we can't just add all shares in blindly, we need to know which ones to exclude
	// Each server sends shares the recipient is missing, one by one (not the sum)

	// (0, 1, 2), with server 2 as the recipient
	F0 := big.NewInt(0)
	F0.Add(F0, EvaluateF(2, []*big.Int{servers[0].Shares["12"]}, round))
	F0.Add(F0, EvaluateF(2, []*big.Int{servers[0].Shares["23"]}, round))
	F0.Add(F0, EvaluateF(2, []*big.Int{servers[0].Shares["24"]}, round))
	// S0 does not add more shares, since S2 has them

	F0.Add(F0, EvaluateF(2, []*big.Int{servers[1].Shares["02"]}, round))
	// S1 sends the following, but they are not added in as they are already added by S0
	// F0.Add(F0, EvaluateF(2, []*big.Int{servers[1].Shares["23"]}, round))
	// F0.Add(F0, EvaluateF(2, []*big.Int{servers[1].Shares["24"]}, round))
	// S1 does not add more shares, since S2 has them

	// S2 received the sum of its missing shares from S0 and S1, and will add its own shares now
	// S2 knows it got its missing shares from S0 and S1
	F0.Add(F0, EvaluateF(2, []*big.Int{servers[2].Shares["01"]}, round))
	F0.Add(F0, EvaluateF(2, []*big.Int{servers[2].Shares["03"]}, round))
	F0.Add(F0, EvaluateF(2, []*big.Int{servers[2].Shares["04"]}, round))
	F0.Add(F0, EvaluateF(2, []*big.Int{servers[2].Shares["13"]}, round))
	F0.Add(F0, EvaluateF(2, []*big.Int{servers[2].Shares["14"]}, round))
	F0.Add(F0, EvaluateF(2, []*big.Int{servers[2].Shares["34"]}, round))

	// (2, 3, 4), with S4 as recipient
	F1 := big.NewInt(0)
	F1.Add(F1, EvaluateF(2, []*big.Int{servers[2].Shares["04"]}, round))
	F1.Add(F1, EvaluateF(2, []*big.Int{servers[2].Shares["14"]}, round))
	F1.Add(F1, EvaluateF(2, []*big.Int{servers[2].Shares["34"]}, round))

	F1.Add(F1, EvaluateF(2, []*big.Int{servers[3].Shares["24"]}, round))
	// Ignored by S4
	// F1.Add(F1, EvaluateF(2, []*big.Int{servers[3].Shares["04"]}, round))
	// F1.Add(F1, EvaluateF(2, []*big.Int{servers[3].Shares["14"]}, round))

	F1.Add(F1, EvaluateF(2, []*big.Int{servers[4].Shares["01"]}, round))
	F1.Add(F1, EvaluateF(2, []*big.Int{servers[4].Shares["02"]}, round))
	F1.Add(F1, EvaluateF(2, []*big.Int{servers[4].Shares["03"]}, round))
	F1.Add(F1, EvaluateF(2, []*big.Int{servers[4].Shares["12"]}, round))
	F1.Add(F1, EvaluateF(2, []*big.Int{servers[4].Shares["13"]}, round))
	F1.Add(F1, EvaluateF(2, []*big.Int{servers[4].Shares["23"]}, round))

	require.Zero(t, F0.Cmp(F1))
}

type Client struct {
	Shares map[string]*big.Int
}

func TestRandomPolynomial(t *testing.T) {
	ys := RandomPolynomialEvals(1, []*big.Int{big.NewInt(1), big.NewInt(2)}, big.NewInt(10))
	require.Zero(t, big.NewInt(10).Cmp(big.NewInt(0).Mod(NevilleInterpolation([]*big.Int{big.NewInt(1), big.NewInt(2)}, ys, big.NewInt(0)), fieldOrder)))
}

func TestServerStreams(t *testing.T) {
	// Setup:= 3 clients, 2 messages, 2-of-3 servers
	// Other than for blinding I'll simply ignore the third server
	rs := unsafe_rand.New(unsafe_rand.NewSource(0))

	clientsSharedSecrets := make([][]SharedKey, 3)
	serversSharedSecrets := make([][]SharedKey, 3)

	for i := 0; i < 3; i++ {
		clientsSharedSecrets[i] = make([]SharedKey, 3)
		serversSharedSecrets[i] = make([]SharedKey, 3)
	}

	for i := range clientsSharedSecrets {
		for j := range serversSharedSecrets {
			sharedSecret := make([]byte, 16)
			rand.Read(sharedSecret)
			clientsSharedSecrets[i][j] = sharedSecret
			serversSharedSecrets[j][i] = sharedSecret
		}
	}

	bigOneTwoThree := []*big.Int{
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
	}

	m0 := big.NewInt(0).Rand(rs, fieldOrder)
	m0evals := RandomPolynomialEvals(1, bigOneTwoThree, m0)

	require.Zero(t, m0.Cmp(big.NewInt(0).Mod(NevilleInterpolation(bigOneTwoThree[:2], m0evals[:2], big.NewInt(0)), fieldOrder)))

	m1 := big.NewInt(0).Rand(rs, fieldOrder)
	m1evals := RandomPolynomialEvals(1, bigOneTwoThree, m1)

	s00Blind := big.NewInt(0)

	// Note: in the implementation c0s0 should all get additional zero-shares on all indexes for anonymity
	c0s0 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[0][0]}, 16, 3, fieldOrder)
	s00Blind.Add(s00Blind, c0s0[0])
	c0s0[0] = FieldAdd(c0s0[0], m0evals[0], fieldOrder)

	c0s1 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[0][1]}, 16, 3, fieldOrder)
	c0s1[0] = FieldAdd(c0s1[0], m0evals[1], fieldOrder)

	c1s0 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[1][0]}, 16, 3, fieldOrder)
	s00Blind.Add(s00Blind, c1s0[0])
	c1s0[1] = FieldAdd(c1s0[1], m1evals[0], fieldOrder)

	c1s1 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[1][1]}, 16, 3, fieldOrder)
	c1s1[1] = FieldAdd(c1s1[1], m1evals[1], fieldOrder)

	c2s0 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[2][0]}, 16, 3, fieldOrder)
	s00Blind.Add(s00Blind, c2s0[0])
	c2s1 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[2][1]}, 16, 3, fieldOrder)

	// Aggregates
	s0Vector := make([]*big.Int, 3)
	for i := range s0Vector {
		s0Vector[i] = big.NewInt(0)
		s0Vector[i] = FieldAdd(s0Vector[i], c0s0[i], fieldOrder)
		s0Vector[i] = FieldAdd(s0Vector[i], c1s0[i], fieldOrder)
		s0Vector[i] = FieldAdd(s0Vector[i], c2s0[i], fieldOrder)
	}

	require.Zero(t, s0Vector[0].Cmp(FieldAdd(new(big.Int).Add(c0s0[0], c1s0[0]), c2s0[0], fieldOrder)))

	s1Vector := make([]*big.Int, 3)
	for i := range s1Vector {
		s1Vector[i] = big.NewInt(0)
		s1Vector[i] = FieldAdd(s1Vector[i], c0s1[i], fieldOrder)
		s1Vector[i] = FieldAdd(s1Vector[i], c1s1[i], fieldOrder)
		s1Vector[i] = FieldAdd(s1Vector[i], c2s1[i], fieldOrder)
	}

	s0UnblindingVector := DeriveBlindingVector(serversSharedSecrets[0], 16, 3, fieldOrder)
	// sanity check
	require.Zero(t, s00Blind.Mod(s00Blind, fieldOrder).Cmp(s0UnblindingVector[0]))
	s1UnblindingVector := DeriveBlindingVector(serversSharedSecrets[1], 16, 3, fieldOrder)

	for i := range s0Vector {
		s0Vector[i] = FieldSub(s0Vector[i], s0UnblindingVector[i], fieldOrder)
		s1Vector[i] = FieldSub(s1Vector[i], s1UnblindingVector[i], fieldOrder)
	}

	require.Zero(t, big.NewInt(0).Mod(NevilleInterpolation(bigOneTwoThree[:2], []*big.Int{s0Vector[0], s1Vector[0]}, big.NewInt(0)), fieldOrder).Cmp(m0))
}


