package crypto

import (
	"math/big"
	"crypto/rand"
	unsafe_rand "math/rand"
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
	FieldAddInplace(c0s0[0], m0evals[0], fieldOrder)

	c0s1 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[0][1]}, 16, 3, fieldOrder)
	FieldAddInplace(c0s1[0], m0evals[1], fieldOrder)

	c1s0 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[1][0]}, 16, 3, fieldOrder)
	s00Blind.Add(s00Blind, c1s0[0])
	FieldAddInplace(c1s0[1], m1evals[0], fieldOrder)

	c1s1 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[1][1]}, 16, 3, fieldOrder)
	FieldAddInplace(c1s1[1], m1evals[1], fieldOrder)

	c2s0 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[2][0]}, 16, 3, fieldOrder)
	s00Blind.Add(s00Blind, c2s0[0])
	c2s1 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[2][1]}, 16, 3, fieldOrder)

	// Aggregates
	s0Vector := make([]*big.Int, 3)
	for i := range s0Vector {
		s0Vector[i] = big.NewInt(0)
		FieldAddInplace(s0Vector[i], c0s0[i], fieldOrder)
		FieldAddInplace(s0Vector[i], c1s0[i], fieldOrder)
		FieldAddInplace(s0Vector[i], c2s0[i], fieldOrder)
	}

	require.Zero(t, s0Vector[0].Cmp(FieldAddInplace(new(big.Int).Add(c0s0[0], c1s0[0]), c2s0[0], fieldOrder)))

	s1Vector := make([]*big.Int, 3)
	for i := range s1Vector {
		s1Vector[i] = big.NewInt(0)
		FieldAddInplace(s1Vector[i], c0s1[i], fieldOrder)
		FieldAddInplace(s1Vector[i], c1s1[i], fieldOrder)
		FieldAddInplace(s1Vector[i], c2s1[i], fieldOrder)
	}

	s0UnblindingVector := DeriveBlindingVector(serversSharedSecrets[0], 16, 3, fieldOrder)
	// sanity check
	require.Zero(t, s00Blind.Mod(s00Blind, fieldOrder).Cmp(s0UnblindingVector[0]))
	s1UnblindingVector := DeriveBlindingVector(serversSharedSecrets[1], 16, 3, fieldOrder)

	for i := range s0Vector {
		FieldSubInplace(s0Vector[i], s0UnblindingVector[i], fieldOrder)
		FieldSubInplace(s1Vector[i], s1UnblindingVector[i], fieldOrder)
	}

	require.Zero(t, big.NewInt(0).Mod(NevilleInterpolation(bigOneTwoThree[:2], []*big.Int{s0Vector[0], s1Vector[0]}, big.NewInt(0)), fieldOrder).Cmp(m0))
}


