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

	res := NevilleInterpolation(xs, ys, big.NewInt(-2), MessageFieldOrder)
	require.Equal(t, int64(2819712005523334122), res.Int64())
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

	res := NevilleInterpolation(xs, ys, big.NewInt(10), MessageFieldOrder)
	require.Equal(t, int64(7564501717226133287), res.Int64())
}

type Client struct {
	Shares map[string]*big.Int
}

func TestRandomPolynomial(t *testing.T) {
	ys := RandomPolynomialEvals(1, []*big.Int{big.NewInt(1), big.NewInt(2)}, big.NewInt(10), MessageFieldOrder)
	require.Zero(t, big.NewInt(10).Cmp(NevilleInterpolation([]*big.Int{big.NewInt(1), big.NewInt(2)}, ys, big.NewInt(0), MessageFieldOrder)))
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

	m0 := big.NewInt(0).Rand(rs, MessageFieldOrder)
	m0evals := RandomPolynomialEvals(1, bigOneTwoThree, m0, MessageFieldOrder)

	require.Zero(t, m0.Cmp(NevilleInterpolation(bigOneTwoThree[:2], m0evals[:2], big.NewInt(0), MessageFieldOrder)))

	m1 := big.NewInt(0).Rand(rs, MessageFieldOrder)
	m1evals := RandomPolynomialEvals(1, bigOneTwoThree, m1, MessageFieldOrder)

	s00Blind := big.NewInt(0)

	// Note: in the implementation c0s0 should all get additional zero-shares on all indexes for anonymity
	c0s0 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[0][0]}, 16, 3, MessageFieldOrder)
	s00Blind.Add(s00Blind, c0s0[0])
	FieldAddInplace(c0s0[0], m0evals[0], MessageFieldOrder)

	c0s1 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[0][1]}, 16, 3, MessageFieldOrder)
	FieldAddInplace(c0s1[0], m0evals[1], MessageFieldOrder)

	c1s0 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[1][0]}, 16, 3, MessageFieldOrder)
	s00Blind.Add(s00Blind, c1s0[0])
	FieldAddInplace(c1s0[1], m1evals[0], MessageFieldOrder)

	c1s1 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[1][1]}, 16, 3, MessageFieldOrder)
	FieldAddInplace(c1s1[1], m1evals[1], MessageFieldOrder)

	c2s0 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[2][0]}, 16, 3, MessageFieldOrder)
	s00Blind.Add(s00Blind, c2s0[0])
	c2s1 := DeriveBlindingVector([]SharedKey{clientsSharedSecrets[2][1]}, 16, 3, MessageFieldOrder)

	// Aggregates
	s0Vector := make([]*big.Int, 3)
	for i := range s0Vector {
		s0Vector[i] = big.NewInt(0)
		FieldAddInplace(s0Vector[i], c0s0[i], MessageFieldOrder)
		FieldAddInplace(s0Vector[i], c1s0[i], MessageFieldOrder)
		FieldAddInplace(s0Vector[i], c2s0[i], MessageFieldOrder)
	}

	require.Zero(t, s0Vector[0].Cmp(FieldAddInplace(new(big.Int).Add(c0s0[0], c1s0[0]), c2s0[0], MessageFieldOrder)))

	s1Vector := make([]*big.Int, 3)
	for i := range s1Vector {
		s1Vector[i] = big.NewInt(0)
		FieldAddInplace(s1Vector[i], c0s1[i], MessageFieldOrder)
		FieldAddInplace(s1Vector[i], c1s1[i], MessageFieldOrder)
		FieldAddInplace(s1Vector[i], c2s1[i], MessageFieldOrder)
	}

	s0UnblindingVector := DeriveBlindingVector(serversSharedSecrets[0], 16, 3, MessageFieldOrder)
	// sanity check
	require.Zero(t, s00Blind.Mod(s00Blind, MessageFieldOrder).Cmp(s0UnblindingVector[0]))
	s1UnblindingVector := DeriveBlindingVector(serversSharedSecrets[1], 16, 3, MessageFieldOrder)

	for i := range s0Vector {
		FieldSubInplace(s0Vector[i], s0UnblindingVector[i], MessageFieldOrder)
		FieldSubInplace(s1Vector[i], s1UnblindingVector[i], MessageFieldOrder)
	}

	require.Zero(t, NevilleInterpolation(bigOneTwoThree[:2], []*big.Int{s0Vector[0], s1Vector[0]}, big.NewInt(0), MessageFieldOrder).Cmp(m0))
}


