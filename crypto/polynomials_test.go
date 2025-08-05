package crypto

import (
	"crypto/rand"
	"math/big"
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

	coeffs := LagrangeCoeffs(xs, MessageFieldOrder)
	lres := LagrangeInterpolation(xs, ys, coeffs, MessageFieldOrder)
	require.Equal(t, int64(7), lres.Int64())
}

func TestPolynomials(t *testing.T) {
	xs := make([]*big.Int, 10)
	for i := range xs {
		xs[i] = big.NewInt(int64(i + 1))
	}

	deg := 5
	coeffs := LagrangeCoeffs(xs[9-deg:10], MessageFieldOrder)

	for i := 0; i < 10; i++ {
		el, _ := rand.Int(rand.Reader, MessageFieldOrder)
		evals := RandomPolynomialEvals(deg, xs, el, MessageFieldOrder)
		for _, eval := range evals {
			require.True(t, eval.Sign() > 0, el.String())
			require.True(t, eval.Cmp(MessageFieldOrder) <= 0, el.String())
		}

		zero := big.NewInt(0)
		intpRes := LagrangeInterpolation(xs[9-deg:10], evals[9-deg:10], coeffs, MessageFieldOrder)

		require.Zero(t, intpRes.Cmp(el), "%s: %s\t(%v): (%v)", el.String(), intpRes.String(), xs[9-deg:10], evals[9-deg:10])

		for j := 0; j < 100; j++ {
			evals2 := RandomPolynomialEvals(deg, xs, zero, MessageFieldOrder)
			for k := range evals {
				evals[k].Add(evals[k], evals2[k])
				evals[k].Mod(evals[k], MessageFieldOrder)
			}
			intpRes2 := LagrangeInterpolation(xs[9-deg:10], evals[9-deg:10], coeffs, MessageFieldOrder)
			require.Zero(t, intpRes2.Cmp(el), "%s: %s", el.String(), intpRes.String())
		}
	}
}

type Client struct {
	Shares map[string]*big.Int
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

	require.Zero(t, m0.Cmp(LagrangeInterpolation(bigOneTwoThree[:2], m0evals[:2], nil, MessageFieldOrder)))

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

	interpolatedValue := LagrangeInterpolation(bigOneTwoThree[:2], []*big.Int{s0Vector[0], s1Vector[0]}, nil, MessageFieldOrder)
	require.Zero(t, interpolatedValue.Cmp(m0), interpolatedValue.String())
}
