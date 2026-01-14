package services

import (
	"testing"

	"github.com/flashbots/adcnet/crypto"
	"github.com/stretchr/testify/require"
)

func TestStaticMeasurementSource(t *testing.T) {
	measurements := PublishedMeasurements{
		{
			MeasurementID: "test-1",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "0102"},
				1: {Expected: "0304"},
			},
		},
		{
			MeasurementID: "test-2",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "0506"},
				1: {Expected: "0708"},
			},
		},
	}

	source := NewStaticMeasurementSource(measurements)

	retrieved, err := source.GetAllowedMeasurements()
	require.NoError(t, err)
	require.Len(t, retrieved, 2)
	require.Equal(t, "test-1", retrieved[0].MeasurementID)
	require.Equal(t, "0102", retrieved[0].Measurements[0].Expected)
}

func TestDemoMeasurementSource(t *testing.T) {
	source := DemoMeasurementSource()

	measurements, err := source.GetAllowedMeasurements()
	require.NoError(t, err)
	require.Len(t, measurements, 1)

	// Demo source should have measurements 0-4 with values "00"-"04"
	m := measurements[0].Measurements
	require.Equal(t, "00", m[0].Expected)
	require.Equal(t, "01", m[1].Expected)
	require.Equal(t, "02", m[2].Expected)
	require.Equal(t, "03", m[3].Expected)
	require.Equal(t, "04", m[4].Expected)
}

func TestVerifyMeasurementsMatch_Success(t *testing.T) {
	allowed := PublishedMeasurements{
		{
			MeasurementID: "test-1",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "01"},
				1: {Expected: "02"},
			},
		},
		{
			MeasurementID: "test-2",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "03"},
				1: {Expected: "04"},
			},
		},
	}

	// Actual matches first allowed set
	actual := Measurements{0: []byte{0x01}, 1: []byte{0x02}}

	matched, err := VerifyMeasurementsMatch(allowed, actual)
	require.NoError(t, err)
	require.Equal(t, "test-1", matched.MeasurementID)
}

func TestVerifyMeasurementsMatch_SecondSet(t *testing.T) {
	allowed := PublishedMeasurements{
		{
			MeasurementID: "test-1",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "01"},
				1: {Expected: "02"},
			},
		},
		{
			MeasurementID: "test-2",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "03"},
				1: {Expected: "04"},
			},
		},
	}

	// Actual matches second allowed set
	actual := Measurements{0: []byte{0x03}, 1: []byte{0x04}}

	matched, err := VerifyMeasurementsMatch(allowed, actual)
	require.NoError(t, err)
	require.Equal(t, "test-2", matched.MeasurementID)
}

func TestVerifyMeasurementsMatch_NoMatch(t *testing.T) {
	allowed := PublishedMeasurements{
		{
			MeasurementID: "test-1",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "01"},
				1: {Expected: "02"},
			},
		},
	}

	// Actual doesn't match any allowed set
	actual := Measurements{0: []byte{0xFF}, 1: []byte{0xFF}}

	_, err := VerifyMeasurementsMatch(allowed, actual)
	require.Error(t, err)
}

func TestVerifyMeasurementsMatch_PartialMatch(t *testing.T) {
	allowed := PublishedMeasurements{
		{
			MeasurementID: "test-1",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "01"},
				1: {Expected: "02"},
			},
		},
	}

	// Actual has one matching and one non-matching register
	actual := Measurements{0: []byte{0x01}, 1: []byte{0xFF}}

	_, err := VerifyMeasurementsMatch(allowed, actual)
	require.Error(t, err)
}

func TestVerifyMeasurementsMatch_EmptyAllowed(t *testing.T) {
	allowed := PublishedMeasurements{}
	actual := Measurements{0: []byte{0x01}}

	_, err := VerifyMeasurementsMatch(allowed, actual)
	require.Error(t, err)
}

func TestVerifyMeasurementsMatch_MissingRegister(t *testing.T) {
	allowed := PublishedMeasurements{
		{
			MeasurementID: "test-1",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "01"},
				1: {Expected: "02"},
			},
		},
	}
	// Actual only has register 0
	actual := Measurements{0: []byte{0x01}}

	_, err := VerifyMeasurementsMatch(allowed, actual)
	require.Error(t, err)
}

func TestMeasurementEntry_ToMeasurements(t *testing.T) {
	entry := MeasurementEntry{
		MeasurementID: "test",
		Measurements: map[int]MeasurementValue{
			0: {Expected: "0102"},
			1: {Expected: "0304"},
		},
	}

	m, err := entry.ToMeasurements()
	require.NoError(t, err)
	require.Equal(t, []byte{0x01, 0x02}, m[0])
	require.Equal(t, []byte{0x03, 0x04}, m[1])
}

func TestMeasurementEntry_ToMeasurements_InvalidHex(t *testing.T) {
	entry := MeasurementEntry{
		MeasurementID: "test",
		Measurements: map[int]MeasurementValue{
			0: {Expected: "invalid"},
		},
	}

	_, err := entry.ToMeasurements()
	require.Error(t, err)
}

func TestReportDataForService(t *testing.T) {
	exchangeKey := []byte("exchange-key-bytes")
	endpoint := "http://localhost:8080"
	pubKey := crypto.PublicKey("public-key-bytes")

	data := ReportDataForService(exchangeKey, endpoint, pubKey)

	// Should return a hash (32 bytes for SHA-256)
	require.Len(t, data, 32)

	// Same inputs should give same output
	data2 := ReportDataForService(exchangeKey, endpoint, pubKey)
	require.Equal(t, data, data2)

	// Different inputs should give different output
	data3 := ReportDataForService(exchangeKey, "http://localhost:8081", pubKey)
	require.NotEqual(t, data, data3)
}
