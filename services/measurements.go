package services

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// PublishedMeasurements contains attestation measurements for released builds.
// Fetched from a public URL and used for client-side attestation verification.
//
// JSON format:
//
//	[
//	  {
//	    "measurement_id": "adcnet-v0.0.1-tdx-abc123...",
//	    "measurements": {
//	      0: {"expected": "hex-encoded-mrtd..."},
//	      1: {"expected": "hex-encoded-rtmr0..."},
//	      2: {"expected": "hex-encoded-rtmr1..."}
//	      3: {"expected": "hex-encoded-rtmr2..."}
//	    }
//	  }
//	]
//
// The file is an array of MeasurementEntry objects. Each entry represents
// an acceptable build. Keys in "measurements" are register indices.
// A service is accepted if its attestation matches any entry in the array.
type PublishedMeasurements []MeasurementEntry

// MeasurementEntry represents a single acceptable build configuration.
type MeasurementEntry struct {
	MeasurementID string                   `json:"measurement_id"`
	Measurements  map[int]MeasurementValue `json:"measurements"`
}

// MeasurementValue holds an expected measurement value.
type MeasurementValue struct {
	Expected string `json:"expected"`
}

// ToMeasurements converts a MeasurementEntry to the internal format.
func (e *MeasurementEntry) ToMeasurements() (Measurements, error) {
	result := make(Measurements)
	for idx, mv := range e.Measurements {
		val, err := hex.DecodeString(mv.Expected)
		if err != nil {
			return nil, fmt.Errorf("invalid hex for index %d: %w", idx, err)
		}
		result[idx] = val
	}
	return result, nil
}

// MeasurementSource provides expected measurements for attestation verification.
type MeasurementSource interface {
	// GetAllowedMeasurements returns all acceptable measurement sets.
	GetAllowedMeasurements() (PublishedMeasurements, error)
}

// StaticMeasurementSource provides measurements from a static configuration.
// Useful for testing and demo deployments where TEE measurements are known
// in advance or when using dummy attestation.
type StaticMeasurementSource struct {
	Measurements PublishedMeasurements
}

// NewStaticMeasurementSource creates a source with predefined measurements.
func NewStaticMeasurementSource(measurements PublishedMeasurements) *StaticMeasurementSource {
	return &StaticMeasurementSource{Measurements: measurements}
}

// DemoMeasurementSource returns a MeasurementSource that accepts dummy attestations.
// The returned measurements match the values produced by tdx.DummyProvider.
// Only use in demo/testing environments.
func DemoMeasurementSource() *StaticMeasurementSource {
	return NewStaticMeasurementSource(PublishedMeasurements{
		{
			MeasurementID: "demo-dummy-attestation",
			Measurements: map[int]MeasurementValue{
				0: {Expected: "00"},
				1: {Expected: "01"},
				2: {Expected: "02"},
				3: {Expected: "03"},
				4: {Expected: "04"},
			},
		},
	})
}

// GetAllowedMeasurements returns the static measurement sets.
func (s *StaticMeasurementSource) GetAllowedMeasurements() (PublishedMeasurements, error) {
	return s.Measurements, nil
}

// RemoteMeasurementSource fetches measurements from a URL.
type RemoteMeasurementSource struct {
	URL        string
	HTTPClient *http.Client

	cacheTimeout time.Time
	cached       PublishedMeasurements
}

// NewRemoteMeasurementSource creates a source that fetches from a URL.
func NewRemoteMeasurementSource(url string) *RemoteMeasurementSource {
	return &RemoteMeasurementSource{
		URL:        url,
		HTTPClient: &http.Client{Timeout: 30 * time.Second},
	}
}

// GetAllowedMeasurements fetches and returns all acceptable measurement sets.
func (r *RemoteMeasurementSource) GetAllowedMeasurements() (PublishedMeasurements, error) {
	if r.cached != nil && time.Now().Before(r.cacheTimeout) {
		return r.cached, nil
	}

	published, err := r.fetchMeasurements()
	if err != nil {
		return nil, err
	}

	r.cached = published
	r.cacheTimeout = time.Now().Add(time.Hour)
	return published, nil
}

func (r *RemoteMeasurementSource) fetchMeasurements() (PublishedMeasurements, error) {
	resp, err := r.HTTPClient.Get(r.URL)
	if err != nil {
		return nil, fmt.Errorf("fetching measurements: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("measurements returned %d: %s", resp.StatusCode, body)
	}

	var pub PublishedMeasurements
	if err := json.NewDecoder(resp.Body).Decode(&pub); err != nil {
		return nil, fmt.Errorf("decoding measurements: %w", err)
	}

	return pub, nil
}

func VerifyMeasurementsMatch(
	publishedAllowedMeasurements PublishedMeasurements,
	actualMeasurements Measurements,
) (MeasurementEntry, error) {
	for _, entry := range publishedAllowedMeasurements {
		matches := true
		for idx, expectedVal := range entry.Measurements {
			actualVal, ok := actualMeasurements[idx]
			if !ok {
				matches = false
				break
			}
			if expectedVal.Expected != hex.EncodeToString(actualVal) {
				matches = false
				break
			}
		}
		if matches {
			return entry, nil
		}
	}

	return MeasurementEntry{}, errors.New("measurements do not match any allowed set")
}
