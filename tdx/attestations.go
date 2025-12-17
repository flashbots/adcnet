package tdx

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/client"
	proto_checkconfig "github.com/google/go-tdx-guest/proto/checkconfig"
	proto "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
)

// TDXProvider generates and verifies attestations using the local TDX device.
type TDXProvider struct{}

func (p *TDXProvider) AttestationType() string {
	return "dcap-tdx"
}

// Attest generates a TDX quote binding the report data.
func (p *TDXProvider) Attest(reportData [64]byte) ([]byte, error) {
	qp := &client.LinuxConfigFsQuoteProvider{}
	return qp.GetRawQuote(reportData)
}

// Verify validates a TDX quote and returns measurements if valid.
func (p *TDXProvider) Verify(attestationReport []byte, expectedReportData [64]byte) (map[int][]byte, error) {
	return VerifyDCAP(attestationReport, expectedReportData[:])
}

// RemoteDCAPProvider generates attestations via a remote service and verifies locally.
type RemoteDCAPProvider struct {
	URL     string
	Timeout time.Duration
}

func (p *RemoteDCAPProvider) AttestationType() string {
	return "dcap-tdx"
}

// Attest requests a TDX quote from the remote attestation service.
func (p *RemoteDCAPProvider) Attest(reportData [64]byte) ([]byte, error) {
	reportDataHex := hex.EncodeToString(reportData[:])
	url := fmt.Sprintf("%s/attest/%s", p.URL, reportDataHex)

	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(p.Timeout))
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("calling remote quote provider: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote quote provider returned status %d: %s", resp.StatusCode, string(body))
	}

	rawQuote, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading quote from response: %w", err)
	}

	return rawQuote, nil
}

// Verify validates a TDX quote and returns measurements if valid.
func (p *RemoteDCAPProvider) Verify(attestationReport []byte, expectedReportData [64]byte) (map[int][]byte, error) {
	return VerifyDCAP(attestationReport, expectedReportData[:])
}

func mustDecodeHex(data string) []byte {
	decoded, err := hex.DecodeString(data)
	if err != nil {
		panic(err.Error())
	}
	return decoded
}

// VerifyDCAP validates a TDX DCAP quote against expected report data.
func VerifyDCAP(attestationReport []byte, expectedReportData []byte) (map[int][]byte, error) {
	anyQuote, err := abi.QuoteToProto(attestationReport)
	if err != nil {
		return nil, fmt.Errorf("could not convert raw bytes to QuoteV4: %v", err)
	}
	quote, ok := anyQuote.(*proto.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("Quote is not a QuoteV4")
	}

	config := &proto_checkconfig.Config{
		RootOfTrust: &proto_checkconfig.RootOfTrust{
			CheckCrl:      true,
			GetCollateral: true,
		},
		Policy: &proto_checkconfig.Policy{
			HeaderPolicy: &proto_checkconfig.HeaderPolicy{
				MinimumQeSvn:  0,
				MinimumPceSvn: 0,
				QeVendorId:    mustDecodeHex("939a7233f79c4ca9940a0db3957f0607"),
			},
			TdQuoteBodyPolicy: &proto_checkconfig.TDQuoteBodyPolicy{
				TdAttributes: mustDecodeHex("0000001000000000"),
				ReportData:   expectedReportData,
			},
		},
	}

	options, err := verify.RootOfTrustToOptions(config.RootOfTrust)
	if err != nil {
		return nil, fmt.Errorf("converting root of trust to options: %w", err)
	}

	if err := verify.TdxQuote(quote, options); err != nil {
		return nil, fmt.Errorf("verifying TDX quote: %w", err)
	}

	opts, err := validate.PolicyToOptions(config.Policy)
	if err != nil {
		return nil, fmt.Errorf("converting policy to options: %v", err)
	}

	if err := validate.TdxQuote(quote, opts); err != nil {
		return nil, fmt.Errorf("error validating the TDX Quote: %v", err)
	}

	return map[int][]byte{
		0: quote.GetTdQuoteBody().MrTd,
		1: quote.GetTdQuoteBody().Rtmrs[0],
		2: quote.GetTdQuoteBody().Rtmrs[1],
		3: quote.GetTdQuoteBody().Rtmrs[2],
		4: quote.GetTdQuoteBody().Rtmrs[3],
	}, nil
}

// DummyProvider provides mock attestation for testing without TEE hardware.
type DummyProvider struct{}

func (p *DummyProvider) AttestationType() string {
	return "dummy-tdx"
}

// Attest returns the report data as a mock attestation.
func (p *DummyProvider) Attest(reportData [64]byte) ([]byte, error) {
	ret := make([]byte, len(reportData))
	copy(ret, reportData[:])
	return ret, nil
}

// Verify checks that attestation matches expected report data.
func (p *DummyProvider) Verify(attestationReport []byte, expectedReportData [64]byte) (map[int][]byte, error) {
	if !bytes.Equal(attestationReport, expectedReportData[:]) {
		return nil, errors.New("attestation mismatch")
	}

	return map[int][]byte{
		0: {0},
		1: {1},
		2: {2},
		3: {3},
		4: {4},
	}, nil
}
