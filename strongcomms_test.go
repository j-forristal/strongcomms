/*
** Copyright (c) 2018 J Forristal LLC
** All Rights Reserved.
 */

package strongcomms

import (
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"
)

const (
	DNSTestHostname = "strongcomms-test.forristal.com"
	DNSTestAnswer   = "1.2.3.4"

	testServerCert = `-----BEGIN CERTIFICATE-----
MIIDtTCCAp2gAwIBAgIJAJRKeb1s0vVYMA0GCSqGSIb3DQEBCwUAMHoxCzAJBgNV
BAYTAkVTMRAwDgYDVQQIDAdNeVN0YXRlMQ8wDQYDVQQHDAZNeUNpdHkxDjAMBgNV
BAoMBU15T3JnMSEwHwYJKoZIhvcNAQkBFhJlbWFpbEBteWRvbWFpbi5jb20xFTAT
BgNVBAMMDG15ZG9tYWluLmNvbTAeFw0xOTAzMDEyMzEzMTJaFw0yODExMjgyMzEz
MTJaMHoxCzAJBgNVBAYTAkVTMRAwDgYDVQQIDAdNeVN0YXRlMQ8wDQYDVQQHDAZN
eUNpdHkxDjAMBgNVBAoMBU15T3JnMSEwHwYJKoZIhvcNAQkBFhJlbWFpbEBteWRv
bWFpbi5jb20xFTATBgNVBAMMDG15ZG9tYWluLmNvbTCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBANrp6NYyGLyhwedQhKvozY2ukaq5F+c/zXdlLCRvaqgr
rFX0guVfq042QRaAb5KA7PiMZ04N1DoyMaDgPiFRvk8mODl5og/e1jC8E5e4qr6L
R76OV2kXtDUNnpNzj3lKXBIbcz4oUlNh9db7oLS6I6yO62M+e78vFrJRICNGcXEj
saazAiGswV+BJ5OxnFM2iKvZwGYkExIyjYHA+Q4DHTO3M3yNzYp6d2kAkk5M7qzi
T+IEWumIhTkZ+dXKVOCZOrn4wrIpRT/EQ15tIEOAJsTvGIMdyr03BiWyL8S1pCnk
yV1b5vKjTlhne0UD5ezk7naV96IzTR6s8vQynHUB3qUCAwEAAaM+MDwwOgYDVR0R
BDMwMYIPd3d3LmV4YW1wbGUuY29tgg0qLmV4YW1wbGUuY29tgglsb2NhbGhvc3SH
BH8AAAEwDQYJKoZIhvcNAQELBQADggEBAH2IrSIhaR4duV5m8C+TWtz06Znfz5n6
jUKQspInIliLdQfQ89KaLU3UQAEKJBZrTVmC5vjb9Ylf9oYdzwe9bJ6DpOfYKUoz
O8VcH+RR2KAtbOrsNPNwpEw10J2FGZ/gY9qnN6/1sSxI2V5vLvFnwafM9v33i+ay
Pdc3LLxGZiP7lpl56cHtCnRJ8QvHgQ11zWMqCmiMLSn1j66LSxKw8S1SWCrRKcYE
54ExwX5Dj8SlSpcMrpfwLNA+/r7TDYZuWclUP8q8SzNkHDl3ycF493AekeyxTzjt
F0brN9QvGBshu7ucCgWfPF5cn8GE3qQ8etfGUFub+WBIksYJ2UQMnIE=
-----END CERTIFICATE-----`

	testServerKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDa6ejWMhi8ocHn
UISr6M2NrpGquRfnP813ZSwkb2qoK6xV9ILlX6tONkEWgG+SgOz4jGdODdQ6MjGg
4D4hUb5PJjg5eaIP3tYwvBOXuKq+i0e+jldpF7Q1DZ6Tc495SlwSG3M+KFJTYfXW
+6C0uiOsjutjPnu/LxayUSAjRnFxI7GmswIhrMFfgSeTsZxTNoir2cBmJBMSMo2B
wPkOAx0ztzN8jc2KendpAJJOTO6s4k/iBFrpiIU5GfnVylTgmTq5+MKyKUU/xENe
bSBDgCbE7xiDHcq9NwYlsi/EtaQp5MldW+byo05YZ3tFA+Xs5O52lfeiM00erPL0
Mpx1Ad6lAgMBAAECggEAf7hQ3AdGX2eQlcBoZ1Pf+XWMDysGQyj6W1pvsqI+e/df
CJcrd1+ltm/48YPllHgbybdA3k07MOjwA4hRN2dVvR/zVbUdVF0SYkSYucBH/fuM
1CR/4xStUvarOiQF5SH5LadOSUmFHpjcsZ0FWevvvFF2C+T8lcKHX2ntcic7MGIq
kwp+OLXsQMNG5lYkqGZYBudBHI8l2wjTO65ABvlAkpunxOW4alkOY9vAp9LtGQcK
y/9FIqtXvQu4xqqLHrZuf4VFb3zkh9sIDmcxSCw3oV9XInRDC+A7FwpCCSdIKvbs
trpBwWEhzCOZZ1b5kLn53qzTKfH/XpEZs6Kr5QGEAQKBgQDwa8PCacEarxwYPGik
xreTl5jWQ9+Amq8O7jJIOe6ldukZu0/9M9ShAcfCKHqsWkiIsSSHaYU1qEugXFBK
y060VyCLfwRH+mslPK4LBgMTSDZRaq8b49w7ovv8UYZwRSJLQkdaYoCj81BoQdtI
qUON5WSmhJiUQKlWlCIzHZmvwQKBgQDpGV7q2snY1PsW75vOt6x0miMG3wTYB4Yv
I/Nqi/oQjRRpZeGf6vpoOEmFYL4PW8/77eGPMgX5CJMSI/8Fp+gtRcMNXNqQj8aL
rvfH0ghyLKBnUH03DndflCn33bXnCzJVF8sIKPSbk5Ka2leAef+8ebAITmREeRmY
pdODuRFn5QKBgQDQFGT0UXVI8/971mS3ICnoOo+T+mBpPPeAE5Y/PqyWVsk+dQiw
23gO9ax/FWu+2dDnRXGZJTGelA8INn1jjnyKxtGrCf6ZkVnEe7UiY0ysFpa0doIh
wF9u2gv/gEu7xYn92tpIlvJBc6fG5CC2zZBjMgOfvykTPreQ8Fp9JQRLwQKBgDrs
vfDSpAnbNSoEIjfseHz1Zftbr0bJCCOsi+EYR3udnlZSeenKJcjoybUc0o7hX79I
0Cc5twbQIxWH4fTVED05kGg1W88FeWRgM6TgtF/gZiAX2b9sOcMAmmddNZmVXADk
xd9nMwaNFJdusIX60Soc/OHspy4kCtNqwABhbUP9AoGALkjQh2Pchq0XjOA6PHs2
X91GqMqtc8fRBdjrFxIMhEo2m5COXkfXUiXFeTUF0lqxycsuT+0dvpp4IyDKAVpe
eHm0AaxUat5tGuVtqjU+MOunzFyMkrqKfnf3UGH9f+2wkCoVYofHCIe7gWaaMdUs
6jhhtJJLmqnWbeGkws/sne8=
-----END PRIVATE KEY-----`
)

var (
	testServerPin = [32]byte{38, 68, 31, 153, 95, 137, 221, 57, 37, 251,
		143, 186, 43, 236, 160, 164, 133, 115, 88, 254, 217, 195, 174,
		51, 181, 201, 248, 169, 55, 10, 132, 62}

	googlePin = [32]byte{127, 195, 103, 16, 86, 113, 67, 129, 49, 20, 232,
		82, 55, 177, 34, 21, 107, 98, 185, 214, 80, 84, 61, 168, 99,
		173, 46, 106, 229, 127, 159, 191}

	zeroPin = [32]byte{0}
)

func TestStaticLookup(t *testing.T) {
	cfg := Config{
		UseGoogleDOH:     true,
		UseCloudflareDOH: true,
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	testIP := net.ParseIP("9.10.11.12")
	client.SetCache(DNSTestHostname, []net.IP{testIP})
	ips, err := client.LookupIP(DNSTestHostname)
	if err != nil {
		t.Error(err)
	} else {
		if len(ips) > 0 {
			if ips[0].Equal(testIP) {
				// Success
			} else {
				t.Error(fmt.Sprintf("Unexpected IP answer %v\n", ips[0].String()))
			}
		} else {
			t.Error("Expected IP answer not found")
		}
	}
}

func TestDOHGoogle(t *testing.T) {
	cfg := Config{
		UseGoogleDOH: true,
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	testDOHCommon(t, client)
}

func TestDOHCloudflare(t *testing.T) {
	cfg := Config{
		UseCloudflareDOH: true,
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	testDOHCommon(t, client)
}

func TestDOHCaching(t *testing.T) {
	cfg := Config{
		UseCloudflareDOH: true,
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var total uint32 = 8
	for i := 0; i < int(total); i++ {
		testDOHCommon(t, client)
	}

	if client.CountDOHRequests != 1 || client.CountDOHCacheHits != (total-1) {
		t.Error("Cache counts not expected")
	}
}

func testDOHCommon(t *testing.T, client *Client) {

	var found bool

	ips, err := client.LookupIP(DNSTestHostname)
	if err != nil {
		t.Error(err)
	} else {
		for _, ip := range ips {
			if ip.String() == DNSTestAnswer {
				found = true
			} else {
				t.Error(fmt.Sprintf("Unexpected IP answer %v\n", ip.String()))
			}
		}
		if !found {
			t.Error("Expected IP answer not found")
		}
	}
}

func testHTTPSClientGoogle(cfg Config, t *testing.T) *Client {

	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequest("GET", "https://www.google.com/", nil)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Error("Google HTTPS test response not 200")
	}

	return client
}

func TestHTTPSClientGoogleDefault(t *testing.T) {
	cfg := Config{
		UseCloudflareDOH: true,
		UseGoogleDOH:     true,
	}

	_ = testHTTPSClientGoogle(cfg, t)
}

func TestHTTPSClientGooglePinned(t *testing.T) {

	pins := make([][]byte, 0)
	pins = append(pins, googlePin[:])

	cfg := Config{
		UseCloudflareDOH:   true,
		UseGoogleDOH:       true,
		CertValidationType: CertValidateSPKIPinAnyDefault,
		CertValidationPins: pins,
	}

	_ = testHTTPSClientGoogle(cfg, t)
}

func TestHTTPSClientGooglePinned2(t *testing.T) {

	pins := make([][]byte, 0)
	pins = append(pins, zeroPin[:])
	pins = append(pins, zeroPin[:])
	pins = append(pins, zeroPin[:])
	pins = append(pins, zeroPin[:])
	pins = append(pins, zeroPin[:])
	pins = append(pins, googlePin[:])

	cfg := Config{
		UseCloudflareDOH:   true,
		UseGoogleDOH:       true,
		CertValidationType: CertValidateSPKIPinAnyDefault,
		CertValidationPins: pins,
	}

	_ = testHTTPSClientGoogle(cfg, t)
}

func TestNetworkTest(t *testing.T) {
	cfg := Config{
		UseCloudflareDOH: true,
		UseGoogleDOH:     true,
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	if !client.TestNetwork() {
		t.Error("Network test failed")
	}
}

func TestGetTimeCurrent(t *testing.T) {
	cfg := Config{
		UseCloudflareDOH: true,
		UseGoogleDOH:     true,
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	tm := time.Now()
	tm2, err := client.GetTime(tm)
	if err != nil {
		t.Error(err)
	} else {
		if tm2.IsZero() {
			t.Error("Zero time returned")
		} else {
			//fmt.Printf("Time: %v\n", tm2)
		}
	}
}

func TestGetTimeZero(t *testing.T) {
	cfg := Config{
		UseCloudflareDOH: true,
		UseGoogleDOH:     true,
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	var tm time.Time
	tm2, err := client.GetTime(tm)
	if err != nil {
		t.Error(err)
	} else {
		if tm2.IsZero() {
			t.Error("Zero time returned")
		} else {
			//fmt.Printf("Time: %v\n", tm2)
		}
	}
}
