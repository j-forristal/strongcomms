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

func TestHTTPSClientGoogleDefault(t *testing.T) {
	cfg := Config{
		UseCloudflareDOH: true,
		UseGoogleDOH:     true,
	}
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
		t.Error("Google HTTPS test not 200")
	}

	if client.CountDOHRequests == 0 {
		t.Error("HTTPS didn't use DOH")
	}

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
