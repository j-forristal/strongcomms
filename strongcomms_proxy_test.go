/*
** Copyright (c) 2019 J Forristal LLC
** All Rights Reserved.
 */

package strongcomms

import (
	//"context"
	"crypto/tls"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/elazarl/goproxy"
)

const (
	proxyAddressHTTP  = "127.0.0.1:8080"
	proxyAddressHTTPS = "127.0.0.1:8081"
)

func runHTTPProxy() *http.Server {
	proxy := goproxy.NewProxyHttpServer()

	srv := &http.Server{
		Addr:    proxyAddressHTTP,
		Handler: proxy,
	}

	go srv.ListenAndServe()
	return srv
}

func runHTTPSProxy() *http.Server {
	proxy := goproxy.NewProxyHttpServer()

	cert, err := tls.X509KeyPair([]byte(testServerCert), []byte(testServerKey))
	if err != nil {
		panic(err)
	}

	srv := &http.Server{
		Addr:    proxyAddressHTTPS,
		Handler: proxy,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	go srv.ListenAndServeTLS("", "")
	return srv
}

func TestMain(m *testing.M) {
	// Run an HTTP proxy on first port
	_ = runHTTPProxy()

	// Run an HTTP proxy on a second port
	_ = runHTTPSProxy()

	// HACK: we need to give ListenAndServe() time to get running;
	// there is no nice way to be informed of when it's running, so
	// we just force wait a few seconds. :(
	time.Sleep(time.Second * 2)

	os.Exit(m.Run())
}

func TestDOHGoogleHTTPProxy(t *testing.T) {

	cfg := Config{
		UseGoogleDOH: true,
		ProxyConfig: &ProxyConfig{
			Url: "http://" + proxyAddressHTTP,
		},
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	commonClient(client)

	testDOHCommon(t, client)
}

func TestDOHCloudflareHTTPProxy(t *testing.T) {

	cfg := Config{
		UseCloudflareDOH: true,
		ProxyConfig: &ProxyConfig{
			Url: "http://" + proxyAddressHTTP,
		},
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	commonClient(client)

	testDOHCommon(t, client)
}

func TestDOHGoogleHTTPSProxy(t *testing.T) {

	cfg := Config{
		UseGoogleDOH: true,
		ProxyConfig: &ProxyConfig{
			Url:      "https://" + proxyAddressHTTPS,
			CertsPEM: []byte(testServerCert),
		},
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	commonClient(client)

	testDOHCommon(t, client)
}

func TestDOHCloudflareHTTPSProxy(t *testing.T) {

	cfg := Config{
		UseCloudflareDOH: true,
		ProxyConfig: &ProxyConfig{
			Url:      "https://" + proxyAddressHTTPS,
			CertsPEM: []byte(testServerCert),
		},
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	commonClient(client)

	testDOHCommon(t, client)
}

func TestHTTPSClientGoogleDefaultHTTPProxy(t *testing.T) {
	cfg := Config{
		UseCloudflareDOH: true,
		UseGoogleDOH:     true,
		ProxyConfig: &ProxyConfig{
			Url: "http://" + proxyAddressHTTP,
		},
	}
	testHTTPSClientGoogle(cfg, t)
}

func TestHTTPSClientGoogleDefaultHTTPSProxy(t *testing.T) {
	cfg := Config{
		UseCloudflareDOH: true,
		UseGoogleDOH:     true,
		ProxyConfig: &ProxyConfig{
			Url:      "https://" + proxyAddressHTTPS,
			CertsPEM: []byte(testServerCert),
		},
	}
	testHTTPSClientGoogle(cfg, t)
}

func TestHTTPSClientGoogleDefaultHTTPSProxyPinned(t *testing.T) {

	pins := make([][]byte, 0)
	pins = append(pins, googlePin[:])
	pins = append(pins, testServerPin[:])

	cfg := Config{
		UseCloudflareDOH:   true,
		UseGoogleDOH:       true,
		CertValidationType: CertValidateSPKIPinAnyDefault,
		CertValidationPins: pins,
		ProxyConfig: &ProxyConfig{
			Url:      "https://" + proxyAddressHTTPS,
			CertsPEM: []byte(testServerCert),
		},
	}
	testHTTPSClientGoogle(cfg, t)
}
