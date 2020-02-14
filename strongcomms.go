/*

Copyright (c) 2019, Jeff Forristal, J Forristal LLC
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:
    * Redistributions of source code must retain the above copyright
      notice, this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of the copyright holder nor the
      names of its contributors may be used to endorse or promote products
      derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

*/

package strongcomms

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io/ioutil"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"fmt"

	"github.com/j-forristal/strongcomms/lru"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	contextKeyDOH = "sc_doh"
	appDNSMessage = "application/dns-message"

	TagDOH         = "DOH"
	TagClient      = "Client"
	TagNetworkTest = "NetTest"
	TagNetworkTime = "NetTime"
)

var (
	DefaultTimeoutNetworkTest  = 5 * time.Second
	DefaultTimeoutDOH          = 30 * time.Second
	DefaultTimeoutHTTPSTotal   = 15 * time.Minute
	DefaultTimeoutHTTPSSetup   = 15 * time.Second
	DefaultMinimumDOHCacheTime = 5 * time.Minute
	DefaultCacheSize           = 32

	DefaultTLSMinVersion    = uint16(tls.VersionTLS12)
	DefaultCurvePreferences = []tls.CurveID{
		tls.CurveP521,
		tls.CurveP384,
		tls.CurveP256,
	}
	DefaultCipherSuites = []uint16{
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
	}
)

type Client struct {
	ClientDOH                 *http.Client
	DOHServers                []*DOHServer
	ClientHTTPS               *http.Client
	HTTPSPins                 [][]byte
	TLSErrorCallback          func(source, errorType string, cert *x509.Certificate)
	DOHErrorCallback          func(source, hostname string, err error)
	DateCallback              func(t time.Time)
	TraceCallback             func(traceMsg string)
	CountDOHCacheHits         uint32
	CountDOHRequests          uint32
	CountDOHResponseErrors    uint32
	CountDOHParsingErrors     uint32
	CountDOHOperationalErrors uint32
	CountDOHResumed           uint32
	CountHTTPSResumed         uint32
	cache                     *lru.Cache
	l                         sync.Mutex
}

type DOHServer struct {
	Url     string
	Dial    string
	Timeout time.Duration
}

type CertValidationType int

const (
	// CertValidationDefault will use standard root certificate parsing against the
	// system default root certificate store
	CertValidationDefault CertValidationType = iota

	// CertValidationDisable will disable all certificate validation.  USE WITH CAUTION.
	CertValidationDisable

	// CertValidateSPKIPinAnyDefault will use standard root certificate parsing against
	// the system default root certificate store; upon successful validation, the successful
	// cert chain will be further scanned and require at least one SPKI pin (specified in
	// CertValidationPins) be present in the chain.
	CertValidateSPKIPinAnyDefault

	// CertValidateSPKIPinFirst will check the first (leaf) certificate of the site
	// uses an SPKI specified in CertValidationPins.  Since the leaf certificate is
	// explicitly checked, full certificate chain validation is not performed. This is
	// only useful for self-signed certificate usages, where you expect a specific
	// single certificate to be presented by the site.
	CertValidateSPKIPinFirst

	// CertValidationCloudfront uses a limited root CAs certificate store particular to
	// the root CAs used for Cloudfront sites. Only use this method if you are
	// exclusively accessing Cloudfront-fronted websites.
	CertValidationCloudfront
)

// Configuration of Strongcomms client
type Config struct {
	// UseCloudflareDOH, when true, will configure default Cloudflare DOH support
	UseCloudflareDOH bool

	// UseGoogleDOH, when true, will configure default Google DOH support
	UseGoogleDOH bool

	// TimeoutDOH controls DOH lookup timeout; if not set, DefaultTimeoutDOH will be used
	TimeoutDOH time.Duration

	// TimeoutHTTPSTotal controls total HTTPS request timeout; if not set,
	// DefaultTimeoutHTTPSTotal will be used
	TimeoutHTTPSTotal time.Duration

	// TimeoutHTTPSSetup controls setup/request phase HTTPS timeout; if not set,
	// DefaultTimeoutHTTPSSetup will be used
	TimeoutHTTPSSetup time.Duration

	// CertValidationType indicates the type of certificate validation to perform for
	// HTTPS requests
	CertValidationType CertValidationType

	// CertValidationPins specifies one or more SPKI hashes (SHA256), when using
	// CertValidateSPKIPinAnyDefault or CertValidateSPKIPinFirst CertValidationType types.
	CertValidationPins [][]byte

	// ProxyConfig specifies an optional HTTP/HTTPS proxy configuration. The default nil
	// value will use the system standard http.ProxyFromEnvironment().  To explicitly
	// disable all proxies (i.e. override the environment values), create a ProxyConfig
	// with an empty ProxyUrl value.
	//
	// Special note: certificate validation of HTTPS proxies is shared with the
	// validation configuration for HTTPS websites. Please see LIMITATIONS documentation
	// regarding configuration nuances and conflicting settings for proxy HTTPS and website
	// HTTPS certificate validation.
	ProxyConfig *ProxyConfig
}

// Proxy configuration of Strongcomms client
type ProxyConfig struct {
	// ProxyUrl should specify a proxy address value that is compatible to the format
	// documented in http.ProxyFromEnvironment(). Setting an empty string value is
	// the equivalent to explicitly disabling all proxy support (including ignoring
	// any values set in the environment).
	Url string

	// ProxyCertsPEM, if not empty, can contain one or more PEM-encoded certificates. The
	// PEM-encoded certificates will be decoded and added into the TLS certificate pools.
	//
	// Special note: certificate validation of HTTPS proxies is shared with the
	// validation configuration for HTTPS websites. Please see LIMITATIONS documentation
	// regarding configuration nuances and conflicting settings for proxy HTTPS and website
	// HTTPS certificate validation.
	CertsPEM []byte
}

type dohCacheEntry struct {
	timeout time.Time
	ips     []net.IP
}

// Create a new Strongcomms client, using the specified Config.
func New(cfg Config) (*Client, error) {

	// Sanity check the config & weave in default values
	if cfg.TimeoutDOH == 0 {
		cfg.TimeoutDOH = DefaultTimeoutDOH
	}
	if cfg.TimeoutHTTPSTotal == 0 {
		cfg.TimeoutHTTPSTotal = DefaultTimeoutHTTPSTotal
	}
	if cfg.TimeoutHTTPSSetup == 0 {
		cfg.TimeoutHTTPSSetup = DefaultTimeoutHTTPSSetup
	}

	// Create our default DOH cert pool
	dohCertPool := x509.NewCertPool()
	if !dohCertPool.AppendCertsFromPEM(CertsDOH) {
		return nil, errors.New("Unable to load DOH certs")
	}

	// SPECIAL: if custom HTTPS proxy certs are being used, we need to add them to
	// the DOH cert pool too, so DOH looks work through the proxy.
	if cfg.ProxyConfig != nil && cfg.ProxyConfig.Url != "" && len(cfg.ProxyConfig.CertsPEM) > 0 {
		if !dohCertPool.AppendCertsFromPEM(cfg.ProxyConfig.CertsPEM) {
			return nil, errors.New("Unable to load proxy certs into DOH cert pool")
		}
	}

	// Resolve what proxy we are going to use
	proxy := http.ProxyFromEnvironment
	if cfg.ProxyConfig != nil {

		if cfg.ProxyConfig.Url == "" { // Empty string explicitly means no proxy
			proxy = nil

		} else { // Explicitly set the proxy
			url, err := url.Parse(cfg.ProxyConfig.Url)
			if err != nil {
				return nil, errors.New("Unable to parse proxy URL: " + err.Error())
			}
			proxy = http.ProxyURL(url)
		}
	}

	c := &Client{}

	// The HTTP client used for DOH requests:
	c.ClientDOH = &http.Client{
		Timeout: cfg.TimeoutDOH,
		Transport: &http.Transport{
			MaxIdleConns:          1,
			IdleConnTimeout:       cfg.TimeoutDOH,
			DisableCompression:    false,
			TLSHandshakeTimeout:   cfg.TimeoutDOH,
			ResponseHeaderTimeout: cfg.TimeoutDOH,
			Proxy:                 proxy,
			TLSClientConfig: &tls.Config{
				MinVersion:         DefaultTLSMinVersion,
				CurvePreferences:   DefaultCurvePreferences,
				CipherSuites:       DefaultCipherSuites,
				RootCAs:            dohCertPool,
				ClientSessionCache: tls.NewLRUClientSessionCache(2),
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				doh, ok := ctx.Value(contextKeyDOH).(*DOHServer)
				if !ok {
					return nil, errors.New("No DOH context")
				}

				// Specifically switch the lookup to IPv4:
				if strings.HasPrefix(network, "tcp") {
					network = "tcp4"
				}

				// If we are using a proxy, we need to dial the proxy, not the DOH server
				dialAddr := doh.Dial
				if proxy != nil && urlIsProxied(proxy, doh.Url) { //  NOTE: proxy is a closure variable
					dialAddr = addr
				}

				// NOTE: net.DialTimeout will use normal DNS to resolve DOH server hostnames:
				if c.TraceCallback != nil {
					c.TraceCallback(fmt.Sprintf("%s Dial %s:%s", TagDOH, network, dialAddr))
				}
				return net.DialTimeout(network, dialAddr, doh.Timeout)
			},
		},
	}

	// The HTTP client used for normal website requests
	c.ClientHTTPS = &http.Client{
		Timeout: cfg.TimeoutHTTPSTotal,
		Transport: &http.Transport{
			MaxIdleConns:          4,
			IdleConnTimeout:       cfg.TimeoutHTTPSSetup,
			DisableCompression:    false,
			TLSHandshakeTimeout:   cfg.TimeoutHTTPSSetup,
			ResponseHeaderTimeout: cfg.TimeoutHTTPSSetup,
			Proxy:                 proxy,
			// NOTE: TLSClientConfig set below
			// NOTE: DialContext set below
		},
	}

	c.cache = lru.New(DefaultCacheSize)

	// SPECIAL NOTE: We are going to install a custom Dialer, which uses our DOH client for DNS lookups
	// rather than the normal system-based DNS lookup. But it is worth explaining how things work when
	// a proxy is involved:
	// - When no proxy, dial will be for website hostname, thus DOH will look up website address
	// - When proxy is used, dial will be for proxy hostname (DOH will be used to look up proxy address),
	//   and then website name is provided to the proxy for the proxy to resolve however it choosed.
	// In other words, using a proxy effectively gives the proxy control of the DNS lookup, and likely
	// it is not using DOH. See LIMITATIONS document.

	// Due to closure references, we now create a closure that references the prior created Client
	var tr *http.Transport = c.ClientHTTPS.Transport.(*http.Transport)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {

		// We need to parse the hostname in order to perform a DOH lookup (rather than
		// the normal system-based DNS lookup)

		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}

		// Specifically switch the lookup to IPv4:
		if strings.HasPrefix(network, "tcp") {
			network = "tcp4"
		}

		// If the host is an IP address, we do not need a DOH lookup -- just go direct
		var ip net.IP
		if ip = net.ParseIP(host); ip != nil {
			if c.TraceCallback != nil {
				c.TraceCallback(fmt.Sprintf("%s Dial %s:%s", TagClient, network, addr))
			}
			return net.DialTimeout(network, addr, cfg.TimeoutHTTPSSetup)
		}

		// Look up (IPv4) IP addresses via DOH
		ips, err := c.LookupIP(host) // Our own DOH lookup
		if err != nil {
			return nil, err
		}

		// Sequentially try each returned IP address, until we get a valid connection
		var conn net.Conn
		for _, ip = range ips {
			if ip.To4() == nil {
				continue
			}

			addr := net.JoinHostPort(ip.String(), port)
			if c.TraceCallback != nil {
				c.TraceCallback(fmt.Sprintf("%s Dial %s:%s", TagClient, network, addr))
			}
			conn, err = net.DialTimeout(network, addr, cfg.TimeoutHTTPSSetup)
			if err == nil {
				return conn, err
			}
			// Errored, try next IP (loop)
		}

		// If we get here, we got no IPs or did not connect
		if len(ips) == 0 {
			return nil, errors.New("Unable to resolve hostname")
		}
		return nil, errors.New("Unable to dial/connect")
	}

	// Now we need to configure our TLS client values.
	// NOTE: keep in mind these values are shared between HTTPS website validation and
	// HTTPS proxy connection!

	var err error
	tr.TLSClientConfig = &tls.Config{
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
		MinVersion:         DefaultTLSMinVersion,
		CurvePreferences:   DefaultCurvePreferences,
		CipherSuites:       DefaultCipherSuites,
	}

	usingSystemCertPool := false

	switch cfg.CertValidationType {
	case CertValidationDefault:
		// Go uses system cert pool be default.
		usingSystemCertPool = true

	case CertValidationDisable:
		// WARNING: this disabled cert validation for both websites and
		// HTTPS proxy connections
		tr.TLSClientConfig.InsecureSkipVerify = true

	case CertValidateSPKIPinAnyDefault:
		// Use system root CA certs, and then add PIN enforcement on top
		// NOTE: HTTPS proxies need their pins added to the pin list
		usingSystemCertPool = true
		tr.DialTLS, err = makePinnedDialer(c, &cfg)
		if err != nil {
			return nil, err
		}

	case CertValidateSPKIPinFirst:
		// Disable certificate verification, and then add PIN enforcement
		// of the first (leaf) cert
		// NOTE: HTTPS proxies need their pins added to the pin list
		tr.TLSClientConfig.InsecureSkipVerify = true
		tr.DialTLS, err = makePinnedDialer(c, &cfg)
		if err != nil {
			return nil, err
		}

	case CertValidationCloudfront:
		// Use a custom RootCA pool having just Cloudfront certs
		cloudfrontCertPool := x509.NewCertPool()
		if !cloudfrontCertPool.AppendCertsFromPEM(CertsCloudfront) {
			return nil, errors.New("Unable to load Cloudfront certs")
		}

		// SPECIAL: if custom HTTPS proxy certs are being used, we need to add them to
		// the cloudfront cert pool too
		if cfg.ProxyConfig != nil && cfg.ProxyConfig.Url != "" && len(cfg.ProxyConfig.CertsPEM) > 0 {
			if !cloudfrontCertPool.AppendCertsFromPEM(cfg.ProxyConfig.CertsPEM) {
				return nil, errors.New("Unable to load proxy certs into RootCA cert pool")
			}
		}

		tr.TLSClientConfig.RootCAs = cloudfrontCertPool

	default:
		return nil, errors.New("Bad cert validation type")
	}

	if usingSystemCertPool {
		// We don't have to do anything special if using system cert pool, unless we are using
		// a proxy and need to append our custom certs to the pool.
		if cfg.ProxyConfig != nil && cfg.ProxyConfig.Url != "" && len(cfg.ProxyConfig.CertsPEM) > 0 {
			if err = AppendPEMCert(cfg.ProxyConfig.CertsPEM, c.ClientHTTPS); err != nil {
				return nil, err
			}
		}
	}

	// Now add in pre-made DOH server configurations, if requested
	if cfg.UseCloudflareDOH {
		/*

			Note: we no longer use 1.1.1.1 due to still-happening misconfigurations
			in routing encountered on networks like AT&T/MVNOs, etc.  The following URLs
			are old, but highlight the nature of the problem that is still present
			(circa 2020, encountered by the author) in select carrier networks.

			https://blog.cloudflare.com/fixing-reachability-to-1-1-1-1-globally/
			https://arstechnica.com/information-technology/2018/05/att-is-blocking-cloudflares-privacy-focused-dns-calls-it-an-accident/

			c.DOHServers = append(c.DOHServers, &DOHServer{
				Timeout: cfg.TimeoutDOH,
				Url:     "https://cloudflare-dns.com/dns-query",
				Dial:    "1.1.1.1:443",
			})
		*/

		c.DOHServers = append(c.DOHServers, &DOHServer{
			Timeout: cfg.TimeoutDOH,
			Url:     "https://cloudflare-dns.com/dns-query",
			Dial:    "1.0.0.1:443",
		})
	}
	if cfg.UseGoogleDOH {
		c.DOHServers = append(c.DOHServers, &DOHServer{
			Timeout: cfg.TimeoutDOH,
			Url:     "https://dns.google/dns-query",
			Dial:    "8.8.8.8:443",
		})
		c.DOHServers = append(c.DOHServers, &DOHServer{
			Timeout: cfg.TimeoutDOH,
			Url:     "https://dns.google/dns-query",
			Dial:    "8.8.4.4:443",
		})
	}

	return c, nil
}

func urlIsProxied(proxy func(*http.Request) (*url.URL, error), testUrl string) bool {

	url, err := url.Parse(testUrl)
	if err != nil {
		return false
	}

	req := &http.Request{
		Method: "GET",
		URL:    url,
	}

	proxyUrl, _ := proxy(req)
	return proxyUrl != nil
}

type Dialer func(network, addr string) (net.Conn, error)

var ErrorTLSPinViolation error = errors.New("TLS pin violation")

func makePinnedDialer(s *Client, cfg *Config) (Dialer, error) {

	if len(cfg.CertValidationPins) == 0 {
		return nil, errors.New("Pin(s) required")
	}
	for _, pin := range cfg.CertValidationPins {
		if len(pin) != 32 { // SHA256 == 32 bytes
			return nil, errors.New("Bad pin length")
		}
	}
	s.HTTPSPins = cfg.CertValidationPins

	return func(network, addr string) (net.Conn, error) {

		// Do a TLS dial using the ClientHTTPS client config
		var tr *http.Transport = s.ClientHTTPS.Transport.(*http.Transport)
		c, err := tls.DialWithDialer(&net.Dialer{
			Timeout:   cfg.TimeoutHTTPSSetup,
			KeepAlive: cfg.TimeoutHTTPSSetup,
		}, network, addr, tr.TLSClientConfig)
		if err != nil {
			return c, err
		}

		// Now iterate through the certificates, and see if any match our pins
		pinned := false
		cs := c.ConnectionState()
		for _, chain := range cs.VerifiedChains {
			for _, cert := range chain {

				hash, err := GetCertificatePin(cert)
				if err != nil {
					return c, err
				}

				// Check each of our pins
				for _, pin := range s.HTTPSPins {
					if bytes.Equal(hash, pin) {
						pinned = true
						goto done
					}

					if s.TraceCallback != nil {
						s.TraceCallback(fmt.Sprintf("TLS Pin %s: %v", cert.Subject, hash))
					}
				}
				// If we matched, or we only wanted to check first cert, we are done
				if cfg.CertValidationType == CertValidateSPKIPinFirst {
					break
				}
			}
		}
	done:

		// Did we match a pin?
		if pinned == false {
			return c, ErrorTLSPinViolation
		}

		// Matched, pass through the connection
		return c, nil
	}, nil
}

// AppendPEMCert is a convenience function to add the provided PEM-encoded
// certificate to the provided HTTP client's root CA certificate pool. It should
// be used in conjuction with Client.ClientDOH and Client.ClientHTTPS.
func AppendPEMCert(pem []byte, client *http.Client) error {
	var tr *http.Transport = client.Transport.(*http.Transport)
	if tr == nil {
		return errors.New("HTTP transport required")
	}
	if tr.TLSClientConfig == nil {
		return errors.New("An explicit TLSClientConfig is required")
	}

	// If the config is using the default system cert pool, we need to
	// explicitly copy the pool in order to append
	if tr.TLSClientConfig.RootCAs == nil {
		tr.TLSClientConfig.RootCAs, _ = x509.SystemCertPool()
	}
	if tr.TLSClientConfig.RootCAs == nil {
		tr.TLSClientConfig.RootCAs = x509.NewCertPool()
	}

	if !tr.TLSClientConfig.RootCAs.AppendCertsFromPEM(pem) {
		return errors.New("Unable to load cert into RootCA cert pool")
	}

	return nil
}

// GetCertificatePin is a convenience function to provide a SHA256 hash of
// a certificate's SPKI
func GetCertificatePin(cert *x509.Certificate) ([]byte, error) {

	// Hash the public SPKI
	der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(der)
	return hash[:], nil
}

// Override the resolution for the given hostname. This will create a non-expiring
// cache entry for the give hostname. If the list of IPs is empty/nil, then the
// existing cache entry (static or otherwise) will be removed.
func (s *Client) SetCache(hostname string, ips []net.IP) {
	// Make sure hostname is normalized and ends with trailing period
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if len(ips) > 0 {
		s.cache.Add(hostname, &dohCacheEntry{
			ips:     ips,
			timeout: time.Now().Add(10 * time.Hour * 24 * 365), // 10 years
		})
	} else {
		s.cache.Remove(hostname)
	}
}

// Legacy function that simply calls TestNetworkWithContext() using a calculated
// timeout of DefaultTimeoutDOH * the number of configured DOH servers.
func (s *Client) TestNetwork() bool {
	if len(s.DOHServers) == 0 {
		return false
	}
	timeout := DefaultTimeoutDOH * time.Duration(len(s.DOHServers))

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	return s.TestNetworkWithContext(ctx)
}

// Utility function to 'test' the network by attempting a TCP connection (IPv4) to
// the configured DOH server(s). This function will internally keep trying until
// either a successful connection is made, or the given context triggers a timeout,
// deadline, or cancel.
func (s *Client) TestNetworkWithContext(ctx context.Context) bool {

	if len(s.DOHServers) == 0 {
		return false
	}

	// We need a new dialer for DialContext use
	dialer := net.Dialer{
		Timeout:       DefaultTimeoutNetworkTest,
		FallbackDelay: -1,
	}

	// Run until success or context timeout/deadline/cancel occurs
	for {
		for _, dohServer := range s.DOHServers {
			if s.TraceCallback != nil {
				s.TraceCallback(fmt.Sprintf("%s Attempting TCP test connection to %s", TagNetworkTest, dohServer.Dial))
			}

			conn, err := dialer.DialContext(ctx, "tcp4", dohServer.Dial)
			if err == nil {
				// Connected, network is good
				conn.Close()
				return true
			}

			if err == context.Canceled || err == context.DeadlineExceeded {
				// Context says we are done
				if s.TraceCallback != nil {
					s.TraceCallback(fmt.Sprintf("%s Context cancelled/timed out", TagNetworkTest))
				}
				return false
			}

			// Swallow all other errors and try next one
			// Loop...
		}
	}
}

// Lookup up IP addresses (A records/IPv4) for the given hostname.  Meant to be
// similar to net.LookupIP() (minus the IPv6 support).
func (s *Client) LookupIP(hostname string) ([]net.IP, error) {
	var err error
	var body []byte

	// If hostname is already an IP address, just return it:
	var ip net.IP
	if ip = net.ParseIP(hostname); ip != nil {
		ip = ip.To4()
		if ip != nil {
			return []net.IP{ip}, nil
		}
		return nil, errors.New("IPv6 not supported")
	}

	// Make sure hostname is normalized and ends with trailing period
	// NOTE: hostname serves as our cache key
	hostname = strings.ToLower(hostname)
	if !strings.HasSuffix(hostname, ".") {
		hostname += "."
	}

	if entry, ok := s.cache.Get(hostname); ok {
		dohEntry := entry.(*dohCacheEntry)
		if time.Now().Before(dohEntry.timeout) {
			atomic.AddUint32(&s.CountDOHCacheHits, 1)
			return dohEntry.ips, nil // Not yet expired, use it
		}
		s.cache.Remove(hostname) // Entry is expired, remove it
	}

	q := dnsmessage.Question{
		Type:  dnsmessage.TypeA,
		Class: dnsmessage.ClassINET,
	}
	if q.Name, err = dnsmessage.NewName(hostname); err != nil {
		return nil, err
	}

	// FUTURE-TODO: RFC7871 EDNS0 Client Subnet, and
	// DNSSEC support

	id, err := rand.Int(rand.Reader, big.NewInt(65535))
	if err != nil {
		return nil, err
	}
	msg := dnsmessage.Message{
		Header: dnsmessage.Header{
			ID:               uint16(id.Int64()),
			RecursionDesired: true,
		},
		Questions: []dnsmessage.Question{q},
	}

	if body, err = msg.Pack(); err != nil {
		return nil, err
	}

	s.l.Lock()
	currentServers := s.DOHServers
	s.l.Unlock()

	var responseBody []byte
	var dohServer *DOHServer
	for _, dohServer = range currentServers {

		request, err := http.NewRequest("POST", dohServer.Url, bytes.NewBuffer(body))
		if err != nil {
			// Error in request construction is likely a configuration problem,
			// so abort (for error feedback) rather than continuing to
			// next sever in list
			return nil, err
		}
		request.Header.Del("User-Agent") // Do not expose our user-agent/version
		request.Header.Add("Accept", appDNSMessage)
		request.Header.Add("Content-Type", appDNSMessage)
		request.ContentLength = int64(len(body))

		ctx, cancel := context.WithTimeout(context.Background(), dohServer.Timeout)
		ctx = context.WithValue(ctx, contextKeyDOH, dohServer)
		request = request.WithContext(ctx)

		atomic.AddUint32(&s.CountDOHRequests, 1)
		response, err := s.ClientDOH.Do(request)

		if err != nil {
			atomic.AddUint32(&s.CountDOHResponseErrors, 1)
			if response != nil && response.Body != nil {
				response.Body.Close() // Cleanup resources
			}

			if s.TLSErrorCallback != nil {
				// Decipher the error reason; security violations get special treatment

				if ue, ok := err.(*url.Error); ok { // BUGFIX: Unwrap any url.Error:
					err = ue.Err
				}

				if uaErr, ok := err.(x509.UnknownAuthorityError); ok {
					s.TLSErrorCallback(TagDOH, "UnknownAuthority", uaErr.Cert)
				} else if ciErr, ok := err.(x509.CertificateInvalidError); ok {
					s.TLSErrorCallback(TagDOH, "CertificateInvalid", ciErr.Cert)
				} else if hnErr, ok := err.(x509.HostnameError); ok {
					s.TLSErrorCallback(TagDOH, "HostnameInvalid", hnErr.Certificate)
				}
			}

			if s.DOHErrorCallback != nil {
				s.DOHErrorCallback(TagDOH, hostname, err)
			}

			cancel()
			continue
		}

		if response.TLS != nil && response.TLS.DidResume {
			atomic.AddUint32(&s.CountDOHResumed, 1)
		}

		if response.StatusCode != 200 || !strings.Contains(response.Header.Get("Content-Type"), appDNSMessage) {
			atomic.AddUint32(&s.CountDOHResponseErrors, 1)
			response.Body.Close() // Cleanup resources
			cancel()
			continue
		}

		// Read the body
		// NOTE: we should technically use a limiting reader here, but we are
		// doing to accept the risk given we do not expect the DOH server to
		// DoS us by returning a large response.
		responseBody, err = ioutil.ReadAll(response.Body)
		response.Body.Close()
		cancel() // All done with request
		if err != nil || len(responseBody) == 0 {
			atomic.AddUint32(&s.CountDOHResponseErrors, 1)
			continue
		}

		if s.DateCallback != nil {
			tm := parseDate(response.Header.Get("Date"))
			if !tm.IsZero() {
				s.DateCallback(tm)
			}
		}

		break // We got a response, so we do not need to loop to next server
	}

	// Did we get a response?
	if len(responseBody) == 0 {
		atomic.AddUint32(&s.CountDOHOperationalErrors, 1)
		return nil, errors.New(TagDOH + " no answers for " + hostname)
	}

	// Parse the response (a DNS message)
	var p dnsmessage.Parser
	var responseHeader dnsmessage.Header
	if responseHeader, err = p.Start(responseBody); err != nil {
		atomic.AddUint32(&s.CountDOHParsingErrors, 1)
		return nil, err
	}

	if responseHeader.RCode != dnsmessage.RCodeSuccess {
		atomic.AddUint32(&s.CountDOHOperationalErrors, 1)
		return nil, errors.New(TagDOH + " lookup returned non-success")
	}
	if !responseHeader.Response {
		atomic.AddUint32(&s.CountDOHOperationalErrors, 1)
		return nil, errors.New(TagDOH + " response was not marked as response")
	}
	if responseHeader.ID != msg.Header.ID {
		atomic.AddUint32(&s.CountDOHOperationalErrors, 1)
		return nil, errors.New(TagDOH + " lookup returned bad ID")
	}
	if responseHeader.Truncated {
		atomic.AddUint32(&s.CountDOHOperationalErrors, 1)
		return nil, errors.New(TagDOH + " response was truncated")
	}

	if err = p.SkipAllQuestions(); err != nil {
		atomic.AddUint32(&s.CountDOHParsingErrors, 1)
		return nil, err
	}

	// Now parse answers
	var hostIPs []net.IP
	var ttl uint32
	for {
		ah, err := p.AnswerHeader()
		if err == dnsmessage.ErrSectionDone {
			break
		}
		if err != nil {
			atomic.AddUint32(&s.CountDOHParsingErrors, 1)
			return hostIPs, err
		}

		if ah.Type != q.Type || ah.Class != q.Class {
			if err = p.SkipAnswer(); err != nil {
				atomic.AddUint32(&s.CountDOHParsingErrors, 1)
				return hostIPs, err
			}
			continue
		}

		if !strings.EqualFold(ah.Name.String(), hostname) {
			if err = p.SkipAnswer(); err != nil {
				atomic.AddUint32(&s.CountDOHParsingErrors, 1)
				return hostIPs, err
			}
			continue
		}

		if ah.Type == dnsmessage.TypeA {
			r, err := p.AResource()
			if err != nil {
				atomic.AddUint32(&s.CountDOHParsingErrors, 1)
				return hostIPs, err
			}
			hostIPs = append(hostIPs, r.A[:])
			ttl = ah.TTL
		}
	}

	// Cache this answer, factoring in the TTL vs. our minimum cache time
	if len(hostIPs) > 0 {
		expire := time.Now()
		ttlDuration := time.Second * time.Duration(ttl)
		if ttlDuration > DefaultMinimumDOHCacheTime {
			expire = expire.Add(ttlDuration)
		} else {
			expire = expire.Add(DefaultMinimumDOHCacheTime)
		}
		s.cache.Add(hostname, &dohCacheEntry{
			ips:     hostIPs,
			timeout: expire,
		})
	}

	// Since this DOH server gave us a parseable answer, move it to the front
	// of the line for next time
	if currentServers[0] != dohServer {
		newServers := make([]*DOHServer, 0, len(currentServers))
		newServers = append(newServers, dohServer)
		for _, s := range currentServers {
			if s == dohServer {
				continue
			}
			newServers = append(newServers, s)
		}

		s.l.Lock()
		s.DOHServers = newServers
		s.l.Unlock()
	}

	return hostIPs, nil
}

// Perform an HTTP(S) request, similar to http.Client.Do().
func (s *Client) Do(r *http.Request) (*http.Response, error) {

	resp, err := s.ClientHTTPS.Do(r)

	// Intercept and report certain errors
	if err != nil && s.TLSErrorCallback != nil {

		if ue, ok := err.(*url.Error); ok { // BUGFIX: Unwrap any url.Error:
			err = ue.Err
		}

		if uaErr, ok := err.(x509.UnknownAuthorityError); ok {
			s.TLSErrorCallback(TagClient, "UnknownAuthority", uaErr.Cert)
		} else if ciErr, ok := err.(x509.CertificateInvalidError); ok {
			s.TLSErrorCallback(TagClient, "CertificateInvalid", ciErr.Cert)
		} else if hnErr, ok := err.(x509.HostnameError); ok {
			s.TLSErrorCallback(TagClient, "HostnameInvalid", hnErr.Certificate)
		} else if err == ErrorTLSPinViolation {
			s.TLSErrorCallback(TagClient, "PinViolation", nil)
		}
	}

	// Otherwise pass through
	return resp, err
}

// Establish the concept of current time using DOH servers.
// This is meant for IoT devices with no RTC, that must securely
// set the time (and prefer to not use NTP). Passed-in time
// can be zero-time or time.Now(), and is assumed to potentially
// be inaccurate (just taken as a starting point).
func (s *Client) GetTime(tm time.Time) (time.Time, error) {
	return s.GetTimeWithContext(tm, context.Background())
}

func (s *Client) GetTimeWithContext(tm time.Time, ctx context.Context) (time.Time, error) {

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(CertsDOH) {
		return tm, errors.New("Unable to load DOH certs")
	}

	// TODO: use multiple sources and correlate, to avoid a single-source
	// cert compromise
	var err error
	if tm, err = s.getTimeSingle(tm, "https://cloudflare-dns.com/", "1.0.0.1:443", certPool, ctx); err == nil {
		return tm, nil
	}
	return s.getTimeSingle(tm, "https://dns.google/", "8.8.8.8:443", certPool, ctx)
}

func (s *Client) getTimeSingle(tm time.Time, u, hostAddr string, roots *x509.CertPool, ctx context.Context) (time.Time, error) {

	tmPtr := &tm

	tlsConfig := &tls.Config{
		MinVersion:       DefaultTLSMinVersion,
		CurvePreferences: DefaultCurvePreferences,
		CipherSuites:     DefaultCipherSuites,
		RootCAs:          roots,
		Time: func() time.Time {
			if s.TraceCallback != nil {
				s.TraceCallback(fmt.Sprintf("%s Using custom time:%v", TagNetworkTime, *tmPtr))
			}
			return *tmPtr
		},
	}

	client := &http.Client{
		Timeout: DefaultTimeoutDOH,
		Transport: &http.Transport{
			MaxIdleConns:          1,
			IdleConnTimeout:       DefaultTimeoutDOH,
			DisableCompression:    false,
			TLSHandshakeTimeout:   DefaultTimeoutDOH,
			ResponseHeaderTimeout: DefaultTimeoutDOH,
			Proxy:                 http.ProxyFromEnvironment,
			TLSClientConfig:       tlsConfig,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				dialer := net.Dialer{}
				return dialer.DialContext(ctx, "tcp4", hostAddr)
			},
		},
	}

	for tries := 0; tries < 8; tries++ {
		// Construct new request
		request, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return *tmPtr, err
		}
		request.Header.Del("User-Agent") // Do not expose our user-agent/version

		ctx2, cancel := context.WithTimeout(ctx, DefaultTimeoutDOH)
		request = request.WithContext(ctx2)

		// Do the actual request
		response, err := client.Do(request)
		cancel()
		if response != nil && response.Body != nil {
			response.Body.Close()
		}

		if err == nil {
			// A successful request indicates a time that led to a validated cert
			// chain...but it may not be the current time.  Now use the Date header to
			// find the actual current time.

			if s.TraceCallback != nil {
				s.TraceCallback(fmt.Sprintf("%s Time usable for connection:%v", TagNetworkTime, *tmPtr))
			}

			tm2 := parseDate(response.Header.Get("Date"))
			if tm2.IsZero() {
				return *tmPtr, errors.New("Response did not include usable date")
			}
			if s.TraceCallback != nil {
				s.TraceCallback(fmt.Sprintf("%s Time from server:%v", TagNetworkTime, tm2))
			}
			return tm2, nil
		}

		if ue, ok := err.(*url.Error); ok { // BUGFIX: Unwrap any url.Error:
			err = ue.Err
		}

		if ciErr, ok := err.(x509.CertificateInvalidError); ok {
			if ciErr.Reason == x509.Expired {
				if ciErr.Cert != nil && tmPtr.Before(ciErr.Cert.NotBefore) {
					tmTmp := ciErr.Cert.NotBefore.Add(1 * time.Second)
					tmPtr = &tmTmp
					if s.TraceCallback != nil {
						s.TraceCallback(fmt.Sprintf("%s Using certificate not-before time:%v", TagNetworkTime, tmTmp))
					}
					continue
				}

				if s.TraceCallback != nil {
					s.TraceCallback(fmt.Sprintf("%s Certificate expired error did not include cert", TagNetworkTime))
				}
			} else if s.TraceCallback != nil {
				s.TraceCallback(fmt.Sprintf("%s Certificate error other than expired: %v", TagNetworkTime, err.Error()))
			}
		} else if s.TraceCallback != nil {
			s.TraceCallback(fmt.Sprintf("%s Non-certificate error %T:%v", TagNetworkTime, err, err.Error()))
		}

		// Whatever error we got, we cannot recover -- so we are done
		return *tmPtr, err
	}

	return *tmPtr, nil
}

func parseDate(date string) time.Time {
	var t time.Time

	if date == "" {
		return t
	}

	layouts := []string{time.RFC1123, time.RFC850, time.ANSIC, time.UnixDate,
		time.RFC822, time.RFC822Z, time.RFC1123Z}

	for _, layout := range layouts {
		tm, err := time.Parse(layout, date)
		if err == nil {
			return tm
		}
	}

	return t
}
