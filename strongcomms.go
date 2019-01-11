/*
** Copyright (c) 2018 J Forristal LLC
** All Rights Reserved.
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
	"strings"
	"sync/atomic"
	"time"

	"github.com/j-forristal/strongcomms/lru"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	contextKeyDOH = "sc_doh"
	appDNSMessage = "application/dns-message"

	TagDOH    = "DOH"
	TagClient = "Client"
)

var (
	DefaultTimeoutDOH          = 30 * time.Second
	DefaultTimeoutHTTPSTotal   = 15 * time.Minute
	DefaultTimeoutHTTPSSetup   = 60 * time.Second
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
	DateCallback              func(t time.Time)
	CountDOHCacheHits         uint32
	CountDOHRequests          uint32
	CountDOHResponseErrors    uint32
	CountDOHParsingErrors     uint32
	CountDOHOperationalErrors uint32
	CountDOHResumed           uint32
	CountHTTPSResumed         uint32
	cache                     *lru.Cache
}

type DOHServer struct {
	Url     string
	Dial    string
	Timeout time.Duration
}

type CertValidationType int

const (
	CertValidationDefault CertValidationType = iota
	CertValidationDisable
	CertValidateSPKIPinAnyDefault
	CertValidateSPKIPinFirst
	CertValidationCloudfront
)

type Config struct {
	UseCloudflareDOH   bool
	UseGoogleDOH       bool
	TimeoutDOH         time.Duration
	TimeoutHTTPSTotal  time.Duration
	TimeoutHTTPSSetup  time.Duration
	CertValidationType CertValidationType
	CertValidationPins [][]byte
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

	dohCertPool := x509.NewCertPool()
	if !dohCertPool.AppendCertsFromPEM(CertsDOH) {
		return nil, errors.New("Unable to load DOH certs")
	}

	c := &Client{
		ClientDOH: &http.Client{
			Timeout: cfg.TimeoutDOH,
			Transport: &http.Transport{
				MaxIdleConns:          1,
				IdleConnTimeout:       cfg.TimeoutDOH,
				DisableCompression:    false,
				TLSHandshakeTimeout:   cfg.TimeoutDOH,
				ResponseHeaderTimeout: cfg.TimeoutDOH,
				Proxy: http.ProxyFromEnvironment,
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
					if strings.HasPrefix(network, "tcp") {
						network = "tcp4"
					}
					return net.DialTimeout(network, doh.Dial, doh.Timeout)
				},
			},
		},

		ClientHTTPS: &http.Client{
			Timeout: cfg.TimeoutHTTPSTotal,
			Transport: &http.Transport{
				MaxIdleConns:          4,
				IdleConnTimeout:       cfg.TimeoutHTTPSSetup,
				DisableCompression:    false,
				TLSHandshakeTimeout:   cfg.TimeoutHTTPSSetup,
				ResponseHeaderTimeout: cfg.TimeoutHTTPSSetup,
				Proxy: http.ProxyFromEnvironment,
				// NOTE: DialContext set below, in closure
			},
		},

		cache: lru.New(DefaultCacheSize),
	}

	// Due to closure references, we now create a closure that references the prior created Client
	var tr *http.Transport = c.ClientHTTPS.Transport.(*http.Transport)
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		var ip net.IP
		if ip = net.ParseIP(host); ip != nil {
			return net.DialTimeout(network, addr, cfg.TimeoutHTTPSSetup)
		}
		if strings.HasPrefix(network, "tcp") {
			network = "tcp4"
		}

		var conn net.Conn
		ips, err := c.LookupIP(host) // Our own DOH lookup
		if err != nil {
			return nil, err
		}
		for _, ip = range ips {
			if ip.To4() == nil {
				continue
			}
			conn, err = net.DialTimeout(network, net.JoinHostPort(ip.String(), port), cfg.TimeoutHTTPSSetup)
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

	var err error
	tr.TLSClientConfig = &tls.Config{
		ClientSessionCache: tls.NewLRUClientSessionCache(0),
		MinVersion:         DefaultTLSMinVersion,
		CurvePreferences:   DefaultCurvePreferences,
		CipherSuites:       DefaultCipherSuites,
	}

	switch cfg.CertValidationType {
	case CertValidationDefault:
		// Nothing else to do, use system root CA certs // Fallthrough

	case CertValidationDisable:
		tr.TLSClientConfig.InsecureSkipVerify = true

	case CertValidateSPKIPinAnyDefault:
		// Use system root CA certs
		tr.DialTLS, err = makePinnedDialer(c, &cfg)
		if err != nil {
			return nil, err
		}

	case CertValidateSPKIPinFirst:
		tr.TLSClientConfig.InsecureSkipVerify = true
		tr.DialTLS, err = makePinnedDialer(c, &cfg)
		if err != nil {
			return nil, err
		}

	case CertValidationCloudfront:
		cloudfrontCertPool := x509.NewCertPool()
		if !cloudfrontCertPool.AppendCertsFromPEM(CertsCloudfront) {
			return nil, errors.New("Unable to load Cloudfront certs")
		}
		tr.TLSClientConfig.RootCAs = cloudfrontCertPool

	default:
		return nil, errors.New("Bad cert validation type")
	}

	if cfg.UseCloudflareDOH {
		c.DOHServers = append(c.DOHServers, &DOHServer{
			Timeout: cfg.TimeoutDOH,
			Url:     "https://cloudflare-dns.com/dns-query",
			Dial:    "1.1.1.1:443",
		})
		c.DOHServers = append(c.DOHServers, &DOHServer{
			Timeout: cfg.TimeoutDOH,
			Url:     "https://cloudflare-dns.com/dns-query",
			Dial:    "1.0.0.1:443",
		})
	}
	if cfg.UseGoogleDOH {
		c.DOHServers = append(c.DOHServers, &DOHServer{
			Timeout: cfg.TimeoutDOH,
			Url:     "https://dns.google.com/experimental",
			Dial:    "dns.google.com:443",
		})
	}

	return c, nil
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

				// Hash the public SPKI
				der, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
				if err != nil {
					return c, err
				}
				hash := sha256.Sum256(der)

				// Check each of our pins
				for _, pin := range s.HTTPSPins {
					if bytes.Equal(hash[:], pin) {
						pinned = true
						goto done
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

// Lookup up IP addresses (A records/IPv4) for the given hostname.  Meant to be
// similar to net.LookupIP() (minus the IPv6 support).
func (s *Client) LookupIP(hostname string) ([]net.IP, error) {
	var err error
	var body []byte

	// BUGFIX: if hostname is already an IP address, just return it:
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
	var responseBody []byte
	var dohServer *DOHServer
	for _, dohServer = range s.DOHServers {

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
				if uaErr, ok := err.(*x509.UnknownAuthorityError); ok {
					s.TLSErrorCallback(TagDOH, "UnknownAuthority", uaErr.Cert)
				} else if ciErr, ok := err.(*x509.CertificateInvalidError); ok {
					s.TLSErrorCallback(TagDOH, "CertificateInvalid", ciErr.Cert)
				} else if hnErr, ok := err.(*x509.HostnameError); ok {
					s.TLSErrorCallback(TagDOH, "HostnameInvalid", hnErr.Certificate)
				}
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
		return nil, errors.New("No DOH answers")
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
		return nil, errors.New("DOH lookup returned non-success")
	}
	if !responseHeader.Response {
		atomic.AddUint32(&s.CountDOHOperationalErrors, 1)
		return nil, errors.New("DOH response was not marked as response")
	}
	if responseHeader.ID != msg.Header.ID {
		atomic.AddUint32(&s.CountDOHOperationalErrors, 1)
		return nil, errors.New("DOH lookup returned bad ID")
	}
	if responseHeader.Truncated {
		atomic.AddUint32(&s.CountDOHOperationalErrors, 1)
		return nil, errors.New("DOH response was truncated")
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
	if s.DOHServers[0] != dohServer {
		currentServers := s.DOHServers
		newServers := make([]*DOHServer, len(currentServers))
		newServers = append(newServers, dohServer)
		for _, s := range s.DOHServers {
			if s == dohServer {
				continue
			}
			newServers = append(newServers, s)
		}
		s.DOHServers = newServers
	}

	return hostIPs, nil
}

// Perform an HTTP(S) request, similar to http.Client.Do().
func (s *Client) Do(r *http.Request) (*http.Response, error) {

	resp, err := s.ClientHTTPS.Do(r)

	// Intercept and report certain errors
	if err != nil && s.TLSErrorCallback != nil {
		if uaErr, ok := err.(*x509.UnknownAuthorityError); ok {
			s.TLSErrorCallback(TagClient, "UnknownAuthority", uaErr.Cert)
		} else if ciErr, ok := err.(*x509.CertificateInvalidError); ok {
			s.TLSErrorCallback(TagClient, "CertificateInvalid", ciErr.Cert)
		} else if hnErr, ok := err.(*x509.HostnameError); ok {
			s.TLSErrorCallback(TagClient, "HostnameInvalid", hnErr.Certificate)
		} else if err == ErrorTLSPinViolation {
			s.TLSErrorCallback(TagClient, "PinViolation", nil)
		}
	}

	// Otherwise pass through
	return resp, err
}

// Establish the concept of current time using Cloudflare servers.
// This is meant for IoT devices with no RTC, that must securely
// set the time (and prefer to not use NTP). Passed-in time
// can be zero-time, time.Now(), and is assumed to potentially
// be inaccurate (just taken as a starting point).
func (s *Client) GetTime(tm time.Time) (time.Time, error) {

	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(CertsCloudflare) {
		return tm, errors.New("Unable to load Cloudflare certs")
	}

	// TODO: use multiple sources and correlate, to avoid a single-source
	// cert compromise

	return s.getTimeSingle(tm, "https://1.1.1.1/", certPool)
}

func (s *Client) getTimeSingle(tm time.Time, url string, roots *x509.CertPool) (time.Time, error) {

	tlsConfig := &tls.Config{
		MinVersion:       DefaultTLSMinVersion,
		CurvePreferences: DefaultCurvePreferences,
		CipherSuites:     DefaultCipherSuites,
		RootCAs:          roots,
		Time:             func() time.Time { return tm },
	}

	client := &http.Client{
		Timeout: DefaultTimeoutHTTPSTotal,
		Transport: &http.Transport{
			MaxIdleConns:          1,
			IdleConnTimeout:       DefaultTimeoutHTTPSSetup,
			DisableCompression:    false,
			TLSHandshakeTimeout:   DefaultTimeoutHTTPSSetup,
			ResponseHeaderTimeout: DefaultTimeoutHTTPSTotal,
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: tlsConfig,
		},
	}

	for tries := 0; tries < 8; tries++ {
		request, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return tm, err
		}
		request.Header.Del("User-Agent") // Do not expose our user-agent/version

		ctx, cancel := context.WithTimeout(context.Background(), DefaultTimeoutHTTPSTotal)
		request = request.WithContext(ctx)

		response, err := client.Do(request)
		if err != nil {
			cancel()
			if response != nil && response.Body != nil {
				response.Body.Close() // Cleanup resources
			}
			if ciErr, ok := err.(*x509.CertificateInvalidError); ok {
				if ciErr.Reason == x509.Expired {
					if ciErr.Cert != nil && ciErr.Cert.NotBefore.After(tm) {
						tm = ciErr.Cert.NotBefore.Add(1 * time.Second)
						continue
					}
				}
			}

			// Whatever error we got, we cannot recover -- so we are done
			return tm, err
		}
		cancel()
		response.Body.Close()

		// A successful request indicates a time that led to a validated cert
		// chain...but it may not be current.  Now use the Date header to
		// find the actual current time.

		tm2 := parseDate(response.Header.Get("Date"))
		if tm2.IsZero() {
			return tm, errors.New("Response did not include usuable date")
		}
		tm = tm2
		break
	}

	return tm, nil
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
