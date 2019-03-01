
## Proxy and HTTPS validation interactions

The Golang HTTP client intermixes the proxy setup code and the direct request code for HTTP(s) clients.

When using an HTTPS connection to a proxy (herein 'HTTPS proxy') and then requesting an HTTPS website
(effectively doing HTTPS over HTTPS), the single TLSConfig is shared both TLS negotiations.

That means your Strongcomms certificate validation configuration needs to be appropriate for both the
HTTPS connection to the proxy and the HTTPS connection to the website.  Further, you must use the same
type of certificate validation for both (cannot mix and match).

Some nuances to keep in mind:

* If you are using CertValidationDefault or CertValidationCloudfront, any certificates added to
ProxyConfig.CertsPEM will be added to the shared certificate pool as valid root CAs. To prevent
your proxy from being a MitM, be sure your proxy certificate is sufficiently limited in scope.

* If you CertValidationDisable for one, you CertValidationDisable for both proxy and HTTPS client.

* If you use CertValidateSPKIPinAnyDefault, you must add pins for your proxy certificate too.

Strengthening how HTTPS connections via HTTPS proxies work (can be made individually secure)  will
be an on-going area of evolution in the next few releases of Strongcomms. 
