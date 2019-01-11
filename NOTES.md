Circa 12/10/18, the following information was known to be true:

- dns.google.com SSL (via Qualys SSL Labs) supports:
	- TLS 1.2; ECDHE_(RSA/ECDSA)_AES128-GCM-SHA256, ECDHE_(RSA/ECDSA)_AES256-GCM-SHA384
	- Certs chain to:
		- Google Internet Authority G3 (Pin SHA256: f8NnEFZxQ4ExFOhSN7EiFWtiudZQVD2oY60uauV/n78=)
		- GlobalSign (Pin SHA256: iie1VXtL7HzAMF+/PVPR9xzT80kQxdZeJ+zduCB3uj0=)

- cloudflare-dns.com SSL (via Qualys SSL Labs)
	- TLS 1.2; ECDHE_(RSA/ECDSA)_AES128-GCM-SHA256, ECDHE_(RSA/ECDSA)_AES256-GCM-SHA384
	- Certs chain to:
		- DigiCert ECC Secure Server CA (Pin SHA256: PZXN3lRAy+8tBKk2Ox6F7jIlnzr2Yzmwqc3JnyfXoCw=)
		- DigiCert Global Root CA (Pin SHA256: r/mIkG3eEpVdm+u/ko/cwxzOMo1bk4TyHIlByibiA5E=)

- (custom).cloudfront.net with AWS-native certificates (via Qualys SSL Labs)
	- SAN for (wildcard).cloudfront.net
	- TLS 1.2; ECDHE_RSA_AES128-GCM-SHA256, ECDHE_RSA_AES256-GCM-SHA384
	- Certs chain to:
		- DigiCert Global CA G2 (Pin SHA256: njN4rRG+22dNXAi+yb8e3UMypgzPUPHlv4+foULwl1g=)
		- DigiCert Global Root G2 (Pin SHA256: i7WTqTvh0OioIruIfFR4kMPnBqrS2rdiVPl/s2uC/CY=)
		- VeriSign Class 3 Public Primary Certification Authority - G5 (Pin SHA256: JbQbUG5JMJUoI6brnx0x3vZF6jilxsapbXGVfjhN8Fg=)


