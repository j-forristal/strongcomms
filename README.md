# strongcomms
Security-minded communications for Go.  Primary goal is to exclusively
use HTTPS/TLS for everything, providing both security and privacy for
common network needs (DNS, NTP, etc).

The functionality includes:

- DNS-over-HTTPS (DOH) client (RFC8484), biased to Cloudflare and Google
servers, and utilizing an internal cache.

- An HTTPS client, using DOH for DNS lookups, that includes various methods
to verify the server/server certificate (system roots, custom roots, pins,
etc). Specific support is provided for Cloudfront and Cloudflare, a la
CDN domain-fronting style obfuscation of traffic destination.

- A method to bootstrap receiving current date/time over HTTPS (instead of
via NTP), for IoT/RTC-challenged devices. The process is more complicated
than it sounds, because you need a reasonably accurate concept of time
in order to correctly validate the HTTPS certificate chain and get to the
point where you can trust the date/time provided to you.

The code is generally concurrency safe for use, but not for live changes
to Client object while running concurrent to lookup/request operations.
