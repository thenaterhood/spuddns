spuddns
============

spuddns is a caching DNS resolver similar to systemd-resolved.
It attempts to proactively keep commonly used DNS queries in its cache
so that clients are more likely to receive a cached (faster) response
to their queries, and will hold actively-used DNS responses in its cache if the upstream resolver(s) have failed.

It also supports prometheus metrics, and basic ACLs.

spuddns can use both standard and DNS-over-HTTPS (DoH) endpoints as 
upstream resolvers, and can server DNS over DNS, DNS over TLS, and DNS
over HTTP (DNS over HTTPS can be achieved by putting spuddns behind an
HTTPS server).

**This is not a production-ready software**


Usage
============

Build spuddns with `go build`. An ArchLinux PKGBUILD is also provided
and can be found in the "dist" directory.

You can use spuddns in place of systemd-resolved or similar on your system. A systemd service file is provided, located in the "dist"
directory. This service file assumes spuddns will be installed to
/usr/bin/spuddns and the config file to /etc/spuddns.json.

Default installation: Start spuddns. By default your /etc/resolv.conf will be respected. If you intend to use spuddns as your local 
resolver, update the resolv conf path in /etc/spuddns.json to point to 
the resolv.conf generated by your DHCP client (such as
/var/run/NetworkManager/resolv.conf if you use NetworkManager), then 
replace /etc/resolv.conf with a file pointing to localhost
(`nameserver 127.0.0.1`).

You can also use spuddns to serve DNS to your network.

If you're setting up DNS over HTTPS, you can place spuddns behind a
standard webserver software such as nginx, or behind a provider such
as Cloudflare.

In either case, you can find an example configuration file 
demonstrating all spuddns configuration options in
spuddns.example.json and specific details about each option in the
app/config.go file.

Note that if you configure spuddns to use a DNS over HTTPS endpoint
by hostname as its upstream resolver and you're using spuddns as the
system's primary resolver, you MUST also provide (either directly in
the spuddns config, or by using your DHCP client's resolv conf) an IP
address endpoint for a resolver, otherwise it will be impossible to
resolve the DNS over HTTPS endpoint and your DNS will not work.

A systemd service file is provided.