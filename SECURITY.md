# Security policy

## Threat model (read this first)

md-review is a **personal, unauthenticated** review tool. Its entire security
story is a network boundary: it serves only clients on your local network
(loopback, RFC-1918 private, link-local, IPv6 ULA), refuses everything else
with no opt-out flag, and adds browser-attack tripwires (Content-Type
enforcement, Origin/Sec-Fetch-Site rejection, Host validation) so that
internet web pages open in a LAN browser cannot write to it.

Anyone who can reach the server **can read every document and post/resolve
comments**. Anyone who can POST can re-render over an existing document
(provenance — which namespaces doc ids — is client-asserted by design, so a
LAN peer can compute a known doc's id and replace its page, inheriting its
comment thread). Do not expose it beyond networks whose members you trust
with your documents.

**Never put md-review behind a public reverse proxy, load balancer, or
source-NAT** — proxied clients arrive as loopback/private and the guard
cannot detect that. For remote access, use a VPN (Tailscale, WireGuard);
VPN clients pass the guard naturally.

## Reporting a vulnerability

If you find a boundary escape (a way for a non-LAN client or an internet
web page to read or write), that's the highest-severity class — please
report it privately via GitHub's security advisory feature on the
repository. Include the request shape and what it achieved; a curl
reproduction is ideal.

Given the threat model above, the following are *accepted* properties, not
bugs: no authentication or authorization, comments editable/resolvable by
any LAN client, client-asserted provenance, and readability of every doc by
every LAN client.

## Supported versions

Only the latest minor release receives security fixes.
