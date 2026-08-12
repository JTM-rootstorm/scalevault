# NPM drift and external exposure

Run this after every NPM edit, restore, image upgrade, Access List change,
certificate change, or public-exposure alert.

1. Record installed NPM/OpenResty versions and immutable image digest where
   available. Obtain the complete generated `nginx -T` into protected scratch.
   Run the static checker against that exact protected capture:

   ```bash
   /usr/local/libexec/kivra-memory-npm-config-check /absolute/protected/nginx-T.conf
   ```

   A pass proves only the checker's bounded static contract; complete the live
   checks below.
2. Verify exactly one generated `/mcp` Custom Location, one deny-only
   application-path catch-all, a closed loopback default upstream, and only the
   static ACME exception. Block Common Exploits and Force SSL must be disabled.
3. Verify the host has exactly one `set_real_ip_from unix:;` and
   `real_ip_recursive off;`; inspect all global/includes for address rewriting,
   `proxy_protocol`, `geo`, and `map` interactions.
4. Verify exact private HTTP backend, port 8443, one `proxy_pass`, source-only
   Access List with `satisfy all`, authorization preservation, reconstructed
   bounded headers, disabled retry/redirect/buffering/cache/gzip/access log, and
   request/lifetime caps.
5. From an unapproved external source, probe baseline plus `Forwarded`,
   `X-Forwarded-For`, and `X-Real-IP` spoofs while a temporary backend firewall
   counter observes connections. Every probe must be rejected at the edge and
   produce zero backend connections.
6. From an approved source, exact HTTPS `/mcp` without credentials must reach
   the uniform application `401`. Invalid path, query, trailing slash, client
   HTTP, and unsupported methods must produce fixed rejection without redirect
   or backend contact as applicable.
7. Scan bounded NPM/container output and service journals for synthetic payload
   and credential canaries; remove protected scratch and the temporary counter.

Any spoof changing edge rejection into backend `401`, any public backend reach,
unexpected redirect, generated-config count drift, or canary match is an
activation blocker. Disable the Proxy Host or Codex ingress as appropriate and
follow [Incident response](incident-alerts.md).
