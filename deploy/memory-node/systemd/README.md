# Memory Node units

Install the application under `/opt/kivra-memory/app`, place service environment
files under `/etc/kivra-memory`, and copy the units to `/etc/systemd/system`.
Persistent database and node-agent state belongs below
`/mnt/memory/kivra-memory`; the units refuse to start without that mount.

The API listens on loopback by default. TLS and request routing are provided by
the separately managed reverse proxy, not by an Nginx package in this container.
When that proxy runs on another host or container, set `KIVRA_MEMORY_HOST` to a
private interface address reachable by the proxy and restrict the port to the
proxy and operator networks with the host firewall. Never bind the canonical
node directly to a public interface.

The API unit starts the Debian PostgreSQL 17 cluster dependency. The node-agent
unit is installed but should remain disabled until relay enrollment is
implemented. Worker, ingress, exporter, and timer units will be added with their
runnable entry points so deployment never advertises an unimplemented service.
