# Edge proxy route

This role owns only the `ansible.vinisantana.com` Nginx server block on the
existing edge proxy. It listens on the existing HTTP and HTTPS origin ports and
forwards requests, including WebSocket upgrades, to the stable Ansible
controller address on port 3000.

Set `edge_proxy_route_controller_address` to the controller's stable private
IPv4 address in the RFC1918 `10/8`, `172.16/12`, or `192.168/16` ranges. The
role rejects non-canonical, public, loopback, link-local, multicast, and
unspecified addresses, any domain other than `ansible.vinisantana.com`, and an
upstream other than the derived HTTP endpoint on port 3000.

The role renders a candidate, compares it with the managed file, creates a
timestamped backup when the route changes, and atomically moves the candidate
into place. A chained handler runs `nginx -t` before it can notify the reload.
Known-Host `/api/ping` must return exactly HTTP 200 and `pong`; an unknown Host
must continue to return HTTP 404. Any validation or probe failure restores the
preceding file (or removes a newly introduced file), validates and reloads that
restored state, and then fails the play.

The template never declares `default_server`. The existing catch-all server on
CT 110 remains solely responsible for explicit unknown-host 404 responses.
Timestamped route backups are retained for operator-managed pruning.
