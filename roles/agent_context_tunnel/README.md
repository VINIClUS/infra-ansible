# agent_context_tunnel

Reconciles the Cloudflare side of the Agent Context stack through the Cloudflare
v4 API (`ansible.builtin.uri`, on localhost). The stack is exposed only through a
Cloudflare Tunnel plus Cloudflare Access: no host port, no Caddy change.

| Object | Reconciled by | Rule |
| --- | --- | --- |
| Remotely managed tunnel (`config_src: cloudflare`) | name | created only when absent, never recreated |
| Tunnel ingress configuration | tunnel id | one rule `hostname -> origin service` plus `http_status:404`; PUT only on drift |
| Proxied DNS CNAME | hostname | `<tunnel id>.cfargotunnel.com`; create/PATCH only on drift; any other record for the name fails the run |
| Access application (self-hosted) | exact domain | short session; created/updated only on drift |
| Access policies | exact name, per application | `non_identity` for the service token only; optional `allow` for `agent_context_tunnel_allowed_emails` |
| Access service token | exact name | created only when absent; rotated only with `agent_context_tunnel_rotate_service_token: true` |

Disabled by default (`agent_context_tunnel_enabled: false`). The playbook is
deliberately not in the deploy boundary's allowlist or any workflow: an operator
runs it by hand, first with `--check`.

Nothing is ever deleted: the role never sends a DELETE, and other tunnels, DNS
records, applications and policies are never touched. A human policy that
already exists is left in place if the email list is later emptied.

## Variables

Required (asserted non-empty): `agent_context_tunnel_api_token` (defaults to
`cloudflare_api_token`), `agent_context_tunnel_account_id` (defaults to
`cloudflare_account_id`), `agent_context_tunnel_zone_id` (defaults to
`cloudflare_zone_id`) and `agent_context_tunnel_hostname` (for example
`agent-context.example.com`).

Optional: `agent_context_tunnel_name` (`agent-context`),
`agent_context_tunnel_origin_service` (`http://ingress:8080`, the stack's internal
Nginx over its Docker network), `agent_context_tunnel_origin_request` (extra
`originRequest` keys; `noTLSVerify` is refused), `agent_context_tunnel_allowed_emails`
(`[]`), `agent_context_tunnel_session_duration` (`30m`),
`agent_context_tunnel_service_token_name`.

## Credentials output

When a secret would be produced (tunnel or service token absent, or rotation
requested) `agent_context_tunnel_credentials_output` must be an absolute,
normalized path on localhost. The run fails before creating anything if it is
empty, if the directory does not exist, if the file already exists, or if the
path is inside a git work tree. The file is written with mode 0600 right after the
secrets are obtained, holds the tunnel token and the service token id, client id
and client secret, and is meant to be moved into the private inventory vault and
removed. The `client_secret` is only returned by Cloudflare at creation or rotation.

## Check mode

`--check` performs only GETs (forced with `check_mode: false`), makes no
POST/PUT/PATCH and writes no file, and reports the changes a real run would make.

## Safety

Every task that carries the Authorization header or a secret is `no_log: true`.
Supply the real API token from the vault or the environment (`cloudflare_api_token`) and never with `-e` on the command line: high verbosity echoes extra vars.
Failures surface only the Cloudflare error codes and messages. The API base URL
must be exactly `https://api.cloudflare.com/client/v4` (a loopback URL is accepted only for the local fake API used by the tests).
