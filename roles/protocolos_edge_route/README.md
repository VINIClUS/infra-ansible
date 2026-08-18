# Protocolos edge route

This disabled-by-default role manages only the public edge route for VM 104,
`SistemaDeProtocolos`. When enabled by private inventory, it accepts only the
pinned domain, upstream, VM identity, Let's Encrypt certificate paths, and
Nginx site paths declared in its defaults.

The role never invokes certificate issuance or renewal. It requires the
existing certificate's sole DNS SAN to be `protocolos.portosoftware.com.br`
and requires `certbot.timer` to be enabled before any Nginx change.

The installed site returns an exact HTTP 301 redirect to HTTPS and proxies all
TLS paths to `http://192.168.1.199:80`. The transaction keeps a timestamped
backup, restores the prior vhost and `sites-enabled` symlink state on any
failure, then revalidates and reloads Nginx before reporting that failure.
