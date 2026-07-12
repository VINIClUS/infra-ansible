# Cloudflare Access application

This localhost role reconciles two self-hosted Cloudflare Access applications
without deleting or changing unrelated Access resources. The catch-all
`ansible.vinisantana.com` application has one identity policy that allows only
`me@vinisantana.com`. The role lists the selected account or zone's identity
providers, requires exactly one provider whose API type is `onetimepin`, and
pins the human application to only that provider with automatic identity
redirect enabled. A missing or ambiguous One-Time PIN provider fails before
any application mutation. The more-specific
`ansible.vinisantana.com/api/ping` application has one `non_identity` policy
that matches only the configured Access service-token resource ID.

Set exactly one of `cloudflare_access_account_id` or
`cloudflare_access_zone_id`, set the non-secret
`cloudflare_access_service_token_id` from private inventory, and provide the
API token only as `CLOUDFLARE_API_TOKEN`. The API token needs Access Apps and
Policies write permission for the selected scope.

The role lists applications with Cloudflare API v4's exact-domain query,
creates missing resources, and updates drift only after matching exact domain
and policy names. Duplicate managed domains or names fail closed. It never
deletes applications or policies. Every bearer-token request is `no_log` and
discards response content; only managed resource IDs are retained as Ansible
facts.

The role validates the fully rendered two-application contract before its
first API call. Overridden names, domains, application types, session duration,
policy decisions, email/service-token rules, or policy shape are rejected.
