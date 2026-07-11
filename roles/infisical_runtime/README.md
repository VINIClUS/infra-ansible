# infisical_runtime

Validates the runtime secret contract for Infisical without storing or printing
secret values. Live API checks are disabled by default and require a token from
the operator environment.

The repository `.env.example` documents authentication names only. Before any
create-only synchronization, validate the remote workspace ID, expected project
slug, environment and explicit secret path. Colliding names must be preserved;
do not use the inventory workspace as an implicit fallback.
