# minio_artifacts

Validates the MinIO bucket contract for artifacts, backups, and validation
evidence. Access keys (`minio_access_key`/`minio_secret_key`) must come from
infra-ansible-inventory's ansible-vault, never from tracked files.

When `minio_validate_access` is enabled, the role performs a read-only bucket
listing and verifies that every declared bucket is visible. It does not create
buckets or objects.
