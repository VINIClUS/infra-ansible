# proxmox_readonly

Read-only contract validation for Proxmox template consumers. This role is a
guardrail for future live checks and must not clone, start, stop, delete, or
modify VMs, CTs, storage, firewall, or network configuration.
