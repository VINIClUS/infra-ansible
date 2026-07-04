# bootstrap_bridge

Validates a sibling bootstrap repository path and optional pinned ref before a
domain-specific playbook delegates work to that repository.

This role does not execute destructive bootstrap commands. Domain playbooks must
add explicit tasks, tags, and operator approvals for real changes.
