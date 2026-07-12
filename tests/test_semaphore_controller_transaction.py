from enum import Enum, auto
from pathlib import Path

import pytest
import yaml


ROOT = Path(__file__).resolve().parents[1]
ROLE = "roles/semaphore_controller"


def read(path: str) -> str:
    return (ROOT / path).read_text(encoding="utf-8")


def load_yaml(path: str):
    return yaml.safe_load(read(path))


def tasks_in(path: str) -> list[dict]:
    return load_yaml(f"{ROLE}/tasks/{path}")


def task_named(path: str, name: str) -> dict:
    return next(task for task in tasks_in(path) if task["name"] == name)


def nested_tasks(path: str):
    def walk(tasks):
        for task in tasks:
            yield task
            for section in ("block", "rescue", "always"):
                yield from walk(task.get(section, []))

    return list(walk(tasks_in(path)))


def nested_task_named(path: str, name: str) -> dict:
    return next(task for task in nested_tasks(path) if task["name"] == name)


class RolloutState(Enum):
    PREFLIGHT = auto()
    BACKED_UP = auto()
    MIGRATED = auto()
    SWITCHED = auto()
    HEALTHY = auto()
    ROLLED_BACK = auto()


class RolloutFixture:
    def __init__(self) -> None:
        self.state = RolloutState.PREFLIGHT
        self.backup_id: str | None = None
        self.rollback_count = 0

    def upload_backup(self, backup_id: str, succeeds: bool = True) -> None:
        if not succeeds:
            raise RuntimeError("encrypted upload failed")
        self.backup_id = backup_id
        self.state = RolloutState.BACKED_UP

    def migrate(self) -> None:
        if self.state is not RolloutState.BACKED_UP:
            raise RuntimeError("migration requires an uploaded backup")
        self.state = RolloutState.MIGRATED

    def switch(self) -> None:
        if self.state is not RolloutState.MIGRATED:
            raise RuntimeError("switch requires migration")
        self.state = RolloutState.SWITCHED

    def mark_healthy(self) -> None:
        if self.state is not RolloutState.SWITCHED:
            raise RuntimeError("health requires switch")
        self.state = RolloutState.HEALTHY

    def rollback(self, backup_id: str) -> None:
        if backup_id != self.backup_id:
            raise RuntimeError("rollback backup is not the preceding backup")
        self.rollback_count += 1
        self.state = RolloutState.ROLLED_BACK

    def publish_evidence(self, succeeds: bool = True) -> None:
        if not succeeds:
            raise RuntimeError("evidence upload failed")


def test_fixture_refuses_migration_before_successful_encrypted_upload():
    rollout = RolloutFixture()

    with pytest.raises(RuntimeError, match="uploaded backup"):
        rollout.migrate()
    with pytest.raises(RuntimeError, match="encrypted upload failed"):
        rollout.upload_backup("20260711T120000000000000Z", succeeds=False)

    assert rollout.state is RolloutState.PREFLIGHT


def test_fixture_uses_exact_preceding_backup_for_rollback():
    rollout = RolloutFixture()
    rollout.upload_backup("20260711T120000000000000Z")
    rollout.migrate()

    with pytest.raises(RuntimeError, match="preceding backup"):
        rollout.rollback("20260710T120000000000000Z")

    rollout.rollback("20260711T120000000000000Z")
    assert rollout.state is RolloutState.ROLLED_BACK


def test_fixture_does_not_roll_back_healthy_service_for_evidence_failure():
    rollout = RolloutFixture()
    rollout.upload_backup("20260711T120000000000000Z")
    rollout.migrate()
    rollout.switch()
    rollout.mark_healthy()

    with pytest.raises(RuntimeError, match="evidence upload failed"):
        rollout.publish_evidence(succeeds=False)

    assert rollout.state is RolloutState.HEALTHY
    assert rollout.rollback_count == 0


def test_transaction_order_is_fail_closed_and_evidence_is_outside_rescue():
    deploy = read(f"{ROLE}/tasks/deploy.yml")
    transaction_end = deploy.index("always:")

    assert deploy.index("include_tasks: backup.yml") < deploy.index("migrate")
    assert deploy.index("migrate") < deploy.index("state: link")
    assert deploy.index("state: link") < deploy.index("state: restarted")
    assert deploy.index("state: restarted") < deploy.index("/api/ping")
    assert "include_tasks: rollback.yml" in deploy
    assert deploy.index("deployment evidence") > transaction_end
    assert deploy.index("semaphore-backup.timer") > transaction_end


def test_backup_is_encrypted_and_uploaded_before_state_allows_migration():
    backup = read(f"{ROLE}/tasks/backup.yml")

    assert backup.index("pg_dump") < backup.index("age")
    assert backup.index("age") < backup.index("amazon.aws.s3_object")
    assert backup.index("amazon.aws.s3_object") < backup.index("BACKED_UP")
    assert "--format=custom" in backup
    assert "no_log: true" in backup
    assert "always:" in backup
    assert "state: absent" in backup


def test_backup_and_rollback_keep_secrets_out_of_argv_and_restore_everything():
    backup = read(f"{ROLE}/tasks/backup.yml")
    rollback = read(f"{ROLE}/tasks/rollback.yml")

    assert "ANSIBLE_BACKUP_AGE_IDENTITY" not in backup
    assert "ANSIBLE_BACKUP_AGE_IDENTITY" not in rollback
    assert "semaphore_controller_transaction_environment.age_identity" in rollback
    assert "no_log: true" in rollback
    assert "pg_restore" in rollback
    assert "semaphore_controller_config_dir" in rollback
    assert "semaphore_controller_current_path" in rollback
    assert "state: link" in rollback
    assert "state: restarted" in rollback
    assert "http://127.0.0.1:3000/api/ping" in rollback
    assert "always:" in rollback
    assert "state: absent" in rollback


def test_backup_staging_allows_postgres_traversal_without_exposing_secrets():
    directories = task_named("backup.yml", "Create protected Semaphore backup directories")
    assert all(isinstance(item, dict) for item in directories["loop"])
    staging = next(
        item
        for item in directories["loop"]
        if item["path"] == "{{ semaphore_controller_backup_staging_root }}"
    )
    transaction = nested_task_named(
        "backup.yml", "Create Semaphore transaction staging directory"
    )["ansible.builtin.file"]
    database = nested_task_named(
        "backup.yml", "Create postgres-only Semaphore database dump directory"
    )["ansible.builtin.file"]
    secrets = nested_task_named(
        "backup.yml", "Create root-only Semaphore secret staging directory"
    )["ansible.builtin.file"]

    assert staging == {
        "path": "{{ semaphore_controller_backup_staging_root }}",
        "owner": "root",
        "group": "postgres",
        "mode": "0710",
    }
    assert transaction["owner"] == "root"
    assert transaction["group"] == "postgres"
    assert transaction["mode"] == "0710"
    assert database["owner"] == "postgres"
    assert database["group"] == "postgres"
    assert database["mode"] == "0700"
    assert secrets["owner"] == "root"
    assert secrets["group"] == "root"
    assert secrets["mode"] == "0700"
    assert "semaphore_controller_backup_database_path" in read(
        f"{ROLE}/tasks/backup.yml"
    )
    assert "semaphore_controller_backup_secret_path" in read(
        f"{ROLE}/tasks/backup.yml"
    )


def test_rollback_staging_separates_postgres_restore_from_root_only_plaintext():
    staging = nested_task_named(
        "rollback.yml", "Create protected Semaphore rollback staging directory"
    )["ansible.builtin.file"]
    database = nested_task_named(
        "rollback.yml", "Create postgres-only Semaphore restore directory"
    )["ansible.builtin.file"]
    secrets = nested_task_named(
        "rollback.yml", "Create root-only Semaphore decrypt directory"
    )["ansible.builtin.file"]
    rollback = read(f"{ROLE}/tasks/rollback.yml")

    assert staging["owner"] == "root"
    assert staging["group"] == "postgres"
    assert staging["mode"] == "0710"
    assert database["owner"] == "postgres"
    assert database["group"] == "postgres"
    assert database["mode"] == "0700"
    assert secrets["owner"] == "root"
    assert secrets["group"] == "root"
    assert secrets["mode"] == "0700"
    assert "semaphore_controller_rollback_database_path" in rollback
    assert "semaphore_controller_rollback_secret_path" in rollback
    assert rollback.index("always:") < rollback.index(
        "Delete Semaphore rollback plaintext and age identity"
    )


def test_database_restore_terminates_connections_then_recreates_exact_database():
    rollback = read(f"{ROLE}/tasks/rollback.yml")
    terminate = nested_task_named(
        "rollback.yml", "Terminate active Semaphore database connections"
    )["ansible.builtin.command"]["argv"]
    drop = nested_task_named("rollback.yml", "Drop changed Semaphore database")
    create = nested_task_named("rollback.yml", "Recreate exact Semaphore database")
    restore = nested_task_named(
        "rollback.yml", "Restore exact Semaphore PostgreSQL backup"
    )

    assert rollback.index("Stop Semaphore before rollback restore") < rollback.index(
        "Terminate active Semaphore database connections"
    )
    assert rollback.index("Terminate active Semaphore database connections") < (
        rollback.index("Drop changed Semaphore database")
    )
    assert rollback.index("Drop changed Semaphore database") < rollback.index(
        "Recreate exact Semaphore database"
    )
    assert rollback.index("Recreate exact Semaphore database") < rollback.index(
        "Restore exact Semaphore PostgreSQL backup"
    )
    assert terminate[0] == "psql"
    assert "pg_terminate_backend" in str(terminate)
    assert drop["ansible.builtin.command"]["argv"] == [
        "dropdb",
        "--if-exists",
        "{{ semaphore_controller_database_name }}",
    ]
    assert create["ansible.builtin.command"]["argv"] == [
        "createdb",
        "--owner",
        "{{ semaphore_controller_database_user }}",
        "--encoding",
        "UTF8",
        "--template",
        "template0",
        "{{ semaphore_controller_database_name }}",
    ]
    restore_argv = restore["ansible.builtin.command"]["argv"]
    assert restore_argv[:6] == [
        "pg_restore",
        "--exit-on-error",
        "--no-owner",
        "--role",
        "{{ semaphore_controller_database_user }}",
        "--dbname",
    ]
    assert "--clean" not in restore_argv
    assert "ansible.builtin.shell" not in rollback


def test_explicit_rollback_is_one_shot_and_exact():
    defaults = load_yaml(f"{ROLE}/defaults/main.yml")
    main = read(f"{ROLE}/tasks/main.yml")
    rollback = read(f"{ROLE}/tasks/rollback.yml")

    assert defaults["semaphore_controller_rollback_mode"] is False
    assert defaults["semaphore_controller_rollback_backup_id"] == ""
    assert "semaphore_controller_rollback_mode" in main
    assert "semaphore_controller_deployment_state_path" in rollback
    assert "semaphore_controller_rollback_marker_path" in rollback
    assert "semaphore_controller_rollback_backup_id" in rollback
    assert "include_tasks: rollback.yml" in main
    assert "Clear consumed Semaphore rollback marker" in main


def test_daily_timer_is_verified_and_backup_script_never_migrates():
    deploy = read(f"{ROLE}/tasks/deploy.yml")
    service = read(f"{ROLE}/templates/semaphore-backup.service.j2")
    timer = read(f"{ROLE}/templates/semaphore-backup.timer.j2")
    script = read(f"{ROLE}/templates/semaphore-backup.sh.j2")

    assert "systemd-analyze" in deploy
    assert "verify" in deploy
    assert "NextElapseUSecRealtime" in deploy
    assert "semaphore-backup.timer" in deploy
    assert "OnCalendar=" in timer
    assert "Persistent=true" in timer
    assert "ExecStart={{ semaphore_controller_backup_script_path }}" in service
    assert "pg_dump" in script
    assert "age" in script
    assert "boto3" in script
    assert "semaphore_controller_backup_prefix" in script
    assert "trap cleanup EXIT" in script
    assert "migrate" not in script.lower()


def test_deployment_record_is_redacted_and_uploaded_after_health():
    deploy = read(f"{ROLE}/tasks/deploy.yml")
    evidence = task_named("deploy.yml", "Upload redacted Semaphore deployment evidence")

    assert deploy.index("/api/ping") < deploy.index("deployment evidence")
    assert evidence["no_log"] is True
    serialized = str(evidence)
    assert "SEMAPHORE_DB_PASSWORD" not in serialized
    assert "ANSIBLE_BACKUP_AGE_IDENTITY" not in serialized
    assert "secret_key:" in deploy
