"""Pure DynamoDB control-plane key builders."""

from datetime import datetime

MEMBERSHIP = "MEMBERSHIP"


def key_component(value: str) -> str:
    """Codifica componente preservando ordem e removendo ambiguidade."""
    return value.encode().hex()


def tenant_partition(tenant_id: str) -> str:
    """Cria a partição base do tenant."""
    return f"TENANT#{key_component(tenant_id)}"


def global_partition() -> str:
    """Cria a partição global com prefixo de tenant."""
    return "TENANT#_GLOBAL"


def run_partition(tenant_id: str, run_id: str) -> str:
    """Cria a partição agregada do run."""
    return f"{tenant_partition(tenant_id)}#RUN#{key_component(run_id)}"


def raw_partition(tenant_id: str, source_type: str, file_subtype: str, competencia: str) -> str:
    """Cria a partição base de uma identidade raw."""
    identity = "#".join(map(key_component, (source_type, file_subtype, competencia)))
    return f"{tenant_partition(tenant_id)}#RAW#{identity}"


def raw_manifest_lookup_key(tenant_id: str, manifest_id: str) -> tuple[str, str]:
    """Cria a projeção forte e imutável por ID do manifesto."""
    return entity_key(tenant_id, "RAW_MANIFEST", manifest_id)


def raw_resync_key(partition: str, agent_id: str) -> tuple[str, str]:
    """Cria a chave forte do marcador de resync do agente."""
    return partition, f"RESYNC#{key_component(agent_id)}"


def entity_key(tenant_id: str, entity: str, identifier: str) -> tuple[str, str]:
    """Cria a chave base de uma entidade do tenant."""
    return tenant_partition(tenant_id), f"{entity}#{key_component(identifier)}"


def certificate_key(tenant_id: str, serial: str) -> tuple[str, str]:
    """Args:
        tenant_id: identificador do tenant.
        serial: serial opaco do certificado.
    Returns:
        Chave base (partição, ordenação) do certificado.
    """
    return entity_key(tenant_id, "CERT", serial)


def membership_key(tenant_id: str, user_id: str) -> tuple[str, str]:
    """Cria a chave base da membership do usuário no tenant."""
    return entity_key(tenant_id, MEMBERSHIP, user_id)


def run_entity_key(tenant_id: str, run_id: str) -> tuple[str, str]:
    """Cria a chave base de um run."""
    return entity_key(tenant_id, "RUN", run_id)


def unit_key(tenant_id: str, run_id: str, unit_id: str) -> tuple[str, str]:
    """Cria a chave base de uma unidade."""
    return run_partition(tenant_id, run_id), f"UNIT#{key_component(unit_id)}"


def dispatch_key(tenant_id: str, run_id: str) -> tuple[str, str]:
    """Cria a chave base do dispatch ativo."""
    return run_partition(tenant_id, run_id), "DISPATCH#ACTIVE"


def idempotency_key(tenant_id: str, scope: str, key: str) -> tuple[str, str]:
    """Cria a chave base de idempotência."""
    return tenant_partition(tenant_id), (f"IDEMPOTENCY#{key_component(scope)}#{key_component(key)}")


def version_key(tenant_id: str, dataset_name: str, version_id: str) -> tuple[str, str]:
    """Cria a chave base de uma versão."""
    return tenant_partition(tenant_id), (
        f"VERSION#{key_component(dataset_name)}#{key_component(version_id)}"
    )


def pointer_key(tenant_id: str, dataset_name: str, pointer_name: str) -> tuple[str, str]:
    """Cria a chave base de um ponteiro."""
    return tenant_partition(tenant_id), (
        f"POINTER#{key_component(dataset_name)}#{key_component(pointer_name)}"
    )


def outbox_key(event_id: str) -> tuple[str, str]:
    """Cria a chave global de um evento."""
    return global_partition(), f"OUTBOX#{key_component(event_id)}"


def dependency_marker_key(tenant_id: str, run_id: str, dependency_key: str) -> tuple[str, str]:
    """Cria a chave de um marcador de dependência."""
    return tenant_partition(tenant_id), (
        f"RUN_DEP#{key_component(run_id)}#{key_component(dependency_key)}"
    )


def timestamp(value: datetime) -> str:
    """Codifica um instante UTC ordenável."""
    return value.isoformat(timespec="microseconds")


def item_key(pk: str, sk: str) -> dict[str, dict[str, str]]:
    """Codifica uma chave no formato low-level do DynamoDB."""
    return {"pk": {"S": pk}, "sk": {"S": sk}}
