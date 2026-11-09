"""Offline boundary tests; these fixtures are never operational host evidence."""
import importlib
import io
import json
import struct
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


def runtime():
    try:
        return importlib.import_module("tools.cnesdata_delivery.host_gate")
    except ModuleNotFoundError:
        pytest.fail("EXT3 bounded host runtime is absent")


H = "a" * 64
SHA = "b" * 40


def manifest(action="deploy"):
    return {"project": "cnesdata", "source_repository": "VINIClUS/CnesData",
            "source_sha": SHA, "expires_at": "2030-01-01T00:00:00Z",
            "platform_plan": {"evidence_id": "object/version", "evidence_sha256": H,
                              "inventory_sha256": H, "dependencies_sha256": H,
                              "host_preflight_sha256": H, "host_key_fingerprint": "SHA256:host"},
            "images": {"api": "ghcr.io/viniclus/cnesdata@sha256:" + H},
            "compose_sha256": H, "config_sha256": H, "requested_action": action}


def envelope(value=None):
    return {"schema_version": 1, "ci_evidence": {"repository": "VINIClUS/CnesData",
            "workflow": "ci.yml", "run_id": 1, "artifact_id": 2,
            "artifact_digest": "sha256:" + H}, "release_manifest": value or manifest()}


def archive(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as tar:
        for name, data, kind in entries:
            item = tarfile.TarInfo(name)
            item.type = kind
            item.size = len(data) if kind == tarfile.REGTYPE else 0
            item.linkname = "compose.yml" if kind == tarfile.SYMTYPE else ""
            tar.addfile(item, io.BytesIO(data) if item.size else None)
    return stream.getvalue()


def good_archive():
    g = runtime()
    value = manifest()
    compose, config = b"services: {}\n", b"{}\n"
    value["compose_sha256"], value["config_sha256"] = g.sha(compose), g.sha(config)
    data = archive([(n, b, tarfile.REGTYPE) for n, b in [
        ("release-manifest.json", g.canonical(value)), ("compose.yml", compose), ("config.json", config)]])
    return value, data


def frame(data):
    return struct.pack(">Q", len(data)) + data


def test_exact_three_frames_and_token_is_redacted_and_erasable():
    g = runtime()
    value, data = good_archive()
    request = g.read_request(io.BytesIO(frame(g.canonical(envelope(value))) + frame(data) + frame(b"secret")))
    assert request.archive == data
    assert request.token == bytearray(b"secret")
    assert "secret" not in repr(request)
    request.erase()
    assert request.token == bytearray(6)


@pytest.mark.parametrize("data", [b"", b"\0" * 7, frame(b"") , struct.pack(">Q", 65537),
                                 frame(b"{}") + frame(b"x") + frame(b"token") + b"extra"])
def test_framing_rejects_before_unbounded_reads(data):
    with pytest.raises(ValueError):
        runtime().read_request(io.BytesIO(data))


@pytest.mark.parametrize("token", [b"a b", b"a\0b", b"a\nb", b"a\rb", b"a\x7fb"])
def test_token_control_bytes_rejected(token):
    g = runtime()
    with pytest.raises(ValueError):
        g.read_request(io.BytesIO(frame(b"{}") + frame(b"x") + frame(token)))


def test_closed_envelope_allowlist_is_trusted_configuration():
    g = runtime()
    value = envelope()
    g.validate_envelope(value, workflows={"ci.yml"}, images={"ghcr.io/viniclus/cnesdata"}, now=0)
    value["ci_evidence"]["run_id"] = True
    with pytest.raises(ValueError):
        g.validate_envelope(value, workflows={"ci.yml"}, images={"ghcr.io/viniclus/cnesdata"}, now=0)
    value = envelope()
    value["release_manifest"]["images"]["api"] = "ghcr.io/viniclus/cnesdata:latest"
    with pytest.raises(ValueError):
        g.validate_envelope(value, workflows={"ci.yml"}, images={"ghcr.io/viniclus/cnesdata"}, now=0)


def test_json_rejects_duplicate_float_depth_and_unknown_fields():
    g = runtime()
    for data in [b'{"a":1,"a":2}', b'{"a":1.0}', b'"\\ud800"', b'[' * 17 + b'0' + b']' * 17]:
        with pytest.raises(ValueError):
            g.host_json(data)
    value = envelope()
    value["override"] = "untrusted"
    with pytest.raises(ValueError):
        g.validate_envelope(value, workflows={"ci.yml"}, images=set(), now=0)


def test_archive_hash_and_manifest_are_exact_before_staging(tmp_path):
    g = runtime()
    value, data = good_archive()
    files = g.inspect_archive(data, value, g.sha(data))
    assert set(files) == {"release-manifest.json", "compose.yml", "config.json"}
    staged = g.stage_archive(tmp_path, files)
    assert (staged / "compose.yml").read_bytes() == files["compose.yml"]
    assert staged.stat().st_mode & 0o777 == 0o700
    assert (staged / "compose.yml").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError):
        g.inspect_archive(data, value, "0" * 64)
    value["source_sha"] = "c" * 40
    with pytest.raises(ValueError):
        g.inspect_archive(data, value, g.sha(data))


@pytest.mark.parametrize("name,kind", [("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                                      ("C:drive", tarfile.REGTYPE), ("compose.yml", tarfile.SYMTYPE),
                                      ("compose.yml", tarfile.DIRTYPE), ("compose.yml", tarfile.FIFOTYPE),
                                      ("extra", tarfile.REGTYPE)])
def test_hostile_archive_members_never_extract(name, kind):
    g = runtime()
    value, _ = good_archive()
    data = archive([(name, b"evil", kind)])
    with pytest.raises(ValueError):
        g.inspect_archive(data, value, g.sha(data))


def test_archive_duplicate_and_size_bomb_fail_closed():
    g = runtime()
    value, _ = good_archive()
    for entries in [[("compose.yml", b"x", tarfile.REGTYPE)] * 2,
                    [("compose.yml", b"x" * (1024**2 + 1), tarfile.REGTYPE)]]:
        data = archive(entries)
        with pytest.raises(ValueError):
            g.inspect_archive(data, value, g.sha(data))
