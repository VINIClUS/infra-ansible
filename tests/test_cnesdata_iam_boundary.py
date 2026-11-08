"""The source boundary verifies immutable blobs and rejects checkout substitutions."""
from types import SimpleNamespace
import pytest

from tools.cnesdata_delivery.iam_boundary import authenticate_sources


@pytest.mark.parametrize("mutation", [None, "dirty", "untracked", "changed-bytes", "symlink", "unsafe-path"])
def test_authenticated_checkout_source_boundary(tmp_path, monkeypatch, mutation):
    path = "infra/opentofu/env/prod/main.tf"
    raw = b'locals { name_prefix = "cnesdata-prod" }\n'
    target = tmp_path / path
    target.parent.mkdir(parents=True)
    target.write_bytes(raw + (b"# altered" if mutation == "changed-bytes" else b""))
    if mutation == "symlink":
        target.unlink()
        original = tmp_path / "outside.tf"
        original.write_bytes(raw)
        target.symlink_to(original)
    calls = []
    def git(command, **_):
        calls.append(command[1])
        output = {"status": b"?? untracked.tf\n" if mutation == "untracked" else b" M " + path.encode() if mutation == "dirty" else b"",
                  "ls-tree": ("infra/opentofu/env/prod/../main.tf" if mutation == "unsafe-path" else path).encode() + b"\0",
                  "show": raw}[command[1]]
        return SimpleNamespace(stdout=output)
    monkeypatch.setattr("tools.cnesdata_delivery.iam_boundary.subprocess.run", git)
    if mutation:
        with pytest.raises(ValueError):
            authenticate_sources(tmp_path, "a" * 40)
    else:
        assert authenticate_sources(tmp_path, "a" * 40) == {path: raw}
        assert calls == ["status", "ls-tree", "show"]
