"""Offline filesystem proof; synthetic loader is not a production getter proof."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path

import jinja2
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
ROLE = ROOT / "roles/proxmox_sdn"


@pytest.fixture
def policy():
    path = ROLE / "files/sdn-bridge-policy.py"
    if not path.exists():
        pytest.skip("helper missing; existence regression fails separately")
    spec = importlib.util.spec_from_file_location("sdn_bridge_policy", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_policy_helper_exists():
    assert (ROLE / "files/sdn-bridge-policy.py").is_file(), "policy helper is missing"


@pytest.fixture
def store(tmp_path, policy, request):
    old_umask = os.umask(0o022)
    request.addfinalizer(lambda: os.umask(old_umask))
    user, vendor = tmp_path / "user", tmp_path / "vendor"
    user.mkdir(mode=0o755); vendor.mkdir(mode=0o755)
    # Independent fixture of the audited shallow merge and getter precedence.
    source = '''import json, glob
class Policy:
    def __init__(self):
        self.arrays = []
        for directory in DIRECTORIES:
            merged = {}
            for filename in glob.glob(directory + '/*.json'):
                with open(filename) as stream:
                    data = json.load(stream)
                for module, settings in data.items():
                    merged.setdefault(module, {}).update(settings)
            self.arrays.append(merged)
    def get_iface_default(self, module_name, ifname, attr):
        for array in self.arrays:
            bridge = array.get(module_name, {})
            if attr in bridge.get('iface_defaults', {}).get(ifname, {}):
                return bridge['iface_defaults'][ifname][attr]
            if attr in bridge.get('defaults', {}):
                return bridge['defaults'][attr]
    def get_attr_default(self, module_name, attr):
        for array in self.arrays:
            if attr in array.get(module_name, {}).get('defaults', {}):
                return array[module_name]['defaults'][attr]
policymanager_api = Policy()
'''
    loader = tmp_path / "policymanager.py"
    loader.write_text("DIRECTORIES = " + repr([str(user), str(vendor)]) + "\n" + source)
    bridge = tmp_path / "bridge.py"; bridge.write_text("# fixture: never imported\n")
    network = tmp_path / "sdn"; network.write_text("untouched network\n")
    hashes = {str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in (loader, bridge)}
    result = policy.PolicyStore(user, vendor, loader, hashes, [network], os.getuid(), os.getgid(), tmp_path)
    (vendor / "mac.json").write_text(json.dumps({"bridge": {"module_globals": {"mac": "yes"}}}))
    return result


def contents(store):
    return {str(p): (p.read_bytes(), p.stat().st_mode, p.stat().st_uid, p.stat().st_gid)
            for directory in (store.user, store.vendor) for p in directory.iterdir() if p.is_file()}


def expected(policy):
    return policy.canonical_policy({"vnold": "4096"})


def test_atomic_install_preserves_other_policies_and_is_idempotent(store, policy):
    (store.user / "other.json").write_text(json.dumps({"ethtool": {"defaults": {"speed": "auto"}},
        "bridge": {"defaults": {"bridge-hashmax": "512"}, "module_globals": {"flag": "yes"}}}))
    original = contents(store)
    content = expected(policy)
    before = store.inspect(content)
    first = store.install(content, before)
    assert first["changed"] is True and first["error"] is None
    assert store.destination.read_text() == content
    assert store.destination.stat().st_mode & 0o777 == 0o644
    assert all(contents(store)[name] == value for name, value in original.items())
    verified = store.verify(content, before)
    assert verified["getter"] == {"vnold": "4096"} and verified["error"] is None
    again = store.install(content, store.inspect(content))
    assert again["changed"] is False


@pytest.mark.parametrize("mapping", [[], {"bad name": "4096"}, {"vnold": 4096},
    {"vnold": True}, {"vnold": "512"}, {"vnew": "4096"}])
def test_map_validation_rejects_unsafe_unknown_or_nonfixed_values(policy, mapping):
    with pytest.raises(ValueError):
        policy.canonical_policy(mapping, {"vnold"})


@pytest.mark.parametrize("payload", ['{', '{"bridge":{},"bridge":{}}',
    '{"bridge":[]}', '{"bridge":{"iface_defaults":{"unrelated":{"bridge-hashmax":"1024"}}}}'])
def test_bad_or_competing_policy_stops_without_writes(store, policy, payload):
    (store.user / "other.json").write_text(payload)
    original = contents(store)
    with pytest.raises(ValueError): store.inspect(expected(policy))
    assert contents(store) == original


@pytest.mark.parametrize("problem", ["directory_mode", "file_mode", "owner", "symlink", "destination", "source"])
def test_unsafe_paths_metadata_unmanaged_destination_and_drift_stop(store, policy, problem):
    other = store.user / "other.json"
    if problem == "directory_mode": store.user.chmod(0o777)
    if problem == "file_mode":
        other.write_text("{}"); other.chmod(0o666)
    if problem == "owner": store.uid += 1
    if problem == "symlink": other.symlink_to(store.vendor / "mac.json")
    if problem == "destination": store.destination.write_text("{}")
    if problem == "source": store.loader.write_text("raise RuntimeError('must not execute')")
    with pytest.raises(ValueError): store.inspect(expected(policy))


def test_fingerprint_change_stops_without_writes(store, policy):
    content = expected(policy); before = store.inspect(content)
    (store.user / "new.json").write_text("{}")
    original = contents(store)
    with pytest.raises(ValueError): store.install(content, before)
    assert contents(store) == original


def test_writable_policy_ancestor_stops_before_writes(store, policy):
    parent = store.user.parent / "policy-parent"
    parent.mkdir()
    moved = parent / "user"
    store.user.rename(moved)
    store.user = moved; store.destination = moved / policy.DESTINATION
    parent.chmod(0o777)
    original = contents(store)
    with pytest.raises(ValueError): store.inspect(expected(policy))
    assert contents(store) == original


def test_empty_network_directory_metadata_is_checked_and_fingerprinted(store, policy):
    directory = store.user.parent / "interfaces.d"
    directory.mkdir()
    store.network_paths.append(directory)
    before = store.inspect(expected(policy))
    directory.chmod(0o777)
    with pytest.raises(ValueError): store.inspect(expected(policy))
    directory.chmod(0o750)
    assert store.inspect(expected(policy))["fingerprint"] != before["fingerprint"]


def test_partial_temp_write_is_cleaned_without_changes(store, policy, monkeypatch):
    content = expected(policy); before = store.inspect(content); original = contents(store)
    def fail(fd, data):
        os.write(fd, data[:3]); raise OSError("injected partial write")
    monkeypatch.setattr(policy, "write_complete", fail)
    result = store.install(content, before)
    assert result["changed"] is False and result["error"]
    assert contents(store) == original
    assert not list(store.user.glob(".sdn-*"))


def test_destination_race_never_replaces_unknown_file(store, policy, monkeypatch):
    content = expected(policy); before = store.inspect(content)
    publish = policy.publish_exclusive
    def race(fd, temporary, destination):
        store.destination.write_text("unmanaged concurrent arrival")
        return publish(fd, temporary, destination)
    monkeypatch.setattr(policy, "publish_exclusive", race)
    result = store.install(content, before)
    assert result["changed"] is False and result["error"]
    assert store.destination.read_text() == "unmanaged concurrent arrival"
    assert not list(store.user.glob(".sdn-*"))


def test_exclusive_temp_collision_never_cleans_someone_elses_file(store, policy, monkeypatch):
    content = expected(policy); before = store.inspect(content)
    class Fixed:
        hex = "existing"
    monkeypatch.setattr(policy.uuid, "uuid4", lambda: Fixed())
    temporary = store.user / ".sdn-existing.tmp"
    temporary.write_text("someone else's temporary")
    result = store.install(content, before)
    assert result["changed"] is False and result["error"]
    assert temporary.read_text() == "someone else's temporary"


def test_post_publish_failure_reports_changed_and_keeps_installed_file(store, policy, monkeypatch):
    content = expected(policy); before = store.inspect(content)
    fsync = os.fsync
    def fail_directory(fd):
        if os.fstat(fd).st_mode & 0o170000 == 0o040000: raise OSError("directory fsync")
        fsync(fd)
    monkeypatch.setattr(policy.os, "fsync", fail_directory)
    result = store.install(content, before)
    assert result["changed"] is True and result["error"]
    assert store.destination.read_text() == content


def test_verification_rejects_untouched_file_drift(store, policy):
    content = expected(policy); before = store.inspect(content)
    assert store.install(content, before)["changed"]
    (store.vendor / "mac.json").write_text("{}")
    with pytest.raises(ValueError): store.verify(content, before)


def test_template_is_canonical_and_default_is_empty(policy):
    defaults = yaml.safe_load((ROLE / "defaults/main.yml").read_text())
    assert defaults["proxmox_sdn_bridge_hashmax"] == {}
    env = jinja2.Environment(loader=jinja2.FileSystemLoader(ROLE / "templates"), keep_trailing_newline=True)
    rendered = env.get_template("bridge-hashmax-policy.json.j2").render(
        proxmox_sdn_bridge_hashmax={"vnb": "4096", "vna": "4096"})
    assert rendered == policy.canonical_policy({"vna": "4096", "vnb": "4096"})
