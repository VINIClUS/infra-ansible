#!/usr/bin/env python3
"""File-only ifupdown2 policy persistence. No link or service operations.

The importable store accepts fixture paths; the streamed CLI uses fixed audited
paths, ownership and source hashes only. All JSON on stdout is a bounded result.
"""
import ctypes
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import uuid

DESTINATION = "90-sdn-existing-bridge-hashmax.json"
LOADER = "/usr/share/ifupdown2/ifupdown/policymanager.py"
SOURCE_HASHES = {
    LOADER: "3d67bb126187b5f2c0ea8465acbbf60798de7be990b24e311992d9778f5e467e",
    "/usr/share/ifupdown2/addons/bridge.py": "8f2aaa8d100e85c61ffed02b73cef57922cbab263504620f6a3b87c696f45c4a",
}


def digest(value):
    return hashlib.sha256(value).hexdigest()


def json_hash(value):
    return digest(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_json(content):
    try:
        return json.loads(content, object_pairs_hook=unique_object)
    except (TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid JSON") from exc


def canonical_policy(mapping, declared=None):
    if not isinstance(mapping, dict):
        raise ValueError("hashmax must be a mapping")
    for name, value in mapping.items():
        if (not isinstance(name, str) or not re.fullmatch(r"[a-z][a-z0-9]{1,7}", name)
                or type(value) is not str or value != "4096"
                or (declared is not None and name not in declared)):
            raise ValueError("invalid hashmax interface or fixed string value")
    return json.dumps({"bridge": {"iface_defaults": {
        name: {"bridge-hashmax": "4096"} for name in sorted(mapping)
    }}}, sort_keys=True, separators=(",", ":")) + "\n"


def write_complete(fd, content):
    view = memoryview(content)
    while view:
        count = os.write(fd, view)
        if count <= 0:
            raise OSError("short policy write")
        view = view[count:]


def publish_exclusive(directory_fd, temporary, destination):
    """Atomic Linux rename with no replacement, including concurrent arrivals."""
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(directory_fd, os.fsencode(temporary), directory_fd, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))


class PolicyStore:
    def __init__(self, user, vendor, loader, source_hashes, network_paths, uid=0, gid=0, trusted_root="/"):
        self.user, self.vendor = Path(user), Path(vendor)
        self.destination = self.user / DESTINATION
        self.loader = Path(loader)
        self.source_hashes = source_hashes
        self.network_paths = [Path(p) for p in network_paths]
        self.uid, self.gid = uid, gid
        self.trusted_root = Path(trusted_root).absolute()
        self.observed_directories = {}

    @staticmethod
    def metadata(info):
        return {"type": stat.S_IFMT(info.st_mode), "uid": info.st_uid, "gid": info.st_gid,
                "mode": stat.S_IMODE(info.st_mode), "dev": info.st_dev, "ino": info.st_ino}

    def safe_metadata(self, info):
        if info.st_uid != self.uid or info.st_gid != self.gid or info.st_mode & 0o022:
            raise ValueError("unsafe ownership or writable policy path")

    def directory(self, path):
        # Anchor every component with O_NOFOLLOW, rather than resolving symlinks.
        if not Path(path).absolute().is_relative_to(self.trusted_root):
            raise ValueError("path outside trusted fixture root")
        fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            current = Path("/")
            if self.trusted_root == current:
                self.safe_metadata(os.fstat(fd))
                self.observed_directories[str(current)] = self.metadata(os.fstat(fd))
            for component in Path(path).absolute().parts[1:]:
                next_fd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                os.close(fd); fd = next_fd
                current = current / component
                if current.is_relative_to(self.trusted_root):
                    self.safe_metadata(os.fstat(fd))
                    self.observed_directories[str(current)] = self.metadata(os.fstat(fd))
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read_file(self, path):
        directory_fd = self.directory(path.parent)
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory_fd)
            try:
                before = os.fstat(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise ValueError("policy path is not a regular file")
                self.safe_metadata(before)
                with os.fdopen(fd, "rb", closefd=False) as stream:
                    content = stream.read()
                after = os.fstat(fd)
                if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                        after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                    raise ValueError("file changed during read")
                return content, dict(self.metadata(after), sha256=digest(content))
            finally:
                os.close(fd)
        finally:
            os.close(directory_fd)

    @staticmethod
    def validate_schema(data):
        if not isinstance(data, dict):
            raise ValueError("policy root must be a dictionary")
        if any(not isinstance(v, dict) for k, v in data.items() if k != "README"):
            raise ValueError("policy module must be a dictionary")
        bridge = data.get("bridge", {})
        for section in ("defaults", "module_globals", "iface_defaults"):
            if section in bridge and not isinstance(bridge[section], dict):
                raise ValueError("invalid bridge policy section")
        if any(not isinstance(v, dict) for v in bridge.get("iface_defaults", {}).values()):
            raise ValueError("invalid interface policy")

    def _inspect(self, content):
        self.observed_directories = {}
        requested = parse_json(content)
        try:
            mapping = {name: attrs["bridge-hashmax"] for name, attrs in requested["bridge"]["iface_defaults"].items()}
        except (KeyError, TypeError, AttributeError) as exc:
            raise ValueError("invalid requested policy structure") from exc
        if not mapping or canonical_policy(mapping) != content:
            raise ValueError("requested policy must be nonempty and canonical")
        files, names, loader_bytes = {}, set(), None
        for directory in (self.user, self.vendor):
            fd = self.directory(directory)
            try:
                files[str(directory)] = self.metadata(os.fstat(fd))
                paths = sorted(name for name in os.listdir(fd) if name.endswith(".json"))
            finally:
                os.close(fd)
            for name in paths:
                path = directory / name
                raw, metadata = self.read_file(path)
                data = parse_json(raw); self.validate_schema(data)
                files[str(path)] = metadata
                names.update(data.get("bridge", {}).get("iface_defaults", {}))
                if path == self.destination:
                    if raw != content.encode() or metadata["mode"] != 0o644:
                        raise ValueError("unmanaged destination; refusing adoption or replacement")
                elif directory == self.user and "iface_defaults" in data.get("bridge", {}):
                    raise ValueError("competing user bridge.iface_defaults; shallow merge is unsafe")
        for name, expected_hash in self.source_hashes.items():
            raw, metadata = self.read_file(Path(name))
            if metadata["sha256"] != expected_hash:
                raise ValueError("installed source contract drift")
            files[name] = metadata
            if Path(name) == self.loader:
                loader_bytes = raw
        if loader_bytes is None:
            raise ValueError("loader is not hash bound")
        for root in self.network_paths:
            paths = [root]
            if root.is_dir() and not root.is_symlink():
                fd = self.directory(root)
                try: files[str(root)] = self.metadata(os.fstat(fd))
                finally: os.close(fd)
                paths = sorted(root.rglob("*"))
            for path in paths:
                if path.is_dir() and not path.is_symlink():
                    fd = self.directory(path)
                    try: files[str(path)] = self.metadata(os.fstat(fd))
                    finally: os.close(fd)
                else:
                    _, files[str(path)] = self.read_file(path)
        files.update(self.observed_directories)
        namespace = {"__name__": "_sdn_hash_verified_policy", "__file__": str(self.loader)}
        exec(compile(loader_bytes, str(self.loader), "exec"), namespace)
        api = namespace["policymanager_api"]
        getter = {name: api.get_iface_default(module_name="bridge", ifname=name, attr="bridge-hashmax")
                  for name in mapping}
        # A name absent from all interface subtrees exercises fallback for every
        # other undeclared name, plus each explicitly mentioned non-target name.
        sentinel = "__sdn_policy_fallback__"
        while sentinel in names: sentinel += "_"
        non_targets = {name: api.get_iface_default(module_name="bridge", ifname=name, attr="bridge-hashmax")
                       for name in sorted((names - mapping.keys()) | {sentinel})}
        fallback = {"interfaces": non_targets,
                    "global": api.get_attr_default(module_name="bridge", attr="bridge-hashmax")}
        preserved = {name: metadata for name, metadata in files.items() if name != str(self.destination)}
        return {"fingerprint": json_hash(files), "preserved": json_hash(preserved),
                "fallback": json_hash(fallback), "getter": getter,
                "destination_hash": files.get(str(self.destination), {}).get("sha256"),
                "directory": files[str(self.user)]}

    def inspect(self, content):
        try:
            return dict(self._inspect(content), action="inspect", changed=False, error=None)
        except (OSError, RuntimeError) as exc:
            raise ValueError("policy inspection failed: " + type(exc).__name__) from exc

    def verify(self, content, baseline):
        current = self.inspect(content)
        if (current["destination_hash"] != digest(content.encode())
                or current["preserved"] != baseline["preserved"]
                or current["fallback"] != baseline["fallback"]
                or any(value != "4096" for value in current["getter"].values())):
            raise ValueError("policy readback, preservation or getter verification failed")
        return dict(current, action="verify")

    def install(self, content, baseline):
        current = self.inspect(content)
        if current["fingerprint"] != baseline["fingerprint"]:
            raise ValueError("preflight fingerprint changed")
        if current["destination_hash"] is not None:
            return dict(self.verify(content, baseline), action="install", changed=False)
        directory_fd = self.directory(self.user)
        temporary, changed, created = ".sdn-" + uuid.uuid4().hex + ".tmp", False, False
        result = dict(current, action="install", changed=False)
        try:
            if self.metadata(os.fstat(directory_fd)) != current["directory"]:
                raise ValueError("policy directory substituted")
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory_fd)
            created = True
            try:
                write_complete(fd, content.encode())
                info = os.fstat(fd)
                if (info.st_uid, info.st_gid) != (self.uid, self.gid):
                    os.fchown(fd, self.uid, self.gid)
                os.fchmod(fd, 0o644)
                os.fsync(fd)
            finally:
                os.close(fd)
            if self.inspect(content)["fingerprint"] != baseline["fingerprint"]:
                raise ValueError("preflight fingerprint changed before publication")
            publish_exclusive(directory_fd, temporary, DESTINATION)
            changed = True
            os.fsync(directory_fd)
            result = dict(self.verify(content, baseline), action="install")
        except Exception as exc:
            # Never roll back a published file, nor claim an unknown readback is
            # unchanged. Only this invocation's unused temporary is removed.
            result["error"] = "policy installation failed: " + type(exc).__name__
            if changed:
                result["destination_hash"] = None
                result["getter"] = {}
        finally:
            if created and not changed:
                try: os.unlink(temporary, dir_fd=directory_fd)
                except FileNotFoundError: pass
            os.close(directory_fd)
        result["changed"] = changed
        return result


def main():
    result = {"action": sys.argv[1] if len(sys.argv) > 1 else None,
              "changed": False, "destination_hash": None, "getter": {}, "error": None}
    try:
        if len(sys.argv) != 4 or sys.argv[1] not in ("inspect", "install", "verify"):
            raise ValueError("expected action, canonical policy JSON and baseline JSON")
        store = PolicyStore("/etc/network/ifupdown2/policy.d", "/var/lib/ifupdown2/policy.d",
                            LOADER, SOURCE_HASHES,
                            ["/etc/network/interfaces", "/etc/network/interfaces.d"])
        action, content, baseline = sys.argv[1], sys.argv[2], parse_json(sys.argv[3])
        result = store.inspect(content) if action == "inspect" else getattr(store, action)(content, baseline)
    except Exception as exc:
        result["error"] = "policy action failed: " + type(exc).__name__
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 1 if result["error"] else 0


if __name__ == "__main__":
    sys.dont_write_bytecode = True
    sys.exit(main())
