"""Guarded first-DC unit convergence, never service adoption or reexec repair."""
import hashlib
from pathlib import Path

from tools.samba_ad.domain import command, require
from tools.samba_ad.pki_files import future_directory, secure_file

MEMBERS = ("samba.service", "smbd.service", "nmbd.service", "winbind.service")
DC = "samba-ad-dc.service"
DROPIN = "/etc/systemd/system/samba-ad-dc.service.d/60-samba-ad-firewall.conf"


class ServiceOps:
    def __init__(self, root=Path("/"), run=command):
        self.root, self.run = Path(root), run

    def path(self, value):
        return self.root / value.lstrip("/")

    def snapshot(self, unit):
        keys = "LoadState UnitFileState ActiveState SubState FragmentPath DropInPaths".split()
        raw = self.run(["systemctl", "show", "--no-pager", "--property=" + ",".join(keys), unit], allowed=(0, 1, 4)).decode()
        data = dict(line.split("=", 1) for line in raw.splitlines())
        require(set(data) == set(keys))
        require(data["DropInPaths"] == "" or unit == DC and data["DropInPaths"] == DROPIN)
        if data["DropInPaths"]: secure_file(self.path(DROPIN))
        mask_paths = []
        for directory in ["/etc/systemd/system", "/run/systemd/system"]:
            path = self.path(directory) / unit
            future_directory(path.parent)
            if path.is_symlink():
                require(str(path.readlink()) == "/dev/null")
                mask_paths.append(directory)
            elif path.exists():
                # Local unit replacement is never treated as a vendor unit.
                require(False)
        if data["LoadState"] == "masked":
            require(mask_paths and data["UnitFileState"] in ["masked", "masked-runtime"])
        else:
            require(not mask_paths)
            require(data["LoadState"] in ["loaded", "not-found"])
        fragment = data["FragmentPath"]
        if fragment.startswith("/lib/"): fragment = "/usr" + fragment
        expected = "/usr/lib/systemd/system/" + unit
        aliases = [expected] + (["/usr/lib/systemd/system/smbd.service"] if unit == "samba.service" else [])
        vendor = self.path(expected)
        if not vendor.exists() and unit == "samba.service":
            vendor = self.path("/usr/lib/systemd/system/smbd.service")
        vendor = vendor.resolve(strict=True)
        require(vendor in [self.path(value) for value in aliases])
        data["vendor_sha256"] = hashlib.sha256(secure_file(vendor).read_bytes()).hexdigest()
        if data["LoadState"] == "loaded": require(fragment in aliases)
        if data["LoadState"] == "not-found": require(unit == "samba.service" and fragment == "")
        data["masks"] = mask_paths
        return data

    def inspect(self, initial):
        snapshot = {unit: self.snapshot(unit) for unit in [*MEMBERS, DC]}
        for unit, data in snapshot.items():
            if initial:
                require(data["ActiveState"] in ["inactive", "failed"])
                require(data["UnitFileState"] in ["", "enabled", "enabled-runtime", "disabled", "masked", "masked-runtime", "static", "indirect", "alias"])
            elif unit == DC:
                require(data["LoadState"] == "loaded" and data["UnitFileState"] == "enabled"
                        and data["ActiveState"] == "active" and data["SubState"] == "running")
            else:
                require(data["LoadState"] == "masked" and data["UnitFileState"] == "masked"
                        and "/etc/systemd/system" in data["masks"] and data["ActiveState"] in ["inactive", "failed"])
        return snapshot

    def converge_initial(self, expected):
        require(self.inspect(initial=True) == expected)
        for unit in MEMBERS:
            data = expected[unit]
            if data["UnitFileState"] not in ["", "masked", "masked-runtime", "alias"]:
                self.run(["systemctl", "disable", unit])
            if "/etc/systemd/system" not in data["masks"]:
                self.run(["systemctl", "mask", unit])
        for directory in expected[DC]["masks"]:
            argv = ["systemctl"] + (["--runtime"] if directory == "/run/systemd/system" else [])
            self.run(argv + ["unmask", DC])
        if expected[DC]["UnitFileState"] != "enabled": self.run(["systemctl", "enable", DC])
        self.run(["systemctl", "daemon-reload"])
        after = self.inspect(initial=True)
        require(all(after[unit]["vendor_sha256"] == expected[unit]["vendor_sha256"] for unit in after))
        require(after[DC]["LoadState"] == "loaded" and after[DC]["UnitFileState"] == "enabled")
        require(all(after[unit]["UnitFileState"] == "masked" and "/etc/systemd/system" in after[unit]["masks"] for unit in MEMBERS))
