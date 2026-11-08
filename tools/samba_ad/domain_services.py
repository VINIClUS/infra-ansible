"""Signed vendor unit identities and fail-closed first-DC activation ordering."""
import hashlib
import posixpath
from pathlib import Path

from tools.samba_ad.domain import command, require
from tools.samba_ad.pki_files import future_directory, secure_file, sync_dir

MEMBERS = ("smbd.service", "nmbd.service", "winbind.service")
MEMBER_ALIASES = {"smbd.service": ["smb.service"], "nmbd.service": ["nmb.service"], "winbind.service": []}
DC = "samba-ad-dc.service"
ALIAS = "samba.service"
DROPIN = "/etc/systemd/system/samba-ad-dc.service.d/60-samba-ad-firewall.conf"
VENDOR_DC = "/usr/lib/systemd/system/" + DC


class ServiceOps:
    def __init__(self, root=Path("/"), run=command):
        self.root, self.run = Path(root), run

    def path(self, value):
        return self.root / value.lstrip("/")

    def target(self, directory, path):
        value = str(path.readlink())
        value = posixpath.normpath(value if value.startswith("/") else directory + "/" + value)
        return "/usr" + value if value.startswith("/lib/") else value

    def local_entries(self, unit):
        masks, aliases, ordered = [], [], []
        for directory in ["/etc/systemd/system", "/run/systemd/system"]:
            path = self.path(directory) / unit
            future_directory(path.parent)
            if path.is_symlink():
                target = self.target(directory, path)
                if target == "/dev/null": masks.append(directory); ordered.append("mask")
                else:
                    require(unit == ALIAS and target == VENDOR_DC)
                    aliases.append(directory); ordered.append("alias")
            elif path.exists():
                require(False)  # Never adopt a local unit replacement.
        return masks, aliases, ordered

    def install_info(self, unit):
        canonical = DC if unit == ALIAS else unit
        path = secure_file(self.path("/usr/lib/systemd/system/" + canonical))
        section, install = None, {}
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")): continue
            if line.startswith("["): section = line
            elif section == "[Install]" and "=" in line:
                name, value = line.split("=", 1)
                require(name not in install); install[name] = value.split()
        require(install.get("Alias", []) == ([ALIAS] if canonical == DC else MEMBER_ALIASES[canonical])
                and install.get("WantedBy") == ["multi-user.target"])
        return path, install

    def vendor(self, unit):
        path, _ = self.install_info(unit)
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def install_links(self, unit):
        _, install = self.install_info(unit)
        result = []
        for directory in ["/etc/systemd/system", "/run/systemd/system"]:
            for relative in ["multi-user.target.wants/" + unit, *install.get("Alias", [])]:
                path = self.path(directory) / relative
                future_directory(path.parent)
                if not path.exists() and not path.is_symlink(): continue
                require(path.is_symlink())
                target = self.target(directory + ("/multi-user.target.wants" if "/" in relative else ""), path)
                if target == "/dev/null" and "/" not in relative: continue  # Preserve existing alias masks.
                require(target == "/usr/lib/systemd/system/" + unit)
                result.append(path)
        return result

    def boot_links(self):
        result = []
        for directory in ["/etc/systemd/system", "/run/systemd/system"]:
            path = self.path(directory) / "multi-user.target.wants" / DC
            future_directory(path.parent)
            if path.exists() or path.is_symlink():
                require(path.is_symlink() and self.target(directory + "/multi-user.target.wants", path) == VENDOR_DC)
                result.append(directory)
        return result

    def snapshot(self, unit):
        keys = "LoadState UnitFileState ActiveState SubState FragmentPath DropInPaths".split()
        raw = self.run(["systemctl", "show", "--no-pager", "--property=" + ",".join(keys), unit], allowed=(0, 1, 4)).decode()
        data = dict(line.split("=", 1) for line in raw.splitlines())
        require(set(data) == set(keys))
        require(data["DropInPaths"] == "" or unit in [DC, ALIAS] and data["DropInPaths"] == DROPIN)
        if data["DropInPaths"]: secure_file(self.path(DROPIN))
        masks, aliases, ordered = self.local_entries(unit)
        fragment = data["FragmentPath"]
        if fragment.startswith("/lib/"): fragment = "/usr" + fragment
        if data["LoadState"] == "masked":
            inherited = unit == ALIAS and aliases and self.local_entries(DC)[0]
            require((ordered and ordered[0] == "mask" or inherited) and data["UnitFileState"] in ["masked", "masked-runtime"])
        elif data["LoadState"] == "not-found":
            require(unit == ALIAS and not ordered and fragment == "")
        else:
            require(data["LoadState"] == "loaded" and (not ordered or ordered[0] == "alias"))
            require(fragment == "/usr/lib/systemd/system/" + (DC if unit == ALIAS else unit))
            if unit == ALIAS: require(aliases)
        data.update(vendor_sha256=self.vendor(unit), masks=masks, aliases=aliases)
        if unit != ALIAS: self.install_links(unit)  # Reject foreign residual links before changing policy.
        if unit == DC: data["boot_links"] = self.boot_links()
        return data

    def inspect(self, initial):
        snapshot = {unit: self.snapshot(unit) for unit in [*MEMBERS, DC, ALIAS]}
        for unit, data in snapshot.items():
            if initial:
                require(data["ActiveState"] in ["inactive", "failed"])
                require(data["UnitFileState"] in ["", "enabled", "enabled-runtime", "disabled", "masked", "masked-runtime", "static", "indirect", "alias", "not-found"])
            elif unit in [DC, ALIAS]:
                require(data["LoadState"] == "loaded" and data["ActiveState"] == "active" and data["SubState"] == "running")
                if unit == DC: require(data["UnitFileState"] == "enabled" and "/etc/systemd/system" in data["boot_links"])
                else: require("/etc/systemd/system" in data["aliases"])
            else:
                require(data["LoadState"] == "masked" and data["UnitFileState"] == "masked" and "/etc/systemd/system" in data["masks"] and data["ActiveState"] in ["inactive", "failed"])
        return snapshot

    def blocked(self):
        state = self.inspect(initial=True)
        require(all("/etc/systemd/system" in data["masks"] and data["UnitFileState"] == "masked" for data in state.values()))
        require(not state[DC]["boot_links"])
        return state

    def converge_initial(self, expected):
        """Only an owned empty DC: prepare members and persistently block the DC."""
        require(self.inspect(initial=True) == expected)
        self.run(["systemctl", "disable", DC])
        for path in self.install_links(DC): path.unlink()
        for unit in MEMBERS:
            self.run(["systemctl", "disable", unit])
            for path in self.install_links(unit): path.unlink()
            if "/etc/systemd/system" not in expected[unit]["masks"]:
                self.run(["systemctl", "mask", unit])
        if "/etc/systemd/system" not in self.local_entries(DC)[0]: self.run(["systemctl", "mask", DC])
        # disable normally removes the vendor alias. Only an exact, already
        # validated residual alias may be removed before its persistent mask.
        for directory in self.local_entries(ALIAS)[1]:
            path = self.path(directory) / ALIAS
            require(self.target(directory, path) == VENDOR_DC); path.unlink()
        if "/etc/systemd/system" not in self.local_entries(ALIAS)[0]: self.run(["systemctl", "mask", ALIAS])
        sync_dir(self.path("/etc/systemd/system"))
        wants = self.path("/etc/systemd/system/multi-user.target.wants")
        if wants.exists(): sync_dir(wants)
        self.run(["systemctl", "daemon-reload"])
        after = self.blocked()
        require(all(after[unit]["vendor_sha256"] == expected[unit]["vendor_sha256"] for unit in after))
        return after

    def activate(self, expected):
        """Called only after Native.pre_activation's real local readbacks."""
        current = self.blocked()
        require(all(current[unit]["vendor_sha256"] == expected[unit]["vendor_sha256"] for unit in current))
        for unit in [DC, ALIAS]:
            for directory in current[unit]["masks"]:
                argv = ["systemctl"] + (["--runtime"] if directory == "/run/systemd/system" else [])
                self.run(argv + ["unmask", unit])
        self.run(["systemctl", "enable", DC])
        self.run(["systemctl", "daemon-reload"])
        after = self.inspect(initial=True)
        require(after[DC]["UnitFileState"] == "enabled" and "/etc/systemd/system" in after[DC]["boot_links"])
        require("/etc/systemd/system" in after[ALIAS]["aliases"] and not after[ALIAS]["masks"])
        require(all("/etc/systemd/system" in after[unit]["masks"] for unit in MEMBERS))
