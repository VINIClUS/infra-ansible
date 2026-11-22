"""Compress public source only; never accepts a private request or credential."""
import base64
import json
import zlib


class FilterModule:
    def filters(self):
        return {"samba_ad_pilot_pack_sources": lambda value:
                base64.b64encode(zlib.compress(json.dumps(value).encode(), 9)).decode()}
