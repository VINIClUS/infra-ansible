"""Transport public helper source below Linux's single-argument size limit."""
import base64
import json
import zlib


def pack_sources(sources):
    return base64.b64encode(zlib.compress(json.dumps(sources).encode(), 9)).decode()


class FilterModule:
    def filters(self):
        return {"samba_ad_domain_pack_sources": pack_sources}
