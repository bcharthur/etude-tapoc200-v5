from __future__ import annotations

from pathlib import Path

from .s3 import download_url


C200V5_142 = {
    "product": "Tapo C200 V5",
    "version": "1.4.2",
    "build": "260513",
    "rel": "33069n",
    "url": (
        "https://download.tplinkcloud.com/firmware/assigned/"
        "Tapo_C200v5_en_1.4.2_Build_260513_Rel.33069n_"
        "up_boot-signed_1778665233392.bin"
    ),
    "source": "Ripthulhu/tp-link-tapo-firmware public bucket snapshot",
    "research_role": (
        "Known pre-1.4.6 C200 V5 baseline. It predates the 1.4.6 fixes "
        "for CVE-2026-15315 and CVE-2026-15316, so it is useful as the "
        "vulnerable-side binary even though it is not 1.4.4."
    ),
}


def info():
    return {
        "baseline": C200V5_142,
        "why_use_it": (
            "The exact 1.4.4 package is not required to begin vulnerable-side "
            "static analysis of the 1.4.6-fixed code paths. 1.4.2 is an exact "
            "same-hardware V5 image from before the fixed release."
        ),
    }


def fetch(output, *, insecure=False):
    result = download_url(
        C200V5_142["url"],
        output,
        insecure=insecure,
    )
    return {
        "baseline": C200V5_142,
        "download": result,
        "next": [
            f"python .\\v5patchlab.py magic-scan {output}",
            f"python .\\v5patchlab.py decrypt {output}",
        ],
    }
