from __future__ import annotations

import argparse
import json
from pathlib import Path

from .decrypt import decrypt_firmware
from .diff import compare
from .evidence import write_json
from .extract import magic_scan, binwalk_extract, find_main_candidates, find_main_report
from .report import build_report
from .s3 import find as s3_find, download as s3_download, download_url as s3_download_url
from .publicbase import info as public_base_info, fetch as public_base_fetch
from .versions import FIRMWARE_MATRIX, CVE_SEEDS
from .wsl import env_report
from .releases import fetch_official_releases
from .camera_fw import query_setup_camera
from .cloudcheck import run_cloud_check
from .normalcheck import normal_ready, run_normal_cloud_check
from .boundcheck import bound_register, bound_auth_probe, bound_cloud_check
from .otahunt import run_ota_hunt, scan_local_file, validate_url
from .otaexact import run_exact_hunt, known_targets
from .cloudaccount import run_cloud_account_fw_probe
from .s1map import build_report as build_s1_static_report, write_report as write_s1_static_report
from .s1controlflow import build_controlflow_report, write_controlflow_report, DEFAULT_TARGETS
from .s1observe import observe_softap
from .s1predicate import build_predicate_report, write_predicate_report


def emit(obj):
    print(json.dumps(obj, indent=2, ensure_ascii=False, default=str))


def cmd_matrix(a):
    emit({
        "firmware_matrix": FIRMWARE_MATRIX,
        "cve_focus": CVE_SEEDS,
    })
    return 0


def cmd_env(a):
    emit(env_report())
    return 0


def cmd_find(a):
    result = s3_find(
        build=a.build,
        version=a.version,
        region=a.region,
    )
    official = None
    if not result.get("backend", {}).get("listing_available", True):
        try:
            official = fetch_official_releases()
        except Exception as exc:
            official = {"error": f"{type(exc).__name__}: {exc}"}
    emit({
        "query": {
            "version": a.version,
            "build": a.build,
            "region": a.region,
        },
        "results": result,
        "official_release_notes_fallback": official,
    })
    return 0


def cmd_download(a):
    emit(s3_download(a.key, a.out, insecure=a.insecure))
    return 0


def cmd_decrypt(a):
    emit(decrypt_firmware(a.firmware, tool=a.tool))
    return 0


def cmd_magic(a):
    emit(magic_scan(a.image))
    return 0


def cmd_extract(a):
    result = binwalk_extract(a.image, a.out)
    write_json(Path(a.out) / "binwalk-extract.json", result)
    emit(result)
    return 0


def cmd_find_main(a):
    emit(find_main_report(a.root))
    return 0


def cmd_diff(a):
    result = compare(a.old, a.new)
    if a.out:
        write_json(a.out, result)
    emit(result)
    return 0


def cmd_report(a):
    result = build_report(a.old, a.new, a.out)
    emit({
        "output_dir": a.out,
        "json": str(Path(a.out) / "patch-report.json"),
        "markdown": str(Path(a.out) / "patch-report.md"),
        "old_sha256": result["diff"]["old"]["sha256"],
        "new_sha256": result["diff"]["new"]["sha256"],
    })
    return 0




def cmd_official_releases(a):
    emit(fetch_official_releases())
    return 0


def cmd_camera_fw(a):
    emit(query_setup_camera(refresh=a.refresh))
    return 0









def cmd_cloud_account_fw(a):
    emit(run_cloud_account_fw_probe(
        target_mac=a.target_mac,
        email=a.email,
        mfa_type=a.mfa_type,
        poll_seconds=a.poll_seconds,
        interval=a.interval,
        trigger=a.arm,
        evidence_base=a.evidence,
    ))
    return 0


def cmd_ota_exact(a):
    emit(run_exact_hunt(
        version=a.version,
        build=a.build,
        rel=a.rel,
        release_date=a.release_date,
        evidence_base=a.evidence,
        ca_bundle=a.ca_bundle,
        wayback_insecure=a.wayback_insecure,
        live_bucket=not a.no_live_bucket,
        validate=not a.no_validate,
    ))
    return 0


def cmd_ota_exact_both(a):
    results = []
    for target in known_targets():
        results.append(run_exact_hunt(
            **target,
            evidence_base=a.evidence,
            ca_bundle=a.ca_bundle,
            wayback_insecure=a.wayback_insecure,
            live_bucket=not a.no_live_bucket,
            validate=not a.no_validate,
        ))
    emit({
        "targets": known_targets(),
        "results": results,
    })
    return 0


def cmd_ota_hunt(a):
    emit(run_ota_hunt(
        version=a.version, build=a.build, rel=a.rel,
        release_date=a.release_date, region=a.region,
        evidence_base=a.evidence, wayback=not a.no_wayback,
        validate=not a.no_validate,
    ))
    return 0


def cmd_ota_hunt_both(a):
    targets = [
        {"version":"1.4.4","build":"260527","rel":"28339n","release_date":"2026-06-02"},
        {"version":"1.4.6","build":"260709","rel":"27675n","release_date":"2026-07-17"},
    ]
    results = [
        run_ota_hunt(**t, region="EU", evidence_base=a.evidence,
                     wayback=not a.no_wayback, validate=not a.no_validate)
        for t in targets
    ]
    emit({"targets": targets, "results": results})
    return 0


def cmd_ota_validate(a):
    emit(validate_url(a.url))
    return 0


def cmd_ota_scan_file(a):
    emit(scan_local_file(path=a.path, version=a.version, build=a.build, rel=a.rel))
    return 0

def cmd_bound_auth_status(a):
    profile = bound_register()
    profile["interpretation"] = {
        "password_attempted": False,
        "pake_share_sent": False,
        "safe_to_repeat": True,
        "note": (
            "This command cannot consume a password attempt because it stops "
            "after pake_register."
        ),
    }
    emit(profile)
    return 0


def cmd_bound_register(a):
    emit(bound_register())
    return 0


def cmd_bound_auth_probe(a):
    emit(bound_auth_probe(
        candidate=a.candidate,
        password_label=a.password_label,
    ))
    return 0


def cmd_bound_cloud_check(a):
    emit(bound_cloud_check(
        candidate=a.candidate,
        password_label=a.password_label,
        poll_seconds=a.poll_seconds,
        interval=a.interval,
        evidence_base=a.evidence,
    ))
    return 0


def cmd_normal_ready(a):
    emit(normal_ready())
    return 0


def cmd_normal_cloud_check(a):
    emit(run_normal_cloud_check(
        username=a.user,
        poll_seconds=a.poll_seconds,
        interval=a.interval,
        evidence_base=a.evidence,
    ))
    return 0


def cmd_cloud_check(a):
    emit(run_cloud_check(
        poll_seconds=a.poll_seconds,
        interval=a.interval,
        evidence_base=a.evidence,
        trigger=not a.no_trigger,
    ))
    return 0


def cmd_download_url(a):
    emit(s3_download_url(a.url, a.out, insecure=a.insecure))
    return 0


def cmd_decryptor_check(a):
    from .wsl import decryptor_status
    status = decryptor_status()
    if not status.get("exists"):
        emit({
            "ok": False,
            "status": status,
            "next": (
                "Run inside Ubuntu WSL: "
                "bash scripts/setup-v5patchlab-wsl.sh"
            ),
        })
        return 2
    emit({"ok": True, "status": status})
    return 0



def cmd_wsl_path_check(a):
    from .wsl import wsl_path_diagnostic
    emit(wsl_path_diagnostic(a.path))
    return 0


def cmd_plan(a):
    print(r"""
V5PatchLab recommended workflow

1) Confirm environment:
   python .\v5patchlab.py env-check

2) Find exact public C200v5 objects:
   python .\v5patchlab.py firmware-find --version 1.4.4 --build 260527
   python .\v5patchlab.py firmware-find --version 1.4.6 --build 260709

3) Download the exact EU objects returned by the listing:
   python .\v5patchlab.py firmware-download --key "<S3 key>" --out .\firmware\1.4.4.bin
   python .\v5patchlab.py firmware-download --key "<S3 key>" --out .\firmware\1.4.6.bin

4) Prepare tp-link-decrypt in Ubuntu WSL:
   wsl -d Ubuntu
   cd ~
   git clone https://github.com/robbins/tp-link-decrypt
   cd tp-link-decrypt
   ./preinstall.sh
   ./extract_keys.sh
   make
   exit

5) Decrypt:
   python .\v5patchlab.py decrypt .\firmware\1.4.4.bin
   python .\v5patchlab.py decrypt .\firmware\1.4.6.bin

6) Inspect before extraction:
   python .\v5patchlab.py magic-scan .\firmware\1.4.4.bin.dec
   python .\v5patchlab.py magic-scan .\firmware\1.4.6.bin.dec

7) Extract with binwalk:
   python .\v5patchlab.py extract .\firmware\1.4.4.bin.dec --out .\analysis\144
   python .\v5patchlab.py extract .\firmware\1.4.6.bin.dec --out .\analysis\146

8) Locate `main`:
   python .\v5patchlab.py find-main .\analysis\144
   python .\v5patchlab.py find-main .\analysis\146

9) Copy/record the exact corresponding `main` paths, then:
   python .\v5patchlab.py report \
     --old "<1.4.4 main>" \
     --new "<1.4.6 main>" \
     --out .\analysis\patch-144-vs-146

10) Review patch-report.md + patch-report.json, then open both binaries in Ghidra.
""".strip())
    return 0



def cmd_public_base_info(a):
    emit(public_base_info())
    return 0


def cmd_public_base_fetch(a):
    emit(public_base_fetch(a.out, insecure=a.insecure))
    return 0


def cmd_s1_static_map(a):
    report = build_s1_static_report(a.main, a.rootfs, xrefs=a.xrefs)
    outputs = write_s1_static_report(report, a.out) if a.out else None
    emit({
        "report": report,
        "outputs": outputs,
    })
    return 0


def cmd_s1_controlflow(a):
    targets = a.target if a.target else DEFAULT_TARGETS
    report = build_controlflow_report(a.main, targets=targets)
    outputs = write_controlflow_report(report, a.out)
    emit({
        "summary": {
            "main": report["main"],
            "target_count": len(report["functions"]),
            "missing_targets": report["missing_targets"],
            "top_bridge_candidates": report["bridge_candidates"][:12],
        },
        "outputs": outputs,
    })
    return 0


def cmd_s1_predicate_slice(a):
    report = build_predicate_report(a.main, root_name=a.root_function)
    outputs = write_predicate_report(report, a.out)
    emit({
        "summary": {
            "root": {
                "name": report["root"]["name"],
                "address_hex": report["root"]["address_hex"],
                "size": report["root"]["size"],
                "caller_site_count": len(report["root"]["caller_sites"]),
            },
            "direct_link_handler_to_onboarding_start": report["interpretation"]["direct_link_handler_to_onboarding_start"],
            "gate_slices": [
                {
                    "source": g["source"],
                    "sink": g["sink"],
                    "call_site_hex": g["call_site_hex"],
                    "preceding_branch_count": len(g["preceding_branches"]),
                    "nearby_string_count": len(g["nearby_strings"]),
                }
                for g in report["gate_slices"]
            ],
        },
        "outputs": outputs,
    })
    return 0


def cmd_s1_observe_softap(a):
    emit(observe_softap(
        seconds=a.seconds,
        interval=a.interval,
        ssid_prefix=a.ssid_prefix,
        out_dir=a.out,
    ))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        description="Tapo C200 V5 firmware acquisition + 1.4.4→1.4.6 patch-diff lab"
    )
    s = p.add_subparsers(dest="command", required=True)

    q = s.add_parser("plan")
    q.set_defaults(func=cmd_plan)

    q = s.add_parser("matrix")
    q.set_defaults(func=cmd_matrix)

    q = s.add_parser("env-check")
    q.set_defaults(func=cmd_env)

    q = s.add_parser(
        "s1-static-map",
        help=(
            "Map reset/provisioning/Wi-Fi event strings and symbols relevant to "
            "the radio-only S1 NORMAL->factory/provisioning objective."
        ),
    )
    q.add_argument("main", help="Extracted camera main ELF")
    q.add_argument("--rootfs", default=None, help="Optional extracted squashfs-root directory")
    q.add_argument("--out", default=r"analysis\s1-static-map")
    q.add_argument(
        "--xrefs",
        action="store_true",
        help="Also run approximate MIPS string xref generation (slower).",
    )
    q.set_defaults(func=cmd_s1_static_map)

    q = s.add_parser(
        "s1-controlflow",
        help=(
            "Recover direct MIPS call/branch/string context around the WLAN -> "
            "onboarding/re-onboarding/SoftAP junction."
        ),
    )
    q.add_argument("main", help="Extracted camera main ELF")
    q.add_argument(
        "--target", action="append", default=None,
        help="Function to analyze; repeatable. Defaults to the S1 onboarding target set.",
    )
    q.add_argument("--out", default=r"analysis\s1-onboarding-controlflow")
    q.set_defaults(func=cmd_s1_controlflow)

    q = s.add_parser(
        "s1-predicate-slice",
        help=(
            "Extract the exact branch windows gating the physical Wi-Fi link-status "
            "handler into onboarding/re-onboarding. Static analysis only."
        ),
    )
    q.add_argument("main", help="Extracted camera main ELF")
    q.add_argument(
        "--root-function",
        default="onboarding_phy_link_status_change_handle",
        help="Root link-status handler to slice.",
    )
    q.add_argument("--out", default=r"analysis\s1-link-predicate")
    q.set_defaults(func=cmd_s1_predicate_slice)

    q = s.add_parser(
        "s1-observe-softap",
        help=(
            "Windows radio-side observer: log appearances of Tapo_Cam_* during a "
            "bounded S1 experiment. Does not inject frames."
        ),
    )
    q.add_argument("--seconds", type=float, default=180.0)
    q.add_argument("--interval", type=float, default=2.0)
    q.add_argument("--ssid-prefix", default="Tapo_Cam_")
    q.add_argument("--out", default=r"evidence\s1-rf-observe")
    q.set_defaults(func=cmd_s1_observe_softap)

    q = s.add_parser("decryptor-check")
    q.set_defaults(func=cmd_decryptor_check)

    q = s.add_parser("official-releases")
    q.set_defaults(func=cmd_official_releases)

    q = s.add_parser(
        "camera-fw",
        help=(
            "NO-ACCOUNT path: read device/upgrade metadata through the scoped "
            "SETUP TPAP pake:[0] session."
        ),
    )
    q.add_argument(
        "--refresh",
        action="store_true",
        help=(
            "Also call checkFirmwareVersionByCloud before the read. "
            "Still uses no Tapo account, but needs camera upstream Internet."
        ),
    )
    q.set_defaults(func=cmd_camera_fw)

    q = s.add_parser(
        "public-base-info",
        help="Show the known public C200 V5 1.4.2 vulnerable-side baseline.",
    )
    q.set_defaults(func=cmd_public_base_info)

    q = s.add_parser(
        "public-base-fetch",
        help=(
            "Download the known public C200 V5 1.4.2 baseline without any "
            "Tapo account authentication."
        ),
    )
    q.add_argument(
        "--out",
        default=r"firmware\Tapo_C200v5_1.4.2_260513.bin",
    )
    q.add_argument(
        "--insecure",
        action="store_true",
        help=(
            "Disable TLS verification only for the public firmware CDN "
            "download if the local CA chain is broken."
        ),
    )
    q.set_defaults(func=cmd_public_base_fetch)

    q = s.add_parser(
        "cloud-account-fw",
        help=(
            "Use the user's own Tapo cloud account to select the scoped "
            "C200 V5 and read firmware upgrade metadata through cloud passthrough."
        ),
    )
    q.add_argument(
        "--target-mac",
        default=None,
        help="Scoped camera MAC; otherwise read config/scope.json.",
    )
    q.add_argument(
        "--email",
        default=None,
        help=(
            "Tapo account email. If omitted, prompt interactively. "
            "Password is always prompted and never persisted."
        ),
    )
    q.add_argument(
        "--mfa-type",
        type=int,
        choices=[1, 2],
        default=None,
        help="1=push, 2=email. Auto-select email when supported.",
    )
    q.add_argument("--poll-seconds", type=float, default=20.0)
    q.add_argument("--interval", type=float, default=2.0)
    q.add_argument("--evidence", default="evidence/runs")
    q.add_argument(
        "--arm",
        action="store_true",
        help=(
            "Also call checkFirmwareVersionByCloud and poll. Without --arm, "
            "read only cached upgrade_info/upgrade_status."
        ),
    )
    q.set_defaults(func=cmd_cloud_account_fw)

    q = s.add_parser(
        "ota-exact",
        help=(
            "Strict C200v5 OTA object-key hunt: exact product/build/Rel only, "
            "with 2026 public bucket indexes and bounded live bucket prefixes."
        ),
    )
    q.add_argument("--version", required=True)
    q.add_argument("--build", required=True)
    q.add_argument("--rel", required=True)
    q.add_argument("--release-date", required=True)
    q.add_argument("--evidence", default="evidence/runs")
    q.add_argument("--ca-bundle", default=None)
    q.add_argument(
        "--wayback-insecure",
        action="store_true",
        help=(
            "Disable certificate verification ONLY for the public Wayback "
            "CDX metadata request. Explicit fallback for broken local CA chains."
        ),
    )
    q.add_argument("--no-live-bucket", action="store_true")
    q.add_argument("--no-validate", action="store_true")
    q.set_defaults(func=cmd_ota_exact)

    q = s.add_parser(
        "ota-exact-both",
        help=(
            "Strictly search the C200 V5 1.4.4/260527 and "
            "1.4.6/260709 object keys."
        ),
    )
    q.add_argument("--evidence", default="evidence/runs")
    q.add_argument("--ca-bundle", default=None)
    q.add_argument(
        "--wayback-insecure",
        action="store_true",
        help=(
            "Disable TLS verification ONLY for public Wayback CDX metadata."
        ),
    )
    q.add_argument("--no-live-bucket", action="store_true")
    q.add_argument("--no-validate", action="store_true")
    q.set_defaults(func=cmd_ota_exact_both)

    q = s.add_parser("ota-hunt", help="Search public sources for one exact C200 V5 OTA object.")
    q.add_argument("--version", required=True)
    q.add_argument("--build", required=True)
    q.add_argument("--rel", default=None)
    q.add_argument("--release-date", required=True)
    q.add_argument("--region", default="EU")
    q.add_argument("--evidence", default="evidence/runs")
    q.add_argument("--no-wayback", action="store_true")
    q.add_argument("--no-validate", action="store_true")
    q.set_defaults(func=cmd_ota_hunt)

    q = s.add_parser("ota-hunt-both", help="Search C200 V5 1.4.4 and 1.4.6 OTA targets.")
    q.add_argument("--evidence", default="evidence/runs")
    q.add_argument("--no-wayback", action="store_true")
    q.add_argument("--no-validate", action="store_true")
    q.set_defaults(func=cmd_ota_hunt_both)

    q = s.add_parser("ota-validate", help="Validate one exact public candidate URL.")
    q.add_argument("--url", required=True)
    q.set_defaults(func=cmd_ota_validate)

    q = s.add_parser("ota-scan-file", help="Scan a local public index/page for a target.")
    q.add_argument("path")
    q.add_argument("--version", required=True)
    q.add_argument("--build", required=True)
    q.add_argument("--rel", default=None)
    q.set_defaults(func=cmd_ota_scan_file)

    q = s.add_parser(
        "bound-auth-status",
        help=(
            "Password-free bound TPAP status/profile. Stops at pake_register "
            "and cannot consume a password attempt."
        ),
    )
    q.set_defaults(func=cmd_bound_auth_status)

    q = s.add_parser(
        "bound-register",
        help=(
            "Inspect the scoped NORMAL pake:[2] userpw register profile. "
            "No password and no pake_share."
        ),
    )
    q.set_defaults(func=cmd_bound_register)

    q = s.add_parser(
        "bound-auth-probe",
        help=(
            "Attempt exactly one bounded TPAP userpw authentication and read "
            "getDeviceInfo if successful."
        ),
    )
    q.add_argument(
        "--candidate",
        choices=["raw", "md5", "sha256"],
        default="raw",
        help="Form applied to the locally entered password before extra_crypt.",
    )
    q.add_argument(
        "--password-label",
        default="TPAP management password",
        help="Prompt label only; never persisted.",
    )
    q.set_defaults(func=cmd_bound_auth_probe)

    q = s.add_parser(
        "bound-cloud-check",
        help=(
            "Use the bound TPAP userpw session to run the same read-only "
            "firmware metadata check."
        ),
    )
    q.add_argument(
        "--candidate",
        choices=["raw", "md5", "sha256"],
        default="raw",
    )
    q.add_argument(
        "--password-label",
        default="TPAP management password",
    )
    q.add_argument("--poll-seconds", type=float, default=20.0)
    q.add_argument("--interval", type=float, default=2.0)
    q.add_argument("--evidence", default="evidence/runs")
    q.set_defaults(func=cmd_bound_cloud_check)

    q = s.add_parser(
        "normal-ready",
        help="Verify the scoped camera is back on its normal LAN IP.",
    )
    q.set_defaults(func=cmd_normal_ready)

    q = s.add_parser(
        "normal-cloud-check",
        help=(
            "Authenticate with the local Camera Account on the normal LAN, "
            "trigger firmware metadata check, and poll upgrade_info."
        ),
    )
    q.add_argument(
        "--user",
        required=True,
        help="Camera Account username only. Password is prompted securely.",
    )
    q.add_argument("--poll-seconds", type=float, default=20.0)
    q.add_argument("--interval", type=float, default=2.0)
    q.add_argument("--evidence", default="evidence/runs")
    q.set_defaults(func=cmd_normal_cloud_check)

    q = s.add_parser(
        "cloud-check",
        help=(
            "Trigger a firmware metadata check, then poll read-only "
            "upgrade_info/upgrade_status; never starts fw_download."
        ),
    )
    q.add_argument("--poll-seconds", type=float, default=20.0)
    q.add_argument("--interval", type=float, default=2.0)
    q.add_argument("--evidence", default="evidence/runs")
    q.add_argument(
        "--no-trigger",
        action="store_true",
        help="Read cached upgrade metadata only; do not call checkFirmwareVersionByCloud.",
    )
    q.set_defaults(func=cmd_cloud_check)

    q = s.add_parser("firmware-download-url")
    q.add_argument("--url", required=True)
    q.add_argument("--out", required=True)
    q.add_argument("--insecure", action="store_true")
    q.set_defaults(func=cmd_download_url)

    q = s.add_parser("firmware-find")
    q.add_argument("--version", default=None)
    q.add_argument("--build", default=None)
    q.add_argument("--region", default=None, help="e.g. eu, us")
    q.set_defaults(func=cmd_find)

    q = s.add_parser("firmware-download")
    q.add_argument("--key", required=True)
    q.add_argument("--out", required=True)
    q.add_argument("--insecure", action="store_true")
    q.set_defaults(func=cmd_download)

    q = s.add_parser(
        "wsl-path-check",
        help="Verify Windows -> WSL path conversion without modifying any file.",
    )
    q.add_argument("path")
    q.set_defaults(func=cmd_wsl_path_check)

    q = s.add_parser("decrypt")
    q.add_argument("firmware")
    q.add_argument(
        "--tool",
        default="~/tp-link-decrypt/bin/tp-link-decrypt",
        help="Executable path inside Ubuntu WSL",
    )
    q.set_defaults(func=cmd_decrypt)

    q = s.add_parser("magic-scan")
    q.add_argument("image")
    q.set_defaults(func=cmd_magic)

    q = s.add_parser("extract")
    q.add_argument("image")
    q.add_argument("--out", required=True)
    q.set_defaults(func=cmd_extract)

    q = s.add_parser("find-main")
    q.add_argument("root")
    q.set_defaults(func=cmd_find_main)

    q = s.add_parser("diff")
    q.add_argument("--old", required=True)
    q.add_argument("--new", required=True)
    q.add_argument("--out", default=None)
    q.set_defaults(func=cmd_diff)

    q = s.add_parser("report")
    q.add_argument("--old", required=True)
    q.add_argument("--new", required=True)
    q.add_argument("--out", required=True)
    q.set_defaults(func=cmd_report)

    return p


def main():
    a = build_parser().parse_args()
    try:
        return a.func(a)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(f"[v5patchlab] ERROR: {type(exc).__name__}: {exc}")
        return 2
