from __future__ import annotations

import os
import subprocess
import threading
import time
from pathlib import Path

from .common import find_executable, run_command, sanitize_text


def _wireshark_interfaces() -> dict:
    exe = find_executable("tshark") or find_executable("dumpcap")
    if not exe:
        return {
            "available": False,
            "executable": None,
            "interfaces": [],
            "error": "tshark/dumpcap not found",
        }
    rc, out, err = run_command([exe, "-D"], timeout=8.0)
    interfaces = [line.strip() for line in out.splitlines() if line.strip()]
    return {
        "available": rc == 0,
        "executable": exe,
        "interfaces": interfaces,
        "error": sanitize_text(err) if rc else None,
    }


def _pktmon_info() -> dict:
    exe = find_executable("pktmon")
    if not exe:
        return {
            "available": False,
            "executable": None,
            "status_rc": None,
            "status": None,
            "error": "pktmon not found",
        }
    rc, out, err = run_command([exe, "status"], timeout=8.0)
    text = sanitize_text((out or "") + ("\n" + err if err else ""))
    # pktmon is built into supported Windows versions. A non-zero status can
    # simply mean the current shell is not elevated; preserve that distinction.
    return {
        "available": True,
        "executable": exe,
        "status_rc": rc,
        "status": text or None,
        "error": None if rc == 0 else (text or f"pktmon status returned {rc}"),
    }


def capture_interfaces() -> dict:
    wireshark = _wireshark_interfaces()
    pktmon = _pktmon_info() if os.name == "nt" else {
        "available": False,
        "executable": None,
        "status_rc": None,
        "status": None,
        "error": "pktmon is Windows-only",
    }
    return {
        "available": bool(wireshark["available"] or pktmon["available"]),
        "preferred_backend": "wireshark" if wireshark["available"] else ("pktmon" if pktmon["available"] else None),
        "wireshark": wireshark,
        "pktmon": pktmon,
        # compatibility fields retained for v1.0 callers/UI
        "executable": wireshark.get("executable") if wireshark["available"] else pktmon.get("executable"),
        "interfaces": wireshark.get("interfaces", []),
        "error": None if (wireshark["available"] or pktmon["available"]) else (wireshark.get("error") or pktmon.get("error")),
    }


class PcapCapture:
    """Capture traffic involving the target from the host network stack.

    This is deliberately not presented as an ambient LAN/802.11 sniffer. On a
    normal client NIC, Wireshark or pktmon mostly sees traffic entering/leaving
    this host. Passive camera<->AP/cloud observation requires a separate monitor
    mode capture (for example the Alfa adapter) or a mirrored network port.
    """

    def __init__(
        self,
        *,
        run: Path,
        timeline,
        interface: str | None,
        capture_filter: str | None,
        target_ip: str,
        backend: str = "auto",
    ):
        self.run = run
        self.timeline = timeline
        self.interface = interface
        self.capture_filter = capture_filter
        self.target_ip = target_ip
        self.backend = backend
        self.active_backend: str | None = None
        self.proc: subprocess.Popen | None = None
        self.stderr_thread: threading.Thread | None = None
        self.pktmon_exe: str | None = None
        self.pktmon_etl: Path | None = None

    def _select_backend(self) -> str | None:
        requested = (self.backend or "auto").lower()
        if requested == "none":
            return None
        wireshark = _wireshark_interfaces()
        pktmon = _pktmon_info() if os.name == "nt" else {"available": False}
        if requested == "wireshark":
            return "wireshark" if wireshark.get("available") else None
        if requested == "pktmon":
            return "pktmon" if pktmon.get("available") else None
        # auto: Wireshark is preferred only when the caller supplied an
        # interface. Otherwise pktmon is more useful than guessing a NIC.
        if self.interface and wireshark.get("available"):
            return "wireshark"
        if pktmon.get("available"):
            return "pktmon"
        return None

    def start(self):
        selected = self._select_backend()
        if selected is None:
            self.timeline.emit(
                "pcap",
                "DISABLED",
                reason="no usable capture backend; install/enable Npcap or run elevated for pktmon",
            )
            return
        self.active_backend = selected
        if selected == "wireshark":
            self._start_wireshark()
        elif selected == "pktmon":
            self._start_pktmon()

    def _start_wireshark(self):
        if not self.interface:
            self.timeline.emit("pcap", "DISABLED", reason="wireshark backend requires --pcap-interface")
            self.active_backend = None
            return
        exe = find_executable("dumpcap") or find_executable("tshark")
        if not exe:
            self.timeline.emit("pcap", "DISABLED", reason="Wireshark dumpcap/tshark not found")
            self.active_backend = None
            return
        out = self.run / "capture.pcapng"
        args = [exe, "-i", str(self.interface), "-w", str(out)]
        if self.capture_filter:
            args += ["-f", self.capture_filter]
        try:
            self.proc = subprocess.Popen(
                args,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
                errors="replace",
                creationflags=(subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0),
            )
            # Detect immediate failures such as invalid interface/Npcap missing.
            time.sleep(0.4)
            if self.proc.poll() is not None:
                err = ""
                try:
                    if self.proc.stderr:
                        err = self.proc.stderr.read()
                except Exception:
                    pass
                self.timeline.emit("pcap", "CAPTURE_ERROR", backend="wireshark", error=sanitize_text(err or f"capture exited {self.proc.returncode}"))
                self.proc = None
                self.active_backend = None
                return
            self.timeline.emit(
                "pcap",
                "CAPTURE_START",
                backend="wireshark",
                scope="host-stack/selected-interface",
                executable=exe,
                interface=self.interface,
                capture_filter=self.capture_filter,
                path=str(out),
            )
            self.stderr_thread = threading.Thread(target=self._drain_stderr, name="observer-pcap-stderr", daemon=True)
            self.stderr_thread.start()
        except Exception as exc:
            self.timeline.emit("pcap", "CAPTURE_ERROR", backend="wireshark", error=sanitize_text(exc))
            self.proc = None
            self.active_backend = None

    def _start_pktmon(self):
        exe = find_executable("pktmon")
        if not exe:
            self.timeline.emit("pcap", "DISABLED", reason="pktmon not found")
            self.active_backend = None
            return
        self.pktmon_exe = exe
        self.pktmon_etl = self.run / "capture-pktmon.etl"
        log = self.run / "pktmon.log"

        # Packet Monitor filters are global. We intentionally remove existing
        # pktmon filters, add one narrow target-IP filter, capture NICs only, and
        # remove our filters again at stop. This should be run from an elevated
        # PowerShell.
        commands = [
            [exe, "stop"],
            [exe, "filter", "remove"],
            [exe, "filter", "add", "TapoC200", "-i", self.target_ip],
            [exe, "start", "--capture", "--comp", "nics", "--pkt-size", "0", "--file-name", str(self.pktmon_etl)],
        ]
        output_lines = []
        last_rc = 0
        try:
            for idx, cmd in enumerate(commands):
                rc, out, err = run_command(cmd, timeout=10.0)
                output_lines.append(f"$ {' '.join(map(str, cmd))}\n{out}\n{err}\n[rc={rc}]\n")
                # Ignore stop failure when nothing is running. All subsequent
                # setup commands must succeed.
                if idx > 0 and rc != 0:
                    last_rc = rc
                    break
            log.write_text("\n".join(output_lines), encoding="utf-8", errors="replace")
            if last_rc != 0:
                self.timeline.emit(
                    "pcap",
                    "CAPTURE_ERROR",
                    backend="pktmon",
                    error="pktmon setup failed; run PowerShell as Administrator and inspect pktmon.log",
                    log=str(log),
                )
                try:
                    run_command([exe, "filter", "remove"], timeout=5.0)
                except Exception:
                    pass
                self.active_backend = None
                return
            self.timeline.emit(
                "pcap",
                "CAPTURE_START",
                backend="pktmon",
                scope="host-stack/NICs-only; target IP filter",
                executable=exe,
                target_ip=self.target_ip,
                path=str(self.pktmon_etl),
                note="Does not capture ambient camera<->AP/cloud traffic unless this host is on-path.",
            )
        except Exception as exc:
            self.timeline.emit("pcap", "CAPTURE_ERROR", backend="pktmon", error=sanitize_text(exc))
            self.active_backend = None

    def _drain_stderr(self):
        if not self.proc or not self.proc.stderr:
            return
        log = self.run / "pcap-stderr.log"
        with log.open("a", encoding="utf-8", errors="replace") as fh:
            for line in self.proc.stderr:
                fh.write(line)
                fh.flush()

    def stop(self):
        if self.active_backend == "wireshark":
            self._stop_wireshark()
        elif self.active_backend == "pktmon":
            self._stop_pktmon()

    def _stop_wireshark(self):
        if not self.proc:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.timeline.emit("pcap", "CAPTURE_STOP", backend="wireshark", returncode=self.proc.returncode)

    def _stop_pktmon(self):
        exe = self.pktmon_exe
        if not exe:
            return
        rc_stop, out_stop, err_stop = run_command([exe, "stop"], timeout=15.0)
        pcapng = self.run / "capture.pcapng"
        convert_rc = None
        convert_err = None
        if self.pktmon_etl and self.pktmon_etl.exists():
            convert_rc, out_conv, err_conv = run_command(
                [exe, "etl2pcap", str(self.pktmon_etl), "--out", str(pcapng)],
                timeout=30.0,
            )
            convert_err = sanitize_text(err_conv or out_conv) if convert_rc else None
        try:
            run_command([exe, "filter", "remove"], timeout=5.0)
        except Exception:
            pass
        self.timeline.emit(
            "pcap",
            "CAPTURE_STOP",
            backend="pktmon",
            returncode=rc_stop,
            convert_returncode=convert_rc,
            pcapng=str(pcapng) if pcapng.exists() else None,
            error=sanitize_text(err_stop) if rc_stop else convert_err,
        )
