from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class CameraCredentials:
    username: str
    password: str


class CredentialError(RuntimeError):
    pass


def load_credentials() -> CameraCredentials:
    username = os.environ.get("TAPO_CAMERA_USER", "")
    password = os.environ.get("TAPO_CAMERA_PASSWORD", "")

    if not username or not password:
        raise CredentialError(
            "Définis TAPO_CAMERA_USER et TAPO_CAMERA_PASSWORD dans le terminal. "
            "Il s'agit du compte caméra local RTSP/ONVIF, pas du compte TP-Link cloud."
        )

    return CameraCredentials(username=username, password=password)


def credential_status() -> dict:
    user = os.environ.get("TAPO_CAMERA_USER", "")
    password = os.environ.get("TAPO_CAMERA_PASSWORD", "")
    return {
        "username_present": bool(user),
        "password_present": bool(password),
        "username": user if user else None,
        "password": "<set>" if password else None,
    }
