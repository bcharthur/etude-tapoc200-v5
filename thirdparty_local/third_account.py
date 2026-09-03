from __future__ import annotations

import base64
import hashlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from .tpap0 import TpapSession


THIRD_ACCOUNT_PUBLIC_KEY_PEM = b'''-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC4D6i0oD/Ga5qb//RfSe8MrPVI
rMIGecCxkcGWGj9kxxk74qQNq8XUuXoy2PczQ30BpiRHrlkbtBEPeWLpq85tfubT
UjhBz1NPNvWrC88uaYVGvzNpgzZOqDC35961uPTuvdUa8vztcUQjEZy16WbmetRj
URFIiWJgFCmemyYVbQIDAQAB
-----END PUBLIC KEY-----
'''


def rsa_ciphertext(password: str) -> str:
    key = serialization.load_pem_public_key(
        THIRD_ACCOUNT_PUBLIC_KEY_PEM
    )
    encrypted = key.encrypt(
        password.encode(),
        padding.PKCS1v15(),
    )
    return base64.b64encode(encrypted).decode()


def enable(
    session: TpapSession,
    *,
    username: str,
    password: str,
) -> dict:
    password_md5 = hashlib.md5(
        password.encode()
    ).hexdigest().upper()

    requests = [
        {
            "method": "setAccountEnabled",
            "params": {
                "user_management": {
                    "set_account_enabled": {
                        "enabled": "on",
                        "secname": "third_account",
                    }
                }
            },
        },
        {
            "method": "changeThirdAccount",
            "params": {
                "user_management": {
                    "change_third_account": {
                        "secname": "third_account",
                        "passwd": password_md5,
                        "old_passwd": "",
                        "ciphertext": rsa_ciphertext(password),
                        "username": username,
                    }
                }
            },
        },
    ]

    return session.send(
        "multipleRequest",
        {"requests": requests},
    )
