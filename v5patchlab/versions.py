FIRMWARE_MATRIX = [
    {
        "version": "1.3.5",
        "build": "260228",
        "status": "historical",
        "notes": "V5 release before 1.4.4.",
    },
    {
        "version": "1.4.4",
        "build": "260527",
        "status": "old/reference",
        "notes": (
            "Fixed CVE-2026-1871 according to TP-Link. "
            "Still affected by CVE-2026-15315/15316 because both records "
            "define affected C200 V5 versions as < 1.4.6 Build 260709."
        ),
    },
    {
        "version": "1.4.6",
        "build": "260709",
        "release": "fixed/current-lab",
        "notes": (
            "Current lab build Rel.27675n; fixing boundary for "
            "CVE-2026-15315 and CVE-2026-15316."
        ),
    },
]

CVE_SEEDS = {
    "CVE-2026-15315": {
        "title": "Unauthenticated administrative authentication bypass",
        "themes": [
            "login",
            "challenge",
            "challenge parameter",
            "device_confirm",
            "dev_confirm",
            "confirm",
            "nonce",
            "cnonce",
            "digest",
            "session",
            "stok",
            "token",
            "pake",
            "pake_register",
            "pake_share",
            "authentication",
            "verify",
        ],
        "reason": (
            "Vendor CNA says challenge parameter validation weaknesses "
            "allowed bypass of normal authentication controls and "
            "administrative session token acquisition."
        ),
    },
    "CVE-2026-15316": {
        "title": "Oversized encrypted credential input DoS",
        "themes": [
            "ciphertext",
            "crypted",
            "encrypt",
            "decrypt",
            "credential",
            "passwd",
            "password",
            "changeThirdAccount",
            "third_account",
            "user_management",
            "rsa",
            "base64",
            "decode",
            "exception",
            "malloc",
            "memcpy",
            "memmove",
            "strlen",
            "strncpy",
            "snprintf",
        ],
        "reason": (
            "Vendor CNA says oversized encrypted credential ciphertext "
            "values in the configuration service could trigger exception "
            "handling failures and crash/restart the device."
        ),
    },
}

COMMON_SECURITY_SEEDS = [
    "memcpy", "memmove", "strcpy", "strncpy", "sprintf", "snprintf",
    "strlen", "malloc", "calloc", "realloc", "free",
    "rsa", "base64", "decrypt", "encrypt",
    "error_code", "securePassthrough", "multipleRequest",
]
