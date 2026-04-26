# ASCII only

import base64
import ctypes
from ctypes import wintypes

CRYPTPROTECT_LOCAL_MACHINE = 0x4


class SecretError(Exception):
    pass


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


crypt32 = ctypes.windll.crypt32
kernel32 = ctypes.windll.kernel32


def _to_blob(data):
    buf = ctypes.create_string_buffer(data)
    return DATA_BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))


def protect_secret(value, machine_scope=True):
    if value is None:
        value = ""
    raw = str(value).encode("utf-8")
    in_blob = _to_blob(raw)
    out_blob = DATA_BLOB()
    flags = CRYPTPROTECT_LOCAL_MACHINE if machine_scope else 0

    ok = crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        flags,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise SecretError("CryptProtectData failed")

    try:
        encrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return base64.b64encode(encrypted).decode("ascii")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def unprotect_secret(value):
    if not value:
        return ""
    try:
        encrypted = base64.b64decode(value)
    except Exception as exc:
        raise SecretError("Secret value is not valid base64") from exc

    in_blob = _to_blob(encrypted)
    out_blob = DATA_BLOB()

    ok = crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        None,
        None,
        None,
        0,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise SecretError("CryptUnprotectData failed")

    try:
        decrypted = ctypes.string_at(out_blob.pbData, out_blob.cbData)
        return decrypted.decode("utf-8")
    finally:
        kernel32.LocalFree(out_blob.pbData)


def encrypt_config_secrets(config):
    result = dict(config)

    api_key = result.pop("palo_api_key", "")
    pfx_password = result.pop("pfx_password", "")

    if api_key:
        result["palo_api_key_dpapi"] = protect_secret(api_key, True)
    if pfx_password:
        result["pfx_password_dpapi"] = protect_secret(pfx_password, True)

    return result


def get_secret(config, plaintext_key, dpapi_key):
    if config.get(dpapi_key):
        return unprotect_secret(config.get(dpapi_key))
    return config.get(plaintext_key, "")
