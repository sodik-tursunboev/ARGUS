'ARGUS - Hardware-backed factor (TPM).'

# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Sodik Tursunboev. All rights reserved.
# Part of ARGUS. See LICENSE for the full terms.

import hashlib
import os

PROVIDER_NAME = "Microsoft Platform Crypto Provider"
KEY_NAME = "ARGUS_HWK"
SECRET_NAME = "ARGUS_HWK_PUB"          # enrolment record in secrets_store
KEY_BITS = 2048

MS_PLATFORM_CRYPTO_PROVIDER = PROVIDER_NAME
NCRYPT_NO_PADDING = 0
NCRYPT_PAD_PKCS1 = 2
NCRYPT_KEY_USAGE_PROPERTY = "Key Usage Property"
NCRYPT_LENGTH_PROPERTY = "Length"


class HardwareUnavailable(Exception):
    """No TPM / no provider. Distinct from a FAILED check, for status()."""


# ── low level (all failures surface as exceptions; the layer above decides) ─
def _ncrypt():
    import ctypes
    nc = ctypes.WinDLL("ncrypt", use_last_error=True)
    nc.NCryptOpenStorageProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                             ctypes.c_wchar_p, ctypes.c_uint32]
    nc.NCryptOpenKey.restype = ctypes.c_uint32
    nc.NCryptOpenKey.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p),
                                 ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
    nc.NCryptCreatePersistedKey.restype = ctypes.c_uint32
    nc.NCryptCreatePersistedKey.argtypes = [ctypes.c_void_p,
                                            ctypes.POINTER(ctypes.c_void_p),
                                            ctypes.c_wchar_p, ctypes.c_wchar_p,
                                            ctypes.c_uint32, ctypes.c_uint32]
    nc.NCryptSetProperty.restype = ctypes.c_uint32
    nc.NCryptSetProperty.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p,
                                     ctypes.POINTER(ctypes.c_uint8),
                                     ctypes.c_uint32, ctypes.c_uint32]
    nc.NCryptFinalizeKey.restype = ctypes.c_uint32
    nc.NCryptFinalizeKey.argtypes = [ctypes.c_void_p]
    nc.NCryptExportKey.restype = ctypes.c_uint32
    nc.NCryptExportKey.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                   ctypes.c_wchar_p, ctypes.c_void_p,
                                   ctypes.POINTER(ctypes.c_uint8),
                                   ctypes.c_uint32,
                                   ctypes.POINTER(ctypes.c_uint32),
                                   ctypes.c_uint32]
    nc.NCryptSignHash.restype = ctypes.c_uint32
    nc.NCryptSignHash.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                  ctypes.POINTER(ctypes.c_uint8),
                                  ctypes.c_uint32,
                                  ctypes.POINTER(ctypes.c_uint8),
                                  ctypes.c_uint32,
                                  ctypes.POINTER(ctypes.c_uint32),
                                  ctypes.c_uint32]
    nc.NCryptFreeObject.restype = ctypes.c_uint32
    nc.NCryptFreeObject.argtypes = [ctypes.c_void_p]
    nc.NCryptFreeBuffer.restype = ctypes.c_uint32
    nc.NCryptFreeBuffer.argtypes = [ctypes.c_void_p]
    return nc


def _bcrypt():
    import ctypes
    bc = ctypes.WinDLL("bcrypt", use_last_error=True)
    bc.BCryptOpenAlgorithmProvider.restype = ctypes.c_uint32
    bc.BCryptOpenAlgorithmProvider.argtypes = [ctypes.POINTER(ctypes.c_void_p),
                                               ctypes.c_wchar_p,
                                               ctypes.c_wchar_p, ctypes.c_uint32]
    bc.BCryptImportKeyPair.restype = ctypes.c_uint32
    bc.BCryptImportKeyPair.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                       ctypes.c_wchar_p,
                                       ctypes.POINTER(ctypes.c_void_p),
                                       ctypes.POINTER(ctypes.c_uint8),
                                       ctypes.c_uint32, ctypes.c_uint32]
    bc.BCryptVerifySignature.restype = ctypes.c_uint32
    bc.BCryptVerifySignature.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                                         ctypes.POINTER(ctypes.c_uint8),
                                         ctypes.c_uint32,
                                         ctypes.POINTER(ctypes.c_uint8),
                                         ctypes.c_uint32, ctypes.c_uint32]
    bc.BCryptDestroyKey.restype = ctypes.c_uint32
    bc.BCryptDestroyKey.argtypes = [ctypes.c_void_p]
    bc.BCryptCloseAlgorithmProvider.restype = ctypes.c_uint32
    bc.BCryptCloseAlgorithmProvider.argtypes = [ctypes.c_void_p]
    return bc


def _export_public(nc, hkey):
    """The TPM key's public blob (BCRYPT_RSAPUBLIC_BLOB format)."""
    import ctypes
    blob_type = ctypes.c_wchar_p("PUBLICBLOB")
    need = ctypes.c_uint32(0)
    st = nc.NCryptExportKey(hkey, None, blob_type, None, None, 0,
                            ctypes.byref(need), 0)
    if st != 0:
        raise OSError(f"NCryptExportKey(size) status=0x{st:08x}")
    buf = (ctypes.c_uint8 * need.value)()
    st = nc.NCryptExportKey(hkey, None, blob_type, None, buf, need.value,
                            ctypes.byref(need), 0)
    if st != 0:
        raise OSError(f"NCryptExportKey status=0x{st:08x}")
    return bytes(buf[:need.value])


def _pkcs1_info():
    """BCRYPT_PKCS1_PADDING_INFO { pszAlgId = L"SHA256" } as a ctypes struct."""
    import ctypes
    class INFO(ctypes.Structure):
        _fields_ = [("pszAlgId", ctypes.c_wchar_p)]
    return INFO("SHA256")


def _verify_with_public(pub: bytes, digest: bytes, sig: bytes) -> bool:
    """Check SIG over DIGEST against the exported public blob."""
    import ctypes
    bc = _bcrypt()
    halg = ctypes.c_void_p()
    if bc.BCryptOpenAlgorithmProvider(ctypes.byref(halg), "RSA", None, 0) != 0:
        return False
    hk = ctypes.c_void_p()
    ok = False
    try:
        pbuf = (ctypes.c_uint8 * len(pub)).from_buffer_copy(pub)
        if bc.BCryptImportKeyPair(halg, None, "RSAPUBLICBLOB",
                                  ctypes.byref(hk), pbuf, len(pub), 0) != 0:
            return False
        dbuf = (ctypes.c_uint8 * len(digest)).from_buffer_copy(digest)
        sbuf = (ctypes.c_uint8 * len(sig)).from_buffer_copy(sig)
        info = _pkcs1_info()
        st = bc.BCryptVerifySignature(hk, ctypes.byref(info), dbuf, len(digest),
                                      sbuf, len(sig), 2)   # BCRYPT_PAD_PKCS1
        ok = (st == 0)          # STATUS_SUCCESS only; invalid == 0xC000A000
    finally:
        if hk.value:
            bc.BCryptDestroyKey(hk)
        bc.BCryptCloseAlgorithmProvider(halg)
    return ok


# ── the factor surface ─────────────────────────────────────────────────
def _public_fingerprint(pub: bytes) -> str:
    return hashlib.sha256(pub).hexdigest()


def status() -> dict:
    """For zt_skill / the security summary. Never raises."""
    out = {"available": False, "backend": "tpm-pcp", "enrolled": False,
           "note": ""}
    if os.name != "nt":
        out["note"] = "not Windows"
        return out
    try:
        nc = _ncrypt()
        prov = ctypes.c_void_p() if False else None
        import ctypes
        prov = ctypes.c_void_p()
        st = nc.NCryptOpenStorageProvider(ctypes.byref(prov), PROVIDER_NAME, 0)
        if st != 0:
            out["note"] = "no TPM provider on this machine"
            return out
        try:
            hk = ctypes.c_void_p()
            st = nc.NCryptOpenKey(prov, ctypes.byref(hk), KEY_NAME, 0, 0)
            if st != 0:
                out["available"] = True
                out["note"] = "TPM present; hardware factor not enrolled"
                return out
            out["available"] = True
            out["enrolled"] = True
            out["note"] = "TPM key present"
            return out
        finally:
            if hk.value:
                nc.NCryptFreeObject(hk)
    except Exception as e:
        out["note"] = f"probe failed: {type(e).__name__}"
        return out


def enroll() -> str:
    """Create (or reuse) the TPM-resident key and record its public half.

    Returns a spoken line. The caller (zt_skill) is L2-gated; this function
    additionally refuses on a non-Windows box or an absent provider.
    """
    if os.name != "nt":
        return "Hardware-backed keys need Windows and a TPM."
    import secrets_store
    nc = _ncrypt()
    import ctypes
    prov = ctypes.c_void_p()
    st = nc.NCryptOpenStorageProvider(ctypes.byref(prov), PROVIDER_NAME, 0)
    if st != 0:
        return ("I couldn't open the TPM's key provider, so there's no "
                "hardware factor to enrol here.")
    hk = ctypes.c_void_p()
    try:
        created = False
        st = nc.NCryptOpenKey(prov, ctypes.byref(hk), KEY_NAME, 0, 0)
        if st != 0:
            st = nc.NCryptCreatePersistedKey(prov, ctypes.byref(hk), "RSA",
                                             KEY_NAME, 0, 0)
            if st != 0:
                return "The TPM refused to create the key."
            bits = ctypes.c_uint32(KEY_BITS)
            st = nc.NCryptSetProperty(hk, NCRYPT_LENGTH_PROPERTY,
                                      ctypes.cast(ctypes.byref(bits),
                                                  ctypes.POINTER(ctypes.c_uint8)),
                                      4, 0)
            if st != 0:
                return "The TPM refused the key size."
            st = nc.NCryptFinalizeKey(hk)
            if st != 0:
                return "The TPM refused to finalise the key."
            created = True
        pub = _export_public(nc, hk)
        # Record WHAT was enrolled, so a swapped or regenerated key is
        # detectable rather than silently accepted.
        secrets_store.put_secret(
            SECRET_NAME,
            _public_fingerprint(pub) + "|" + pub.hex())
        return (f"{'Created' if created else 'Reused'} a TPM-resident signing "
                f"key and enrolled its public half. The private half never "
                f"leaves the TPM.")
    except Exception as e:
        return f"Enrolment failed: {type(e).__name__}."
    finally:
        if hk.value:
            nc.NCryptFreeObject(hk)


def forget() -> bool:
    """Delete the enrolment record (the TPM key itself is left in place --
    NCryptDeleteKey exists, but a stale key in the TPM is inert without its
    record, and deleting it is the irreversible kind of tidy-up a security
    module should not do on a maybe)."""
    import secrets_store
    return secrets_store.delete_secret(SECRET_NAME)


def verify(_supplied=None) -> bool:
    """The auth factor. Fresh nonce -> TPM signs -> verify against enrolment.

    Deliberately takes the same (supplied) signature as every other factor in
    auth.FACTORS. Nothing external can be "supplied" here: the challenge is
    minted inside this call, so there is nothing to replay and nothing for a
    recorded voice, a pasted token, or a model's output to satisfy.
    """
    import secrets as _secrets
    if os.name != "nt":
        return False
    try:
        import secrets_store
        rec = secrets_store.get_secret(SECRET_NAME, "")
        if not rec or "|" not in rec:
            return False
        want_fp, hexblob = rec.split("|", 1)
        pub = bytes.fromhex(hexblob)
        if _public_fingerprint(pub) != want_fp:
            return False              # enrolment record tampered -> refuse

        nc = _ncrypt()
        import ctypes
        prov = ctypes.c_void_p()
        if nc.NCryptOpenStorageProvider(ctypes.byref(prov), PROVIDER_NAME, 0) != 0:
            return False
        hk = ctypes.c_void_p()
        try:
            if nc.NCryptOpenKey(prov, ctypes.byref(hk), KEY_NAME, 0, 0) != 0:
                return False
            nonce = _secrets.token_bytes(32)
            digest = hashlib.sha256(nonce).digest()
            need = ctypes.c_uint32(0)
            info = _pkcs1_info()
            st = nc.NCryptSignHash(hk, ctypes.byref(info), digest, len(digest),
                                   None, 0, ctypes.byref(need), 2)
            if st != 0 or need.value == 0:
                return False
            sig = (ctypes.c_uint8 * need.value)()
            st = nc.NCryptSignHash(hk, ctypes.byref(info), digest, len(digest),
                                   sig, need.value, ctypes.byref(need), 2)
            if st != 0:
                return False
            signature = bytes(sig[:need.value])
        finally:
            if hk.value:
                nc.NCryptFreeObject(hk)
        return _verify_with_public(pub, digest, signature)
    except Exception:
        return False
