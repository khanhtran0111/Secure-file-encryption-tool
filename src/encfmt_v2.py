from __future__ import annotations
from pathlib import Path
import os, io, json, struct, tarfile, tempfile, shutil
from typing import BinaryIO, Optional
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

import unicodedata
from dataclasses import dataclass

MAGIC = b"CC20"
VERSION = 2
KDF_ID_SCRYPT = 1
ALGO_ID_CHACHA20POLY1305 = 1

FLAG_CHUNKED = 1 << 0
FLAG_FOOTER = 1 << 1
FLAG_ENVELOPE = 1 << 2

NONCE_PREFIX_LEN = 8
AEAD_NONCE_SIZE = 12
TAG_SIZE = 16
MAX_KDF_LEN = 8192
MAX_CHUNK_SIZE = 64 * 1024 * 1024
SENTINEL_FOOTER = 0xFFFFFFFF
FOOTER_MARKER    = b"CC20END\x00"

DEFAULT_SCRYPT = dict(n = 2**15, r = 8, p = 1) 
DEFAULT_CHUNK_SIZE = 1024 * 1024


@dataclass
class ParsedHeader:
    key: bytes
    header_bytes: bytes
    nonce_prefix: bytes
    chunk_size: int
    has_footer: bool
    is_envelope: bool

def _pw_bytes(password: str) -> bytes:
    return unicodedata.normalize("NFKC", password).encode("utf-8")

class EncDecError(Exception):
    pass

def _kdf_scrypt(password: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    pw = _pw_bytes(password)
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(pw)

def _wrap_fek(kek: bytes, fek: bytes) -> tuple[bytes, bytes]:
    aead = ChaCha20Poly1305(kek)
    nonce = os.urandom(AEAD_NONCE_SIZE)
    ct = aead.encrypt(nonce, fek, b"CC20WRAP")
    return ct, nonce

def _unwrap_fek(kek: bytes, wrapped: bytes, nonce: bytes) -> bytes:
    aead = ChaCha20Poly1305(kek)
    try:
        return aead.decrypt(nonce, wrapped, b"CC20WRAP")
    except InvalidTag:
        raise EncDecError("Wrong password or corrupted data")

def _build_header_scrypt(*, salt: bytes, scrypt_params: dict, nonce_prefix: bytes, chunk_size: int, has_footer: bool = True, envelope: Optional[dict] = None,) -> bytes:
    """
    Header format (little-endian):
    MAGIC[4] | VERSION[1] | kdf_id[1] | algo_id[1] | flags[1] |
    kdf_len[2] | kdf_params_json[kdf_len] | nonce_prefix_len[1] | nonce_prefix |
    chunk_size[4]
    """
    flags = FLAG_CHUNKED
    if has_footer:
        flags |= FLAG_FOOTER
    if envelope is not None:
        flags |= FLAG_ENVELOPE

    kdf_params = {
        "salt": salt.hex(),
        "n": scrypt_params["n"],
        "r": scrypt_params["r"],
        "p": scrypt_params["p"],
    }
    if envelope is not None:
        kdf_params["fek_wrapped"] = envelope["fek_wrapped"].hex()
        kdf_params["fek_nonce"]   = envelope["fek_nonce"].hex()

    kdf_blob = json.dumps(kdf_params, separators=(",", ":")).encode()

    if len(kdf_blob) > MAX_KDF_LEN:
        raise EncDecError("KDF params too large")

    if len(nonce_prefix) != NONCE_PREFIX_LEN:
        raise EncDecError("Invalid nonce prefix length")

    if not (1 <= chunk_size <= MAX_CHUNK_SIZE):
        raise EncDecError("Invalid chunk size")

    hdr = bytearray()
    hdr += MAGIC
    hdr += struct.pack("B", VERSION)
    hdr += struct.pack("B", KDF_ID_SCRYPT)
    hdr += struct.pack("B", ALGO_ID_CHACHA20POLY1305)
    hdr += struct.pack("B", flags)
    hdr += struct.pack("<H", len(kdf_blob))
    hdr += kdf_blob
    hdr += struct.pack("B", len(nonce_prefix))
    hdr += nonce_prefix
    hdr += struct.pack("<I", chunk_size)
    return bytes(hdr)

def _parse_header_and_key(password: str, f: BinaryIO) -> ParsedHeader:
    head = f.read(4 + 1 + 1 + 1 + 1 + 2)
    if len(head) < 9:
        raise EncDecError("Truncated header")

    magic, ver, kdf_id, algo_id, flags, kdf_len = struct.unpack("<4sBBBBH", head)
    if magic != MAGIC:
        raise EncDecError("Unknown format (missing MAGIC)")
    if ver != VERSION:
        raise EncDecError(f"Unsupported version {ver}")
    if kdf_len == 0 or kdf_len > MAX_KDF_LEN:
        raise EncDecError("Suspicious KDF params length")

    kdf_blob = f.read(kdf_len)
    if len(kdf_blob) != kdf_len:
        raise EncDecError("Truncated KDF params")

    try:
        kdf_params = json.loads(kdf_blob.decode())
    except Exception:
        raise EncDecError("Invalid KDF params JSON")

    try:
        salt = bytes.fromhex(kdf_params["salt"])
    except Exception:
        raise EncDecError("Invalid salt in KDF params")

    if kdf_id != KDF_ID_SCRYPT:
        raise EncDecError(f"Unsupported KDF id {kdf_id}")
    if algo_id != ALGO_ID_CHACHA20POLY1305:
        raise EncDecError(f"Unsupported algo id {algo_id}")

    nonce_plen_b = f.read(1)
    if len(nonce_plen_b) != 1:
        raise EncDecError("Truncated nonce prefix length")
    nonce_plen = nonce_plen_b[0]
    if nonce_plen != NONCE_PREFIX_LEN:
        raise EncDecError("Unsupported nonce prefix length")

    nonce_prefix = f.read(nonce_plen)
    if len(nonce_prefix) != nonce_plen:
        raise EncDecError("Truncated nonce prefix")

    chunk_size_b = f.read(4)
    if len(chunk_size_b) != 4:
        raise EncDecError("Truncated chunk size")
    (chunk_size,) = struct.unpack("<I", chunk_size_b)
    if not (1 <= chunk_size <= MAX_CHUNK_SIZE):
        raise EncDecError("Invalid chunk size in header")

    # Derive KEK
    key_kek = _kdf_scrypt(password, salt, n=kdf_params["n"], r=kdf_params["r"], p=kdf_params["p"])

    # Envelope?
    is_envelope = bool(flags & FLAG_ENVELOPE)
    if is_envelope:
        try:
            fek_wrapped = bytes.fromhex(kdf_params["fek_wrapped"])
            fek_nonce   = bytes.fromhex(kdf_params["fek_nonce"])
        except Exception:
            raise EncDecError("Invalid FEK wrap fields")
        if len(fek_nonce) != AEAD_NONCE_SIZE:
            raise EncDecError("Invalid FEK nonce size")
        key_fek = _unwrap_fek(key_kek, fek_wrapped, fek_nonce)  # may raise
        key = key_fek
    else:
        key = key_kek

    header = MAGIC + bytes([VERSION, KDF_ID_SCRYPT, ALGO_ID_CHACHA20POLY1305, flags]) \
             + struct.pack("<H", kdf_len) + kdf_blob + bytes([nonce_plen]) + nonce_prefix \
             + struct.pack("<I", chunk_size)

    has_footer = bool(flags & FLAG_FOOTER)
    return ParsedHeader(key=key, header_bytes=header, nonce_prefix=nonce_prefix,
                        chunk_size=chunk_size, has_footer=has_footer, is_envelope=is_envelope)

def encrypt_stream(password: str, src: BinaryIO, dst: BinaryIO, *, chunk_size: int = DEFAULT_CHUNK_SIZE, scrypt_params: Optional[dict] = None, use_footer: bool = True, use_envelope: bool = True,):
    if scrypt_params is None:
        scrypt_params = DEFAULT_SCRYPT

    if not (1 <= chunk_size <= MAX_CHUNK_SIZE):
        raise EncDecError("Invalid chunk_size")

    salt = os.urandom(16)
    kek  = _kdf_scrypt(password, salt, **scrypt_params)
    envelope = None
    key = kek
    if use_envelope:
        fek = os.urandom(32)
        fek_wrapped, fek_nonce = _wrap_fek(kek, fek)
        envelope = {"fek_wrapped": fek_wrapped, "fek_nonce": fek_nonce}
        key = fek

    nonce_prefix = os.urandom(NONCE_PREFIX_LEN)  # 8B
    header = _build_header_scrypt(
        salt=salt,
        scrypt_params=scrypt_params,
        nonce_prefix=nonce_prefix,
        chunk_size=chunk_size,
        has_footer=use_footer,
        envelope=envelope,
    )
    dst.write(header)

    aead = ChaCha20Poly1305(key)

    total_chunks = 0
    total_plain  = 0
    counter = 1 
    while True:
        chunk = src.read(chunk_size)
        if not chunk:
            break
        if counter == 0:
            raise EncDecError("Too many chunks (counter overflow)")

        nonce = nonce_prefix + struct.pack("<I", counter)  
        ct = aead.encrypt(nonce, chunk, header) 
        dst.write(struct.pack("<I", len(ct)))
        dst.write(ct)

        total_chunks += 1
        total_plain  += len(chunk)
        counter = (counter + 1) & 0xFFFFFFFF

    if use_footer:
        footer_pt = FOOTER_MARKER + struct.pack("<I", total_chunks) + struct.pack("<Q", total_plain)
        footer_nonce = nonce_prefix + struct.pack("<I", 0)  # counter=0
        footer_ct = aead.encrypt(footer_nonce, footer_pt, header)
        dst.write(struct.pack("<I", SENTINEL_FOOTER))
        dst.write(struct.pack("<I", len(footer_ct)))
        dst.write(footer_ct)

def decrypt_stream(password: str, src: BinaryIO, dst: BinaryIO):
    try:
        ph = _parse_header_and_key(password, src)
    except InvalidTag:
        raise EncDecError("Wrong password or corrupted data")
    
    aead = ChaCha20Poly1305(ph.key)

    observed_chunks = 0
    observed_plain  = 0
    expect_footer   = ph.has_footer

    while True:
        szb = src.read(4)
        if not szb:
            if expect_footer:
                raise EncDecError("Missing footer (possible truncation)")
            break
        if len(szb) != 4:
            raise EncDecError("Truncated chunk length")

        (token,) = struct.unpack("<I", szb)
        if token == SENTINEL_FOOTER:
            len_footer_b = src.read(4)
            if len(len_footer_b) != 4:
                raise EncDecError("Truncated footer length")
            (flen,) = struct.unpack("<I", len_footer_b)
            footer_ct = src.read(flen)
            if len(footer_ct) != flen:
                raise EncDecError("Truncated footer")
            footer_nonce = ph.nonce_prefix + struct.pack("<I", 0)
            try:
                footer_pt = aead.decrypt(footer_nonce, footer_ct, ph.header_bytes)
            except InvalidTag:
                raise EncDecError("Wrong password or corrupted footer")
            if not footer_pt.startswith(FOOTER_MARKER) or len(footer_pt) != (len(FOOTER_MARKER)+4+8):
                raise EncDecError("Invalid footer marker")
            tot_chunks = struct.unpack("<I", footer_pt[len(FOOTER_MARKER):len(FOOTER_MARKER)+4])[0]
            tot_plain  = struct.unpack("<Q", footer_pt[len(FOOTER_MARKER)+4:])[0]
            if tot_chunks != observed_chunks or tot_plain != observed_plain:
                raise EncDecError("Footer counters mismatch (possible truncation)")
            trailing = src.read(1)
            if trailing:
                raise EncDecError("Unexpected trailing data after footer")
            return
        clen = token
        if clen < TAG_SIZE or clen > ph.chunk_size + TAG_SIZE:
            raise EncDecError("Ciphertext length out of bounds")

        ct = src.read(clen)
        if len(ct) != clen:
            raise EncDecError("Truncated chunk")
        counter = observed_chunks + 1 
        nonce = ph.nonce_prefix + struct.pack("<I", counter)
        try:
            pt = aead.decrypt(nonce, ct, ph.header_bytes)
        except InvalidTag:
            raise EncDecError("Wrong password or corrupted data")
        dst.write(pt)
        observed_chunks += 1
        observed_plain  += len(pt)

def encrypt_file(password: str, in_path: str, out_path: str, *, chunk_size: int = DEFAULT_CHUNK_SIZE):
    with open(in_path, "rb") as f_in, open(out_path, "wb") as f_out:
        encrypt_stream(password, f_in, f_out, chunk_size=chunk_size)

def decrypt_file(password: str, in_path: str, out_path: str):
    with open(in_path, "rb") as f_in, open(out_path, "wb") as f_out:
        decrypt_stream(password, f_in, f_out)

def encrypt_folder_tar_then_encrypt(password: str, folder_path: str, out_path: str, *, chunk_size: int = DEFAULT_CHUNK_SIZE):
    folder_path = os.path.abspath(folder_path)
    base = os.path.basename(folder_path.rstrip(os.sep))
    tmp_dir = tempfile.mkdtemp(prefix="cc20_")
    tmp_tar = os.path.join(tmp_dir, f"{base}.tar")
    try:
        with tarfile.open(tmp_tar, "w") as tar:
            tar.add(folder_path, arcname=base, recursive=True)
        encrypt_file(password, tmp_tar, out_path, chunk_size=chunk_size)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)

def _safe_extractall(tar: tarfile.TarFile, path: str):
    def is_within_directory(directory: str, target: str) -> bool:
        abs_directory = os.path.abspath(directory)
        abs_target = os.path.abspath(target)
        return os.path.commonprefix([abs_directory, abs_target]) == abs_directory
    for m in tar.getmembers():
        target_path = os.path.join(path, m.name)
        if not is_within_directory(path, target_path):
            raise EncDecError("Path traversal in tar")
    tar.extractall(path=path)

def decrypt_to_folder(password: str, enc_path: str, out_dir: str):
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    tmp_dir = tempfile.mkdtemp(prefix="cc20dec_")
    tmp_tar = os.path.join(tmp_dir, "out.tar")
    try:
        decrypt_file(password, enc_path, tmp_tar)
        with tarfile.open(tmp_tar, "r") as tar:
            _safe_extractall(tar, out_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
