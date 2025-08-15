from __future__ import annotations
from pathlib import Path
import os, io, json, struct, tarfile, tempfile, shutil
from typing import BinaryIO, Optional
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MAGIC = b"CC20"
VERSION = 2
KDF_ID_SCRYPT = 1
ALGO_ID_CHACHA20POLY1305 = 1

DEFAULT_SCRYPT = dict(n=2**15, r=8, p=1) 
DEFAULT_CHUNK_SIZE = 1024 * 1024

class EncDecError(Exception):
    pass

def _kdf_scrypt(password: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(password.encode())

def _build_header_scrypt(*, salt: bytes, scrypt_params: dict, nonce_prefix: bytes, chunk_size: int) -> bytes:
    """
    Header format (little-endian):
    MAGIC[4] | VERSION[1] | kdf_id[1] | algo_id[1] | flags[1] (bit0=chunked) |
    kdf_len[2] | kdf_params_json[kdf_len] | nonce_prefix_len[1] | nonce_prefix |
    chunk_size[4]
    """
    flags = 1  
    kdf_params = {
        "salt": salt.hex(),
        "n": scrypt_params["n"],
        "r": scrypt_params["r"],
        "p": scrypt_params["p"],
    }
    kdf_blob = json.dumps(kdf_params, separators=(",", ":")).encode()
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

def _parse_header_and_key(password: str, f: BinaryIO):
    head = f.read(4 + 1 + 1 + 1 + 1 + 2)  
    if len(head) < 9:
        raise EncDecError("Truncated header")
    magic, ver, kdf_id, algo_id, flags, kdf_len = struct.unpack("<4sBBBBH", head)
    if magic != MAGIC:
        raise EncDecError("Unknown format (missing MAGIC).")
    if ver != VERSION:
        raise EncDecError(f"Unsupported version {ver}.")
    kdf_blob = f.read(kdf_len)
    if len(kdf_blob) != kdf_len:
        raise EncDecError("Truncated KDF params")
    kdf_params = json.loads(kdf_blob.decode())
    salt = bytes.fromhex(kdf_params["salt"])
    if kdf_id != KDF_ID_SCRYPT:
        raise EncDecError(f"Unsupported KDF id {kdf_id}.")
    if algo_id != ALGO_ID_CHACHA20POLY1305:
        raise EncDecError(f"Unsupported algo id {algo_id}.")
    nonce_plen_b = f.read(1)
    if len(nonce_plen_b) != 1:
        raise EncDecError("Truncated nonce prefix length")
    nonce_plen = nonce_plen_b[0]
    nonce_prefix = f.read(nonce_plen)
    if len(nonce_prefix) != nonce_plen:
        raise EncDecError("Truncated nonce prefix")
    chunk_size_b = f.read(4)
    if len(chunk_size_b) != 4:
        raise EncDecError("Truncated chunk size")
    (chunk_size,) = struct.unpack("<I", chunk_size_b)

    key = _kdf_scrypt(password, salt, n=kdf_params["n"], r=kdf_params["r"], p=kdf_params["p"])
    header = MAGIC + bytes([VERSION, KDF_ID_SCRYPT, ALGO_ID_CHACHA20POLY1305, flags]) + struct.pack("<H", kdf_len) + kdf_blob + bytes([nonce_plen]) + nonce_prefix + struct.pack("<I", chunk_size)
    return key, header, nonce_prefix, chunk_size

def encrypt_stream(password: str, src: BinaryIO, dst: BinaryIO, *, chunk_size: int = DEFAULT_CHUNK_SIZE, scrypt_params: Optional[dict] = None):
    if scrypt_params is None:
        scrypt_params = DEFAULT_SCRYPT
    salt = os.urandom(16)
    key = _kdf_scrypt(password, salt, **scrypt_params)
    nonce_prefix = os.urandom(8)  # 8B prefix + 4B counter -> 12B nonce
    header = _build_header_scrypt(salt=salt, scrypt_params=scrypt_params, nonce_prefix=nonce_prefix, chunk_size=chunk_size)
    dst.write(header)

    aead = ChaCha20Poly1305(key)
    counter = 1
    while True:
        chunk = src.read(chunk_size)
        if not chunk:
            break
        nonce = nonce_prefix + struct.pack("<I", counter)
        ct = aead.encrypt(nonce, chunk, header)  # header is AAD
        dst.write(struct.pack("<I", len(ct)))
        dst.write(ct)
        counter += 1

def decrypt_stream(password: str, src: BinaryIO, dst: BinaryIO):
    key, header, nonce_prefix, chunk_size = _parse_header_and_key(password, src)
    aead = ChaCha20Poly1305(key)
    counter = 1
    while True:
        szb = src.read(4)
        if not szb:
            break  # EOF
        if len(szb) != 4:
            raise EncDecError("Truncated chunk length")
        (clen,) = struct.unpack("<I", szb)
        ct = src.read(clen)
        if len(ct) != clen:
            raise EncDecError("Truncated chunk")
        nonce = nonce_prefix + struct.pack("<I", counter)
        pt = aead.decrypt(nonce, ct, header)  # raises on tamper
        dst.write(pt)
        counter += 1

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

def decrypt_to_folder(password: str, enc_path: str, out_dir: str):
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    tmp_dir = tempfile.mkdtemp(prefix="cc20dec_")
    tmp_tar = os.path.join(tmp_dir, "out.tar")
    try:
        decrypt_file(password, enc_path, tmp_tar)
        with tarfile.open(tmp_tar, "r") as tar:
            tar.extractall(path=out_dir)
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)
