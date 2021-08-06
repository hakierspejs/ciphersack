#!/usr/bin/env python3

import base64
import argparse
import pathlib
import dataclasses
import logging

import hashlib
from Crypto.Cipher import AES
import bencodepy


@dataclasses.dataclass(frozen=True)
class ChunkMetadata:
    offset: int = 0
    number: int = 0
    size: int = 0
    h: bytes = b""
    filename: bytes = b""


def get_offset(chunk_hash, chunk_size, storage_size):
    logging.debug(
        "get_offset(chunk_hash=%r, chunk_size=%r, storage_size=%r)",
        chunk_hash,
        chunk_size,
        storage_size,
    )
    num_chunks = storage_size // chunk_size
    chunk_hash_int = int(base64.b16encode(chunk_hash).decode(), 16)
    chunk_no = chunk_hash_int % num_chunks
    ret = chunk_no * chunk_size
    return ret


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--loglevel", default="INFO")
    parser.add_argument("--decryptedfile", required=True)
    parser.add_argument("--metafile", required=True)
    parser.add_argument("--storagefile", required=True)
    parser.add_argument("--mode", required=True, choices=["decode", "encode"])
    return parser.parse_args().__dict__


def get_chunks_hashes(bdecoded):
    chunk_size = bdecoded[b"piece length"]
    chunk_no = 0
    offset = 0
    num_chunks = len(bdecoded[b"pieces"]) // 20
    file_length = bdecoded[b"files"][0][b"length"]
    if num_chunks * chunk_size != file_length:
        last_chunk_size = file_length - ((num_chunks - 1) * chunk_size)
    else:
        last_chunk_size = chunk_size
    for chunk_no in range(num_chunks):
        chunk_hash = bdecoded[b"pieces"][chunk_no * 20 : (chunk_no + 1) * 20]
        yield ChunkMetadata(
            offset=offset,
            number=chunk_no,
            size=chunk_size
            if chunk_no != (num_chunks - 1)
            else last_chunk_size,
            h=chunk_hash,
            filename=bdecoded[b"files"][0][b"path"],
        )
        offset += chunk_size


def encrypt_chunk(chunk_metadata, chunk_contents):
    return chunk_contents  # TODO


def decrypt_chunk(chunk_metadata, chunk_contents):
    return chunk_contents  # TODO


def encode(decryptedfile, metafile, storagefile):
    with open(metafile, "rb") as f:
        bdecoded = bencodepy.decode(f.read())
    storage_size = pathlib.Path(storagefile).stat().st_size
    with open(storagefile, "wb") as f_storage, open(
        decryptedfile, "rb"
    ) as f_decrypted:
        for chunk in get_chunks_hashes(bdecoded):
            f_decrypted.seek(chunk.offset)
            chunk_encrypted = encrypt_chunk(
                chunk, f_decrypted.read(chunk.size)
            )
            f_storage.seek(get_offset(chunk.h, chunk.size, storage_size))
            f_storage.write(chunk_encrypted)


def decode(decryptedfile, metafile, storagefile):
    with open(metafile, "rb") as f:
        bdecoded = bencodepy.decode(f.read())
    storage_size = pathlib.Path(storagefile).stat().st_size
    with open(storagefile, "rb") as f_storage, open(
        decryptedfile, "wb"
    ) as f_decrypted:
        for chunk in get_chunks_hashes(bdecoded):
            f_storage.seek(get_offset(chunk.h, chunk.size, storage_size))
            chunk_decrypted = decrypt_chunk(chunk, f_storage.read(chunk.size))
            f_decrypted.seek(chunk.offset)
            f_decrypted.write(chunk_decrypted)


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(level=args.pop("loglevel").upper())
    mode = args.pop("mode")
    if mode == "encode":
        encode(**args)
    elif mode == "decode":
        decode(**args)
    else:
        raise RuntimeError("unexpected mode: %r" % mode)
