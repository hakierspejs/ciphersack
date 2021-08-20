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
    logging.debug("...=%r", ret)
    return ret


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("--loglevel", default="INFO")
    parser.add_argument("--decryptedfile", required=True)
    parser.add_argument("--metafile", required=True)
    parser.add_argument("--storagefile", required=True)
    parser.add_argument(
        "--mode",
        required=True,
        choices=["decode", "encode", "verify_decryptedfile"],
    )
    return parser.parse_args().__dict__


def get_chunks_hashes(bdecoded):
    chunk_size = bdecoded[b"piece length"]
    chunk_no = 0
    offset = 0
    num_chunks = len(bdecoded[b"pieces"]) // 20
    file_length = bdecoded[b"files"][0][b"length"]
    if num_chunks * chunk_size != file_length:
        last_chunk_size = file_length - ((num_chunks - 1) * chunk_size)
        # last_chunk_size = ((num_chunks) * chunk_size) - file_length
    else:
        last_chunk_size = chunk_size
    logging.debug(
        "get_chunks_hashes: chunk_size=%r, last_chunk_size=%r",
        chunk_size,
        last_chunk_size,
    )
    for chunk_no in range(num_chunks):
        chunk_hash = bdecoded[b"pieces"][chunk_no * 20 : (chunk_no + 1) * 20]
        chunk = ChunkMetadata(
            offset=offset,
            number=chunk_no,
            size=chunk_size
            if chunk_no != (num_chunks - 1)
            else last_chunk_size,
            h=chunk_hash,
            filename=bdecoded[b"files"][0][b"path"],
        )
        logging.debug("get_chunks_hashes: yielding: %r" % chunk)
        yield chunk
        offset += chunk_size


def encrypt_chunk(chunk_metadata, chunk_contents):
    return chunk_contents  # TODO


def decrypt_chunk(chunk_metadata, chunk_contents):
    return chunk_contents  # TODO


def encode(decryptedfile, metafile, storagefile):
    with open(metafile, "rb") as f:
        bdecoded = bencodepy.decode(f.read())
    storage_size = pathlib.Path(storagefile).stat().st_size
    with open(storagefile, "r+b") as f_storage, open(
        decryptedfile, "rb"
    ) as f_decrypted:
        for chunk in get_chunks_hashes(bdecoded):
            f_decrypted.seek(chunk.offset)
            chunk_decrypted = f_decrypted.read(chunk.size)
            chunk_encrypted = encrypt_chunk(
                chunk, chunk_decrypted
            )
            f_storage_offset = get_offset(chunk.h, chunk.size, storage_size)
            f_storage.seek(f_storage_offset)
            f_storage.write(chunk_encrypted)
            f_storage.flush()
            logging.debug(
                "Copied from f_encrypted_offset=%r to f_storage_offset=%r: %r",
                chunk.offset,
                f_storage_offset,
                chunk_decrypted,
            )


def decode(decryptedfile, metafile, storagefile):
    with open(metafile, "rb") as f:
        bdecoded = bencodepy.decode(f.read())
    storage_size = pathlib.Path(storagefile).stat().st_size
    with open(storagefile, "rb") as f_storage, open(
        decryptedfile, "wb"
    ) as f_decrypted:
        for chunk in get_chunks_hashes(bdecoded):
            f_storage_offset = get_offset(chunk.h, chunk.size, storage_size)
            f_storage.seek(f_storage_offset)
            encrypted_chunk = f_storage.read(chunk.size)
            chunk_decrypted = decrypt_chunk(chunk, encrypted_chunk)
            logging.debug(
                "Copied from f_storage_offset=%r to f_decrypted_offset=%r: %r",
                f_storage_offset,
                chunk.offset,
                chunk_decrypted,
            )
            f_decrypted.seek(chunk.offset)
            f_decrypted.write(chunk_decrypted)
#            break


def verify_decryptedfile(decryptedfile, metafile, storagefile):
    logging.warning("NOTE: in this mode, --storagefile is ignored.")
    with open(metafile, "rb") as f:
        bdecoded = bencodepy.decode(f.read())
    with open(decryptedfile, "rb") as f_decrypted:
        for chunk in get_chunks_hashes(bdecoded):
            f_decrypted.seek(chunk.offset)
            decrypted_chunk = f_decrypted.read(chunk.size)
            expected_hash = hashlib.sha1(decrypted_chunk).digest()
            if chunk.h != expected_hash:
                logging.info("Wrong chunk: %r", chunk)


if __name__ == "__main__":
    args = parse_args()
    logging.basicConfig(level=args.pop("loglevel").upper())
    mode = args.pop("mode")
    if mode == "encode":
        encode(**args)
    elif mode == "decode":
        decode(**args)
    elif mode == "verify_decryptedfile":
        verify_decryptedfile(**args)
    else:
        raise RuntimeError("unexpected mode: %r" % mode)
