import io
import struct
import zipfile


def make_zip(entries=None, compression=zipfile.ZIP_STORED):
    handle = io.BytesIO()
    with zipfile.ZipFile(handle, "w", compression=compression) as archive:
        for name, body in entries or [("readme.txt", b"Synthetic test data only.")]:
            archive.writestr(name, body)
    return handle.getvalue()


def patch_u16(data, offset, value):
    buffer = bytearray(data)
    struct.pack_into("<H", buffer, offset, value)
    return bytes(buffer)


def patch_u32(data, offset, value):
    buffer = bytearray(data)
    struct.pack_into("<I", buffer, offset, value)
    return bytes(buffer)
