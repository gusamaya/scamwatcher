"""Screenshot storage for web-form uploads and email image attachments.

Files are saved under UPLOAD_DIR with random names, so nothing a submitter
types ends up in a file path. Only real image formats are accepted, checked by
their first bytes rather than the file name.
"""

import os
import secrets

DB_PATH = os.getenv("DB_PATH", "/var/data/scamwatcher.db")
UPLOAD_DIR = os.getenv("UPLOAD_DIR", os.path.join(os.path.dirname(DB_PATH) or ".", "uploads"))
MAX_UPLOAD_MB = int(os.getenv("MAX_UPLOAD_MB", "10"))

# extension -> mime type
IMAGE_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "heic": "image/heic",
}


def detect_image_type(data: bytes):
    """Return a file extension for a supported image, or None."""
    if not data or len(data) < 12:
        return None
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    # iPhone photos: ISO base media file with a HEIC/HEIF brand
    if data[4:8] == b"ftyp" and data[8:12] in (b"heic", b"heix", b"hevc", b"heim", b"heis", b"mif1", b"msf1"):
        return "heic"
    return None


def save_image(data: bytes):
    """Save image bytes and return the stored file name, or None if the data is
    not a supported image or is too large."""
    if not data or len(data) > MAX_UPLOAD_MB * 1024 * 1024:
        return None
    ext = detect_image_type(data)
    if not ext:
        return None
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    name = f"{secrets.token_hex(16)}.{ext}"
    with open(os.path.join(UPLOAD_DIR, name), "wb") as fh:
        fh.write(data)
    return name


def file_path(name: str):
    """Absolute path for a stored file name, or None if the name is not one we
    could have created (guards against path tricks)."""
    if not name or "/" in name or "\\" in name or name.startswith("."):
        return None
    stem, _, ext = name.partition(".")
    if ext not in IMAGE_TYPES or len(stem) != 32 or any(c not in "0123456789abcdef" for c in stem):
        return None
    return os.path.join(UPLOAD_DIR, name)


def mime_type(name: str):
    return IMAGE_TYPES.get(name.rpartition(".")[2], "application/octet-stream")


def delete_files(names):
    for name in names or []:
        path = file_path(name)
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError as exc:
                print(f"[Uploads] Could not delete {name}: {exc}", flush=True)
