"""
Unit tests for Safe Project ZIP Extraction [Role A].
Verifies rejection of malicious archives (Zip Slip, zip bombs, symlinks, absolute/UNC paths)
and safe extraction of valid project archives.
"""

import os
import stat
import zipfile
import pytest
import io
from app.ingestion.zip_extractor import (
    SafeZipExtractor,
    SafeZipLimits,
    SafeZipError,
    extract_project_zip
)


def create_in_memory_zip(entries: dict) -> bytes:
    """Helper to build a ZIP file in memory from a dict of filename -> bytes or ZipInfo."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, content in entries.items():
            if isinstance(content, zipfile.ZipInfo):
                zf.writestr(content, b"test content")
            elif isinstance(content, (bytes, str)):
                data = content.encode("utf-8") if isinstance(content, str) else content
                zf.writestr(name, data)
    return buf.getvalue()


def test_valid_zip_extraction(tmp_path):
    """Verifies that a well-behaved project archive extracts correctly."""
    zip_bytes = create_in_memory_zip({
        "package.json": '{"name": "test-project", "version": "1.0.0"}',
        "src/index.js": 'console.log("hello world");',
        "docs/readme.txt": 'Project documentation'
    })
    archive_file = tmp_path / "valid_project.zip"
    archive_file.write_bytes(zip_bytes)

    dest_dir = tmp_path / "extracted"
    result = extract_project_zip(str(archive_file), target_dir=str(dest_dir))

    assert result.file_count == 3
    assert os.path.exists(dest_dir / "package.json")
    assert os.path.exists(dest_dir / "src" / "index.js")
    assert os.path.exists(dest_dir / "docs" / "readme.txt")
    assert (dest_dir / "src" / "index.js").read_text() == 'console.log("hello world");'


def test_reject_path_traversal(tmp_path):
    """Verifies rejection of Zip Slip path traversal patterns (../)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../evil.txt", b"malicious content")
    
    archive = tmp_path / "traversal.zip"
    archive.write_bytes(buf.getvalue())

    extractor = SafeZipExtractor()
    with pytest.raises(SafeZipError, match="traversal"):
        extractor.extract(str(archive), target_dir=str(tmp_path / "out"))


def test_reject_nested_path_traversal(tmp_path):
    """Verifies rejection of nested traversal sequences like foo/../../bar."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("subfolder/../../escaped.txt", b"escape content")

    archive = tmp_path / "nested_traversal.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="traversal"):
        extract_project_zip(str(archive), target_dir=str(tmp_path / "out"))


def test_reject_absolute_paths(tmp_path):
    """Verifies rejection of absolute root-relative paths (/etc/passwd)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("/etc/passwd", b"root:x:0:0:")

    archive = tmp_path / "absolute.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="Absolute paths"):
        extract_project_zip(str(archive), target_dir=str(tmp_path / "out"))


def test_reject_windows_drive_letters(tmp_path):
    """Verifies rejection of Windows drive paths (C:evil.txt or C:\\evil.txt)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("C:system.ini", b"evil")

    archive = tmp_path / "drive.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="drive paths are rejected"):
        extract_project_zip(str(archive), target_dir=str(tmp_path / "out"))


def test_reject_unc_paths(tmp_path):
    """Verifies rejection of UNC network share paths (\\\\evil-host\\share)."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("\\\\evil-server\\share\\loot.txt", b"evil")

    archive = tmp_path / "unc.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="UNC network paths are rejected"):
        extract_project_zip(str(archive), target_dir=str(tmp_path / "out"))


def test_reject_symbolic_links(tmp_path):
    """Verifies rejection of archives containing symlink entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        info = zipfile.ZipInfo("symlink_entry")
        # Set Unix symlink mode
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zf.writestr(info, b"/etc/shadow")

    archive = tmp_path / "symlink.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="Symbolic links are strictly rejected"):
        extract_project_zip(str(archive), target_dir=str(tmp_path / "out"))


def test_reject_encrypted_entries(tmp_path):
    """Verifies rejection of encrypted entries."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("secret.txt", b"encrypted payload")

    data = bytearray(buf.getvalue())
    # Set general purpose bit flag 0 (encrypted) in local file header
    idx = data.find(b"PK\x03\x04")
    if idx != -1:
        data[idx + 6] |= 0x01
    # Set general purpose bit flag 0 in central directory header
    cidx = data.find(b"PK\x01\x02")
    if cidx != -1:
        data[cidx + 8] |= 0x01

    archive = tmp_path / "encrypted.zip"
    archive.write_bytes(bytes(data))

    with pytest.raises(SafeZipError, match="Encrypted archive entries are not permitted"):
        extract_project_zip(str(archive), target_dir=str(tmp_path / "out"))


def test_reject_excessive_file_count(tmp_path):
    """Verifies rejection when file count exceeds configured boundary."""
    limits = SafeZipLimits(max_file_count=3)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for i in range(5):
            zf.writestr(f"file_{i}.txt", b"x")

    archive = tmp_path / "too_many_files.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="Archive contains 5 entries, exceeding limit"):
        extract_project_zip(str(archive), limits=limits)


def test_reject_excessive_extracted_size(tmp_path):
    """Verifies rejection when cumulative extracted size exceeds limit."""
    limits = SafeZipLimits(max_extracted_size_bytes=100)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("large.txt", b"A" * 200)

    archive = tmp_path / "large.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="Cumulative extracted size exceeds limit"):
        extract_project_zip(str(archive), limits=limits)


def test_reject_excessive_nesting_depth(tmp_path):
    """Verifies rejection of deeply nested folders exceeding nesting limit."""
    limits = SafeZipLimits(max_nesting_depth=3)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("a/b/c/d/deep.txt", b"too deep")

    archive = tmp_path / "deep.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="nesting depth"):
        extract_project_zip(str(archive), limits=limits)


def test_reject_zip_bomb_ratio(tmp_path):
    """Verifies rejection when compression ratio is suspiciously high."""
    limits = SafeZipLimits(
        max_extracted_size_bytes=10 * 1024 * 1024,
        max_compression_ratio=20.0,
        min_size_for_ratio_check=1000
    )
    # Highly compressible data
    uncompressed = b"0" * 50000
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.txt", uncompressed)

    archive = tmp_path / "bomb.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="Suspicious compression ratio"):
        extract_project_zip(str(archive), limits=limits)


def test_regression_destination_symlink_escape(tmp_path):
    """
    Regression test:
    Destination contains a symlink or junction pointing outside.
    ZIP contains a file under that link name ('link_dir/escaped.txt').
    Extraction must reject it and must NOT create or overwrite the outside file.
    """
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()

    link_path = dest_dir / "link_dir"
    try:
        os.symlink(str(outside_dir), str(link_path), target_is_directory=True)
    except OSError:
        import _winapi
        _winapi.CreateJunction(str(outside_dir), str(link_path))

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("link_dir/escaped.txt", b"evil escaped content")

    archive = tmp_path / "escape.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="(Symlink traversal|escapes)"):
        extract_project_zip(str(archive), target_dir=str(dest_dir))

    # Assert outside file was NEVER created
    assert not (outside_dir / "escaped.txt").exists()


def test_reject_windows_drive_letters_platform_independent(monkeypatch):
    """Verifies that Windows drive letters (C:system.ini) are rejected even when splitdrive behaves as on Linux."""
    # Force splitdrive to return ('', filename) as it does on Linux/POSIX
    monkeypatch.setattr(os.path, "splitdrive", lambda p: ("", p))
    extractor = SafeZipExtractor()
    info = zipfile.ZipInfo("C:system.ini")
    with pytest.raises(SafeZipError, match="drive paths are rejected"):
        extractor._validate_entry_security(info)

    info2 = zipfile.ZipInfo("d:/windows/system32/calc.exe")
    with pytest.raises(SafeZipError, match="drive paths are rejected"):
        extractor._validate_entry_security(info2)


def test_regression_hard_link_overwrite_prevented(tmp_path):
    """
    Regression test:
    Outside file exists. A hard link inside extraction directory points to outside file.
    Archive contains a file with the same relative name.
    Extraction must reject the operation and the outside file must remain unchanged.
    """
    outside_dir = tmp_path / "outside_dir"
    outside_dir.mkdir()
    outside_file = outside_dir / "target.txt"
    outside_file.write_text("original critical content")

    dest_dir = tmp_path / "extract_dest"
    dest_dir.mkdir()
    hardlink_path = dest_dir / "target.txt"
    try:
        os.link(str(outside_file), str(hardlink_path))
    except (OSError, NotImplementedError):
        pytest.skip("Filesystem does not support hard links")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("target.txt", b"evil overwritten content")

    archive = tmp_path / "hardlink_attack.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="(already exists|refusing overwrite|exclusive)"):
        extract_project_zip(str(archive), target_dir=str(dest_dir))

    # Assert outside file was NOT modified or truncated
    assert outside_file.read_text() == "original critical content"


def test_reject_ordinary_preexisting_destination_file(tmp_path):
    """Verifies that an ordinary pre-existing file in the destination is never overwritten."""
    dest_dir = tmp_path / "dest"
    dest_dir.mkdir()
    existing_file = dest_dir / "existing.txt"
    existing_file.write_text("preexisting content")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("existing.txt", b"new content")

    archive = tmp_path / "archive.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="(already exists|refusing overwrite|exclusive)"):
        extract_project_zip(str(archive), target_dir=str(dest_dir))

    # Assert existing file is preserved intact
    assert existing_file.read_text() == "preexisting content"


def test_reject_duplicate_archive_paths(tmp_path):
    """Verifies that an archive with duplicate entry paths is rejected."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("foo.txt", b"first")
        zf.writestr("foo.txt", b"second")

    archive = tmp_path / "dupe.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="Duplicate archive entry"):
        extract_project_zip(str(archive), target_dir=str(tmp_path / "out"))


def test_reject_conflicting_file_and_directory_entries(tmp_path):
    """Verifies that conflicting file and directory paths in the same archive are rejected."""
    # File followed by directory entry with same name
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("conflict_name", b"I am a file")
        zf.writestr("conflict_name/nested.txt", b"I am in a directory with the file's name")

    archive = tmp_path / "conflict.zip"
    archive.write_bytes(buf.getvalue())

    with pytest.raises(SafeZipError, match="(conflict|is not a directory|already exists)"):
        extract_project_zip(str(archive), target_dir=str(tmp_path / "dest"))


