"""
DWZP Extractor - DataWin Backup File Extractor

Extracts files from DataWin's proprietary backup format (.a01)

Format (per entry):
- Offset 0x00: 8 bytes unknown
- Offset 0x08: 4 bytes compressed size (little-endian)
- Offset 0x0C: 4 bytes unknown (zeros)
- Offset 0x10: 2 bytes path length
- Offset 0x12: path string
- After path: raw deflate compressed data

First entry has "DWZP" magic at offset 0, subsequent entries don't.

Author: Claude Code
"""

import struct
import zlib
import os
import re
from pathlib import Path
from typing import Generator, Tuple, List


class DWZPExtractor:
    """Extracts files from DataWin DWZP backup archives"""

    def __init__(self, archive_path: str):
        self.archive_path = archive_path
        self.file = None
        self.data = None

    def __enter__(self):
        self.file = open(self.archive_path, 'rb')
        return self

    def __exit__(self, *args):
        if self.file:
            self.file.close()

    def _find_entries(self) -> List[dict]:
        """
        Find all file entries by searching for DWZP markers.

        Entry format:
        +0: DWZP (4 bytes magic)
        +4: 8 bytes (unknown/zeros)
        +12: compressed_size (4 bytes little-endian)
        +16: 4 bytes (unknown/zeros)
        +20: path_length (2 bytes little-endian)
        +22: 2 bytes (unknown/zeros)
        +24: path string
        After path: raw deflate compressed data
        """
        self.file.seek(0)
        data = self.file.read()
        self.data = data

        entries = []

        # Find all DWZP markers
        pos = 0
        while True:
            pos = data.find(b'DWZP', pos)
            if pos == -1:
                break

            try:
                # Parse entry header
                header = data[pos:pos+60]
                if len(header) < 30:
                    pos += 1
                    continue

                compressed_size = struct.unpack('<I', header[12:16])[0]
                path_length = struct.unpack('<H', header[20:22])[0]

                # Validate
                if path_length == 0 or path_length > 300:
                    pos += 1
                    continue
                if compressed_size == 0 or compressed_size > 100_000_000:
                    pos += 1
                    continue

                # Read path
                path_bytes = header[24:24+path_length]
                try:
                    path = path_bytes.decode('ascii')
                except:
                    pos += 1
                    continue

                # Data starts after header + path
                data_offset = pos + 24 + path_length

                entries.append({
                    'path': path,
                    'compressed_size': compressed_size,
                    'data_offset': data_offset,
                    'header_offset': pos,
                })

            except Exception as e:
                pass

            pos += 1

        return entries

    def iter_entries(self) -> Generator[Tuple[str, bytes], None, None]:
        """
        Iterate over all entries in the archive.

        Yields:
            Tuple of (path, decompressed_data)
        """
        entries = self._find_entries()

        for entry in entries:
            path = entry['path']
            size = entry['compressed_size']
            offset = entry['data_offset']

            # Read compressed data
            compressed_data = self.data[offset:offset + size]

            if len(compressed_data) < size:
                print(f"Warning: Truncated data for {path}")
                continue

            # Decompress
            try:
                decompressor = zlib.decompressobj(-15)  # Raw deflate
                decompressed = decompressor.decompress(compressed_data)
                yield (path, decompressed)
            except zlib.error as e:
                print(f"Warning: Failed to decompress {path}: {e}")
                continue

    def extract_all(self, output_dir: str, filter_ext: list = None):
        """
        Extract all files to output directory.

        Args:
            output_dir: Directory to extract to
            filter_ext: Optional list of extensions to extract (e.g., ['.pas', '.dfm'])
        """
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        count = 0
        total_size = 0

        for path, data in self.iter_entries():
            # Check filter
            if filter_ext:
                ext = os.path.splitext(path)[1].lower()
                if ext not in filter_ext:
                    continue

            # Create output path
            out_file = output_path / path

            # Create parent directories
            out_file.parent.mkdir(parents=True, exist_ok=True)

            # Write file
            try:
                out_file.write_bytes(data)
                count += 1
                total_size += len(data)
                print(f"Extracted: {path} ({len(data):,} bytes)")
            except Exception as e:
                print(f"Error writing {path}: {e}")

        print()
        print(f"Extracted {count} files, {total_size:,} bytes total")

    def list_files(self) -> list:
        """List all files in the archive"""
        files = []
        for path, data in self.iter_entries():
            files.append({
                'path': path,
                'size': len(data),
            })
        return files


def main():
    import sys

    if len(sys.argv) < 2:
        print("DWZP Extractor - DataWin Backup File Extractor")
        print()
        print("Usage:")
        print("  python dwzp_extractor.py <archive.a01> [output_dir]")
        print("  python dwzp_extractor.py <archive.a01> --list")
        print("  python dwzp_extractor.py <archive.a01> --source  # Extract only source code")
        print()
        sys.exit(1)

    archive_path = sys.argv[1]

    if '--list' in sys.argv:
        # List files
        with DWZPExtractor(archive_path) as extractor:
            files = extractor.list_files()
            print(f"Files in {archive_path}:")
            print()
            for f in files:
                print(f"  {f['path']} ({f['size']:,} bytes)")
            print()
            print(f"Total: {len(files)} files")

    elif '--source' in sys.argv:
        # Extract only source code
        output_dir = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else 'extracted_source'
        source_ext = ['.pas', '.dfm', '.dpr', '.dpk', '.inc', '.h', '.cpp', '.c']

        with DWZPExtractor(archive_path) as extractor:
            extractor.extract_all(output_dir, filter_ext=source_ext)

    else:
        # Extract all
        output_dir = sys.argv[2] if len(sys.argv) > 2 else 'extracted'

        with DWZPExtractor(archive_path) as extractor:
            extractor.extract_all(output_dir)


if __name__ == "__main__":
    main()
