#!/usr/bin/env python3 -B
# coding=utf-8

"""
Dell PFS Extract
Dell PFS Update Extractor
Copyright (C) 2018-2025 Plato Mavropoulos
"""

import contextlib
import ctypes
import io
import lzma
import os
import zlib

from re import Match
from typing import Any, Final

from biosutilities.common.checksums import checksum_8_xor
from biosutilities.common.compression import is_szip_supported, szip_decompress
from biosutilities.common.paths import (delete_dirs, delete_file, path_files, is_file_read, make_dirs,
                                        path_name, path_parent, path_stem, safe_name)
from biosutilities.common.patterns import PAT_DELL_FTR, PAT_DELL_HDR, PAT_DELL_PKG
from biosutilities.common.structs import CHAR, ctypes_struct, UINT8, UINT16, UINT32, UINT64
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import file_to_bytes, to_ordinal

from biosutilities.ami_pfat_extract import AmiPfatExtract, IntelBiosGuardHeader


class DellPfsHeader(ctypes.LittleEndianStructure):
    """ Dell PFS Header Structure """

    _pack_ = 1
    _fields_ = [
        ('Tag',             CHAR * 8),      # 0x00
        ('HeaderVersion',   UINT32),        # 0x08
        ('PayloadSize',     UINT32)         # 0x0C
        # 0x10
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Header Tag    :', self.Tag.decode('utf-8')], padding=padding, new_line=False)
        printer(message=['Header Version:', self.HeaderVersion], padding=padding, new_line=False)
        printer(message=['Payload Size  :', f'0x{self.PayloadSize:X}'], padding=padding, new_line=False)


class DellPfsFooter(ctypes.LittleEndianStructure):
    """ Dell PFS Footer Structure """

    _pack_ = 1
    _fields_ = [
        ('PayloadSize',     UINT32),        # 0x00
        ('Checksum',        UINT32),        # 0x04 ~CRC32 w/ Vector 0
        ('Tag',             CHAR * 8)       # 0x08
        # 0x10
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Payload Size    :', f'0x{self.PayloadSize:X}'], padding=padding, new_line=False)
        printer(message=['Payload Checksum:', f'0x{self.Checksum:08X}'], padding=padding, new_line=False)
        printer(message=['Footer Tag      :', self.Tag.decode('utf-8')], padding=padding, new_line=False)


class DellPfsEntryBase(ctypes.LittleEndianStructure):
    """ Dell PFS Entry Base Structure """

    _pack_ = 1
    _fields_ = [
        ('GUID',            UINT32 * 4),    # 0x00 Little Endian
        ('HeaderVersion',   UINT32),        # 0x10 1 or 2
        ('VersionType',     UINT8 * 4),     # 0x14
        ('Version',         UINT16 * 4),    # 0x18
        ('Reserved',        UINT64),        # 0x20
        ('DataSize',        UINT32),        # 0x28
        ('DataSigSize',     UINT32),        # 0x2C
        ('DataMetSize',     UINT32),        # 0x30
        ('DataMetSigSize',  UINT32)         # 0x34
        # 0x38 (parent class, base)
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        guid: str = f'{int.from_bytes(self.GUID, byteorder="little"):0{0x10 * 2}X}'
        unknown: str = f'{int.from_bytes(self.Unknown, byteorder="little"):0{len(self.Unknown) * 8}X}'
        version: str = DellPfsExtract.get_entry_ver(version_fields=self.Version, version_types=self.VersionType)

        printer(message=['Entry GUID             :', guid], padding=padding, new_line=False)
        printer(message=['Entry Version          :', self.HeaderVersion], padding=padding, new_line=False)
        printer(message=['Payload Version        :', version], padding=padding, new_line=False)
        printer(message=['Reserved               :', f'0x{self.Reserved:X}'], padding=padding, new_line=False)
        printer(message=['Payload Data Size      :', f'0x{self.DataSize:X}'], padding=padding, new_line=False)
        printer(message=['Payload Signature Size :', f'0x{self.DataSigSize:X}'], padding=padding, new_line=False)
        printer(message=['Metadata Data Size     :', f'0x{self.DataMetSize:X}'], padding=padding, new_line=False)
        printer(message=['Metadata Signature Size:', f'0x{self.DataMetSigSize:X}'], padding=padding, new_line=False)
        printer(message=['Unknown                :', f'0x{unknown}'], padding=padding, new_line=False)


class DellPfsEntryR1(DellPfsEntryBase):
    """ Dell PFS Entry Revision 1 Structure """

    _pack_ = 1
    _fields_ = [
        ('Unknown',         UINT32 * 4)     # 0x38
        # 0x48 (child class, R1)
    ]


class DellPfsEntryR2(DellPfsEntryBase):
    """ Dell PFS Entry Revision 2 Structure """

    _pack_ = 1
    _fields_ = [
        ('Unknown',         UINT32 * 8)     # 0x38
        # 0x58 (child class, R2)
    ]


class DellPfsInfo(ctypes.LittleEndianStructure):
    """ Dell PFS Information Header Structure """

    _pack_ = 1
    _fields_ = [
        ('HeaderVersion',   UINT32),        # 0x00
        ('GUID',            UINT32 * 4)     # 0x04 Little Endian
        # 0x14
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        guid: str = f'{int.from_bytes(self.GUID, byteorder="little"):0{0x10 * 2}X}'

        printer(message=['Info Version:', self.HeaderVersion], padding=padding, new_line=False)
        printer(message=['Entry GUID  :', guid], padding=padding, new_line=False)


class DellPfsName(ctypes.LittleEndianStructure):
    """ Dell PFS FileName Header Structure """

    _pack_ = 1
    _fields_ = [
        ('Version',         UINT16 * 4),    # 0x00
        ('VersionType',     UINT8 * 4),     # 0x08
        ('CharacterCount',  UINT16)         # 0x0C UTF-16 2-byte Characters
        # 0x0E
    ]

    def struct_print(self, name: str, padding: int = 0) -> None:
        """ Display structure information """

        version: str = DellPfsExtract.get_entry_ver(self.Version, self.VersionType)

        printer(message=['Payload Version:', version], padding=padding, new_line=False)
        printer(message=['Character Count:', self.CharacterCount], padding=padding, new_line=False)
        printer(message=['Payload Name   :', name], padding=padding, new_line=False)


class DellPfsMetadata(ctypes.LittleEndianStructure):
    """ Dell PFS Metadata Header Structure """

    _pack_ = 1
    _fields_ = [
        ('ModelIDs',        CHAR * 501),    # 0x000
        ('FileName',        CHAR * 100),    # 0x1F5
        ('FileVersion',     CHAR * 33),     # 0x259
        ('Date',            CHAR * 33),     # 0x27A
        ('Brand',           CHAR * 80),     # 0x29B
        ('ModelFile',       CHAR * 80),     # 0x2EB
        ('ModelName',       CHAR * 100),    # 0x33B
        ('ModelVersion',    CHAR * 33)      # 0x39F
        # 0x3C0
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        model_ids: str = self.ModelIDs.decode('utf-8').removesuffix(',END')

        printer(message=['Model IDs    :', model_ids], padding=padding, new_line=False)
        printer(message=['File Name    :', self.FileName.decode('utf-8')], padding=padding, new_line=False)
        printer(message=['File Version :', self.FileVersion.decode('utf-8')], padding=padding, new_line=False)
        printer(message=['Date         :', self.Date.decode('utf-8')], padding=padding, new_line=False)
        printer(message=['Brand        :', self.Brand.decode('utf-8')], padding=padding, new_line=False)
        printer(message=['Model File   :', self.ModelFile.decode('utf-8')], padding=padding, new_line=False)
        printer(message=['Model Name   :', self.ModelName.decode('utf-8')], padding=padding, new_line=False)
        printer(message=['Model Version:', self.ModelVersion.decode('utf-8')], padding=padding, new_line=False)


class DellPfsPfatMetadata(ctypes.LittleEndianStructure):
    """ Dell PFS BIOS Guard Metadata Structure """

    _pack_ = 1
    _fields_ = [
        ('Address',         UINT32),        # 0x00
        ('Unknown0',        UINT32),        # 0x04
        ('Offset',          UINT32),        # 0x08 Matches BG Script > I0
        ('DataSize',        UINT32),        # 0x0C Matches BG Script > I2 & Header > Data Size
        ('Unknown1',        UINT32),        # 0x10
        ('Unknown2',        UINT32),        # 0x14
        ('Unknown3',        UINT8)          # 0x18
        # 0x19
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Address  :', f'0x{self.Address:X}'], padding=padding, new_line=False)
        printer(message=['Unknown 0:', f'0x{self.Unknown0:X}'], padding=padding, new_line=False)
        printer(message=['Offset   :', f'0x{self.Offset:X}'], padding=padding, new_line=False)
        printer(message=['Length   :', f'0x{self.DataSize:X}'], padding=padding, new_line=False)
        printer(message=['Unknown 1:', f'0x{self.Unknown1:X}'], padding=padding, new_line=False)
        printer(message=['Unknown 2:', f'0x{self.Unknown2:X}'], padding=padding, new_line=False)
        printer(message=['Unknown 3:', f'0x{self.Unknown3:X}'], padding=padding, new_line=False)


class DellPfsExtract(BIOSUtility):
    """ Dell PFS Update Extractor """

    TITLE: str = 'Dell PFS Update Extractor'

    PFS_HEAD_LEN: Final[int] = ctypes.sizeof(DellPfsHeader)
    PFS_FOOT_LEN: Final[int] = ctypes.sizeof(DellPfsFooter)
    PFS_INFO_LEN: Final[int] = ctypes.sizeof(DellPfsInfo)
    PFS_NAME_LEN: Final[int] = ctypes.sizeof(DellPfsName)
    PFS_META_LEN: Final[int] = ctypes.sizeof(DellPfsMetadata)
    PFS_PFAT_LEN: Final[int] = ctypes.sizeof(DellPfsPfatMetadata)
    PFAT_HDR_LEN: Final[int] = ctypes.sizeof(IntelBiosGuardHeader)

    def __init__(self, input_object: str | bytes | bytearray = b'', extract_path: str = '', padding: int = 0,
                 advanced: bool = False, structure: bool = False) -> None:
        super().__init__(input_object=input_object, extract_path=extract_path, padding=padding)

        self.advanced: bool = advanced
        self.structure: bool = structure

    def check_format(self) -> bool:
        """ Check if input is Dell PFS/PKG image """

        if self._is_pfs_pkg(input_object=self.input_buffer):
            return True

        if self._is_pfs_hdr(input_object=self.input_buffer) and self._is_pfs_ftr(input_object=self.input_buffer):
            return True

        return False

    def parse_format(self) -> bool:
        """ Parse & Extract Dell PFS Update image """

        make_dirs(in_path=self.extract_path)

        is_dell_pkg: bool = self._is_pfs_pkg(input_object=self.input_buffer)

        if is_dell_pkg:
            pfs_results: dict[str, bytes] = self._thinos_pkg_extract(
                input_object=self.input_buffer, extract_path=self.extract_path)
        else:
            pfs_results = {path_stem(in_path=self.input_object) if isinstance(self.input_object, str) and is_file_read(
                in_path=self.input_object) else 'Image': self.input_buffer}

        # Parse each Dell PFS image contained in the input file
        for pfs_index, (pfs_name, pfs_buffer) in enumerate(pfs_results.items(), start=1):
            # At ThinOS PKG packages, multiple PFS images may be included in separate model-named folders
            pfs_path: str = os.path.join(
                self.extract_path, f'{pfs_index} {pfs_name}') if is_dell_pkg else self.extract_path

            # Parse each PFS ZLIB section
            for zlib_offset in self._get_section_offsets(buffer=pfs_buffer):
                # Call the PFS ZLIB section parser function
                self._pfs_section_parse(zlib_data=pfs_buffer, zlib_start=zlib_offset, extract_path=pfs_path,
                                        pfs_name=pfs_name, pfs_index=pfs_index, pfs_count=1, is_rec=False,
                                        padding=self.padding)

        return True

    @staticmethod
    def _is_pfs_pkg(input_object: str | bytes | bytearray) -> bool:
        """
        The Dell ThinOS PKG update images usually contain multiple sections.
        Each section starts with a 0x30 header, which begins with pattern 72135500.
        The section length is found at 0x10-0x14 and its (optional) MD5 hash at 0x20-0x30.
        Section data can be raw or LZMA2 (7zXZ) compressed. The latter contains the PFS update image.
        """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        return bool(PAT_DELL_PKG.search(input_buffer))

    @staticmethod
    def _is_pfs_hdr(input_object: str | bytes | bytearray) -> bool:
        """
        The Dell PFS update images usually contain multiple sections.
        Each section is zlib-compressed with header pattern ********++EEAA761BECBB20F1E651--789C,
        where ******** is the zlib stream size, ++ is the section type and -- the header Checksum XOR 8.
        The "Firmware" section has type AA and its files are stored in PFS format.
        The "Utility" section has type BB and its files are stored in PFS, BIN or 7z formats.
        """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        return bool(PAT_DELL_HDR.search(input_buffer))

    @staticmethod
    def _is_pfs_ftr(input_object: str | bytes | bytearray) -> bool:
        """
        Each section is followed by the footer pattern ********EEAAEE8F491BE8AE143790--,
        where ******** is the zlib stream size and ++ the footer Checksum XOR 8.
        """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        return bool(PAT_DELL_FTR.search(input_buffer))

    def _thinos_pkg_extract(self, input_object: str | bytes | bytearray, extract_path: str) -> dict[str, bytes]:
        """ Extract Dell ThinOS PKG 7zXZ """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        # Initialize PFS results (Name: Buffer)
        pfs_results: dict[str, bytes] = {}

        # Search input image for ThinOS PKG 7zXZ header
        thinos_pkg_match: Match[bytes] | None = PAT_DELL_PKG.search(input_buffer)

        if not thinos_pkg_match:
            return pfs_results

        lzma_len_off: int = thinos_pkg_match.start() + 0x10
        lzma_len_int: int = int.from_bytes(input_buffer[lzma_len_off:lzma_len_off + 0x4], byteorder='little')
        lzma_bin_off: int = thinos_pkg_match.end() - 0x5

        lzma_bin_dat: bytes = input_buffer[lzma_bin_off:lzma_bin_off + lzma_len_int]

        # Check if the compressed 7zXZ stream is complete
        if len(lzma_bin_dat) != lzma_len_int:
            return pfs_results

        working_path: str = os.path.join(extract_path, 'THINOS_PKG_TEMP')

        make_dirs(in_path=working_path, delete=True)

        pkg_tar_path: str = os.path.join(working_path, 'THINOS_PKG.TAR')

        with open(pkg_tar_path, 'wb') as pkg_payload:
            pkg_payload.write(lzma.decompress(lzma_bin_dat))

        if is_szip_supported(in_path=pkg_tar_path, args=['-tTAR']):
            if szip_decompress(in_path=pkg_tar_path, out_path=working_path, in_name='TAR', padding=0,
                               args=['-tTAR'], check=True, silent=True):
                delete_file(in_path=pkg_tar_path)
            else:
                return pfs_results
        else:
            return pfs_results

        for pkg_file in path_files(in_path=working_path):
            if is_szip_supported(in_path=pkg_file, args=['-tCAB']):
                pkg_file_out: str = os.path.join(str(path_parent(in_path=pkg_file)), path_stem(in_path=pkg_file))

                if szip_decompress(in_path=pkg_file, out_path=pkg_file_out, in_name='CAB',
                                   padding=0, args=['-tCAB'], check=True, silent=True):
                    delete_file(in_path=pkg_file)

        for pkg_file in path_files(in_path=working_path):
            if is_file_read(in_path=pkg_file):
                if self._is_pfs_hdr(input_object=pkg_file):
                    pkg_name_parent: str = path_name(in_path=str(path_parent(in_path=pkg_file)))
                    pkg_name_binary: str = path_stem(in_path=pkg_file)

                    pfs_name: str = safe_name(in_name=f'{pkg_name_parent}_{pkg_name_binary}')

                    pfs_results.update({pfs_name: file_to_bytes(in_object=pkg_file)})

        delete_dirs(in_path=working_path)

        return pfs_results

    @staticmethod
    def _get_section_offsets(buffer: bytes | bytearray) -> list[int]:
        """ Get PFS ZLIB Section Offsets """

        pfs_zlib_list: list[int] = []  # Initialize PFS ZLIB offset list

        pfs_zlib_init: list[Match[bytes]] = list(PAT_DELL_HDR.finditer(buffer))

        if not pfs_zlib_init:
            return pfs_zlib_list  # No PFS ZLIB detected

        # Remove duplicate/nested PFS ZLIB offsets
        for zlib_c in pfs_zlib_init:
            is_duplicate: bool = False  # Initialize duplicate/nested PFS ZLIB offset

            for zlib_o in pfs_zlib_init:
                zlib_o_size: int = int.from_bytes(buffer[zlib_o.start() - 0x5:zlib_o.start() - 0x1],
                                                  byteorder='little')

                # If current PFS ZLIB offset is within another PFS ZLIB range (start-end), set as duplicate
                if zlib_o.start() < zlib_c.start() < zlib_o.start() + zlib_o_size:
                    is_duplicate = True

            if not is_duplicate:
                pfs_zlib_list.append(zlib_c.start())

        return pfs_zlib_list

    def _pfs_section_parse(self, zlib_data: bytes | bytearray, zlib_start: int, extract_path: str, pfs_name: str,
                           pfs_index: int, pfs_count: int, is_rec: bool, padding: int = 0) -> None:
        """ Dell PFS ZLIB Section Parser """

        # Initialize PFS ZLIB-related error state
        is_zlib_error: bool = False

        # Byte before PFS ZLIB Section pattern is Section Type (e.g. AA, BB)
        section_type: int = zlib_data[zlib_start - 0x1]

        section_name: str = {0xAA: 'Firmware', 0xBB: 'Utilities'}.get(section_type, f'Unknown ({section_type:02X})')

        # Show extraction complete message for each main PFS ZLIB Section
        printer(message=f'Extracting Dell PFS {pfs_index} > {pfs_name} > {section_name}', padding=padding)

        # Set PFS ZLIB Section extraction subdirectory path
        section_path: str = os.path.join(extract_path, safe_name(in_name=section_name))

        # Create extraction subdirectory and delete old (if present, not in recursions)
        make_dirs(in_path=section_path, delete=not is_rec)

        # Store the compressed zlib stream start offset
        compressed_start: int = zlib_start + 0xB

        # Store the PFS ZLIB section header start offset
        header_start: int = zlib_start - 0x5

        # Store the PFS ZLIB section header contents (16 bytes)
        header_data: bytes = zlib_data[header_start:compressed_start]

        # Check if the PFS ZLIB section header Checksum XOR 8 is valid
        if len(header_data) > 0xF and checksum_8_xor(data=header_data[:0xF]) != header_data[0xF]:
            printer(message='Error: Invalid Dell PFS ZLIB section Header Checksum!', padding=padding)

            is_zlib_error = True

        # Store the compressed zlib stream size from the header contents
        compressed_size_hdr: int = int.from_bytes(header_data[:0x4], byteorder='little')

        # Store the compressed zlib stream end offset
        compressed_end: int = compressed_start + compressed_size_hdr

        # Store the compressed zlib stream contents
        compressed_data: bytes = zlib_data[compressed_start:compressed_end]

        # Check if the compressed zlib stream is complete, based on header
        if len(compressed_data) != compressed_size_hdr:
            printer(message='Error: Incomplete Dell PFS ZLIB section data (Header)!', padding=padding)

            is_zlib_error = True

        # Store the PFS ZLIB section footer contents (16 bytes)
        footer_data: bytes = zlib_data[compressed_end:compressed_end + 0x10]

        # Check if PFS ZLIB section footer was found in the section
        if not self._is_pfs_ftr(input_object=footer_data):
            printer(message='Error: This Dell PFS ZLIB section is corrupted!', padding=padding)

            is_zlib_error = True

        # Check if the PFS ZLIB section footer Checksum XOR 8 is valid
        if len(footer_data) > 0xF and checksum_8_xor(data=footer_data[:0xF]) != footer_data[0xF]:
            printer(message='Error: Invalid Dell PFS ZLIB section Footer Checksum!', padding=padding)

            is_zlib_error = True

        # Store the compressed zlib stream size from the footer contents
        compressed_size_ftr: int = int.from_bytes(footer_data[:0x4], byteorder='little')

        # Check if the compressed zlib stream is complete, based on footer
        if compressed_size_ftr != compressed_size_hdr:
            printer(message='Error: Incomplete Dell PFS ZLIB section data (Footer)!', padding=padding)

            is_zlib_error = True

        # Decompress PFS ZLIB section payload
        try:
            if is_zlib_error:
                raise ValueError('ZLIB_ERROR_OCCURRED')  # ZLIB errors are critical

            section_data: bytes = zlib.decompress(compressed_data)  # ZLIB decompression
        except Exception as error:  # pylint: disable=broad-except
            printer(message=f'Error: Failed to decompress PFS ZLIB section: {error}!', padding=padding)

            section_data = zlib_data  # Fallback to raw ZLIB data upon critical error

        # Call the PFS Extract function on the decompressed PFS ZLIB Section
        self._pfs_extract(buffer=section_data, pfs_index=pfs_index, pfs_name=pfs_name, pfs_count=pfs_count,
                          extract_path=section_path, padding=padding)

    def _pfs_extract(self, buffer: bytes | bytearray, pfs_index: int, pfs_name: str, pfs_count: int,
                     extract_path: str, padding: int = 0) -> None:
        """ Parse & Extract Dell PFS Volume """

        # Show PFS Volume indicator
        if self.structure:
            printer(message='PFS Volume:', padding=padding)

        # Get PFS Header Structure values
        pfs_hdr: Any = ctypes_struct(buffer=buffer, start_offset=0, class_object=DellPfsHeader)

        # Validate that a PFS Header was parsed
        if pfs_hdr.Tag != b'PFS.HDR.':
            printer(message='Error: PFS Header could not be found!', padding=padding + 4)

            return  # Critical error, abort

        # Show PFS Header Structure info
        if self.structure:
            printer(message='PFS Header:\n', padding=padding + 4)

            pfs_hdr.struct_print(padding=padding + 8)

        # Validate that a known PFS Header Version was encountered
        self._chk_hdr_ver(version=pfs_hdr.HeaderVersion, text='PFS', padding=padding + 8)

        # Get PFS Payload Data
        pfs_payload: bytes = buffer[self.PFS_HEAD_LEN:self.PFS_HEAD_LEN + pfs_hdr.PayloadSize]

        # Parse all PFS Payload Entries/Components
        entry_index: int = 1  # Index number of each PFS Entry
        entry_start: int = 0  # Increasing PFS Entry starting offset
        entries_all: list[list] = []  # Storage for each PFS Entry details
        filename_info = b''  # Buffer for FileName Information Entry Data
        signature_info = b''  # Buffer for Signature Information Entry Data

        # Get PFS Entry Info
        pfs_entry_struct, pfs_entry_size = self._get_pfs_entry(buffer=pfs_payload, offset=entry_start)

        while len(pfs_payload[entry_start:entry_start + pfs_entry_size]) == pfs_entry_size:
            # Analyze PFS Entry Structure and get relevant info
            _, entry_version, entry_guid, entry_data, entry_data_sig, entry_met, entry_met_sig, next_entry = \
                self._parse_pfs_entry(entry_buffer=pfs_payload, entry_start=entry_start, entry_size=pfs_entry_size,
                                      entry_struct=pfs_entry_struct, text='PFS Entry', padding=padding)

            entry_type: str = 'OTHER'  # Adjusted later if PFS Entry is Zlib, PFAT, PFS Info, Model Info

            # Get PFS Information from the relevant (hardcoded) PFS Entry GUIDs
            if entry_guid in ['E0717CE3A9BB25824B9F0DC8FD041960', 'B033CB16EC9B45A14055F80E4D583FD3']:
                entry_type = 'NAME_INFO'

                filename_info = entry_data

            # Get Model Information from the relevant (hardcoded) PFS Entry GUID
            elif entry_guid == '6F1D619A22A6CB924FD4DA68233AE3FB':
                entry_type = 'MODEL_INFO'

            # Get Signature Information from the relevant (hardcoded) PFS Entry GUID
            elif entry_guid == 'D086AFEE3ADBAEA94D5CED583C880BB7':
                entry_type = 'SIG_INFO'

                signature_info = entry_data

            # Get Nested PFS from the relevant (hardcoded) PFS Entry GUID
            elif entry_guid == '900FAE60437F3AB14055F456AC9FDA84':
                entry_type = 'NESTED_PFS'  # Nested PFS are usually zlib-compressed so it might change to 'ZLIB' later

            # Store all relevant PFS Entry details
            entries_all.append([entry_index, entry_guid, entry_version, entry_type,
                                entry_data, entry_data_sig, entry_met, entry_met_sig])

            entry_index += 1  # Increase PFS Entry Index number for user-friendly output and name duplicates

            entry_start = next_entry  # Next PFS Entry starts after PFS Entry Metadata Signature

        # Parse all PFS Information Entries/Descriptors
        info_start: int = 0  # Increasing PFS Information Entry starting offset
        info_all: list[list] = []  # Storage for each PFS Information Entry details

        while len(filename_info[info_start:info_start + self.PFS_INFO_LEN]) == self.PFS_INFO_LEN:
            # Get PFS Information Header Structure info
            filename_info_hdr: Any = ctypes_struct(buffer=filename_info, start_offset=info_start,
                                                   class_object=DellPfsInfo)

            # Show PFS Information Header Structure info
            if self.structure:
                printer(message='PFS Filename Information Header:\n', padding=padding + 4)

                filename_info_hdr.struct_print(padding=padding + 8)

            # Validate that a known PFS Information Header Version was encountered
            if filename_info_hdr.HeaderVersion != 1:
                printer(message=f'Error: Unknown PFS Filename Information Header '
                                f'Version {filename_info_hdr.HeaderVersion}!', padding=padding + 8)

                break  # Skip PFS Information Entries/Descriptors in case of unknown PFS Information Header Version

            # Get PFS Information Header GUID in Big Endian format, in order
            # to match each Info to the equivalent stored PFS Entry details.
            entry_guid = f'{int.from_bytes(filename_info_hdr.GUID, byteorder="little"):0{0x10 * 2}X}'

            # Get PFS FileName Structure values
            entry_info_mod: Any = ctypes_struct(buffer=filename_info, start_offset=info_start + self.PFS_INFO_LEN,
                                                class_object=DellPfsName)

            # The PFS FileName Structure is not complete by itself. The size of the last field (Entry Name)
            # is determined from CharacterCount multiplied by 2 due to usage of UTF-16 2-byte Characters.
            # Any Entry Name leading and/or trailing space/null characters are stripped and Windows
            # reserved/illegal filename characters are replaced.
            name_start: int = info_start + self.PFS_INFO_LEN + self.PFS_NAME_LEN  # PFS Entry's FileName start offset

            name_size: int = entry_info_mod.CharacterCount * 2  # PFS Entry's FileName buffer total size

            name_data: bytes = filename_info[name_start:name_start + name_size]  # PFS Entry's FileName buffer

            # PFS Entry's FileName value
            entry_name: str = safe_name(in_name=name_data.decode('utf-16').strip())

            # Show PFS FileName Structure info
            if self.structure:
                printer(message='PFS FileName Entry:\n', padding=padding + 8)

                entry_info_mod.struct_print(name=entry_name, padding=padding + 12)

            # Get PFS FileName Version string via "Version" and "VersionType" fields
            # PFS FileName Version string must be preferred over PFS Entry's Version
            entry_version = self.get_entry_ver(version_fields=entry_info_mod.Version,
                                               version_types=entry_info_mod.VersionType)

            # Store all relevant PFS FileName details
            info_all.append([entry_guid, entry_name, entry_version])

            # The next PFS Information Header starts after the calculated FileName size
            # Two space/null characters seem to always exist after each FileName value
            info_start += (self.PFS_INFO_LEN + self.PFS_NAME_LEN + name_size + 0x2)

        # Parse Nested PFS Metadata when its PFS Information Entry is missing
        for entry in entries_all:
            _, entry_guid, _, entry_type, _, _, entry_metadata, _ = entry

            if entry_type == 'NESTED_PFS' and not filename_info:
                # When PFS Information Entry exists, Nested PFS Metadata contains only Model IDs
                # When it's missing, the Metadata structure is large and contains equivalent info
                if len(entry_metadata) >= self.PFS_META_LEN:
                    # Get Nested PFS Metadata Structure values
                    entry_info: Any = ctypes_struct(buffer=entry_metadata, start_offset=0, class_object=DellPfsMetadata)

                    # Show Nested PFS Metadata Structure info
                    if self.structure:
                        printer(message='PFS Metadata Information:\n', padding=padding + 4)

                        entry_info.struct_print(padding=padding + 8)

                    # As Nested PFS Entry Name, we'll use the actual PFS File Name
                    # Replace common Windows reserved/illegal filename characters
                    entry_name = safe_name(in_name=entry_info.FileName.decode('utf-8').removesuffix('.exe')
                                           .removesuffix('.bin'))

                    # As Nested PFS Entry Version, we'll use the actual PFS File Version
                    entry_version = entry_info.FileVersion.decode('utf-8')

                    # Store all relevant Nested PFS Metadata/Information details
                    info_all.append([entry_guid, entry_name, entry_version])

                    # Re-set Nested PFS Entry Version from Metadata
                    entry[2] = entry_version

        # Parse all PFS Signature Entries/Descriptors
        sign_start: int = 0  # Increasing PFS Signature Entry starting offset

        while len(signature_info[sign_start:sign_start + self.PFS_INFO_LEN]) == self.PFS_INFO_LEN:
            # Get PFS Information Header Structure info
            signature_info_hdr: Any = ctypes_struct(buffer=signature_info, start_offset=sign_start,
                                                    class_object=DellPfsInfo)

            # Show PFS Information Header Structure info
            if self.structure:
                printer(message='PFS Signature Information Header:\n', padding=padding + 4)

                signature_info_hdr.struct_print(padding=padding + 8)

            # Validate that a known PFS Information Header Version was encountered
            if signature_info_hdr.HeaderVersion != 1:
                printer(message=f'Error: Unknown PFS Signature Information Header '
                                f'Version {signature_info_hdr.HeaderVersion}!', padding=padding + 8)

                break  # Skip PFS Signature Entries/Descriptors in case of unknown Header Version

            # PFS Signature Entries have DellPfsInfo + DellPfsEntryR* + Sign Size [0x2] + Sign Data [Sig Size]
            pfs_entry_struct, pfs_entry_size = self._get_pfs_entry(buffer=signature_info,
                                                                   offset=sign_start + self.PFS_INFO_LEN)

            # Get PFS Entry Header Structure info
            entry_hdr: Any = ctypes_struct(buffer=signature_info, start_offset=sign_start + self.PFS_INFO_LEN,
                                           class_object=pfs_entry_struct)

            # Show PFS Information Header Structure info
            if self.structure:
                printer(message='PFS Information Entry:\n', padding=padding + 8)

                entry_hdr.struct_print(padding=padding + 12)

            # Show PFS Signature Size & Data (after DellPfsEntryR*)
            sign_info_start: int = sign_start + self.PFS_INFO_LEN + pfs_entry_size

            sign_size: int = int.from_bytes(signature_info[sign_info_start:sign_info_start + 0x2],
                                            byteorder='little')

            sign_data_raw: bytes = signature_info[sign_info_start + 0x2:sign_info_start + 0x2 + sign_size]

            sign_data_txt: str = f'{int.from_bytes(sign_data_raw, byteorder="little"):0{sign_size * 2}X}'

            if self.structure:
                printer(message='Signature Information:\n', padding=padding + 8)

                printer(message=f'Signature Size: 0x{sign_size:X}', padding=padding + 12, new_line=False)

                printer(message=f'Signature Data: {sign_data_txt[:32]} [...]', padding=padding + 12, new_line=False)

            # The next PFS Signature Entry/Descriptor starts after the previous Signature Data
            sign_start += (self.PFS_INFO_LEN + pfs_entry_size + 0x2 + sign_size)

        # Parse each PFS Entry Data for special types (zlib or PFAT)
        for entry in entries_all:
            _, _, _, entry_type, entry_data, _, _, _ = entry

            # Very small PFS Entry Data cannot be of special type
            if len(entry_data) < self.PFS_HEAD_LEN:
                continue

            # Check if PFS Entry contains zlib-compressed sub-PFS Volume
            pfs_zlib_offsets: list[int] = self._get_section_offsets(buffer=entry_data)

            # Parse PFS Entry which contains zlib-compressed sub-PFS Volume
            if pfs_zlib_offsets:
                entry_type = 'ZLIB'  # Re-set PFS Entry Type from OTHER to ZLIB, to use such info afterward

                pfs_count += 1  # Increase the count/index of parsed main PFS structures by one

                # Parse each sub-PFS ZLIB Section
                for offset in pfs_zlib_offsets:
                    # Get the Name of the zlib-compressed full PFS structure via the already stored PFS Information
                    # The zlib-compressed full PFS structure(s) are used to contain multiple FW (CombineBiosNameX)
                    # When zlib-compressed full PFS structure(s) exist within the main/first full PFS structure,
                    # its PFS Information should contain their names (CombineBiosNameX). Since the main/first
                    # full PFS structure has count/index 1, the rest start at 2+ and thus, their PFS Information
                    # names can be retrieved in order by subtracting 2 from the main/first PFS Information values
                    sub_pfs_name = f'{info_all[pfs_count - 2][1]} v{info_all[pfs_count - 2][2]}' \
                        if info_all else ' UNKNOWN'

                    # Set the sub-PFS output path (create sub-folders for each sub-PFS and its ZLIB sections)
                    sub_pfs_path: str = os.path.join(extract_path, f'{pfs_count} {safe_name(in_name=sub_pfs_name)}')

                    # Recursively call the PFS ZLIB Section Parser for the sub-PFS Volume (pfs_index = pfs_count)
                    self._pfs_section_parse(zlib_data=entry_data, zlib_start=offset, extract_path=sub_pfs_path,
                                            pfs_name=sub_pfs_name, pfs_index=pfs_count, pfs_count=pfs_count,
                                            is_rec=True, padding=padding + 4)

            # Initialize possible PFAT PFS Entry Offset
            pfat_pfs_header_off: int = 0

            while entry_data[pfat_pfs_header_off:pfat_pfs_header_off + 8] == b'PFS.HDR.':
                pfat_pfs_header: Any = ctypes_struct(buffer=entry_data, start_offset=pfat_pfs_header_off,
                                                     class_object=DellPfsHeader)

                # Show PFS Volume indicator
                if self.structure:
                    printer(message='PFS Volume:', padding=padding + 4)

                # Show sub-PFS Header Structure Info
                if self.structure:
                    printer(message='PFS Header:\n', padding=padding + 8)

                    pfat_pfs_header.struct_print(padding=padding + 12)

                # Validate that a known sub-PFS Header Version was encountered
                self._chk_hdr_ver(version=pfat_pfs_header.HeaderVersion, text='Sub-PFS', padding=padding + 12)

                pfat_pfs_entry_off: int = pfat_pfs_header_off + self.PFS_HEAD_LEN
                pfat_pfs_footer_off: int = pfat_pfs_entry_off + pfat_pfs_header.PayloadSize

                # Get sub-PFS Entry Structure and Size
                pfat_pfs_entry_struct, pfat_pfs_entry_size = self._get_pfs_entry(
                    buffer=entry_data, offset=pfat_pfs_entry_off)

                # Show sub-PFS Entry Structure Info
                _, _, _, _, _, _, _, _ = self._parse_pfs_entry(
                    entry_buffer=entry_data, entry_start=pfat_pfs_entry_off, entry_size=pfat_pfs_entry_size,
                    entry_struct=pfat_pfs_entry_struct, text='Sub-PFS Entry', padding=padding + 12)

                # Get sub-PFS Payload Data
                pfat_pfs_entry_payload: bytes = entry_data[pfat_pfs_entry_off:pfat_pfs_footer_off]

                # Get sub-PFS Footer Data
                pfat_pfs_entry_footer: bytes = entry_data[pfat_pfs_footer_off:pfat_pfs_footer_off + self.PFS_FOOT_LEN]

                # Next nested PFS or PFAT Entries start after PFS Header and Entry
                pfat_pfs_header_off += self.PFS_HEAD_LEN + pfat_pfs_entry_size

                if len(entry_data[pfat_pfs_header_off:]) <= self.PFAT_HDR_LEN:
                    continue

                pfat_intel_header: Any = ctypes_struct(buffer=entry_data, start_offset=pfat_pfs_header_off,
                                                       class_object=IntelBiosGuardHeader)

                # Parse PFS Entry which contains sub-PFS Volume with PFAT Payload
                if pfat_intel_header.get_platform_id().upper().startswith('DELL'):
                    # Re-set PFS Entry Type from OTHER to PFAT, to use such info afterward
                    entry_type = 'PFAT'

                    # Parse sub-PFS PFAT Volume
                    entry_data = self._parse_pfat_pfs(pfat_payload=pfat_pfs_entry_payload, padding=padding)

                    # Analyze sub-PFS Footer Structure
                self._chk_pfs_ftr(footer_buffer=pfat_pfs_entry_footer, data_buffer=pfat_pfs_entry_payload,
                                  data_size=pfat_pfs_header.PayloadSize, text='Sub-PFS', padding=padding + 4)

            # Adjust PFS Entry Data after parsing PFAT (same ZLIB raw data, not stored afterward)
            entry[4] = entry_data

            # Adjust PFS Entry Type from OTHER to PFAT or ZLIB (ZLIB is ignored at file extraction)
            entry[3] = entry_type

        # Name & Store each PFS Entry/Component Data, Data Signature, Metadata, Metadata Signature
        for entry in entries_all:
            file_index, file_guid, file_version, file_type, file_data, file_data_sig, file_meta, file_meta_sig = entry

            # Give Names to special PFS Entries, not covered by PFS Information
            if file_type == 'MODEL_INFO':
                file_name: str = 'Model Information'
            elif file_type == 'NAME_INFO':
                file_name = 'Filename Information'

                if not self.advanced:
                    continue  # Don't store Filename Information in non-advanced user mode
            elif file_type == 'SIG_INFO':
                file_name = 'Signature Information'

                if not self.advanced:
                    continue  # Don't store Signature Information in non-advanced user mode
            else:
                file_name = ''

            # Most PFS Entry Names & Versions are found at PFS Information via their GUID
            # Version can be found at DellPfsEntryR* but prefer PFS Information when possible
            for info in info_all:
                info_guid, info_name, info_version = info

                # Give proper Name & Version info if Entry/Information GUIDs match
                if info_guid == file_guid:
                    file_name = info_name

                    file_version = info_version

                    # PFS with zlib-compressed sub-PFS use the same GUID
                    info[0] = 'USED'

                    # Break at 1st Name match to not rename again from
                    # next zlib-compressed sub-PFS with the same GUID.
                    break

            # For both advanced & non-advanced users, the goal is to store final/usable files only
            # so empty or intermediate files such as sub-PFS, PFS w/ PFAT or zlib-PFS are skipped
            # Main/First PFS CombineBiosNameX Metadata files must be kept for accurate Model Information
            # All users should check these files in order to choose the correct CombineBiosNameX modules
            write_files: list[list] = []  # Initialize list of output PFS Entry files to be written/extracted

            is_zlib: bool = bool(file_type == 'ZLIB')  # Determine if PFS Entry Data was zlib-compressed

            if file_data and not is_zlib:
                write_files.append([file_data, 'data'])  # PFS Entry Data Payload

            if file_data_sig and self.advanced:
                write_files.append([file_data_sig, 'sign_data'])  # PFS Entry Data Signature

            if file_meta and (is_zlib or self.advanced):
                write_files.append([file_meta, 'meta'])  # PFS Entry Metadata Payload

            if file_meta_sig and self.advanced:
                write_files.append([file_meta_sig, 'sign_meta'])  # PFS Entry Metadata Signature

            # Write/Extract PFS Entry files
            for file in write_files:
                # Full PFS Entry Name
                full_name: str = f'{pfs_index} {pfs_name} -- {file_index} {file_name} v{file_version}'

                self._pfs_file_write(bin_buff=file[0], bin_name=file[1], bin_type=file_type, full_name=full_name,
                                     out_path=extract_path, padding=padding)

        # Get PFS Footer Data after PFS Header Payload
        pfs_footer: bytes = buffer[self.PFS_HEAD_LEN + pfs_hdr.PayloadSize:
                                   self.PFS_HEAD_LEN + pfs_hdr.PayloadSize + self.PFS_FOOT_LEN]

        # Analyze PFS Footer Structure
        self._chk_pfs_ftr(footer_buffer=pfs_footer, data_buffer=pfs_payload, data_size=pfs_hdr.PayloadSize,
                          text='PFS', padding=padding)

    def _parse_pfs_entry(self, entry_buffer: bytes | bytearray, entry_start: int, entry_size: int,
                         entry_struct: Any, text: str, padding: int = 0) -> tuple:
        """ Analyze Dell PFS Entry Structure """

        # Get PFS Entry Structure values
        pfs_entry: Any = ctypes_struct(buffer=entry_buffer, start_offset=entry_start, class_object=entry_struct)

        # Show PFS Entry Structure info
        if self.structure:
            printer(message='PFS Entry:\n', padding=padding + 4)

            pfs_entry.struct_print(padding=padding + 8)

        # Validate that a known PFS Entry Header Version was encountered
        self._chk_hdr_ver(version=pfs_entry.HeaderVersion, text=text, padding=padding + 8)

        # Validate that the PFS Entry Reserved field is empty
        if pfs_entry.Reserved != 0:
            printer(message=f'Error: Detected non-empty {text} Reserved field!', padding=padding + 8)

        # Get PFS Entry Version string via "Version" and "VersionType" fields
        entry_version: str = self.get_entry_ver(version_fields=pfs_entry.Version, version_types=pfs_entry.VersionType)

        # Get PFS Entry GUID in Big Endian format
        entry_guid: str = f'{int.from_bytes(pfs_entry.GUID, byteorder="little"):0{0x10 * 2}X}'

        # PFS Entry Data starts after the PFS Entry Structure
        entry_data_start: int = entry_start + entry_size
        entry_data_end: int = entry_data_start + pfs_entry.DataSize

        # PFS Entry Data Signature starts after PFS Entry Data
        entry_data_sig_start: int = entry_data_end
        entry_data_sig_end: int = entry_data_sig_start + pfs_entry.DataSigSize

        # PFS Entry Metadata starts after PFS Entry Data Signature
        entry_met_start: int = entry_data_sig_end
        entry_met_end: int = entry_met_start + pfs_entry.DataMetSize

        # PFS Entry Metadata Signature starts after PFS Entry Metadata
        entry_met_sig_start: int = entry_met_end
        entry_met_sig_end: int = entry_met_sig_start + pfs_entry.DataMetSigSize

        # Store PFS Entry Data
        entry_data: bytes = entry_buffer[entry_data_start:entry_data_end]

        # Store PFS Entry Data Signature
        entry_data_sig: bytes = entry_buffer[entry_data_sig_start:entry_data_sig_end]

        # Store PFS Entry Metadata
        entry_met: bytes = entry_buffer[entry_met_start:entry_met_end]

        # Store PFS Entry Metadata Signature
        entry_met_sig: bytes = entry_buffer[entry_met_sig_start:entry_met_sig_end]

        return (pfs_entry, entry_version, entry_guid, entry_data, entry_data_sig,
                entry_met, entry_met_sig, entry_met_sig_end)

    def _parse_pfat_pfs(self, pfat_payload: bytes | bytearray, padding: int = 0) -> bytes:
        """ Parse Dell PFS Volume with PFAT Payload """

        # Parse all sub-PFS Payload PFAT Entries
        pfat_entries_all: list[tuple] = []  # Storage for all sub-PFS PFAT Entries Order/Offset & Payload/Raw Data
        pfat_entry_start: int = 0  # Increasing sub-PFS PFAT Entry start offset
        pfat_entry_index: int = 1  # Increasing sub-PFS PFAT Entry count index

        # Get initial PFS PFAT Entry Size for loop
        _, pfs_entry_size = self._get_pfs_entry(buffer=pfat_payload, offset=0)

        # Initialize sub-PFS PFAT Signature length
        _pfat_sign_len: int = 0

        while len(pfat_payload[pfat_entry_start:pfat_entry_start + pfs_entry_size]) == pfs_entry_size:
            # Get sub-PFS PFAT Entry Structure & Size info
            pfat_entry_struct, pfat_entry_size = self._get_pfs_entry(buffer=pfat_payload, offset=pfat_entry_start)

            # Analyze sub-PFS PFAT Entry Structure and get relevant info
            pfat_entry, _, _, pfat_entry_data, _, pfat_entry_met, _, pfat_next_entry = \
                self._parse_pfs_entry(entry_buffer=pfat_payload, entry_start=pfat_entry_start,
                                      entry_size=pfat_entry_size, entry_struct=pfat_entry_struct,
                                      text='sub-PFS PFAT Entry', padding=padding + 4)

            # Each sub-PFS PFAT Entry includes an AMI BIOS Guard (a.k.a. PFAT) block at the beginning
            # We need to parse the PFAT block and remove its contents from the final Payload/Raw Data
            pfat_hdr_off: int = pfat_entry_start + pfat_entry_size  # PFAT block starts after PFS Entry

            # Get sub-PFS PFAT Header Structure values
            pfat_hdr: Any = ctypes_struct(buffer=pfat_payload, start_offset=pfat_hdr_off,
                                          class_object=IntelBiosGuardHeader)

            # Get ordinal value of the sub-PFS PFAT Entry Index
            pfat_entry_idx_ord: str = to_ordinal(in_number=pfat_entry_index)

            # Show sub-PFS PFAT Header Structure info
            if self.structure:
                printer(message=f'PFAT Block {pfat_entry_idx_ord} - Header:\n', padding=padding + 12)

                pfat_hdr.struct_print(padding=padding + 16)

            pfat_script_start: int = pfat_hdr_off + self.PFAT_HDR_LEN  # PFAT Block Script Start

            pfat_script_end: int = pfat_script_start + pfat_hdr.ScriptSize  # PFAT Block Script End

            pfat_script_data: bytes = pfat_payload[pfat_script_start:pfat_script_end]  # PFAT Block Script Data

            pfat_payload_start: int = pfat_script_end  # PFAT Block Payload Start (at Script end)

            pfat_payload_end: int = pfat_script_end + pfat_hdr.DataSize  # PFAT Block Data End

            pfat_payload_data: bytes = pfat_payload[pfat_payload_start:pfat_payload_end]  # PFAT Block Raw Data

            pfat_hdr_bgs_size: int = self.PFAT_HDR_LEN + pfat_hdr.ScriptSize  # PFAT Block Header & Script Size

            # The PFAT Script End should match the total Entry Data Size w/o PFAT block
            if pfat_hdr_bgs_size != pfat_entry.DataSize - pfat_hdr.DataSize:
                printer(message=f'Error: Detected sub-PFS PFAT Block {pfat_entry_idx_ord} Header & '
                                f'PFAT Size mismatch!', padding=padding + 16)

            # Get PFAT Header Flags (SFAM, ProtectEC, GFXMitDis, FTU, Reserved)
            is_sfam, _, _, _, _ = pfat_hdr.get_flags()

            ami_pfat_extract: AmiPfatExtract = AmiPfatExtract()

            # Parse sub-PFS PFAT Signature, if applicable (only when PFAT Header > SFAM flag is set)
            if is_sfam:
                if self.structure:
                    printer(message=f'PFAT Block {pfat_entry_idx_ord} - Signature:\n', padding=padding + 12)

                # Get sub-PFS PFAT Signature Size from Header pattern (not necessary for Dell PFS)
                if _pfat_sign_len == 0:
                    _pfat_sign_sig: bytes = pfat_hdr.get_hdr_marker()
                    _pfat_sign_pfs: int = pfs_entry_size + self.PFS_PFAT_LEN
                    _pfat_sign_max: int = _pfat_sign_pfs + ami_pfat_extract.PFAT_INT_SIG_MAX_LEN + len(_pfat_sign_sig)
                    _pfat_sign_lim: int = pfat_payload_end + _pfat_sign_max
                    _pfat_sign_off: int = pfat_payload.find(_pfat_sign_sig, pfat_payload_end, _pfat_sign_lim)
                    _pfat_sign_len = _pfat_sign_off - pfat_payload_end - _pfat_sign_pfs

                # Get sub-PFS PFAT Signature Structure values
                pfat_sign_len: int = ami_pfat_extract.parse_bg_sign(
                    input_data=pfat_payload, sign_offset=pfat_payload_end, sign_length=_pfat_sign_len,
                    print_info=self.structure, padding=padding + 16)

                if not len(pfat_payload[pfat_payload_end:pfat_payload_end + pfat_sign_len]
                           ) == pfat_sign_len == _pfat_sign_len:
                    printer(message=f'Error: Detected sub-PFS PFAT Block {pfat_entry_idx_ord} Signature '
                                    f'Size mismatch!', padding=padding + 12)

            # Show PFAT Script via BIOS Guard Script Tool
            if self.structure:
                printer(message=f'PFAT Block {pfat_entry_idx_ord} - Script:\n', padding=padding + 12)

                _ = ami_pfat_extract.parse_bg_script(script_data=pfat_script_data, padding=padding + 16)

            # The payload of sub-PFS PFAT Entries is not in proper order by default
            # We can get each payload's order from PFAT Script > OpCode #2 (set I0 imm)
            # PFAT Script OpCode #2 > Operand #3 stores the payload Offset in final image
            pfat_entry_off: int = int.from_bytes(pfat_script_data[0xC:0x10], byteorder='little')

            # We can get each payload's length from PFAT Script > OpCode #4 (set I2 imm)
            # PFAT Script OpCode #4 > Operand #3 stores the payload Length in final image
            pfat_entry_len: int = int.from_bytes(pfat_script_data[0x1C:0x20], byteorder='little')

            # Check that the PFAT Entry Length from Header & Script match
            if pfat_hdr.DataSize != pfat_entry_len:
                printer(message=f'Error: Detected sub-PFS PFAT Block {pfat_entry_idx_ord} Header & '
                                f'Script Size mismatch!', padding=padding + 12)

            # Initialize sub-PFS PFAT Entry Metadata Address
            pfat_entry_adr: int = pfat_entry_off

            # Parse sub-PFS PFAT Entry/Block Metadata
            if len(pfat_entry_met) >= self.PFS_PFAT_LEN:
                # Get sub-PFS PFAT Metadata Structure values
                pfat_met: Any = ctypes_struct(buffer=pfat_entry_met, start_offset=0, class_object=DellPfsPfatMetadata)

                # Store sub-PFS PFAT Entry Metadata Address
                pfat_entry_adr = pfat_met.Address

                # Show sub-PFS PFAT Metadata Structure info
                if self.structure:
                    printer(message=f'PFAT Block {pfat_entry_idx_ord} - Metadata:\n', padding=padding + 12)

                    pfat_met.struct_print(padding=padding + 16)

                # Another way to get each PFAT Entry Offset is from its Metadata, if applicable
                # Check that the PFAT Entry Offsets from PFAT Script and PFAT Metadata match
                if pfat_entry_off != pfat_met.Offset:
                    printer(message=f'Error: Detected sub-PFS PFAT Block {pfat_entry_idx_ord} Metadata & '
                                    f'PFAT Offset mismatch!', padding=padding + 16)

                    # Prefer Offset from Metadata, in case PFAT Script differs
                    pfat_entry_off = pfat_met.Offset

                # Another way to get each PFAT Entry Length is from its Metadata, if applicable
                # Check that the PFAT Entry Length from PFAT Script and PFAT Metadata match
                if not pfat_hdr.DataSize == pfat_entry_len == pfat_met.DataSize:
                    printer(message=f'Error: Detected sub-PFS PFAT Block {pfat_entry_idx_ord} Metadata & '
                                    f'PFAT Length mismatch!', padding=padding + 16)

                # Check that the PFAT Entry payload Size from PFAT Header matches the one from PFAT Metadata
                if pfat_hdr.DataSize != pfat_met.DataSize:
                    printer(message=f'Error: Detected sub-PFS PFAT Block {pfat_entry_idx_ord} Metadata & '
                                    f'PFAT Block Size mismatch!', padding=padding + 16)

            # Get sub-PFS Entry Raw Data by subtracting PFAT Header & Script from PFAT Entry Data
            pfat_entry_data_raw: bytes = pfat_entry_data[pfat_hdr_bgs_size:]

            # The sub-PFS Entry Raw Data (w/o PFAT Header & Script) should match with the PFAT Block payload
            if pfat_entry_data_raw != pfat_payload_data:
                printer(message=f'Error: Detected sub-PFS PFAT Block {pfat_entry_idx_ord} w/o PFAT & '
                                f'PFAT Block Data mismatch!', padding=padding + 16)

                # Prefer Data from PFAT Block, in case PFAT Entry differs
                pfat_entry_data_raw = pfat_payload_data

            # Store each sub-PFS PFAT Entry/Block Offset, Address, Ordinal Index and Payload/Raw Data
            # Goal is to sort these based on Offset first and Address second, in cases of same Offset
            # For example, Precision 3430 has two PFAT Entries with the same Offset of 0x40000 at both
            # BG Script and PFAT Metadata but their PFAT Metadata Address is 0xFF040000 and 0xFFA40000
            pfat_entries_all.append((pfat_entry_off, pfat_entry_adr, pfat_entry_idx_ord, pfat_entry_data_raw))

            # Check if next sub-PFS PFAT Entry offset is valid
            if pfat_next_entry <= 0:
                printer(message=f'Error: Detected sub-PFS PFAT Block {pfat_entry_idx_ord} with invalid '
                                f'next PFAT Block offset!', padding=padding + 16)

                # Avoid a potential infinite loop if next sub-PFS PFAT Entry offset is bad
                pfat_next_entry += pfs_entry_size

            # Next sub-PFS PFAT Entry starts after sub-PFS Entry Metadata Signature
            pfat_entry_start = pfat_next_entry

            pfat_entry_index += 1

        # Sort all sub-PFS PFAT Entries based on their Offset/Address
        pfat_entries_all.sort()

        block_start_exp: int = 0  # Initialize sub-PFS PFAT Entry expected Offset
        total_pfat_data: bytes = b''  # Initialize final/ordered sub-PFS Entry Data

        # Parse all sorted sub-PFS PFAT Entries and merge their payload/data
        for block_start, _, block_index, block_data in pfat_entries_all:
            # Fill any data gaps between sorted sub-PFS PFAT Entries with padding
            # For example, Precision 7960 v0.16.68 has gap at 0x1190000-0x11A0000
            block_data_gap: int = block_start - block_start_exp

            if block_data_gap > 0:
                if self.structure:
                    printer(message=f'Warning: Filled sub-PFS PFAT {block_index} data gap 0x{block_data_gap:X} '
                                    f'[0x{block_start_exp:X}-0x{block_start:X}]!', padding=padding + 8)

                # Use 0xFF padding to fill in data gaps in PFAT UEFI firmware images
                total_pfat_data += b'\xFF' * block_data_gap

            total_pfat_data += block_data  # Append sorted sub-PFS PFAT Entry payload/data

            block_start_exp = len(total_pfat_data)  # Set next sub-PFS PFAT Entry expected Start

        # Verify that the end offset of the last PFAT Entry matches the final sub-PFS Entry Data Size
        if len(total_pfat_data) != pfat_entries_all[-1][0] + len(pfat_entries_all[-1][3]):
            printer(message='Error: Detected sub-PFS PFAT total buffer size and '
                            'last block end mismatch!', padding=padding + 8)

        return total_pfat_data

    @staticmethod
    def _get_pfs_entry(buffer: bytes | bytearray, offset: int) -> tuple:
        """ Get Dell PFS Entry Structure & Size via its Version """

        # PFS Entry Version
        pfs_entry_ver: int = int.from_bytes(buffer[offset + 0x10:offset + 0x14], byteorder='little')

        if pfs_entry_ver == 1:
            return DellPfsEntryR1, ctypes.sizeof(DellPfsEntryR1)

        if pfs_entry_ver == 2:
            return DellPfsEntryR2, ctypes.sizeof(DellPfsEntryR2)

        return DellPfsEntryR2, ctypes.sizeof(DellPfsEntryR2)

    @staticmethod
    def get_entry_ver(version_fields: bytes, version_types: bytes) -> str:
        """ Determine Dell PFS Entry Version string """

        version: str = ''  # Initialize Version string

        # Version Type (1 byte) determines the type of Version Value (2 bytes)
        # Version Type 'N' is Number, 'A' is Text and ' ' is Empty/Unused
        for index, field in enumerate(version_fields):
            eol: str = '' if index == len(version_fields) - 1 else '.'

            if version_types[index] == 65:
                version += f'{field:X}{eol}'  # 0x41 = ASCII
            elif version_types[index] == 78:
                version += f'{field:d}{eol}'  # 0x4E = Number
            elif version_types[index] in (0, 32):
                version = version.strip('.')  # 0x00 or 0x20 = Unused
            else:
                version += f'{field:X}{eol}'  # Unknown

        return version

    @staticmethod
    def _chk_hdr_ver(version: int, text: str, padding: int = 0) -> None:
        """ Check if Dell PFS Header Version is known """

        if version not in (1, 2):
            printer(message=f'Error: Unknown {text} Header Version {version}!', padding=padding)

    def _chk_pfs_ftr(self, footer_buffer: bytes | bytearray, data_buffer: bytes | bytearray,
                     data_size: int, text: str, padding: int = 0) -> None:
        """ Analyze Dell PFS Footer Structure """

        # Get PFS Footer Structure values
        pfs_ftr: Any = ctypes_struct(buffer=footer_buffer, start_offset=0, class_object=DellPfsFooter)

        # Validate that a PFS Footer was parsed
        if pfs_ftr.Tag == b'PFS.FTR.':
            # Show PFS Footer Structure info
            if self.structure:
                printer(message='PFS Footer:\n', padding=padding + 4)

                pfs_ftr.struct_print(padding=padding + 8)
        else:
            printer(message=f'Error: {text} Footer could not be found!', padding=padding + 4)

        # Validate that PFS Header Payload Size matches the one at PFS Footer
        if data_size != pfs_ftr.PayloadSize:
            printer(message=f'Error: {text} Header & Footer Payload Size mismatch!', padding=padding + 4)

        # Calculate the PFS Payload Data CRC-32 w/ Vector 0
        pfs_ftr_crc: int = ~zlib.crc32(data_buffer, 0) & 0xFFFFFFFF

        # Validate PFS Payload Data Checksum via PFS Footer
        if pfs_ftr.Checksum != pfs_ftr_crc:
            printer(message=f'Error: Invalid {text} Footer Payload Checksum!', padding=padding + 4)

    def _pfs_file_write(self, bin_buff: bytes | bytearray, bin_name: str, bin_type: str,
                        full_name: str, out_path: str, padding: int = 0) -> None:
        """ Write/Extract Dell PFS Entry Files (Data, Metadata, Signature) """

        # Store Data/Metadata Signature (advanced users only)
        if bin_name.startswith('sign'):
            final_name: str = f'{safe_name(in_name=full_name)}.{bin_name.split("_")[1]}.sig'

            final_path: str = os.path.join(out_path, final_name)

            with open(final_path, 'wb') as pfs_out:
                pfs_out.write(bin_buff)  # Write final Data/Metadata Signature

            return  # Skip further processing for Signatures

        # Store Data/Metadata Payload (simpler Data/Metadata Extension for non-advanced users)
        bin_ext: str = f'.{bin_name}.bin' if self.advanced else '.bin'

        # Some Data may be Text or XML files with useful information for non-advanced users
        final_data, file_ext = self._bin_is_text(buffer=bin_buff, file_type=bin_type,
                                                 is_metadata=bin_name == 'meta', padding=padding)

        is_text: bool = isinstance(final_data, str)

        final_name = f'{safe_name(in_name=full_name)}{bin_ext[:-4] + file_ext if is_text else bin_ext}'

        final_path = os.path.join(out_path, final_name)

        # Write final Data/Metadata Payload
        with open(final_path, 'w' if is_text else 'wb', encoding='utf-8' if is_text else None) as pfs_out:
            pfs_out.write(final_data)

    def _bin_is_text(self, buffer: bytes | bytearray, file_type: str, is_metadata: bool, padding: int = 0) -> tuple:
        """
        Check if Dell PFS Entry file/data is Text/XML and Convert

        Only for non-advanced users due to signature (.sig) invalidation
        """

        extension: str = '.bin'

        if self.advanced:
            return buffer, extension

        buffer_text: str = ''

        if b',END' in buffer[-0x8:]:  # Text Type 1
            extension = '.txt'

            buffer_text = buffer.decode('utf-8').split(',END')[0].replace(';', '\n')
        elif buffer.startswith(b'VendorName=Dell'):  # Text Type 2
            extension = '.txt'

            buffer_text = buffer.split(b'\x00')[0].decode('utf-8').replace(';', '\n')
        elif b'<Rimm x-schema="' in buffer[:0x50]:  # XML Type
            extension = '.xml'

            buffer_text = buffer.decode('utf-8')
        elif file_type in ('NESTED_PFS', 'ZLIB') and is_metadata and len(buffer) == self.PFS_META_LEN:  # Text Type 3
            extension = '.txt'

            with io.StringIO() as text_buffer, contextlib.redirect_stdout(text_buffer):
                ctypes_struct(buffer=buffer, start_offset=0, class_object=DellPfsMetadata).struct_print(padding=0)

                # noinspection PyUnresolvedReferences
                buffer_text = text_buffer.getvalue()

        # Show Model/PCR XML Information, if applicable
        # Metadata is shown at initial DellPfsMetadata analysis
        if self.structure and buffer_text and not is_metadata:
            metadata_info_type: str = {".txt": "Model", ".xml": "PCR XML"}[extension]

            printer(message=f'PFS {metadata_info_type} Information:\n', padding=padding + 8)

            for line in [line for line in buffer_text.split('\n') if line]:
                printer(message=line.strip('\r'), padding=padding + 12, new_line=False)

        return buffer_text or buffer, extension
