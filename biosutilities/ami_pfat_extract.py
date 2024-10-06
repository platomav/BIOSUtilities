#!/usr/bin/env python3 -B
# coding=utf-8

"""
AMI PFAT Extract
AMI BIOS Guard Extractor
Copyright (C) 2018-2024 Plato Mavropoulos
"""

import ctypes
import os
import re
import struct

from typing import Any, Final, Type

from biosutilities.common.externals import big_script_tool
from biosutilities.common.paths import extract_suffix, extract_folder, make_dirs, path_name, safe_name
from biosutilities.common.patterns import PAT_AMI_PFAT
from biosutilities.common.structs import CHAR, ctypes_struct, UINT8, UINT16, UINT32
from biosutilities.common.system import printer
from biosutilities.common.templates import BIOSUtility
from biosutilities.common.texts import bytes_to_hex, file_to_bytes, to_ordinal


class AmiBiosGuardHeader(ctypes.LittleEndianStructure):
    """ AMI BIOS Guard Header """

    _pack_ = 1
    _fields_ = [
        ('Size',            UINT32),        # 0x00 Header + Entries
        ('Checksum',        UINT32),        # 0x04 ?
        ('Tag',             CHAR * 8),      # 0x04 _AMIPFAT
        ('Flags',           UINT8)          # 0x10 ?
        # 0x11
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Size    :', f'0x{self.Size:X}'], padding=padding, new_line=False)
        printer(message=['Checksum:', f'0x{self.Checksum:04X}'], padding=padding, new_line=False)
        printer(message=['Tag     :', self.Tag.decode(encoding='utf-8')], padding=padding, new_line=False)
        printer(message=['Flags   :', f'0x{self.Flags:02X}'], padding=padding, new_line=False)


class IntelBiosGuardHeader(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Header """

    _pack_ = 1
    _fields_ = [
        ('BGVerMajor',      UINT16),        # 0x00
        ('BGVerMinor',      UINT16),        # 0x02
        ('PlatformID',      UINT8 * 16),    # 0x04
        ('Attributes',      UINT32),        # 0x14
        ('ScriptVerMajor',  UINT16),        # 0x16
        ('ScriptVerMinor',  UINT16),        # 0x18
        ('ScriptSize',      UINT32),        # 0x1C
        ('DataSize',        UINT32),        # 0x20
        ('BIOSSVN',         UINT32),        # 0x24
        ('ECSVN',           UINT32),        # 0x28
        ('VendorInfo',      UINT32)         # 0x2C
        # 0x30
    ]

    def get_platform_id(self) -> str:
        """ Get Intel BIOS Guard Platform ID """

        id_byte: bytes = bytes(self.PlatformID)

        id_text: str = re.sub(r'[\n\t\r\x00 ]', '', id_byte.decode(encoding='utf-8', errors='ignore'))

        id_hexs: str = f'{int.from_bytes(bytes=id_byte, byteorder="big"):0{0x10 * 2}X}'

        id_guid: str = f'{{{id_hexs[:8]}-{id_hexs[8:12]}-{id_hexs[12:16]}-{id_hexs[16:20]}-{id_hexs[20:]}}}'

        return f'{id_text} {id_guid}'

    def get_hdr_marker(self) -> bytes:
        """ Get Intel BIOS Guard Header Marker """

        return struct.pack('<HH16B', self.BGVerMajor, self.BGVerMinor, *self.PlatformID)

    def get_flags(self) -> tuple:
        """ Get Intel BIOS Guard Header Attributes """

        attr: IntelBiosGuardHeaderGetAttributes = IntelBiosGuardHeaderGetAttributes()

        attr.asbytes = self.Attributes  # pylint: disable=attribute-defined-outside-init

        return attr.b.SFAM, attr.b.ProtectEC, attr.b.GFXMitDis, attr.b.FTU, attr.b.Reserved

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        no_yes: dict[int, str] = {0: 'No', 1: 'Yes'}

        sfam, ec_opc, gfx_dis, ft_upd, attr_res = self.get_flags()

        bg_version: str = f'{self.BGVerMajor}.{self.BGVerMinor}'
        script_version: str = f'{self.ScriptVerMajor}.{self.ScriptVerMinor}'

        printer(message=['BIOS Guard Version          :', bg_version], padding=padding, new_line=False)
        printer(message=['Platform Identity           :', self.get_platform_id()], padding=padding, new_line=False)
        printer(message=['Signed Flash Address Map    :', no_yes[sfam]], padding=padding, new_line=False)
        printer(message=['Protected EC OpCodes        :', no_yes[ec_opc]], padding=padding, new_line=False)
        printer(message=['Graphics Security Disable   :', no_yes[gfx_dis]], padding=padding, new_line=False)
        printer(message=['Fault Tolerant Update       :', no_yes[ft_upd]], padding=padding, new_line=False)
        printer(message=['Attributes Reserved         :', f'0x{attr_res:X}'], padding=padding, new_line=False)
        printer(message=['Script Version              :', script_version], padding=padding, new_line=False)
        printer(message=['Script Size                 :', f'0x{self.ScriptSize:X}'], padding=padding, new_line=False)
        printer(message=['Data Size                   :', f'0x{self.DataSize:X}'], padding=padding, new_line=False)
        printer(message=['BIOS Security Version Number:', f'0x{self.BIOSSVN:X}'], padding=padding, new_line=False)
        printer(message=['EC Security Version Number  :', f'0x{self.ECSVN:X}'], padding=padding, new_line=False)
        printer(message=['Vendor Information          :', f'0x{self.VendorInfo:X}'], padding=padding, new_line=False)


class IntelBiosGuardHeaderAttributes(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Header Attributes """

    _pack_ = 1
    _fields_ = [
        ('SFAM',            UINT32,     1),     # Signed Flash Address Map
        ('ProtectEC',       UINT32,     1),     # Protected EC OpCodes
        ('GFXMitDis',       UINT32,     1),     # GFX Security Disable
        ('FTU',             UINT32,     1),     # Fault Tolerant Update
        ('Reserved',        UINT32,     28)     # Reserved/Unknown
    ]


class IntelBiosGuardHeaderGetAttributes(ctypes.Union):
    """ Intel BIOS Guard Header Attributes Getter """

    _pack_ = 1
    _fields_ = [
        ('b',               IntelBiosGuardHeaderAttributes),
        ('asbytes',         UINT32)
    ]


class IntelBiosGuardSignatureHeader(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Signature Header """

    _pack_ = 1
    _fields_ = [
        ('Unknown0',        UINT32),        # 0x000
        ('Unknown1',        UINT32)         # 0x004
        # 0x8
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        printer(message=['Unknown 0:', f'0x{self.Unknown0:X}'], padding=padding, new_line=False)
        printer(message=['Unknown 1:', f'0x{self.Unknown1:X}'], padding=padding, new_line=False)


class IntelBiosGuardSignatureRsa2k(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Signature Block 2048-bit """

    _pack_ = 1
    _fields_ = [
        ('Modulus',         UINT8 * 256),   # 0x000
        ('Exponent',        UINT32),        # 0x100
        ('Signature',       UINT8 * 256)    # 0x104
        # 0x204
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        modulus: str = f'{bytes_to_hex(in_buffer=self.Modulus, order="little", data_len=0x100, slice_len=32)} [...]'
        exponent: str = f'0x{self.Exponent:X}'
        signature: str = f'{bytes_to_hex(in_buffer=self.Signature, order="little", data_len=0x100, slice_len=32)} [...]'

        printer(message=['Modulus  :', modulus], padding=padding, new_line=False)
        printer(message=['Exponent :', exponent], padding=padding, new_line=False)
        printer(message=['Signature:', signature], padding=padding, new_line=False)


class IntelBiosGuardSignatureRsa3k(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Signature Block 3072-bit """

    _pack_ = 1
    _fields_ = [
        ('Modulus',         UINT8 * 384),   # 0x000
        ('Exponent',        UINT32),        # 0x180
        ('Signature',       UINT8 * 384)    # 0x184
        # 0x304
    ]

    def struct_print(self, padding: int = 0) -> None:
        """ Display structure information """

        modulus: str = f'{int.from_bytes(bytes=self.Modulus, byteorder="little"):0{0x180 * 2}X}'[:64]
        exponent: str = f'0x{self.Exponent:X}'
        signature: str = f'{int.from_bytes(bytes=self.Signature, byteorder="little"):0{0x180 * 2}X}'[:64]

        printer(message=['Modulus  :', modulus], padding=padding, new_line=False)
        printer(message=['Exponent :', exponent], padding=padding, new_line=False)
        printer(message=['Signature:', signature], padding=padding, new_line=False)


class AmiPfatExtract(BIOSUtility):
    """ AMI BIOS Guard Extractor """

    TITLE: str = 'AMI BIOS Guard Extractor'

    PFAT_AMI_HDR_LEN: Final[int] = ctypes.sizeof(AmiBiosGuardHeader)
    PFAT_INT_HDR_LEN: Final[int] = ctypes.sizeof(IntelBiosGuardHeader)
    PFAT_INT_SIG_HDR_LEN: Final[int] = ctypes.sizeof(IntelBiosGuardSignatureHeader)
    PFAT_INT_SIG_R2K_LEN: Final[int] = ctypes.sizeof(IntelBiosGuardSignatureRsa2k)
    PFAT_INT_SIG_R3K_LEN: Final[int] = ctypes.sizeof(IntelBiosGuardSignatureRsa3k)
    PFAT_INT_SIG_MAX_LEN: Final[int] = PFAT_INT_SIG_HDR_LEN + PFAT_INT_SIG_R3K_LEN

    def check_format(self, input_object: str | bytes | bytearray) -> bool:
        """ Check if input is AMI BIOS Guard """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        return bool(self._get_ami_pfat(input_object=input_buffer))

    def parse_format(self, input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> bool:
        """ Process and store AMI BIOS Guard output file """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        pfat_buffer: bytes = self._get_ami_pfat(input_object=input_buffer)

        file_path: str = ''

        all_blocks_dict: dict = {}

        bg_sign_len: int = 0

        extract_name: str = path_name(in_path=extract_path).removesuffix(extract_suffix())

        make_dirs(in_path=extract_path, delete=True)

        block_all, block_off, file_count = self._parse_pfat_hdr(buffer=pfat_buffer, padding=padding)

        for block in block_all:
            file_desc, file_name, _, _, _, file_index, block_index, block_count = block

            if block_index == 0:
                printer(message=file_desc, padding=padding + 4)

                file_path = os.path.join(extract_path, self._get_file_name(index=file_index + 1, name=file_name))

                all_blocks_dict[file_index] = b''

            block_status: str = f'{block_index + 1}/{block_count}'

            bg_hdr: Any = ctypes_struct(buffer=pfat_buffer, start_offset=block_off, class_object=IntelBiosGuardHeader)

            printer(message=f'Intel BIOS Guard {block_status} Header:\n', padding=padding + 8)

            bg_hdr.struct_print(padding=padding + 12)

            bg_script_bgn: int = block_off + self.PFAT_INT_HDR_LEN
            bg_script_end: int = bg_script_bgn + bg_hdr.ScriptSize

            bg_data_bgn: int = bg_script_end
            bg_data_end: int = bg_data_bgn + bg_hdr.DataSize

            bg_data_bin: bytes = pfat_buffer[bg_data_bgn:bg_data_end]

            block_off = bg_data_end  # Assume next block starts at data end

            is_sfam, _, _, _, _ = bg_hdr.get_flags()  # SFAM, ProtectEC, GFXMitDis, FTU, Reserved

            if is_sfam:
                printer(message=f'Intel BIOS Guard {block_status} Signature:\n', padding=padding + 8)

                # Manual BIOS Guard Signature length detection from Header pattern (e.g. Panasonic)
                if bg_sign_len == 0:
                    bg_sign_sig: bytes = bg_hdr.get_hdr_marker()
                    bg_sign_lim: int = bg_data_end + self.PFAT_INT_SIG_MAX_LEN + len(bg_sign_sig)
                    bg_sign_len = pfat_buffer.find(bg_sign_sig, bg_data_end, bg_sign_lim) - bg_data_end

                # Adjust next block to start after current block Data + Signature
                block_off += self.parse_bg_sign(input_data=pfat_buffer, sign_offset=bg_data_end,
                                                sign_length=bg_sign_len, print_info=True, padding=padding + 12)

            printer(message=f'Intel BIOS Guard {block_status} Script:\n', padding=padding + 8)

            _ = self.parse_bg_script(script_data=pfat_buffer[bg_script_bgn:bg_script_end], padding=padding + 12)

            with open(file=file_path, mode='ab') as out_dat:
                out_dat.write(bg_data_bin)

            all_blocks_dict[file_index] += bg_data_bin

            if block_index + 1 == block_count:
                if self.check_format(input_object=all_blocks_dict[file_index]):
                    self.parse_format(input_object=all_blocks_dict[file_index],
                                      extract_path=extract_folder(file_path), padding=padding + 8)

        pfat_oob_data: bytes = pfat_buffer[block_off:]  # Store out-of-bounds data after the end of PFAT files

        pfat_oob_name: str = self._get_file_name(index=file_count + 1, name=f'{extract_name}_OOB.bin')

        pfat_oob_path: str = os.path.join(extract_path, pfat_oob_name)

        with open(file=pfat_oob_path, mode='wb') as out_oob:
            out_oob.write(pfat_oob_data)

        if self.check_format(input_object=pfat_oob_data):
            self.parse_format(input_object=pfat_oob_data, extract_path=extract_folder(pfat_oob_path),
                              padding=padding)

        in_all_data: bytes = b''.join([block[1] for block in sorted(all_blocks_dict.items())])

        in_all_name: str = self._get_file_name(index=0, name=f'{extract_name}_ALL.bin')

        in_all_path: str = os.path.join(extract_path, in_all_name)

        with open(file=in_all_path, mode='wb') as out_all:
            out_all.write(in_all_data + pfat_oob_data)

        return True

    def parse_bg_sign(self, input_data: bytes, sign_offset: int, sign_length: int = 0,
                      print_info: bool = False, padding: int = 0) -> int:
        """ Process Intel BIOS Guard Signature """

        bg_sig_hdr: Any = ctypes_struct(buffer=input_data, start_offset=sign_offset,
                                        class_object=IntelBiosGuardSignatureHeader)

        if bg_sig_hdr.Unknown0 == 1:
            bg_sig_rsa_struct: Any = IntelBiosGuardSignatureRsa2k  # Unknown0/Unknown1 = 1,1
        elif bg_sig_hdr.Unknown0 in (2, 3):
            bg_sig_rsa_struct = IntelBiosGuardSignatureRsa3k  # Unknown0/Unknown1 = 2/3, 3/5, 3/6
        elif sign_length == self.PFAT_INT_SIG_HDR_LEN + self.PFAT_INT_SIG_R2K_LEN:
            bg_sig_rsa_struct = IntelBiosGuardSignatureRsa2k

            printer(message='Warning: Detected Intel BIOS Guard Signature 2K length via pattern!\n',
                    padding=padding, new_line=False)
        elif sign_length == self.PFAT_INT_SIG_HDR_LEN + self.PFAT_INT_SIG_R3K_LEN:
            bg_sig_rsa_struct = IntelBiosGuardSignatureRsa3k

            printer(message='Warning: Detected Intel BIOS Guard Signature 3K length via pattern!\n',
                    padding=padding, new_line=False)
        else:
            bg_sig_rsa_struct = IntelBiosGuardSignatureRsa3k

            printer(message='Error: Could not detect Intel BIOS Guard Signature length, assuming 3K!\n',
                    padding=padding, new_line=False)

        bg_sig_rsa: Any = ctypes_struct(buffer=input_data, start_offset=sign_offset + self.PFAT_INT_SIG_HDR_LEN,
                                        class_object=bg_sig_rsa_struct)

        if print_info:
            bg_sig_hdr.struct_print(padding=padding)

            bg_sig_rsa.struct_print(padding=padding)

        # Total size of Signature Header and RSA Structure
        return self.PFAT_INT_SIG_HDR_LEN + ctypes.sizeof(bg_sig_rsa_struct)

    @staticmethod
    def _get_ami_pfat(input_object: str | bytes | bytearray) -> bytes:
        """ Get actual AMI BIOS Guard buffer """

        input_buffer: bytes = file_to_bytes(in_object=input_object)

        match: re.Match[bytes] | None = PAT_AMI_PFAT.search(string=input_buffer)

        return input_buffer[match.start() - 0x8:] if match else b''

    @staticmethod
    def _get_file_name(index: int, name: str) -> str:
        """ Create AMI BIOS Guard output filename """

        return safe_name(in_name=f'{index:02d} -- {name}')

    @staticmethod
    def parse_bg_script(script_data: bytes, padding: int = 0) -> int:
        """ Process Intel BIOS Guard Script """

        is_opcode_div: bool = len(script_data) % 8 == 0

        if not is_opcode_div:
            printer(message='Error: BIOS Guard script is not divisible by OpCode length!',
                    padding=padding, new_line=False)

            return 1

        is_begin_end: bool = script_data[:8] + script_data[-8:] == b'\x01' + b'\x00' * 7 + b'\xFF' + b'\x00' * 7

        if not is_begin_end:
            printer(message='Error: BIOS Guard script lacks Begin and/or End OpCodes!',
                    padding=padding, new_line=False)

            return 2

        big_script: Type | None = big_script_tool()

        if not big_script:
            printer(message='Note: BIOS Guard Script Tool optional dependency is missing!',
                    padding=padding, new_line=False)

            return 3

        script: list[str] = big_script(code_bytes=script_data).to_string().replace('\t', '    ').split('\n')

        for opcode in script:
            if opcode.endswith(('begin', 'end')):
                spacing: int = padding
            elif opcode.endswith(':'):
                spacing = padding + 4
            else:
                spacing = padding + 12

            operands: list[str] = [operand for operand in opcode.split(' ') if operand]

            # Largest opcode length is 11 (erase64kblk) and largest operand length is 10 (0xAABBCCDD).
            printer(message=f'{operands[0]:11s}{"".join((f" {o:10s}" for o in operands[1:]))}',
                    padding=spacing, new_line=False)

        return 0

    def _parse_pfat_hdr(self, buffer: bytes | bytearray, padding: int = 0) -> tuple:
        """ Parse AMI BIOS Guard Header """

        block_all: list = []

        pfat_hdr: Any = ctypes_struct(buffer=buffer, start_offset=0, class_object=AmiBiosGuardHeader)

        hdr_size: int = pfat_hdr.Size

        hdr_data: bytes = buffer[self.PFAT_AMI_HDR_LEN:hdr_size]

        hdr_text: list[str] = hdr_data.decode(encoding='utf-8').splitlines()

        printer(message='AMI BIOS Guard Header:\n', padding=padding)

        pfat_hdr.struct_print(padding=padding + 4)

        hdr_title, *hdr_files = hdr_text

        files_count: int = len(hdr_files)

        hdr_tag, *hdr_indexes = hdr_title.split('II')

        printer(message=hdr_tag + '\n', padding=padding + 4)

        bgt_indexes: list = [int(h, 16) for h in re.findall(r'.{1,4}', hdr_indexes[0])] if hdr_indexes else []

        for index, entry in enumerate(hdr_files):
            entry_parts: list = entry.split(';')

            info: list = entry_parts[0].split()

            name: str = entry_parts[1]

            flags: int = int(info[0])

            param: str = info[1]

            count: int = int(info[2])

            order: str = to_ordinal(in_number=(bgt_indexes[index] if bgt_indexes else index) + 1)

            desc = f'{name} (Index: {index + 1:02d}, Flash: {order}, ' \
                   f'Parameter: {param}, Flags: 0x{flags:X}, Blocks: {count})'

            block_all += [(desc, name, order, param, flags, index, i, count) for i in range(count)]

        for block in block_all:
            if block[6] == 0:
                printer(message=block[0], padding=padding + 8, new_line=False)

        return block_all, hdr_size, files_count


if __name__ == '__main__':
    AmiPfatExtract().run_utility()
