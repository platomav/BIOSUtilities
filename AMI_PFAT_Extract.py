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

from common.externals import get_bgs_tool
from common.num_ops import get_ordinal
from common.path_ops import extract_suffix, get_extract_path, make_dirs, path_name, safe_name
from common.patterns import PAT_AMI_PFAT
from common.struct_ops import Char, get_struct, UInt8, UInt16, UInt32
from common.system import printer
from common.templates import BIOSUtility
from common.text_ops import bytes_to_hex, file_to_bytes

TITLE = 'AMI BIOS Guard Extractor v5.0'


class AmiBiosGuardHeader(ctypes.LittleEndianStructure):
    """ AMI BIOS Guard Header """

    _pack_ = 1

    # noinspection PyTypeChecker
    _fields_ = [
        ('Size',            UInt32),        # 0x00 Header + Entries
        ('Checksum',        UInt32),        # 0x04 ?
        ('Tag',             Char * 8),      # 0x04 _AMIPFAT
        ('Flags',           UInt8),         # 0x10 ?
        # 0x11
    ]

    def struct_print(self, padd: int) -> None:
        """ Display structure information """

        printer(['Size    :', f'0x{self.Size:X}'], padd, False)
        printer(['Checksum:', f'0x{self.Checksum:04X}'], padd, False)
        printer(['Tag     :', self.Tag.decode('utf-8')], padd, False)
        printer(['Flags   :', f'0x{self.Flags:02X}'], padd, False)


class IntelBiosGuardHeader(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Header """

    _pack_ = 1

    # noinspection PyTypeChecker
    _fields_ = [
        ('BGVerMajor',      UInt16),        # 0x00
        ('BGVerMinor',      UInt16),        # 0x02
        ('PlatformID',      UInt8 * 16),    # 0x04
        ('Attributes',      UInt32),        # 0x14
        ('ScriptVerMajor',  UInt16),        # 0x16
        ('ScriptVerMinor',  UInt16),        # 0x18
        ('ScriptSize',      UInt32),        # 0x1C
        ('DataSize',        UInt32),        # 0x20
        ('BIOSSVN',         UInt32),        # 0x24
        ('ECSVN',           UInt32),        # 0x28
        ('VendorInfo',      UInt32),        # 0x2C
        # 0x30
    ]

    def get_platform_id(self) -> str:
        """ Get Intel BIOS Guard Platform ID """

        id_byte: bytes = bytes(self.PlatformID)

        id_text: str = re.sub(r'[\n\t\r\x00 ]', '', id_byte.decode('utf-8', 'ignore'))

        id_hexs: str = f'{int.from_bytes(id_byte, "big"):0{0x10 * 2}X}'
        id_guid: str = f'{{{id_hexs[:8]}-{id_hexs[8:12]}-{id_hexs[12:16]}-{id_hexs[16:20]}-{id_hexs[20:]}}}'

        return f'{id_text} {id_guid}'

    def get_flags(self) -> tuple:
        """ Get Intel BIOS Guard Header Attributes """

        attr = IntelBiosGuardHeaderGetAttributes()

        attr.asbytes = self.Attributes  # pylint: disable=W0201

        return attr.b.SFAM, attr.b.ProtectEC, attr.b.GFXMitDis, attr.b.FTU, attr.b.Reserved

    def struct_print(self, padd: int) -> None:
        """ Display structure information """

        no_yes: dict[int, str] = {0: 'No', 1: 'Yes'}

        sfam, ec_opc, gfx_dis, ft_upd, attr_res = self.get_flags()

        printer(['BIOS Guard Version          :', f'{self.BGVerMajor}.{self.BGVerMinor}'], padd, False)
        printer(['Platform Identity           :', self.get_platform_id()], padd, False)
        printer(['Signed Flash Address Map    :', no_yes[sfam]], padd, False)
        printer(['Protected EC OpCodes        :', no_yes[ec_opc]], padd, False)
        printer(['Graphics Security Disable   :', no_yes[gfx_dis]], padd, False)
        printer(['Fault Tolerant Update       :', no_yes[ft_upd]], padd, False)
        printer(['Attributes Reserved         :', f'0x{attr_res:X}'], padd, False)
        printer(['Script Version              :', f'{self.ScriptVerMajor}.{self.ScriptVerMinor}'], padd, False)
        printer(['Script Size                 :', f'0x{self.ScriptSize:X}'], padd, False)
        printer(['Data Size                   :', f'0x{self.DataSize:X}'], padd, False)
        printer(['BIOS Security Version Number:', f'0x{self.BIOSSVN:X}'], padd, False)
        printer(['EC Security Version Number  :', f'0x{self.ECSVN:X}'], padd, False)
        printer(['Vendor Information          :', f'0x{self.VendorInfo:X}'], padd, False)


class IntelBiosGuardHeaderAttributes(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Header Attributes """

    _pack_ = 1

    _fields_ = [
        ('SFAM',            UInt32,     1),     # Signed Flash Address Map
        ('ProtectEC',       UInt32,     1),     # Protected EC OpCodes
        ('GFXMitDis',       UInt32,     1),     # GFX Security Disable
        ('FTU',             UInt32,     1),     # Fault Tolerant Update
        ('Reserved',        UInt32,     28)     # Reserved/Unknown
    ]


class IntelBiosGuardHeaderGetAttributes(ctypes.Union):
    """ Intel BIOS Guard Header Attributes Getter """

    _pack_ = 1

    _fields_ = [
        ('b',               IntelBiosGuardHeaderAttributes),
        ('asbytes',         UInt32)
    ]


class IntelBiosGuardSignatureHeader(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Signature Header """

    _pack_ = 1

    _fields_ = [
        ('Unknown0',        UInt32),        # 0x000
        ('Unknown1',        UInt32),        # 0x004
        # 0x8
    ]

    def struct_print(self, padd: int) -> None:
        """ Display structure information """

        printer(['Unknown 0:', f'0x{self.Unknown0:X}'], padd, False)
        printer(['Unknown 1:', f'0x{self.Unknown1:X}'], padd, False)


class IntelBiosGuardSignatureRsa2k(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Signature Block 2048-bit """

    _pack_ = 1

    # noinspection PyTypeChecker
    _fields_ = [
        ('Modulus',         UInt8 * 256),   # 0x000
        ('Exponent',        UInt32),        # 0x100
        ('Signature',       UInt8 * 256),   # 0x104
        # 0x204
    ]

    def struct_print(self, padd: int) -> None:
        """ Display structure information """

        printer(['Modulus  :', f'{bytes_to_hex(self.Modulus, "little", 0x100, 32)} [...]'], padd, False)
        printer(['Exponent :', f'0x{self.Exponent:X}'], padd, False)
        printer(['Signature:', f'{bytes_to_hex(self.Signature, "little", 0x100, 32)} [...]'], padd, False)


class IntelBiosGuardSignatureRsa3k(ctypes.LittleEndianStructure):
    """ Intel BIOS Guard Signature Block 3072-bit """

    _pack_ = 1

    # noinspection PyTypeChecker
    _fields_ = [
        ('Modulus',         UInt8 * 384),   # 0x000
        ('Exponent',        UInt32),        # 0x180
        ('Signature',       UInt8 * 384),   # 0x184
        # 0x304
    ]

    def struct_print(self, padd: int) -> None:
        """ Display structure information """

        printer(['Modulus  :', f'{int.from_bytes(self.Modulus, "little"):0{0x180 * 2}X}'[:64]], padd, False)
        printer(['Exponent :', f'0x{self.Exponent:X}'], padd, False)
        printer(['Signature:', f'{int.from_bytes(self.Signature, "little"):0{0x180 * 2}X}'[:64]], padd, False)


def is_ami_pfat(input_object: str | bytes | bytearray) -> bool:
    """ Check if input is AMI BIOS Guard """

    input_buffer: bytes = file_to_bytes(input_object)

    return bool(get_ami_pfat(input_buffer))


def get_ami_pfat(input_object: str | bytes | bytearray) -> bytes:
    """ Get actual AMI BIOS Guard buffer """

    input_buffer: bytes = file_to_bytes(input_object)

    match = PAT_AMI_PFAT.search(input_buffer)

    return input_buffer[match.start() - 0x8:] if match else b''


def get_file_name(index: int, name: str) -> str:
    """ Create AMI BIOS Guard output filename """

    return safe_name(f'{index:02d} -- {name}')


def parse_bg_script(script_data: bytes, padding: int = 0) -> int:
    """ Process Intel BIOS Guard Script """

    is_opcode_div: bool = len(script_data) % 8 == 0

    if not is_opcode_div:
        printer('Error: BIOS Guard script is not divisible by OpCode length!', padding, False)

        return 1

    is_begin_end: bool = script_data[:8] + script_data[-8:] == b'\x01' + b'\x00' * 7 + b'\xFF' + b'\x00' * 7

    if not is_begin_end:
        printer('Error: BIOS Guard script lacks Begin and/or End OpCodes!', padding, False)

        return 2

    big_script = get_bgs_tool()

    if not big_script:
        printer('Note: BIOS Guard Script Tool optional dependency is missing!', padding, False)

        return 3

    script = big_script(code_bytes=script_data).to_string().replace('\t', '    ').split('\n')

    for opcode in script:
        if opcode.endswith(('begin', 'end')):
            spacing: int = padding
        elif opcode.endswith(':'):
            spacing = padding + 4
        else:
            spacing = padding + 12

        operands = [operand for operand in opcode.split(' ') if operand]

        # Largest opcode length is 11 (erase64kblk) and largest operand length is 10 (0xAABBCCDD).
        printer(f'{operands[0]:11s}{"".join((f" {o:10s}" for o in operands[1:]))}', spacing, False)

    return 0


def parse_bg_sign(input_data: bytes, sign_offset: int, print_info: bool = False, padding: int = 0) -> int:
    """ Process Intel BIOS Guard Signature """

    bg_sig_hdr = get_struct(input_data, sign_offset, IntelBiosGuardSignatureHeader)

    if bg_sig_hdr.Unknown0 == 1:
        # Unknown0 = 1, Unknown1 = 1
        bg_sig_rsa_struct = IntelBiosGuardSignatureRsa2k
    else:
        # Unknown0 = 2, Unknown1 = 3
        bg_sig_rsa_struct = IntelBiosGuardSignatureRsa3k

    bg_sig_rsa = get_struct(input_data, sign_offset + PFAT_BLK_SIG_LEN, bg_sig_rsa_struct)

    if print_info:
        bg_sig_hdr.struct_print(padding)

        bg_sig_rsa.struct_print(padding)

    # Total size of Signature Header and RSA Structure
    return PFAT_BLK_SIG_LEN + ctypes.sizeof(bg_sig_rsa_struct)


def parse_pfat_hdr(buffer: bytes | bytearray, padding: int = 0) -> tuple:
    """ Parse AMI BIOS Guard Header """

    block_all: list = []

    pfat_hdr = get_struct(buffer, 0x0, AmiBiosGuardHeader)

    hdr_size: int = pfat_hdr.Size

    hdr_data: bytes = buffer[PFAT_AMI_HDR_LEN:hdr_size]

    hdr_text: list[str] = hdr_data.decode('utf-8').splitlines()

    printer('AMI BIOS Guard Header:\n', padding)

    pfat_hdr.struct_print(padding + 4)

    hdr_title, *hdr_files = hdr_text

    files_count: int = len(hdr_files)

    hdr_tag, *hdr_indexes = hdr_title.split('II')

    printer(hdr_tag + '\n', padding + 4)

    bgt_indexes: list = [int(h, 16) for h in re.findall(r'.{1,4}', hdr_indexes[0])] if hdr_indexes else []

    for index, entry in enumerate(hdr_files):
        entry_parts: list = entry.split(';')

        info: list = entry_parts[0].split()

        name: str = entry_parts[1]

        flags: int = int(info[0])

        param: str = info[1]

        count: int = int(info[2])

        order: str = get_ordinal((bgt_indexes[index] if bgt_indexes else index) + 1)

        desc = f'{name} (Index: {index + 1:02d}, Flash: {order}, ' \
               f'Parameter: {param}, Flags: 0x{flags:X}, Blocks: {count})'

        block_all += [(desc, name, order, param, flags, index, i, count) for i in range(count)]

    _ = [printer(block[0], padding + 8, False) for block in block_all if block[6] == 0]

    return block_all, hdr_size, files_count


def parse_pfat_file(input_object: str | bytes | bytearray, extract_path: str, padding: int = 0) -> int:
    """ Process and store AMI BIOS Guard output file """

    input_buffer: bytes = file_to_bytes(input_object)

    pfat_buffer: bytes = get_ami_pfat(input_buffer)

    file_path: str = ''

    all_blocks_dict: dict = {}

    extract_name: str = path_name(extract_path).removesuffix(extract_suffix())

    make_dirs(extract_path, delete=True)

    block_all, block_off, file_count = parse_pfat_hdr(pfat_buffer, padding)

    for block in block_all:
        file_desc, file_name, _, _, _, file_index, block_index, block_count = block

        if block_index == 0:
            printer(file_desc, padding + 4)

            file_path = os.path.join(extract_path, get_file_name(file_index + 1, file_name))

            all_blocks_dict[file_index] = b''

        block_status: str = f'{block_index + 1}/{block_count}'

        bg_hdr = get_struct(pfat_buffer, block_off, IntelBiosGuardHeader)

        printer(f'Intel BIOS Guard {block_status} Header:\n', padding + 8)

        bg_hdr.struct_print(padding + 12)

        bg_script_bgn: int = block_off + PFAT_BLK_HDR_LEN
        bg_script_end: int = bg_script_bgn + bg_hdr.ScriptSize

        bg_data_bgn: int = bg_script_end
        bg_data_end: int = bg_data_bgn + bg_hdr.DataSize

        bg_data_bin: bytes = pfat_buffer[bg_data_bgn:bg_data_end]

        block_off: int = bg_data_end  # Assume next block starts at data end

        is_sfam, _, _, _, _ = bg_hdr.get_flags()  # SFAM, ProtectEC, GFXMitDis, FTU, Reserved

        if is_sfam:
            printer(f'Intel BIOS Guard {block_status} Signature:\n', padding + 8)

            # Adjust next block to start after current block Data + Signature
            block_off += parse_bg_sign(pfat_buffer, bg_data_end, True, padding + 12)

        printer(f'Intel BIOS Guard {block_status} Script:\n', padding + 8)

        _ = parse_bg_script(pfat_buffer[bg_script_bgn:bg_script_end], padding + 12)

        with open(file_path, 'ab') as out_dat:
            out_dat.write(bg_data_bin)

        all_blocks_dict[file_index] += bg_data_bin

        if block_index + 1 == block_count:
            if is_ami_pfat(all_blocks_dict[file_index]):
                parse_pfat_file(all_blocks_dict[file_index], get_extract_path(file_path), padding + 8)

    pfat_oob_data: bytes = pfat_buffer[block_off:]  # Store out-of-bounds data after the end of PFAT files

    pfat_oob_name: str = get_file_name(file_count + 1, f'{extract_name}_OOB.bin')

    pfat_oob_path: str = os.path.join(extract_path, pfat_oob_name)

    with open(pfat_oob_path, 'wb') as out_oob:
        out_oob.write(pfat_oob_data)

    if is_ami_pfat(pfat_oob_data):
        parse_pfat_file(pfat_oob_data, get_extract_path(pfat_oob_path), padding)

    in_all_data: bytes = b''.join([block[1] for block in sorted(all_blocks_dict.items())])

    in_all_name: str = get_file_name(0, f'{extract_name}_ALL.bin')

    in_all_path: str = os.path.join(extract_path, in_all_name)

    with open(in_all_path, 'wb') as out_all:
        out_all.write(in_all_data + pfat_oob_data)

    return 0


PFAT_AMI_HDR_LEN: int = ctypes.sizeof(AmiBiosGuardHeader)
PFAT_BLK_HDR_LEN: int = ctypes.sizeof(IntelBiosGuardHeader)
PFAT_BLK_SIG_LEN: int = ctypes.sizeof(IntelBiosGuardSignatureHeader)

if __name__ == '__main__':
    BIOSUtility(title=TITLE, check=is_ami_pfat, main=parse_pfat_file).run_utility()
