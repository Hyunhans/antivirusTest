"""Minimalistic DEX parser for static feature extraction."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence


DEX_MAGIC = b"dex\n035\x00"


class DexParsingError(RuntimeError):
    """Raised when a DEX file cannot be parsed."""


@dataclass
class MethodDescriptor:
    index: int
    class_descriptor: str
    name: str
    proto: str

    @property
    def fqname(self) -> str:
        return f"{self.class_descriptor}->{self.name}{self.proto}"


@dataclass
class DexCode:
    opcodes: List[int]
    called_methods: List[int]


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    value = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
    return value, offset


class DexFile:
    """Parser for the Dalvik Executable (DEX) format."""

    def __init__(self, data: bytes) -> None:
        if not data.startswith(DEX_MAGIC):
            raise DexParsingError("Invalid DEX magic header")
        self.data = data
        self.header = self._parse_header()
        self.strings = self._parse_strings()
        self.type_ids = self._parse_type_ids()
        self.proto_ids = self._parse_proto_ids()
        self.method_ids = self._parse_method_ids()
        self.class_defs = self._parse_class_defs()
        self.method_map = self._build_method_map()

    def _parse_header(self) -> Dict[str, int]:
        header_fields = struct.unpack_from(
            "<8sI20sIIIIIIIIIIIIIIII",
            self.data,
            0,
        )
        (
            magic,
            checksum,
            signature,
            file_size,
            header_size,
            endian_tag,
            link_size,
            link_off,
            map_off,
            string_ids_size,
            string_ids_off,
            type_ids_size,
            type_ids_off,
            proto_ids_size,
            proto_ids_off,
            field_ids_size,
            field_ids_off,
            method_ids_size,
            method_ids_off,
            class_defs_size,
            class_defs_off,
            data_size,
            data_off,
        ) = header_fields
        return {
            "string_ids_size": string_ids_size,
            "string_ids_off": string_ids_off,
            "type_ids_size": type_ids_size,
            "type_ids_off": type_ids_off,
            "proto_ids_size": proto_ids_size,
            "proto_ids_off": proto_ids_off,
            "method_ids_size": method_ids_size,
            "method_ids_off": method_ids_off,
            "class_defs_size": class_defs_size,
            "class_defs_off": class_defs_off,
        }

    def _parse_strings(self) -> List[str]:
        size = self.header["string_ids_size"]
        offset = self.header["string_ids_off"]
        strings: List[str] = []
        for i in range(size):
            (string_off,) = struct.unpack_from("<I", self.data, offset + i * 4)
            value, _ = self._read_string_at(string_off)
            strings.append(value)
        return strings

    def _read_string_at(self, offset: int) -> tuple[str, int]:
        length, cursor = read_uleb128(self.data, offset)
        # The UTF-16 length is stored, but we only need actual bytes
        result_bytes = bytearray()
        while True:
            byte = self.data[cursor]
            cursor += 1
            if byte == 0:
                break
            result_bytes.append(byte)
        try:
            value = result_bytes.decode("utf-8")
        except UnicodeDecodeError:
            value = result_bytes.decode("utf-8", errors="replace")
        return value, cursor

    def _parse_type_ids(self) -> List[int]:
        size = self.header["type_ids_size"]
        offset = self.header["type_ids_off"]
        return list(struct.unpack_from(f"<{size}I", self.data, offset)) if size else []

    def _parse_proto_ids(self) -> List[tuple[int, int, int]]:
        size = self.header["proto_ids_size"]
        offset = self.header["proto_ids_off"]
        protos: List[tuple[int, int, int]] = []
        for i in range(size):
            shorty_idx, return_type_idx, parameters_off = struct.unpack_from("<III", self.data, offset + i * 12)
            protos.append((shorty_idx, return_type_idx, parameters_off))
        return protos

    def _parse_method_ids(self) -> List[tuple[int, int, int]]:
        size = self.header["method_ids_size"]
        offset = self.header["method_ids_off"]
        methods: List[tuple[int, int, int]] = []
        for i in range(size):
            class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", self.data, offset + i * 8)
            methods.append((class_idx, proto_idx, name_idx))
        return methods

    def _parse_class_defs(self) -> List[Dict[str, int]]:
        size = self.header["class_defs_size"]
        offset = self.header["class_defs_off"]
        class_defs: List[Dict[str, int]] = []
        for i in range(size):
            (
                class_idx,
                access_flags,
                superclass_idx,
                interfaces_off,
                source_file_idx,
                annotations_off,
                class_data_off,
                static_values_off,
            ) = struct.unpack_from("<IIIIIIII", self.data, offset + i * 32)
            class_defs.append(
                {
                    "class_idx": class_idx,
                    "class_data_off": class_data_off,
                }
            )
        return class_defs

    def get_string(self, index: int) -> str:
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return ""

    def get_type(self, index: int) -> str:
        if 0 <= index < len(self.type_ids):
            string_idx = self.type_ids[index]
            return self.get_string(string_idx)
        return ""

    def _get_proto(self, index: int) -> str:
        if not (0 <= index < len(self.proto_ids)):
            return "()V"
        shorty_idx, return_type_idx, parameters_off = self.proto_ids[index]
        return_type = self.get_type(return_type_idx)
        params = self._read_type_list(parameters_off)
        return f"({''.join(params)}){return_type}"

    def _read_type_list(self, offset: int) -> List[str]:
        if offset == 0:
            return []
        size = struct.unpack_from("<I", self.data, offset)[0]
        types = []
        for i in range(size):
            (type_idx,) = struct.unpack_from("<H", self.data, offset + 4 + i * 2)
            types.append(self.get_type(type_idx))
        return types

    def _build_method_map(self) -> Dict[int, MethodDescriptor]:
        method_map: Dict[int, MethodDescriptor] = {}
        for index, (class_idx, proto_idx, name_idx) in enumerate(self.method_ids):
            class_desc = self.get_type(class_idx)
            name = self.get_string(name_idx)
            proto = self._get_proto(proto_idx)
            method_map[index] = MethodDescriptor(index=index, class_descriptor=class_desc, name=name, proto=proto)
        return method_map

    # Opcode size approximations in code units (16-bit words)
    OPCODE_UNIT_SIZES: Dict[int, int] = {opcode: 1 for opcode in range(0x100)}

    _LENGTH_2 = {
        0x02,
        0x05,
        0x08,
        0x13,
        0x15,
        0x16,
        0x19,
        0x1A,
        0x1C,
        0x1F,
        0x20,
        0x22,
        0x23,
        0x29,
        0x2D,
        0x2E,
        0x2F,
        0x30,
        0x31,
        0x32,
        0x33,
        0x34,
        0x35,
        0x36,
        0x37,
        0x38,
        0x39,
        0x3A,
        0x3B,
        0x3C,
        0x3D,
        *range(0x44, 0x52),
        *range(0x52, 0x60),
        *range(0x60, 0x6E),
        *range(0x90, 0xB0),
        *range(0xD0, 0xE0),
    }

    _LENGTH_3 = {
        0x03,
        0x06,
        0x09,
        0x14,
        0x17,
        0x1B,
        0x24,
        0x25,
        0x26,
        0x2A,
        0x2B,
        0x2C,
        *range(0x6E, 0x79),
    }

    _LENGTH_5 = {0x18, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE}

    _LENGTH_4 = set()

    for opcode in _LENGTH_2:
        OPCODE_UNIT_SIZES[opcode] = 2
    for opcode in _LENGTH_3:
        OPCODE_UNIT_SIZES[opcode] = 3
    for opcode in _LENGTH_4:
        OPCODE_UNIT_SIZES[opcode] = 4
    for opcode in _LENGTH_5:
        OPCODE_UNIT_SIZES[opcode] = 5

    def iter_methods(self) -> Iterable[tuple[MethodDescriptor, Optional[DexCode]]]:
        for class_def in self.class_defs:
            class_idx = class_def["class_idx"]
            class_data_off = class_def["class_data_off"]
            if class_data_off == 0:
                continue
            yield from self._parse_class_data(class_idx, class_data_off)

    def _parse_class_data(self, class_idx: int, offset: int) -> Iterable[tuple[MethodDescriptor, Optional[DexCode]]]:
        cursor = offset
        static_fields_size, cursor = read_uleb128(self.data, cursor)
        instance_fields_size, cursor = read_uleb128(self.data, cursor)
        direct_methods_size, cursor = read_uleb128(self.data, cursor)
        virtual_methods_size, cursor = read_uleb128(self.data, cursor)

        # Skip fields
        field_idx = 0
        for _ in range(static_fields_size + instance_fields_size):
            field_idx_diff, cursor = read_uleb128(self.data, cursor)
            access_flags, cursor = read_uleb128(self.data, cursor)
            field_idx += field_idx_diff

        method_idx = 0
        total_methods = direct_methods_size + virtual_methods_size
        for _ in range(total_methods):
            method_idx_diff, cursor = read_uleb128(self.data, cursor)
            access_flags, cursor = read_uleb128(self.data, cursor)
            code_off, cursor = read_uleb128(self.data, cursor)
            method_idx += method_idx_diff
            descriptor = self.method_map.get(method_idx)
            if descriptor is None:
                continue
            code = self._parse_code_item(code_off) if code_off else None
            yield descriptor, code

    def _parse_code_item(self, offset: int) -> DexCode:
        (
            registers_size,
            ins_size,
            outs_size,
            tries_size,
            debug_info_off,
            insns_size,
        ) = struct.unpack_from("<HHHHII", self.data, offset)
        instructions_offset = offset + 16
        insns = list(struct.unpack_from(f"<{insns_size}H", self.data, instructions_offset))
        opcodes: List[int] = []
        calls: List[int] = []
        i = 0
        while i < len(insns):
            word = insns[i]
            opcode = word & 0xFF
            opcodes.append(opcode)
            size = self.OPCODE_UNIT_SIZES.get(opcode, 1)
            if size <= 0:
                size = 1
            if opcode in {0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73}:
                if i + 2 < len(insns):
                    calls.append(insns[i + 2])
            elif opcode in {0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B}:
                if i + 1 < len(insns):
                    calls.append(insns[i + 1])
            elif opcode in {0xFA, 0xFB, 0xFC, 0xFD, 0xFE}:
                if i + 2 < len(insns):
                    calls.append(insns[i + 2])
            i += size
            if size == 0:
                break
        return DexCode(opcodes=opcodes, called_methods=calls)

    def collect_strings(self) -> List[str]:
        return list(self.strings)

    def resolve_calls(self, indices: Sequence[int]) -> List[str]:
        resolved = []
        for index in indices:
            descriptor = self.method_map.get(index)
            if descriptor:
                resolved.append(descriptor.fqname)
        return resolved
