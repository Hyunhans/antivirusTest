"""Binary AndroidManifest.xml parser utilities."""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional
from xml.etree.ElementTree import Element, tostring

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class BufferReader:
    """Helper to read primitive values from a bytes buffer."""

    def __init__(self, data: bytes) -> None:
        self._data = data
        self._offset = 0

    def tell(self) -> int:
        return self._offset

    def seek(self, offset: int) -> None:
        self._offset = offset

    def skip(self, count: int) -> None:
        self._offset += count

    def read(self, size: int) -> bytes:
        chunk = self._data[self._offset : self._offset + size]
        self._offset += size
        return bytes(chunk)

    def read_u8(self) -> int:
        value = self._data[self._offset]
        self._offset += 1
        return value

    def read_u16(self) -> int:
        (value,) = struct.unpack_from("<H", self._data, self._offset)
        self._offset += 2
        return value

    def read_u32(self) -> int:
        (value,) = struct.unpack_from("<I", self._data, self._offset)
        self._offset += 4
        return value


def read_uleb128(data: bytes, offset: int) -> tuple[int, int]:
    """Read a ULEB128 encoded integer."""

    result = 0
    shift = 0
    while True:
        byte = data[offset]
        offset += 1
        result |= (byte & 0x7F) << shift
        if byte & 0x80 == 0:
            break
        shift += 7
    return result, offset


def read_utf16(data: bytes, offset: int) -> tuple[str, int]:
    length, offset = read_length16(data, offset)
    byte_len = length * 2
    raw = data[offset : offset + byte_len]
    offset += byte_len
    string = raw.decode("utf-16le", errors="replace")
    offset += 2  # null terminator
    return string, offset


def read_utf8(data: bytes, offset: int) -> tuple[str, int]:
    # UTF-8 strings use two lengths: number of UTF-16 code units, then bytes
    _, offset = read_length8(data, offset)
    byte_len, offset = read_length8(data, offset)
    raw = data[offset : offset + byte_len]
    offset += byte_len
    string = raw.decode("utf-8", errors="replace")
    offset += 1  # null terminator
    return string, offset


def read_length16(data: bytes, offset: int) -> tuple[int, int]:
    (first,) = struct.unpack_from("<H", data, offset)
    offset += 2
    if first & 0x8000:
        (second,) = struct.unpack_from("<H", data, offset)
        offset += 2
        length = ((first & 0x7FFF) << 16) | second
    else:
        length = first
    return length, offset


def read_length8(data: bytes, offset: int) -> tuple[int, int]:
    first = data[offset]
    offset += 1
    if first & 0x80:
        second = data[offset]
        offset += 1
        length = ((first & 0x7F) << 8) | second
    else:
        length = first
    return length, offset


class BinaryXMLParser:
    """Parse Android's binary XML format into an ElementTree."""

    RES_XML_TYPE = 0x0003
    RES_STRING_POOL_TYPE = 0x0001
    RES_XML_RESOURCE_MAP_TYPE = 0x0180
    RES_XML_START_NAMESPACE_TYPE = 0x0100
    RES_XML_END_NAMESPACE_TYPE = 0x0101
    RES_XML_START_ELEMENT_TYPE = 0x0102
    RES_XML_END_ELEMENT_TYPE = 0x0103
    RES_XML_CDATA_TYPE = 0x0104

    def __init__(self, data: bytes) -> None:
        self.reader = BufferReader(data)
        self.strings: List[str] = []
        self.resource_ids: List[int] = []
        self.namespaces: List[tuple[Optional[str], Optional[str]]] = []

    def parse(self) -> Element:
        header_type = self.reader.read_u16()
        if header_type != self.RES_XML_TYPE:
            raise ValueError("Not a binary XML file")
        header_size = self.reader.read_u16()
        _ = self.reader.read_u32()  # file size
        # Skip remaining header bytes if any
        if header_size > 8:
            self.reader.skip(header_size - 8)

        root: Optional[Element] = None
        stack: List[Element] = []

        while self.reader.tell() < len(self.reader._data):
            chunk_start = self.reader.tell()
            chunk_type = self.reader.read_u16()
            header_size = self.reader.read_u16()
            chunk_size = self.reader.read_u32()
            data_start = chunk_start + header_size
            data_end = chunk_start + chunk_size

            if chunk_type == self.RES_STRING_POOL_TYPE:
                self._parse_string_pool(chunk_start, header_size, chunk_size)
            elif chunk_type == self.RES_XML_RESOURCE_MAP_TYPE:
                self._parse_resource_map(chunk_start, chunk_size)
            elif chunk_type == self.RES_XML_START_NAMESPACE_TYPE:
                self._parse_start_namespace()
            elif chunk_type == self.RES_XML_END_NAMESPACE_TYPE:
                self._parse_end_namespace()
            elif chunk_type == self.RES_XML_START_ELEMENT_TYPE:
                element = self._parse_start_element()
                if root is None:
                    root = element
                if stack:
                    stack[-1].append(element)
                stack.append(element)
            elif chunk_type == self.RES_XML_END_ELEMENT_TYPE:
                if stack:
                    stack.pop()
            elif chunk_type == self.RES_XML_CDATA_TYPE:
                self._parse_cdata(stack)
            else:
                # Unknown chunk type; skip the payload
                pass

            self.reader.seek(data_end)

        if root is None:
            raise ValueError("Failed to parse binary XML")
        return root

    def _parse_string_pool(self, chunk_start: int, header_size: int, chunk_size: int) -> None:
        reader = self.reader
        reader.seek(chunk_start + 8)
        string_count = reader.read_u32()
        style_count = reader.read_u32()
        flags = reader.read_u32()
        strings_start = reader.read_u32()
        styles_start = reader.read_u32()
        is_utf8 = (flags & 0x00000100) != 0

        offsets = [reader.read_u32() for _ in range(string_count)]
        strings_base = chunk_start + strings_start
        data = reader._data

        self.strings = []
        for offset in offsets:
            absolute = strings_base + offset
            if is_utf8:
                value, _ = read_utf8(data, absolute)
            else:
                value, _ = read_utf16(data, absolute)
            self.strings.append(value)

    def _parse_resource_map(self, chunk_start: int, chunk_size: int) -> None:
        reader = self.reader
        reader.seek(chunk_start + 8)
        count = (chunk_size - 8) // 4
        self.resource_ids = [reader.read_u32() for _ in range(count)]

    def _parse_start_namespace(self) -> None:
        reader = self.reader
        _line = reader.read_u32()
        _comment = reader.read_u32()
        prefix_idx = reader.read_u32()
        uri_idx = reader.read_u32()
        prefix = self._get_string(prefix_idx)
        uri = self._get_string(uri_idx)
        self.namespaces.append((prefix, uri))

    def _parse_end_namespace(self) -> None:
        reader = self.reader
        _line = reader.read_u32()
        _comment = reader.read_u32()
        reader.read_u32()
        reader.read_u32()
        if self.namespaces:
            self.namespaces.pop()

    def _parse_start_element(self) -> Element:
        reader = self.reader
        _line = reader.read_u32()
        _comment = reader.read_u32()
        ns_idx = reader.read_u32()
        name_idx = reader.read_u32()
        reader.read_u16()  # attributeStart
        attr_size = reader.read_u16()
        attr_count = reader.read_u16()
        reader.read_u16()  # idIndex
        reader.read_u16()  # classIndex
        reader.read_u16()  # styleIndex

        tag_name = self._qualified_name(ns_idx, name_idx)
        element = Element(tag_name)

        for _ in range(attr_count):
            attr_ns = reader.read_u32()
            attr_name = reader.read_u32()
            attr_raw_value = reader.read_u32()
            attr_size = reader.read_u16()
            reader.read_u8()  # res0
            data_type = reader.read_u8()
            data = reader.read_u32()
            value = self._get_attribute_value(attr_raw_value, data_type, data)
            attr_qname = self._qualified_name(attr_ns, attr_name)
            element.attrib[attr_qname] = value
        return element

    def _parse_cdata(self, stack: List[Element]) -> None:
        reader = self.reader
        _line = reader.read_u32()
        _comment = reader.read_u32()
        data_idx = reader.read_u32()
        reader.read_u16()
        reader.read_u8()
        data_type = reader.read_u8()
        data = reader.read_u32()
        value = self._get_attribute_value(data_idx, data_type, data)
        if stack:
            current = stack[-1]
            current.text = (current.text or "") + value

    def _qualified_name(self, ns_idx: int, name_idx: int) -> str:
        name = self._get_string(name_idx)
        if name is None:
            name = ""
        if ns_idx == 0xFFFFFFFF:
            return name
        namespace = self._get_string(ns_idx)
        if namespace is None:
            return name
        return f"{{{namespace}}}{name}"

    def _get_string(self, index: int) -> Optional[str]:
        if index == 0xFFFFFFFF:
            return None
        if 0 <= index < len(self.strings):
            return self.strings[index]
        return None

    def _get_attribute_value(self, raw_idx: int, data_type: int, data: int) -> str:
        raw = self._get_string(raw_idx)
        if raw is not None:
            return raw
        if data_type == 0x10:  # string
            return self._get_string(data) or ""
        if data_type == 0x12:  # boolean
            return "true" if data != 0 else "false"
        if data_type in {0x01, 0x02, 0x03, 0x04}:  # integers
            return str(data)
        if data_type == 0x1C:  # fraction
            return str(data / 0x1000000)
        if data_type == 0x1D:  # dimension
            return str(data)
        return str(data)


@dataclass
class IntentFilter:
    component: str
    actions: List[str]
    categories: List[str]
    data_schemes: List[str]


@dataclass
class ManifestData:
    package_name: Optional[str]
    version_code: Optional[str]
    version_name: Optional[str]
    permissions: List[str]
    components: Dict[str, List[str]]
    intent_filters: List[IntentFilter]


class ManifestParser:
    """High level helper for extracting manifest metadata."""

    def __init__(self, data: bytes) -> None:
        self._root = BinaryXMLParser(data).parse()

    @property
    def root(self) -> Element:
        return self._root

    def to_xml(self) -> str:
        return tostring(self._root, encoding="unicode")

    def extract(self) -> ManifestData:
        package_name = self._root.attrib.get("package")
        version_code = self._root.attrib.get(f"{{{ANDROID_NS}}}versionCode")
        version_name = self._root.attrib.get(f"{{{ANDROID_NS}}}versionName")

        permissions: List[str] = []
        for child in self._root.findall("uses-permission"):
            name = child.attrib.get(f"{{{ANDROID_NS}}}name")
            if name:
                permissions.append(name)

        components: Dict[str, List[str]] = {"activity": [], "service": [], "receiver": [], "provider": []}
        intent_filters: List[IntentFilter] = []

        application = self._root.find("application")
        if application is not None:
            for component_tag, key in (
                ("activity", "activity"),
                ("activity-alias", "activity"),
                ("service", "service"),
                ("receiver", "receiver"),
                ("provider", "provider"),
            ):
                for comp in application.findall(component_tag):
                    name = comp.attrib.get(f"{{{ANDROID_NS}}}name")
                    if not name:
                        continue
                    components.setdefault(key, []).append(name)
                    filters = self._parse_intent_filters(name, comp)
                    intent_filters.extend(filters)

        return ManifestData(
            package_name=package_name,
            version_code=version_code,
            version_name=version_name,
            permissions=permissions,
            components=components,
            intent_filters=intent_filters,
        )

    def _parse_intent_filters(self, component_name: str, element: Element) -> List[IntentFilter]:
        filters: List[IntentFilter] = []
        for intent in element.findall("intent-filter"):
            actions = [
                node.attrib.get(f"{{{ANDROID_NS}}}name")
                for node in intent.findall("action")
                if node.attrib.get(f"{{{ANDROID_NS}}}name")
            ]
            categories = [
                node.attrib.get(f"{{{ANDROID_NS}}}name")
                for node in intent.findall("category")
                if node.attrib.get(f"{{{ANDROID_NS}}}name")
            ]
            data_schemes = [
                node.attrib.get(f"{{{ANDROID_NS}}}scheme")
                for node in intent.findall("data")
                if node.attrib.get(f"{{{ANDROID_NS}}}scheme")
            ]
            filters.append(
                IntentFilter(
                    component=component_name,
                    actions=actions,
                    categories=categories,
                    data_schemes=data_schemes,
                )
            )
        return filters


def decode_manifest(data: bytes) -> tuple[str, ManifestData]:
    parser = ManifestParser(data)
    return parser.to_xml(), parser.extract()
