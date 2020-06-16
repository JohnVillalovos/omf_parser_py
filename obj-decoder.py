#!/usr/bin/python3 -ttu
# vim: ai ts=4 sts=4 et sw=4

# Copyright (c) 2019 John L. Villalovos
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Documentation on the Relocatable Object Module Format (OMF) is in the
# document "Tool Interface Standard (TIS) Portable Formats Specification
# Version 1.1" located at:
# https://refspecs.linuxfoundation.org/elf/TIS1.1.pdf
# The later version 1.2 removed documentation on OMF.

import copy
import os
import pprint
import sys
from typing import Any, Callable, Dict, List, Optional, Tuple


def main():
    with open("novnet.obj", "rb") as in_file:
        data = in_file.read()

    # pprint.pprint(parse_object_module(data))
    parse_object_module(data)


def extract_records(object_module_data: bytes) -> List[bytes]:
    """Extract each record from the data from an object file"""
    records = []
    data = copy.copy(object_module_data)
    while data:
        # Record length is stored in offset 1 & 2 of the record as a 16 bit
        # little-endian integer
        record_length = int.from_bytes(data[1:2], byteorder="little", signed=False)
        record = data[: record_length + 3]
        records.append(record)
        data = data[3 + record_length :]
    return records


def parse_object_module(object_module_data: bytes):
    raw_records = extract_records(object_module_data)
    records = []

    for raw_record in raw_records:
        record = create_record(record_data=raw_record)
        print(record)
        print()

        records.append(record)

    return records


def get_name(data: bytes):
    name_length = data[0]
    name = data[1 : name_length + 1]
    return os.fsdecode(name)


def get_multiple_names(data: bytes):
    names = []
    while len(data) > 1:
        name = get_name(data)
        names.append(name)
        data = data[1 + len(name) :]
    assert len(data) == 1
    return names


class Record:
    def __init__(self, *, record_data: bytes):
        self.record_data = record_data

        self.record_type = record_data[0]
        self.record_type_desc = "Unknown"
        if self.record_type in RECORD_TYPES:
            self.record_type_desc = RECORD_TYPES[self.record_type].description
        self.record_length = int.from_bytes(
            record_data[1:2], byteorder="little", signed=False
        )
        self._validate_record()
        self.checksum: int = self.record_data[-1]
        self._payload = self.get_record_payload()

    def get_record_payload(self):
        # Return the contents of the recrd data without the record type or
        # record length
        return copy.copy(self.record_data[3:])

    def _validate_record(self):
        if len(self.record_data) != 3 + self.record_length:
            raise ValueError(
                "ERROR: Record length incorrect. Expected {} is {}".format(
                    3 + self.record_length, len(self.record_data)
                )
            )
        # Check the checksum
        chk_sum = 0
        for character in self.record_data:
            chk_sum += character
        if chk_sum % 256 != 0:
            print("ERROR: Checksum failure")
            print(data)
            print("chk_sum:", chk_sum)
            print("chk_sum:", chk_sum % 256)
            sys.exit()

    def _get_name(self, offset: int) -> str:
        # This should only be called if sure have a name
        name_length = self._payload[offset]
        name = self._payload[offset + 1 : name_length + offset + 1]
        return os.fsdecode(name)

    def __str__(self, *, extra: str = ""):
        out_string = f"Record: <record_type: 0x{self.record_type:X},"
        out_string += " record_type_desc: {!r},".format(self.record_type_desc)
        out_string += extra
        out_string += " data: {!r},".format(self._payload)

        out_string += ">"
        return out_string

    def is_theader(self):
        return self.record_type == THEADR

    def is_lnames(self):
        return self.record_type == LNAMES

    def get_index_value(self, offset) -> Tuple[int, int]:
        index_1 = self._payload[offset]
        if index_1 & 0x80:
            index = (index_1 & 0x74) * 0x100 + self._payload[offset + 1]
            size = 2
        else:
            index = index_1
            size = 1
        return (index, size)


class THeaderRecord(Record):
    def __init__(self, record_data: bytes):
        super().__init__(record_data=record_data)
        assert self.record_type == THEADR
        self.name = self._get_name(offset=0)

    def __str__(self):
        out_str = " name: {!r},".format(self.name)
        return super().__str__(extra=out_str)


class LNamesRecord(Record):
    def __init__(self, record_data: bytes):
        super().__init__(record_data=record_data)
        assert self.record_type == LNAMES
        self.names = get_multiple_names(data=self._payload)

    def __str__(self):
        out_str = " names: {!r},".format(self.names)
        return super().__str__(extra=out_str)


class SegdefRecord(Record):
    def __init__(self, record_data: bytes):
        super().__init__(record_data=record_data)
        assert self.record_type in (SEGDEF, SEGDEF_32)
        # 0x98 is 16 bit (2 bytes), 0x99 is 32 bit (4 byte). For the Segment
        # Length field
        self.bit_32: bool = (self.record_type == 0x99)
        self.__parse_segment_attributes()
        self.__parse_segment_length()
        self.__parse_indexes()

    def __parse_segment_attributes(self):
        attributes = self._payload[0]
        self.attributes = attributes
        self.have_attribute_frame = False
        self.attribute_frame_number = 0
        self.attribute_offset = 0

        self.alignment = attributes >> 5
        if self.alignment == 0:
            self.have_attribute_frame = True
            self.frame_number = int.from_bytes(
                self._payload[1:2], byteorder="little", signed=False
            )
            self.frame_offset: int = self._payload[3]

        self.alignment_desc = {
            0: "Absolute segment.",
            1: "Relocatable, byte aligned.",
            2: "Relocatable, word (2-byte, 16-bit) aligned.",
            3: "Relocatable, paragraph (16-byte) aligned.",
            4: "Relocatable, aligned on a page boundary.",
            5: "Relocatable, aligned on a double word (4-byte) boundary.",
            6: "Not supported",
            7: "Not supported",
        }[self.alignment]

        self.combination = (attributes >> 2) & 0x7
        self.combination_desc = {
            0: "Private. Do not combine with any other program segment.",
            1: "Reserved.",
            2: (
                "Public. Combine by appending at an offset that meets the alignment "
                "requirement."
            ),
            3: "Reserved.",
            4: (
                "Public. Combine by appending at an offset that meets the alignment "
                "requirement."
            ),
            5: "Stack. Combine as for C=2. This combine type forces byte alignment.",
            6: "Common. Combine by overlay using maximum size.",
            7: (
                "Public. Combine by appending at an offset that meets the alignment "
                "requirement."
            ),
        }[self.combination]

        self.big = (attributes >> 1) & 0x01
        self.bit_field = attributes & 0x01

    def __parse_segment_length(self):
        offset = 1
        if self.have_attribute_frame:
            offset += 3
        end_offset = offset + 1
        if self.bit_32:
            end_offset = offset + 3

        self.segment_length = int.from_bytes(
            self._payload[offset:end_offset], byteorder="little", signed=False
        )

    def __parse_indexes(self):
        offset = 3
        if self.have_attribute_frame:
            offset += 3
        if self.bit_32:
            offset += 2
        self.segment_name_index, add_offset = self.get_index_value(offset)

        offset += add_offset
        self.class_name_index, add_offset = self.get_index_value(offset)

        offset += add_offset
        self.overlay_name_index, add_offset = self.get_index_value(offset)

    def __str__(self):
        extra = " alignment: {}, alignment_desc: {!r},".format(
            self.alignment, self.alignment_desc
        )
        if self.have_attribute_frame:
            extra += "attribute_frame_number: {}, attribute_offset: {},".format(
                self.attribute_frame_number, self.attribute_offset
            )
        extra += " combination: {}, combination_desc: {!r},".format(
            self.combination, self.combination_desc
        )
        extra += " big: {},".format(1 if self.big else 0)
        extra += " bit_field: {},".format(1 if self.bit_field else 0)
        extra += " seg_name_idx: {},".format(self.segment_name_index)
        extra += " cls_name_idx: {},".format(self.class_name_index)
        extra += " ovr_name_idx: {},".format(self.overlay_name_index)

        return super().__str__(extra=extra)


class GrpdefRecord(Record):
    def __init__(self, record_data: bytes):
        super().__init__(record_data=record_data)
        assert self.record_type == GRPDEF
        self._parse_indexes()

    def _parse_indexes(self):
        offset = 0
        self.group_name_index, size = self.get_index_value(offset)
        offset += size
        self.group_components = []
        # compensate for the check_sum as last byte
        while offset < (len(self._payload) - 1):
            assert self._payload[offset] == 0xFF
            offset += 1
            index, size = self.get_index_value(offset)
            self.group_components.append(index)
            offset += size
        # Our offset should be pointing at the last byte
        assert offset == (len(self._payload) - 1)

    def __str__(self):
        extra = " grp_name_idx: {},".format(self.group_name_index)
        extra += " grp_components: {!r},".format(self.group_components)
        return super().__str__(extra=extra)


class ExtdefRecord(Record):
    def __init__(self, record_data: bytes):
        super().__init__(record_data=record_data)
        assert self.record_type == EXTDEF
        self._parse_names()

    def _parse_names(self):
        self.names = []
        self.indexes = []
        offset = 0
        while offset < (len(self._payload) - 1):
            name = self._get_name(offset=offset)
            self.names.append(name)
            # Increase offset by length of name plus the length byte
            offset += len(name) + 1
            index, size = self.get_index_value(offset=offset)
            self.indexes.append(index)
            offset += size
        # Our offset should be pointing at the last byte
        assert offset == (len(self._payload) - 1)

    def __str__(self):
        extra = " names: {!r},".format(self.names)
        extra += " indexes: {!r},".format(self.indexes)
        return super().__str__(extra=extra)


class PubdefRecord(Record):
    def __init__(self, record_data: bytes):
        super().__init__(record_data=record_data)
        assert self.record_type == PUBDEF
        self._parse_record()

    def _parse_record(self):
        offset = 0
        self.base_group_index, count = self.get_index_value(offset=offset)
        offset += count
        self.base_segment_index, count = self.get_index_value(offset=offset)
        offset += count

        self.base_frame = None
        if self.base_segment_index == 0:
            # Docs say this normally shouldn't occur
            self.base_frame = int.from_bytes(
                self._payload[offset : offset + 2], byteorder="little", signed=False
            )
            offset += 2

        self.names = []
        self.public_offsets = []
        self.type_indexes = []
        while offset < (len(self._payload) - 1):
            name = self._get_name(offset=offset)
            self.names.append(name)
            offset += len(name) + 1
            public_offset = int.from_bytes(
                self._payload[offset : offset + 2], byteorder="little", signed=False
            )
            self.public_offsets.append(public_offset)
            offset += 2
            type_index = self._payload[offset]
            self.type_indexes.append(type_index)
            offset += 1

        # Our offset should be pointing at the last byte
        assert offset == (len(self._payload) - 1)

    def __str__(self):
        extra = " base_grp_idx: {},".format(self.base_group_index)
        extra += " base_seg_idx: {},".format(self.base_segment_index)
        if self.base_frame != None:
            extra += " base_frame: {}".format(self.base_frame)
        extra += " names: {!r},".format(self.names)
        extra += " public_offsets: {!r},".format(self.public_offsets)
        extra += " type_indexes: {!r},".format(self.type_indexes)
        return super().__str__(extra=extra)


class LedataRecord(Record):
    def __init__(self, record_data: bytes):
        super().__init__(record_data=record_data)
        assert self.record_type == LEDATA
        self._parse_record()

    def _parse_record(self):
        offset = 0
        self.segment_index, count = self.get_index_value(offset=offset)
        offset += count
        self.enumerated_data_offset = int.from_bytes(
            self._payload[offset : offset + 2], byteorder="little", signed=False
        )
        offset += 2
        self.data_bytes = self._payload[offset:-1]
        offset += len(self.data_bytes)
        # Our offset should be pointing at the last byte
        assert offset == (len(self._payload) - 1)

    def __str__(self):
        extra = " segment_idx: {},".format(self.segment_index)
        extra += " enum_data_off: {},".format(self.enumerated_data_offset)
        data_bytes_hex = ""
        for char in self.data_bytes:
            data_bytes_hex += "0x{:02X} ".format(char)
        #        extra += " data_bytes: {!r},".format(self.data_bytes)
        extra += " data_bytes: {!r},".format(data_bytes_hex)
        return super().__str__(extra=extra)


class ComentRecord(Record):
    def __init__(self, record_data: bytes):
        super().__init__(record_data=record_data)
        print("payload:", self._payload)
        assert self.record_type == COMENT
        self.record_type_desc = "Comment Record"
        self._parse_record()

    def _parse_record(self):
        offset = 0
        self.comment_type = self._payload[offset]
        offset += 1
        self.comment_class = self._payload[offset]
        offset += 1
        self.comment_string = self._payload[offset:-1]
        offset += len(self.comment_string)

        # Our offset should be pointing at the last byte
        assert offset == (len(self._payload) - 1)

    def __str__(self):
        extra = " comment_type: 0x{:02X},".format(self.comment_type)
        extra += " comment_class: 0x{:02X},".format(self.comment_class)
        extra += " comment: {!r},".format(self.comment_string)
        return super().__str__(extra=extra)


def create_record(record_data: bytes) -> Record:
    base_record = Record(record_data=record_data)
    record_type = base_record.record_type

    if record_type == THEADR:
        return THeaderRecord(record_data)
    if record_type == LNAMES:
        return LNamesRecord(record_data)
    if record_type in (SEGDEF, SEGDEF_32):
        return SegdefRecord(record_data)
    if record_type == GRPDEF:
        return GrpdefRecord(record_data)
    if record_type == EXTDEF:
        return ExtdefRecord(record_data)
    # TODO(jlvillal): Add support for 32 bit PUBDEF
    if record_type == PUBDEF:
        return PubdefRecord(record_data)
    # TODO(jlvillal): Add support for 32 bit LEDATA
    if record_type == LEDATA:
        return LedataRecord(record_data)
    if record_type == COMENT:
        return ComentRecord(record_data)

    raise ValueError("Unknown type: 0x{:02X}".format(record_type))
    return base_record


##################################################################


class RecordLayout:
    def __init__(
        self,
        *,
        record_type: int,
        description: str,
        has_name: bool,
        parser: Optional[Callable] = None,
        multiple_names: bool = False,
    ):
        self.record_type = record_type
        self.description = description
        self.has_name = has_name
        self.multiple_names = multiple_names
        self.parser = parser

        if multiple_names and not has_name:
            raise ValueError(
                "Error: Sepcified 'multiple_names' but did not specify 'has_name'"
            )


# Constants
THEADR = 0x80
LHEADR = 0x82
RHEADR = 0x63
COMENT = 0x88
MODEND = 0x8A
EXTDEF = 0x8C
PUBDEF = 0x90
LNAMES = 0x96
SEGDEF = 0x98
GRPDEF = 0x9A
LEDATA = 0xA0
# 32 Bit version of SEGDEF
SEGDEF_32 = 0x99


RECORD_TYPES = {
    THEADR: RecordLayout(
        record_type=THEADR, description="T-Module Header Record", has_name=True,
    ),
    LNAMES: RecordLayout(
        record_type=LNAMES,
        description="List of Names Record",
        has_name=True,
        multiple_names=True,
    ),
    SEGDEF: RecordLayout(
        record_type=SEGDEF, description="Segment Definition Record", has_name=False,
    ),
    GRPDEF: RecordLayout(
        record_type=GRPDEF, description="Group Definition Record", has_name=False,
    ),
    PUBDEF: RecordLayout(
        record_type=PUBDEF,
        description="Public Names Definition Record",
        has_name=False,
    ),
    LEDATA: RecordLayout(
        record_type=LEDATA,
        description="Logical Enumerated Data Record",
        has_name=False,
    ),
    MODEND: RecordLayout(
        record_type=MODEND, description="Module End Record", has_name=False,
    ),
    EXTDEF: RecordLayout(
        record_type=EXTDEF,
        description="External Names Definition Record",
        has_name=False,
    ),
}

RECORD_TYPES_WITH_NAMES = {THEADR, LNAMES}


if "__main__" == __name__:
    sys.exit(main())
