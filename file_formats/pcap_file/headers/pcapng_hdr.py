import struct
from dataclasses import dataclass
from typing import Optional, TypeVar, List


_T = TypeVar("_T")

@dataclass
class TLV:
    type: int            # uint16
    length: int          # uint16
    value: _T

_TLV = TypeVar("_TLV", TLV)

@dataclass
class SectionHeaderBlock:
    block_type: int             # uint32
    block_total_length: int     # uint32
    byte_order_magic: int       # uint32
    major_version: int = 1      # uint16
    minor_version: int = 0      # uint16
    section_length: int         # int64
    options: Optional[List[TLV]] = None  # List of TLV objects
    block_total_length_2: int   # uint32


class PCAPNG:

    def __init__(self, data: bytes):
        self.data = data
        self.offset = 0
        self.blocks = []
        self.parse_blocks()

    def parse_blocks(self):
        pass