import ctypes as ct
import re
import struct
from typing import Tuple, Any

from utils.file_sigs import MagicValues


class PDFDisasm:
    """
    Class to handle post script data parsing 

    - Boolean: true, false
    - Strings contain 8-bit chars between brackets:
        ASCII: (...)
        Hex: <...>
    - Names followed by forward slash /
    - Arrays: [...]
    - Dictionaries: <<...>>
    - Streams: optionally compressed binary data preceeded by dictionary between 'stream' and 'endstream' keywords
    - Comments: preceeded by '%'
    """
    MAGIC_VAL = MagicValues.PDF
    EOF_VAL = "%%EOF"

    BOOL_REGX = re.compile(br"\b*(true|false)\b*")
    STR_ASCII_REGX = re.compile(br"\([\w\d\s]+\)")
    STR_HEX_REGX = re.compile(br"<[0-9A-Fa-f]+>")
    NAME_REGX = re.compile(br"/[a-zA-Z0-9#]+")
    ARRAY_REGX = re.compile(br"\[[^\]]+\]")
    DICT_REGX = re.compile(br"<<[^\>]+>>")
    STREAM_REGX = re.compile(br"stream")
    ENDSTREAM_REGX = re.compile(br"endstream")
    COMMENT_REGX = re.compile(br"%[^\n]*")

    def __init__(self, filename):
        with open(filename, "rb") as fh:
            self.raw_data = fh.read()
        self.objects = {}
        self.keywords = {}
        self.properties = {}

    def extract_obj(self, line: bytes):
        """Takes chunk of binary data and extracts ps object"""
        obj_type, obj_bytes = self._match_obj(line) 

    def _match_obj(self, line: bytes) -> Tuple[str, bytes]:
        """Determines object type and returns tuple of object type and object bytes"""
        
