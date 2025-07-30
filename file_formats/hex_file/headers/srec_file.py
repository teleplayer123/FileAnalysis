import struct
import ctypes as ct
from typing import NamedTuple


"""
-----------------------------------------------------
| S | Type | Byte Count | Address | Data | Checksum |
-----------------------------------------------------
An SREC format file consists of a series of ASCII text records. The records have the following structure from
left to right:

1. Record start - each record begins with an uppercase letter "S" character (ASCII
0x53) which stands for "Start-of-Record".

2. Record type - single numeric digit "0" to "9", defining the type of record.

3. Byte count - two hex digits, indicating the number of bytes (hex digit pairs) that
follow in the rest of the record (address + data + checksum). This field has a
minimum value of 3 for 16-bit address field plus 1 checksum byte, and a maximum
value of 255 (0xFF).

4. Address - four / six / eight hex digits as determined by the record type. The address
bytes are arranged in big-endian format.

5. Data - a sequence of 2n hex digits, for n bytes of the data. For S1/S2/S3 records, a
maximum of 32 bytes per record is typical since it will fit on an 80 character wide
terminal screen, though 16 bytes would be easier to visually decode each byte at a
specific address.

6. Checksum - two hex digits, the least significant byte of ones' complement of the
sum of the values represented by the two hex digit pairs for the byte count,
address and data fields. See example section for a detailed checksum example.
"""

class RecordAddr(ct.Structure):

    S0_COMMON = "\x48\x44\x52"

    _fields_ = [
        ("S0", ct.c_ubyte * 2), #header, address=0000
        ("S1", ct.c_ubyte * 2), #data starts at 16 bit address, len of data is 'Byte Count' field minus 3 (2 bytes for address, 1 byte for checksum)
        ("S2", ct.c_ubyte * 3), #data starts at 24 bit address, data len is 'Byte Count' field minus 4 (3 bytes for address 1 byte for checksum)
        ("S4", ct.c_ubyte * 4),
    ]

hex_t = str

class SREC(NamedTuple):
    rec_start: str  #start record literal 's'
    rec_type: int  #record type int 0-9
    byte_count: hex_t  #one hex byte value 0x03 - 0xff indicates number of bytes in rest of record
    addr: hex_t  #hex addr size specified hy rec_type in big endian
    data: hex_t  #sequence of bytes in hex; data size = byte_count - len(addr) - 1
    checksum: hex_t  #one byte in hex, the least significant byte of ones' complement of the
                     #sum of the values represented by the two hex digit pairs for the byte count, address and data fields.

class SREC_File:

    def __init__(self, filename: str):
        self._data = []
        with open(filename, "r") as fh:
            for line in fh:
                self._data.append(line.strip())
        self._records = []

    def parse(self) -> list[SREC]:
        """
        Parse the SREC file and store the records.
        """
        for line in self._data:
            record = self._parse_record(line.strip())
            if record:
                self._records.append(record)
        return self._records
    
    def _parse_record(self, line: str) -> SREC:
        """
        Parse a single SREC record line.

        :param line: A single line from the SREC file
        :return: Parsed record as a dictionary or None if invalid
        """
        rec_start = line[0]
        if rec_start != 'S':
            return None
        rec_type = int(line[1])
        byte_count = int(line[2:4], 16)
        addr_length = self._get_address_length(rec_type)
        addr = line[4:4 + addr_length]
        data_start = 4 + addr_length
        data_end = data_start + (byte_count - (addr_length // 2) - 1) * 2
        data = line[data_start:data_end]
        checksum = line[data_end:]

        return SREC(rec_start, rec_type, byte_count, addr, data, checksum)
        
    def _get_address_length(self, rec_type: int) -> int:
        """
        Get the address length based on the record type.

        :param rec_type: SREC record type
        :return: Address length in characters
        """
        if rec_type in [1, 9]:
            return 4  # 2 bytes
        elif rec_type in [2, 8]:    
            return 6
        elif rec_type in [3, 7]:
            return 8
        else:
            return 0
