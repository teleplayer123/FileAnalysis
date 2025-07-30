import ctypes as ct
import struct


MAGIC_NUM_MICRO = 0xA1B2C3D4 
MAGIC_NUM_NANO = 0xA1B23C4D
MAGIC_NUM_MOD = 0xA1B2CD34

class PCAP_HDR(ct.Structure):

    _fields_ = [
        ("magic_number", ct.c_uint32),
        ("version_major", ct.c_uint16),
        ("version_minor", ct.c_uint16),
        ("thiszone", ct.c_uint32),
        ("sigfigs", ct.c_uint32),
        ("snaplen", ct.c_uint32),
        ("network", ct.c_uint32)
    ]

class PCAP_REC(ct.Structure):

    _fields_ = [
        ("ts_sec", ct.c_uint32),
        ("ts_usec", ct.c_uint32),
        ("incl_len", ct.c_uint32), # size of data the imediately follows pcap record
        ("orig_len", ct.c_uint32)
    ]

class PCAP_REC_MOD(ct.Structure):

    _fields_ = [
        ("pcaprec_hdr", PCAP_REC),
        ("ifindex", ct.c_uint32),
        ("protocol", ct.c_uint16),
        ("pkt_type", ct.c_uint8),
        ("pad", ct.c_uint8)
    ]

class PCAPHeader:
    
    HDR_STRUCT = struct.Struct("LHHLLLL")
    HDR_SIZE = HDR_STRUCT.size

    def __init__(self, raw_data, create=False):
        if create == False:
            self.data = self.HDR_STRUCT.unpack(raw_data)
        else:
            self.data = self.HDR_STRUCT.pack(raw_data)
        self.phdr = self.unpack_hdr()

    def unpack_hdr(self):
        return PCAP_HDR(*self.data[:self.HDR_SIZE])
    
    def __str__(self):
        return f"PCAPHeader(magic_number: {hex(self.phdr.magic_number)}, version_major: {self.phdr.version_major}, version_minor: {self.phdr.version_minor}, thiszone: {self.phdr.thiszone}, sigfigs: {self.phdr.sigfigs}, snaplen: {self.phdr.snaplen}, network: {self.phdr.network})"
        


class PacketRecord:

    PKT_STRUCT = struct.Struct("LLLL")
    PKT_SIZE = PKT_STRUCT.size

    def __init__(self, raw_data, create=False):
        if create == False:
            self.data = self.PKT_STRUCT.unpack(raw_data)
        else:
            self.data = self.PKT_STRUCT.pack(raw_data)
        self.prec = self.unpack_hdr()
        self.data_size = self.prec.incl_len
        self.pkt_data = self.unpack_data(self.data_size)
    
    def unpack_hdr(self):
        return PCAP_REC(*self.data[:self.PKT_SIZE])
    
    def unpack_data(self, data_size):
        return

    def __str__(self):
        return f"PacketRecord(ts_sec: {self.prec.ts_sec}, ts_usec: {self.prec.ts_usec})"


class PCAP:
    def __init__(self, fname):
        self.fname = fname
        self.header = None
        self.pcap = {}
        self.records = {}

    def read(self):
        with open(self.fname, "rb") as f:
            raw_header = f.read(PCAPHeader.HDR_SIZE)
            if len(raw_header) < PCAPHeader.HDR_SIZE:
                raise EOFError("File too short for PCAP header")
            self.header = PCAPHeader(raw_header)
            idx = self.header.HDR_SIZE
            while True:
                f.seek(idx)
                raw_record = f.read(PacketRecord.PKT_SIZE)
                if len(raw_record) < PacketRecord.PKT_SIZE:
                    if len(raw_record) == 0:
                        break
                    break
                record = PacketRecord(raw_record)
                self.records[idx] = record
                idx += PacketRecord.PKT_SIZE
        self.pcap = {
            "header": str(self.header),
            "records": self.records
        }
        return self.pcap