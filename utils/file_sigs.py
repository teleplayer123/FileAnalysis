from typing import NamedTuple


class MagicValues:
    """
    Magic file signatures
    Tuple format: (hex_value, offset)
    Assumes little endian
    """
    AVI = ("\x52\x49\x46\x46\x00\x00\x00\x00\x41\x56\x49\x20", 0) # audio video interleave video format
    BGP = ("\x42\x50\x47\xFB", 0) # better portable graphics format
    BMP = ("\x42\x4D", 0) # bitmap format mostly used in windows
    BZ2 = ("\x42\x5A\x68", 0) # bzip2 compressiom
    CHM = ("\x49\x54\x53\x46\x03\x00\x00\x00\x60\x00\x00\x00", 0) # MS Windows HtmlHelp 
    EXR = ("\x76\x2F\x31\x01", 0) # openEXR image
    GIF1 = ("\x47\x49\x46\x38\x37\x61", 0)
    GIF2 = ("\x47\x49\x46\x38\x39\x61", 0)
    GZIP = ("\x1F\x8B", 0) # gzipped tar archive
    H5 = ("\x89\x48\x44\x46\x0D\x0A\x1A\x0A", [0, 512, 1024, 2048]) # hierarchical data format version 5 (HDF5)
    ICNS = ("\x69\x63\x6e\x73", 0) # apple icon image format
    ICO = ("\x00\x00\x01\x00", 0) # computer icon encoded in ICO file format
    ISO = ("\x43\x44\x30\x30\x31", [0x8001, 0x8801, 0x9001]) # ISO9660 CD/DVD image file
    JPEG = ("\xFF\xD8\xFF\xE0", 0) # jpeg raw or in JFIF or Exif format
    JPG = ("\xFF\xD8\xFF\xDB", 0) # jpeg raw or in JFIF or Exif format
    LZ4 = ("\x04\x22\x4D\x18", 0) # lz4 compressed file
    MP3 = ("\x49\x44\x33", 0) # mp3 file format with ID3v2 container
    MP4 = ("\x66\x74\x79\x70\x4D\x53\x4E\x56", 4) # mpeg-4 video file
    MP4_ISO = ("\x66\x74\x79\x70\x69\x73\x6F\x6D", 4) # ISO base media file format (mp4)
    OGG = ("\x4F\x67\x67\x53", 0) # ogg open source media container format
    PDF = ("\x25\x50\x44\x46\x2D", 0)
    PCAP = ("\xD4\xC3\xB2\xA1", 0)
    PCAPNG = ("\x0A\x0D\x0D\x0A", 0) # palindrome header for pcapng files endian independent
    PNG = ("\x89\x50\x4E\x47\x0D\x0A\x1A\x0A", 0) # portable network graphics format
    PSD = ("\x38\x42\x50\x53", 0) # adobe phtotoshop native file format
    RPM = ("\xED\xAB\xEE\xDB", 0) # red hat package manager package
    SEVEN_ZIP = ("\x37\x7A\xBC\xAF\x27\x1C", 0) # 7-zip archive
    SHEBANG = ("\x23\x21", 0) # shebang for scripts
    SQLLITE = ("\x53\x51\x4C\x69\x74\x65\x20\x66\x6F\x72\x6D\x61\x74\x20\x33\x00", 0)
    TAR_Z_LZW = ("\x1F\x9D", 0) # tar archive compressed with lempel-ziv-welch algorithm
    TAR_Z_LZH = ("\x1F\xA0", 0) # tar archive compressed with LZH algorithm
    TAR = ("\x75\x73\x74\x61\x72", 257) # tar archive
    TIF = ("\x49\x49\x2A\x00", 0) # tagged image file format (TIFF)
    WAV = ("\x52\x49\x46\x46\x00\x00\x00\x00\x57\x41\x56\x45", 0) # wav audio file format
    XZ_LZMA2 = ("\xFD\x37\x7A\x58\x5A\x00", 0) # xz archive compressed with LZMA2 algorithm
    ZLIB_NOT_COMPRESSED = ("\x78\x01", 0) # zlib compressed data with no compression
    ZLIB_BEST_SPEED = ("\x78\x5e", 0) # zlib compressed data with best speed compression
    ZLIB_DEFAULT_COMPRESSION = ("\x78\x9c", 0) # zlib compressed data with default compression

    @staticmethod
    def x2a(vals):
        """convert raw hex string to ascii"""
        return "".join([v for v in vals])
    
    @staticmethod
    def x2i(vals):
        """convert raw hex string to space separated hex string format 0xXX"""
        return " ".join([hex(ord(v)) for v in vals])

#maybe use another way to access magic value data?

MAGIC_NUMS = {
    "PDF": {
        "hex": "\x25\x50\x44\x46\x2D",
        "ascii": "%PDF-",
        "offset": 0
    },
    "PCAP": {
        "hex": "\xD4\xC3\xB2\xA1",
        "ascii": f"{chr(0xD4)}{chr(0xC3)}{chr(0xB2)}{chr(0xA1)}",
        "offset": 0
    }
}