def xdump(data, bs=16, en="utf8"):
    if data == "" or data is None:
        return
    width = (bs * 2) + (bs // 2)
    lines = []
    cols = """
BLOCK  BYTES{} {}\n""".format(" " * (width + (width % bs) - 5), en.upper())
    dashes = """
{0:-<6} {1:-<{2}}{3}{4}\n""".format("", "", width + (width % bs), " ","-" * (len(en)+1))
    lines.append(cols)
    lines.append(dashes)
    for i in range(0, len(data), bs):
        block_data = data[i:i+bs]
        hexstr = " ".join(["%02x" %ord(chr(x)) for x in block_data])
        txtstr = "".join(["%s" %chr(x) if 32 <= ord(chr(x)) < 127  else "." for x in block_data])
        line = "{:06x} {:48}  {:16}\n".format(i, hexstr, txtstr)
        lines.append(line)
    return "".join([i for i in lines])

bfh = lambda s: bytes.fromhex(s)
int_from_str = lambda s: int.from_bytes(s.encode(), byteorder="big")
hex_to_int = lambda s: int.from_bytes(bfh(s), byteorder="little")
str_from_hex = lambda h: bfh(rev_hex(h)).decode().strip("\x00")
hex_to_str = lambda h: bfh(rev_hex(h))

def hex2rgb(x):
    r = x >> 16
    g = (x >> 8) & 0b11111111
    b = x & 0b11111111
    return (r, g, b)

def align_data(data, bs=16):
    if len(data) % bs == 0:
        return data
    pad_size = (bs - (len(data) % bs)) % bs
    return data + bytes(pad_size)

def pad(data, block_size=16):
    pad_len = block_size - len(data) % block_size
    if type(data) not in {bytes, bytearray}:
        data = data.encode()
    return data + pad_len * bytes([pad_len])

def unpad(padded_data, block_size=16):
    pdata_len = len(padded_data)
    pad_len = padded_data[-1]
    if pdata_len % block_size:
        raise ValueError("data not padded properly")
    return padded_data[:-pad_len].decode()

def rev_hex(x):
    bfh = bytes.fromhex
    x = bfh(x)[::-1]
    return x.hex()

def int_to_hex(i, length=1):
    range_size = 256**length
    if i < -(range_size//2) or i >= range_size:
        raise OverflowError("cannot convert int {} into hex ({} bytes)".format(i, length))
    if i < 0:
        i = range_size + 1
    h = hex(i)[2:]
    h = "0" * (2 * length - len(h)) + h
    return rev_hex(h)

def parse_uboot_dump(filename):
    outfile = filename.replace(".log", ".bin")
    new_fh = open(outfile, "w+b")
    with open(filename, "r") as fh:
        for line in fh.readlines():
            line = line.split("  ", maxsplit=1)[0]
            line = line.split(":", maxsplit=1)
            if len(line) < 2:
                continue
            line = line[1].replace(" ", "")[:32]
            data = bytes.fromhex(line)
            new_fh.write(data)
    new_fh.close()