import socket, struct

def send(name, pkt):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(1.0)
    s.sendto(pkt, ("127.0.0.1", 5353))
    try:
        data, _ = s.recvfrom(512)
        print(f"{name}: got {len(data)} bytes back")
    except socket.timeout:
        print(f"{name}: no response (dropped)")

hdr = lambda flags: struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0)
qname = b"\x06google\x03com\x00"
tail = struct.pack("!HH", 1, 1)

send("too short (5 bytes)",       b"\x12\x34\x01\x00\x00")
send("QR=1 sent as query",        hdr(0x8100) + qname + tail)
send("opcode=1 (IQUERY)",         hdr(0x0800) + qname + tail)
send("label length overflows",    hdr(0x0100) + b"\xff" + b"abc")
send("no terminating zero",       hdr(0x0100) + b"\x03abc\x03def")
send("missing QTYPE/QCLASS",      hdr(0x0100) + qname)
send("only 2 bytes of QTYPE",     hdr(0x0100) + qname + b"\x00\x01")
send("valid control query",       hdr(0x0100) + qname + tail)