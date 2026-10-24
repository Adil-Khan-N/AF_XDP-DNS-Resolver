import socket, struct, sys

port = int(sys.argv[1])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

# Forged response (QR=1) for google.com A, txid 0, from a random local source port
pkt = struct.pack("!HHHHHH", 0, 0x8180, 1, 1, 0, 0) \
      + b"\x06google\x03com\x00\x00\x01\x00\x01"

for _ in range(5):
    s.sendto(pkt, ("127.0.0.1", port))
print(f"sent 5 forged packets to port {port}")
