# UDP DNS Forwarder (AF_XDP Baseline)

A single-threaded, epoll-based UDP DNS forwarder written in C. It is the **socket-based baseline** for a later AF_XDP (zero-copy) implementation.

- Listens on `0.0.0.0:5353`
- Forwards `A` (1) and `AAAA` (28) queries to `8.8.8.8:53`
- Rejects every other QTYPE immediately with `NOTIMP` (in-place buffer rewrite, no upstream I/O)
- O(1) state table of 65,536 slots maps upstream TXIDs back to the original client address and TXID

## Build

```bash
# Sanitizer build: correctness and malformed-packet testing
gcc -g -O1 -Wall -Wextra -fsanitize=address,undefined -o resolver_asan resolver.c

# Optimized build: benchmarking only
gcc -O3 -Wall -Wextra -o udp_resolver resolver.c
```

Check that port 5353 is free first (avahi/mDNS often uses it):

```bash
ss -ulnp | grep 5353
```

## Hardening Summary

| Area | Change |
|---|---|
| Sockets | `SOCK_NONBLOCK`; every syscall return value checked |
| IP parsing | `inet_pton()` instead of `inet_addr()` |
| Parsing | `skip_qname()` is bounded by `buffer_end`; 4-byte QTYPE/QCLASS check |
| Alignment | QTYPE built byte-by-byte (no unaligned casts) |
| State | Bounded linear probing (100 attempts), drop when saturated |
| Endianness | `htons()` / `ntohs()` at the application boundary |
| Anti-spoofing | Upstream replies accepted only from `8.8.8.8:53` |
| Validation | Upstream packets must have `qr == 1`; client packets must have `qr == 0` and `opcode == 0` |

## Test Procedure

Use three WSL terminals, all in the project directory. Run the resolver and all test tools **inside WSL**, not across the Windows/WSL boundary.

### 1. Functional regression (run `./resolver_asan` in terminal 1)

```bash
dig @127.0.0.1 -p 5353 google.com A +tries=1        # expect NOERROR + IP
dig @127.0.0.1 -p 5353 cloudflare.com AAAA +tries=1 # expect NOERROR + IPv6
dig @127.0.0.1 -p 5353 google.com TXT +tries=1      # expect NOTIMP, ~0 ms
dig @127.0.0.1 -p 5353 google.com MX +tries=1       # expect NOTIMP
dig @127.0.0.1 -p 5353 apple.com A                  # sequential TXID check
```

### 2. Malformed packet test

```bash
python3 malformed.py
```

Sends 7 malformed packets (too short, QR=1 as query, IQUERY opcode, label overflow, missing terminator, missing QTYPE/QCLASS, truncated QTYPE) and one valid control query.

**Pass:** the 7 malformed packets get no response, the control query gets a response, and the ASAN terminal shows no `AddressSanitizer` or `runtime error:` lines.

### 3. Anti-spoofing test

Add a log line to the anti-spoof branch in Path B:

```c
fprintf(stderr, "dropped spoofed packet from %s:%d\n",
        inet_ntoa(sender_addr.sin_addr), ntohs(sender_addr.sin_port));
```

Then:

```bash
# Rebuild and start (terminal 1)
gcc -g -O1 -Wall -Wextra -fsanitize=address,undefined -o resolver_asan resolver.c
./resolver_asan

# Make the upstream socket get an ephemeral port (it is never bind()ed)
dig @127.0.0.1 -p 5353 google.com A +short

# Find the upstream port: the resolver_asan line that is NOT 5353
ss -ulnp | grep resolver_asan

# Send forged responses to that upstream port
python3 spoof.py <UPSTREAM_PORT>

# Optional: forge every TXID while a real query is in flight
python3 spoof_all.py <UPSTREAM_PORT> & dig @127.0.0.1 -p 5353 example.org A
```

**Pass:** terminal 1 prints one `dropped spoofed packet` line per forged packet, the resolver stays alive, and the real `dig` still returns the genuine answer.

### 4. Concurrency test

```bash
for i in $(seq 1 200); do
  dig @127.0.0.1 -p 5353 google.com A +tries=1 +short &
done | sort | uniq -c
wait
```

**Pass:** 200 answers and no `no servers could be reached` errors.

### 5. Benchmark

Stop the ASAN build first (ASAN slows the resolver several times over), then:

```bash
sudo apt update && sudo apt install -y dnsperf
gcc -O3 -Wall -Wextra -o udp_resolver resolver.c
./udp_resolver                                              # terminal 1
dnsperf -s 127.0.0.1 -p 5353 -d payload.txt -l 10 -Q 100000 # terminal 2
```

`payload.txt` has about 1,000 lines of `name TYPE`, weighted roughly 78% A/AAAA and 22% TXT/MX. Run it 3 times and compare the average, because results against a live upstream vary by 10-20% between runs.

## Current Results

### Functional regression (ASAN build)

| Query | Status | Latency | Result |
|---|---|---|---|
| `google.com A` | NOERROR | 35 ms | Pass |
| `cloudflare.com AAAA` | NOERROR | 63 ms | Pass |
| `google.com TXT` | NOTIMP | 3 ms | Pass |
| `google.com MX` | NOTIMP | 0 ms | Pass |
| `google.com A` (repeat) | NOERROR | 20 ms | Pass |
| `apple.com A` | NOERROR | 27 ms | Pass |
| `cloudflare.com AAAA` (repeat) | NOERROR | 27 ms | Pass |

The original client TXID was restored correctly on every response.

### Malformed packet test

| Case | Result |
|---|---|
| Too short (5 bytes) | Dropped |
| QR=1 sent as query | Dropped |
| Opcode=1 (IQUERY) | Dropped |
| Label length overflows | Dropped |
| No terminating zero | Dropped |
| Missing QTYPE/QCLASS | Dropped |
| Only 2 bytes of QTYPE | Dropped |
| Valid control query | Response, 44 bytes |

### Anti-spoofing test

**Status: incomplete, needs a re-run.** The forged packets in the last run went to port 41872 (not the resolver's real upstream port, 41705) and to port 5353 (the client-facing socket). Neither exercised the `8.8.8.8:53` source check. The 5353 run only confirms that a QR=1 packet is rejected on the client path. Re-run against the real upstream port with the log line enabled.

### Benchmark (`dnsperf`, 10 s, `-Q 100000`)

| Metric | Baseline | Hardened build |
|---|---|---|
| Queries sent | 30,711 | 33,180 |
| Queries completed | 30,691 (99.93%) | 33,093 (99.74%) |
| Queries lost | 20 (0.07%) | 87 (0.26%) |
| NOERROR | 23,867 (77.77%) | 25,361 (76.64%) |
| NOTIMP | 6,824 (22.23%) | 7,732 (23.36%) |
| Queries per second | 3,059 | 3,303 |
| Average latency | 29.26 ms | 16.80 ms |
| Min / max latency | 0.013 / 121.49 ms | 0.007 / 299.05 ms |
| Latency std dev | n/a | 10.7 ms |
| Avg packet size (req / resp) | n/a | 29 / 63 bytes |

**Reading the numbers:** throughput and latency are dominated by the round trip to 8.8.8.8 and its cache state, not by the parsing code, so the hardening shows no measurable cost. The latency drop and the slightly different NOERROR/NOTIMP split are most likely due to a different payload file and a warmer upstream cache. The loss rate rose from 0.07% to 0.26%, still low, and consistent with UDP loss to the upstream or leaked state slots (see below).

## Known Limitations

- **State slot leak:** there is no timeout. If an upstream reply is lost, its slot stays `active = 1` permanently, so repeated runs gradually exhaust the 65,536 slots. Fix: add a timestamp to `query_state` and expire stale entries during probing.
- **512-byte buffer:** `BUF_SIZE` is 512, but EDNS clients advertise 1232 and upstream may reply with more, so `recvfrom()` silently truncates. Raise `BUF_SIZE` to 1232 or more.
- **`ad` flag on NOTIMP:** the fast path reflects the client's `ad` bit. Add `dns->ad = 0;` to the fast path.
- **Predictable TXIDs:** upstream TXIDs come from a sequential counter, which weakens the anti-spoofing protection. Randomize them.
- **Compile warnings:** the inner probing loop variable `i` shadows the outer `i`; rename it to `attempt`.