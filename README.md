# DXP — Direct Exchange Protocol

A small C++17 library for building reliable, optionally encrypted packet exchange
over any byte stream (serial, socket, radio, or an in-memory test transport).

DXP handles framing, CRC integrity checking, encryption + authentication,
acknowledgements, retransmission, duplicate suppression, broadcast, and
multi-hop relay — you only provide a `DXP_Transport` that can read and write bytes.

```cpp
#include "DXP.h"
#include "DXP_transmit.h"
#include "DXP_receive.h"
#include "DXP_keys.h"

DXP_Keys keys;
uint8_t key[16];
keys.generateKey(key);

DXP dxp;
dxp.Type(1);
dxp.Sender(1);
dxp.Receiver(2);
dxp.Encryption(true);
dxp.AESKey(key);
dxp.Payload(reinterpret_cast<const uint8_t*>("hello"), 5);

DXPPacket packet = dxp.process();
std::vector<uint8_t> frame = serializePacket(packet, key);
// write frame to your transport...
```

See `example.cpp` for a complete round trip and `demo.cpp` for the full feature tour.

## Features

- **Framing** — `0x7E` delimited frames with stream resynchronisation after garbage
- **Integrity** — CRC-16/CCITT on every frame
- **Encryption** — AES-128-CBC with random per-frame IVs
- **Authentication** — HMAC-SHA256 encrypt-then-MAC, constant-time verification,
  MAC key derived separately from the encryption key
- **Reliability** — acknowledgements, timed retransmission, delivery-failure reporting
- **Duplicate suppression** — separate replay windows for data frames and ACKs
- **Topology** — unicast, broadcast, static routes, multi-hop relay with hop limits
- **Threading** — `DXP_Link` is mutex-protected; poll from any thread
- **Portability** — Windows (BCrypt), Linux (`getrandom`), macOS/BSD (`arc4random`)
  for CSPRNG; MSVC, MinGW, and GCC/Clang supported

## Building

Windows (MSVC or MinGW, auto-detected):

```bat
build.bat          rem release build + runs the test suite
build.bat asan     rem AddressSanitizer + UBSan build
```

Linux / macOS:

```sh
bash build.sh          # release build + runs the test suite
bash build.sh asan     # AddressSanitizer + UBSan build
```

Both scripts compile the static library, run the self-tests (non-zero exit on
failure), and produce a consumer package:

```
build/include/   public headers
build/lib/       dxp.lib (MSVC) or libdxp.a (GCC/Clang)
build/example/   a minimal consumer program, pre-built against the package
```

To consume the package, add `build/include` to your include path, link the
static library, and (on Linux) link `-pthread`. MinGW consumers also need `-lbcrypt`.

## Packet format

| Offset | Field | Size |
|--------|-------|------|
| 0 | Separator (`0x7E`) | 1 |
| 1 | Type | 1 |
| 2 | Flags (`0x01` encrypted, `0x02` authenticated) | 1 |
| 3 | Hop count | 1 |
| 4 | Sequence count | 1 |
| 5 | Sequences | 2 × n |
| — | Sender ID | 2 |
| — | Receiver ID | 2 |
| — | Route count | 1 |
| — | Route entries | 2 × m |
| — | Payload length | 2 |
| — | IV (only when encrypted) | 16 |
| — | Payload | len |
| — | MAC tag (only when authenticated) | 32 |
| — | CRC-16/CCITT over everything above | 2 |

Frame types: `1` data, `2` ack, `3` data (hop-limited), `4` data (routed),
`5` discovery.

Limits: 10 sequences, 10 route entries, 256-byte payload (240 bytes of
plaintext when encrypted, to leave room for PKCS#7 padding).

## API surface

| Class / function | Purpose |
|------------------|---------|
| `DXP` | Build a packet field-by-field, then `process()` it |
| `serializePacket` / `deserializePacket` | Frame encoding with CRC + MAC verification |
| `processReceivedPacket` | Decrypt an authenticated frame |
| `DXP_Link` | Send/receive/retry/relay endpoint over a `DXP_Transport` |
| `DXP_Transport` | Abstract read/write interface you implement |
| `DXP_Keys` | CSPRNG-backed key and IV generation |
| `DXP_Stream` | Incremental frame reassembly from a byte stream |

Setters such as `Payload()`, `Route()`, and `AESKeys()` return `false` when
input is rejected (too large, null, or invalid) instead of silently truncating;
`status()` reports the reason.

## Security notes

Design properties:

- Encrypt-then-MAC; the MAC is verified **before** any decryption happens
- MAC key derived from the link key with an HMAC label (key separation)
- Random IVs from the operating system CSPRNG; generation failure aborts the send
- Constant-time MAC comparison; key material wiped from memory on teardown
- Sending with encryption enabled but no key fails closed
- Frames are rejected if they are encrypted without a MAC, or MACed while a key
  is configured but the frame is not authenticated (downgrade protection)

**Known limitations — please read before using this in an attack-exposed system:**

- **One static network key.** All nodes share a single 128-bit key with no
  rotation or per-node identity: any node can impersonate any other. Key
  distribution is out of band.
- **Replay protection is a 32-entry window** per peer for data and ACK frames
  separately. Frames replayed after the window has moved on, or after a node
  restarts (state is in memory only), are accepted. This stops casual
  duplication, not a determined attacker on a long-lived link.
- **Hop count is excluded from the MAC** so relays can decrement it; treat it
  as advisory, not trusted input.
- **The crypto primitives are hand-written** (AES-128, SHA-256, HMAC) and are
  verified against FIPS-197, FIPS 180-4, RFC 4231, and NIST SP 800-38A test
  vectors, but they have **not** been independently audited and the AES
  implementation is not hardened against cache-timing attacks.

For high-value secrets, use a reviewed protocol (Noise, DTLS, IPsec) or swap
`DXP_AES`/`DXP_SHA256` for a vetted library.

## Testing

`demo.cpp` is a self-checking suite (run automatically by both build scripts)
covering:

- Known-answer tests: AES-128 block (FIPS-197), AES-CBC (SP 800-38A),
  SHA-256 (FIPS 180-4), HMAC-SHA256 (RFC 4231)
- Round trips for encrypted and plaintext frames
- Tampering with a recomputed CRC, truncation, corruption, key mismatch,
  and downgrade attempts are all rejected
- Duplicate data frames and replayed ACKs are suppressed
- Lossy links recover via retransmission; delivery gives up after max attempts
- Multi-hop relay, broadcast, bidirectional traffic, and concurrent
  poll/send from two threads

## Project layout

```
DXP.h / DXP.cpp            packet builder facade
DXP_packet.*               frame structure, MAC tag compute/verify
DXP_transmit.*             serialization (CRC + MAC appended)
DXP_receive.*              parsing, validation, decryption
DXP_stream.*               incremental frame reassembly
DXP_link.*                 reliability: acks, retries, dedup, relay
DXP_process.*              packet assembly rules per frame type
DXP_crypto.*  DXP_AES.*    AES-128-CBC
DXP_SHA256.*               SHA-256 + HMAC + MAC key derivation
DXP_CRC.*                  CRC-16/CCITT
DXP_keys.*                CSPRNG key/IV generation
demo.cpp                   self-test suite
example.cpp                minimal consumer of the packaged library
build.bat / build.sh       Windows / Unix builds
```

## License

MIT — see [LICENSE](LICENSE).
