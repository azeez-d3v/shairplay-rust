# Legacy PIN reference fixtures

`pin_reference.txt` is deterministic test data, not captured credentials. It was
produced by compiling `pin_reference.c` against the working AirPlayer UxPlay
`lib/srp.c` and OpenSSL on 2026-10-28. The generator computes the client proof,
checks it through that C server's `srp_verifier_verify_session`, then emits both
sides' AES-128-GCM key exchange. Ed25519 keys come from RFC 8032 test vectors.

Reference checkout: UxPlay `d9e293da6d5276315af6820d10542a859bbc3424`.
File SHA-256 checksums (working reference):

- `srp.c`: `3ec7b0cb04045591b39acab5bad91e70865c8fa0bc8cf1555ec44cb10e67ebd8`
- `pairing.c`: `c05894ec0bac668dde4c795f62d53885e7f7278be61f3ea32e97d2b9e036368b`
- `crypto.c`: `3912b4630cb3718e182224ca4f94770cfc2df00f73d17da2cce875a5ee4718fe`

Generate with GCC/Clang and OpenSSL (on Windows add `-ladvapi32`):

```sh
cc -std=c11 -Wall -I /path/to/UxPlay/lib tests/support/pin_reference.c \
  -lcrypto -o pin-reference
./pin-reference > tests/support/pin_reference.txt
```

Cases use the same fixture username `A1B2C3D4E5F6`, PIN `1234`, and deterministic
server/client ephemeral secrets. They cover normal values, a leading-zero salt,
and an all-zero salt with one-byte client public value `A=2`. In Apple's variant,
`k/u` hash fixed-width padded group elements; the salt and proof integers use
minimal big-endian representation. The session key concatenates two SHA1 hashes
of the shared integer followed by counters 0 and 1. GCM uses a 16-byte nonce,
with its last octet incremented separately for each side.

Rust tests compare the actual C-generated server public key, SRP server proof,
authenticated peer key, encrypted receiver public key, and authentication tag.
The C program is an optional fixture generator, not part of the build/runtime.
