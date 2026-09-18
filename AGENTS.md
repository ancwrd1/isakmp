# AGENTS.md

Guidance for AI coding agents working in this repository.

## What this is

`isakmp` is a Rust library implementing a **minimal IKE/ISAKMP initiator** — both
IKEv1 (RFC 2409) and IKEv2 (RFC 7296) — plus the ESP data path, specialised for
**Check Point VPN gateways**. It is consumed mainly by
[snx-rs](https://github.com/ancwrd1/snx-rs). Only the subset of IKE needed to
bring up a Check Point IPSec tunnel is implemented; this is not a general-purpose
IKE stack, and it has no responder-side state machine.

Licensed AGPL-3.0 (`COPYING`). Edition 2024; toolchain in use is Rust 1.98.

## Build, test, lint

The CI gate (`.github/workflows/ci.yml`) is exactly three commands — run all
three before considering a change done:

```sh
cargo fmt --check
cargo clippy --workspace --examples --tests -- -D warnings
cargo test --workspace --examples --tests
```

The suite is ~137 tests and runs in well under a second; there is no reason to
run a narrower subset. `openssl` and `cryptoki` are linked from the system, so a
build needs OpenSSL development headers.

`rustfmt.toml` sets `max_width = 120`. The `imports_granularity` and
`group_imports` options are present but commented out (nightly-only), so import
style is maintained by hand: `std` first, external crates next, `crate::…` last,
each group nested with braces (`use crate::{ikev1::{model::*, payload::*}, …}`).

## Layout

```
src/
  lib.rs          module list only
  message.rs      ISAKMP_HEADER_LEN, version bytes, IsakmpMessageCodec<M> trait
  payload.rs      generic 4-byte payload header, PayloadLike, BasicPayload
  model.rs        registry! macro, DataAttribute TLV, Identity, EspCryptMaterial
  session.rs      IsakmpSession trait, EndpointData, OfficeMode, SessionType
  crypto.rs       DigestType/CipherType/GroupType, Crypto (OpenSSL wrapper)
  certs.rs        ClientCertificate impls: PKCS12/PKCS8, PKCS11, Windows store
  esp.rs          EspCodec — ESP encap/decap over IPv4, CBC+HMAC and AEAD
  rfc1751.rs      key_to_english for the hybrid-auth word list
  transport.rs    IsakmpTransport<M>, CheckInformational; udp + tcpt impls
  ikev1/          codec, message, model, payload, service, session
  ikev2/          codec, message, model, payload, service, session, eap
tests/            integration tests + binary fixtures (mm.bin, ip-udp-esp.bin)
examples/         cp-ikev1.rs, cp-ikev2.rs — CLI clients against a live gateway
```

## Architecture

**The two IKE versions are parallel implementations, not one generalised one.**
They share only the 28-byte header length, the generic payload header, the
attribute TLV, and the layers underneath: `crypto`, `certs`, `esp`, `transport`.
Everything above — wire registries, key schedule, message framing, exchange
state machine — is per-version and must stay that way. Do not try to unify the
model or session types; `src/model.rs` and `src/session.rs` document why.

The seams are generic over the message type `M`:

- `IsakmpMessageCodec<M>` (`message.rs`) — version-specific encode/decode,
  implemented by `Ikev1Codec` and `Ikev2Codec`.
- `IsakmpTransport<M>` (`transport.rs`) — `UdpTransport` and `TcptTransport`
  (Check Point's TCP encapsulation) carry either version.
- `IsakmpSession` (`session.rs`) — the version-neutral surface: SPIs, endpoint
  data, ESP material, certificate, persistence. Version-specific state lives on
  `Ikev1Session` / `Ikev2Session` directly.

Each session is an `Arc<Mutex<…Impl>>` newtype with a thin forwarding method per
operation and an `inner()` helper that recovers from poisoning
(`lock().unwrap_or_else(|e| e.into_inner())`). Keep new session methods in that
shape rather than exposing the guard.

`Ikev1Service` exposes the exchange one phase at a time (`do_sa_proposal`,
`do_key_exchange`, `do_identity_protection`, `send_om_request`,
`do_esp_proposal`). `Ikev2Service` cannot mirror it: IKE_AUTH absorbs auth, MFA,
office mode and the child SA, so the API is `do_sa_init`, then `do_auth` driving
a caller loop over `Ikev2Step::NeedsChallenge`, plus `rekey_child_sa`,
`create_child_sa`, `renew_office_mode`, `poll_request`/`handle_request`.

## Conventions

- **Errors**: `anyhow` everywhere — `anyhow::Result<T>`, `.context(…)`,
  `anyhow::bail!`. No custom error enum, no `unwrap()` outside tests.
- **Logging**: `tracing` (`debug!`, `trace!`, `warn!`). Never log key material.
- **Bytes**: `bytes::Bytes`/`BytesMut` for wire data, `byteorder` for reads.
- **Wire registries**: declared with the `registry!` macro in `src/model.rs`.
  Every registry has a fallback variant (`Other(repr)`) so unknown values
  survive a decode/encode round trip unchanged. Add values there, never as bare
  integer matches.
- **Secrets**: `secrecy::SecretString`, read with `expose_secret()` at the last
  moment.
- **Doc comments**: module- and item-level docs cite the governing RFC section
  (`RFC 7296 §2.14`). Match that when adding protocol code — especially where
  behaviour is driven by an observed Check Point trace rather than a spec, which
  should be said explicitly.
- **Comments** explain *why* a constant or branch exists (which capture settled
  it, which RFC requires it), not what the line does.

## Gotchas

- **Payload bodies exclude the generic header.** `PayloadLike::len` and
  `to_bytes` cover the body only; the 4 header bytes are owned by
  `src/payload.rs` (`read_next_payload` / `write_payload`).
- **The same transform number means different things in the two versions.**
  E.g. 5 is HMAC-SHA2-256 in `ikev1::model::EspAuthAlgorithm` and
  AUTH_AES_XCBC_96 in `ikev2::model::IntegrityAlgorithm`. Resolve to the
  version-neutral `EspCryptMaterial` / `crypto` types before crossing layers;
  never pass a raw wire number down.
- **IKEv2 config attributes use a different TLV** from `model::DataAttribute`
  (no short form) — see `ikev2::payload::ConfigurationAttribute`.
- **AEAD ciphers must be negotiated with `IntegrityAlgorithm::None`**, and carry
  no `sk_a`; `Ikev2Crypt::new` enforces it.
- **IKEv1 flags a whole message encrypted; IKEv2 wraps payloads in an SK
  payload** (`IV | ciphertext | ICV`). The codecs are not analogous.
- `.claude`, `.idea`, `.cargo` and `/target` are gitignored.

## Testing

- Unit tests live inline in `#[cfg(test)] mod tests` next to the code
  (`crypto.rs`, `esp.rs`, and most of `ikev1/`, `ikev2/`).
- Integration tests in `tests/` parse **byte-exact fixtures**: `mm.bin` (captured
  IKEv1 main mode), a hand-laid-out IKE_SA_INIT hex string in
  `test_parse_sa_init.rs`, and `ip-udp-esp.bin` for the ESP path. Prefer this
  over round-trip-only tests — a round trip can agree with itself while every
  field sits at the wrong offset.
- `test_ikev1_model.rs` exhaustively round-trips each registry over its full
  integer range. Add a `check!` line when adding a registry.
- `ikev2/service.rs` tests drive the state machine through a scripted
  `IsakmpTransport` (`Script`) that queues responses and records requests, and
  generates throwaway RSA certs with `openssl` for auth paths. Reuse that
  harness for new exchange logic.
- Crypto is pinned to published test vectors (NIST for AES-GCM) where they
  exist.
- The examples need a **live Check Point gateway** and are not exercised by CI
  beyond compiling.

## Working notes

`ikev2.md` (untracked, in the working tree) is the living IKEv2 implementation
plan: phase-by-phase status, the Check Point wire details resolved by capture,
what is still guessed, and the open risks. Read it before touching `src/ikev2/`,
and update its checkboxes and "settled by …" notes when a phase item lands or a
gateway run resolves an unknown.

## Git

Commit subjects are short, capitalised, past tense, no prefix or scope
(`Added lifetime() method`, `Fixed clippy warning`, `Updated dependencies`).
Work on IKEv2 happens on the `ikev2` branch; `main` is the base for PRs.
