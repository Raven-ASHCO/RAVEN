# Raven decoder fuzzing (cargo-fuzz)

Coverage-guided libFuzzer targets for the decoders a remote peer or another
local process can reach. The crate is **outside** the `node/` workspace (its
own `[workspace]` root and `Cargo.lock`), so `libfuzzer-sys` never enters
normal or release builds.

| target | decoder(s) | invariant checked on accepted input |
|---|---|---|
| `envelope` | `Envelope::unpack`, `bridge::decide`, BLE RVN1 check | re-encode is byte-identical |
| `store_object` | RSO1 `StoreObject::unpack` | re-encode is stable |
| `rlb1_offer` | RLB1 LAN offer `decode_offer` | encode → decode round trip |
| `carrier_frames` | Internet/LAN `deframe_prefix`, mock-BLE `ble_frame_decode`, RIH1 hello | length accounting, re-frame identical |
| `pair_init` | PairInit / PairResponse | re-encode is byte-identical |
| `device_cert` | `DeviceCertificate` / `PrekeyBundleJson` JSON + verify | no panic |
| `device_revocation` | `DeviceRevocationV1::decode` | re-encode is byte-identical |
| `ipc_frame` | IPC request / response frames | request round trip |
| `session_and_records` | indexed-session header / signed ACK, RVNA1 header, alias, PeerRecord, contact request/accept | no panic |

The target bodies live in [`src/lib.rs`](src/lib.rs). The same file is compiled
into `node/crates/raven-core/tests/fuzz_smoke.rs`, which runs every target over
pseudo-random mutations of all `shared-vectors/rvn1` values on **stable** in CI
(`cargo test -p raven-core --test fuzz_smoke`), so a target that no longer
type-checks, or a decoder that panics on a mutated vector, fails the normal
test run. Longer smoke runs:

```bash
cd node
RAVEN_FUZZ_SMOKE_ROUNDS=500 RAVEN_FUZZ_SMOKE_SEED=$RANDOM \
  cargo test -p raven-core --test fuzz_smoke fuzz_smoke_all_targets_random
```

## Real campaigns (nightly)

```bash
rustup toolchain install nightly
cargo +nightly install cargo-fuzz --locked
cd node/fuzz
cargo +nightly fuzz list
cargo +nightly fuzz run envelope -- -max_total_time=600
```

Seed a corpus from the committed vectors (hex values become binary seeds):

```bash
mkdir -p corpus/envelope
python3 - <<'PY'
import hashlib, json, pathlib
out = pathlib.Path("corpus/envelope")
for p in pathlib.Path("../../shared-vectors/rvn1").rglob("*.json"):
    def walk(v):
        if isinstance(v, str) and len(v) >= 8 and len(v) % 2 == 0:
            try:
                b = bytes.fromhex(v)
            except ValueError:
                return
            (out / hashlib.sha1(b).hexdigest()).write_bytes(b)
        elif isinstance(v, dict):
            for x in v.values(): walk(x)
        elif isinstance(v, list):
            for x in v: walk(x)
    walk(json.loads(p.read_text()))
PY
```

A crash reproducer lands in `artifacts/<target>/`; add the input as a
regression case (e.g. a new negative vector or a unit test in the owning
module) together with the fix.
