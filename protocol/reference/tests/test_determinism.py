# tests/test_determinism.py
import subprocess, sys, filecmp, os, shutil, tempfile, pathlib

REPO = pathlib.Path(__file__).resolve().parents[3]  # .../hybrid_messenger
GEN = REPO / "protocol/reference/generate_rvn1.py"
OUT = REPO / "shared-vectors/rvn1"

def test_regeneration_is_byte_identical():
    """Lock generate_rvn1.py output to committed bytes.

    Hand-authored / other-generator fixtures (LAN Noise, Full Braid, TR lab
    KATs, …) live beside the rvn1 freeze and are not emitted here. Those
    extras must stay out of this comparison; `git diff --exit-code` after
    an in-tree generate_rvn1.py run still proves the generator does not
    rewrite committed files it owns.
    """
    assert OUT.exists(), "run generate_rvn1.py once before this test"
    with tempfile.TemporaryDirectory() as tmp:
        subprocess.run([sys.executable, str(GEN), "--out", tmp], check=True)
        tmp_root = pathlib.Path(tmp)
        regenerated = {f.relative_to(tmp_root) for f in tmp_root.rglob("*.json")}
        assert regenerated, "generate_rvn1.py emitted no vectors"
        missing = sorted(rel for rel in regenerated if not (OUT / rel).is_file())
        assert not missing, f"generated but not committed: {missing}"
        for rel in regenerated:
            assert filecmp.cmp(OUT / rel, tmp_root / rel, shallow=False), f"drift in {rel}"
