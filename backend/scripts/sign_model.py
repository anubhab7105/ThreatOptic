
import os
import sys


def _keypair_from_seed(seed_hex: str):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex.strip()))


def cmd_keygen() -> int:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.generate()
    seed = priv.private_bytes_raw().hex()
    pub = priv.public_key().public_bytes_raw().hex()
    print("MODEL_SIGN_KEY (keep OFFLINE, never deploy):")
    print(seed)
    print("MODEL_VERIFY_KEY (deploy to server env):")
    print(pub)
    return 0


def cmd_sign(path: str) -> int:
    seed = (os.environ.get("MODEL_SIGN_KEY", "") or "").strip()
    if len(seed) != 64:
        print("error: MODEL_SIGN_KEY must be a 64-hex-char Ed25519 seed", file=sys.stderr)
        return 2
    if not os.path.isfile(path):
        print(f"error: no such file: {path}", file=sys.stderr)
        return 2
    try:
        priv = _keypair_from_seed(seed)
    except Exception as e:
        print(f"error: bad MODEL_SIGN_KEY: {e}", file=sys.stderr)
        return 2
    with open(path, "rb") as f:
        data = f.read()
    sig = priv.sign(data)
    with open(path + ".sig", "w", encoding="utf-8") as f:
        f.write(sig.hex() + "\n")
    print(f"signed {path} -> {path}.sig")
    return 0


def cmd_verify(path: str) -> int:
    pub = (os.environ.get("MODEL_VERIFY_KEY", "") or "").strip()
    if len(pub) != 64:
        print("error: MODEL_VERIFY_KEY must be a 64-hex-char Ed25519 public key", file=sys.stderr)
        return 2
    sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    try:
        from app.modules.model_trust import verify_model_artifact, ModelTrustError
    except Exception as e:
        print(f"error: cannot import verifier: {e}", file=sys.stderr)
        return 2
    try:
        verify_model_artifact(os.path.abspath(path), purpose="sign-check")
    except ModelTrustError as e:
        print(f"UNTRUSTED: {e}", file=sys.stderr)
        return 1
    print(f"TRUSTED: {path}")
    return 0


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[1] == "--keygen":
        return cmd_keygen()
    if len(argv) == 3 and argv[2] == "--verify":
        return cmd_verify(argv[1])
    if len(argv) == 2:
        return cmd_sign(argv[1])
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
