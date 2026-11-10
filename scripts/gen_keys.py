"""Generate development-only RSA signing keys for the auth capability token."""

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def main() -> None:
    output = Path("secrets")
    output.mkdir(mode=0o700, exist_ok=True)
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_path = output / "auth_private.pem"
    public_path = output / "auth_public.pem"
    private_path.write_bytes(private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    public_path.write_bytes(private.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    private_path.chmod(0o600)
    public_path.chmod(0o644)
    print(f"Wrote {private_path} and {public_path}")


if __name__ == "__main__":
    main()
