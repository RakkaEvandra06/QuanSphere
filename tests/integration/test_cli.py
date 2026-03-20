"""Integration tests for CLI commands using Typer's test runner."""

import base64
from pathlib import Path

import pytest
from typer.testing import CliRunner

from crypto_toolkit.cli.main import app
from crypto_toolkit.core.random_gen import generate_key

runner = CliRunner(mix_stderr=False)


class TestEncryptDecryptCli:
    def test_encrypt_with_key(self) -> None:
        key = generate_key(32).hex()
        result = runner.invoke(app, ["encrypt", "hello world", "--key", key])
        assert result.exit_code == 0

    def test_encrypt_decrypt_roundtrip_with_key(self) -> None:
        key = generate_key(32).hex()
        enc = runner.invoke(app, ["encrypt", "round trip test", "--key", key])
        assert enc.exit_code == 0
        # Extract token from panel output (last non-empty line)
        token = _extract_panel_value(enc.output)
        dec = runner.invoke(app, ["decrypt", token, "--key", key])
        assert dec.exit_code == 0
        assert "round trip test" in dec.output

    def test_encrypt_with_password(self) -> None:
        result = runner.invoke(app, ["encrypt", "secret", "--password", "mypassword"])
        assert result.exit_code == 0

    def test_encrypt_decrypt_with_password(self) -> None:
        enc = runner.invoke(app, ["encrypt", "pbe test", "--password", "testpass"])
        assert enc.exit_code == 0
        token = _extract_panel_value(enc.output)
        dec = runner.invoke(app, ["decrypt", token, "--password", "testpass"])
        assert dec.exit_code == 0
        assert "pbe test" in dec.output

    def test_encrypt_no_key_no_password_fails(self) -> None:
        result = runner.invoke(app, ["encrypt", "data"])
        assert result.exit_code != 0

    def test_decrypt_wrong_key_fails(self) -> None:
        key = generate_key(32).hex()
        enc = runner.invoke(app, ["encrypt", "data", "--key", key])
        token = _extract_panel_value(enc.output)
        wrong_key = generate_key(32).hex()
        result = runner.invoke(app, ["decrypt", token, "--key", wrong_key])
        assert result.exit_code != 0

    def test_chacha20_algorithm(self) -> None:
        key = generate_key(32).hex()
        enc = runner.invoke(app, ["encrypt", "chacha test", "--key", key, "--algo", "chacha20"])
        assert enc.exit_code == 0
        token = _extract_panel_value(enc.output)
        dec = runner.invoke(app, ["decrypt", token, "--key", key])
        assert dec.exit_code == 0
        assert "chacha test" in dec.output


class TestHashCli:
    def test_hash_text(self) -> None:
        result = runner.invoke(app, ["hash", "hello"])
        assert result.exit_code == 0
        assert len(_extract_panel_value(result.output)) == 64  # sha256 hex length

    def test_hash_sha512(self) -> None:
        result = runner.invoke(app, ["hash", "hello", "--algo", "sha512"])
        assert result.exit_code == 0
        assert len(_extract_panel_value(result.output)) == 128

    def test_hash_file(self, tmp_path: Path) -> None:
        f = tmp_path / "test.txt"
        f.write_bytes(b"file content")
        result = runner.invoke(app, ["hash", "--file", str(f)])
        assert result.exit_code == 0

    def test_hash_unsupported_algo_fails(self) -> None:
        result = runner.invoke(app, ["hash", "data", "--algo", "md5"])
        assert result.exit_code != 0


class TestGenerateKeyCli:
    def test_generate_symmetric(self) -> None:
        result = runner.invoke(app, ["generate-key", "--type", "symmetric"])
        assert result.exit_code == 0

    def test_generate_token(self) -> None:
        result = runner.invoke(app, ["generate-key", "--type", "token"])
        assert result.exit_code == 0

    def test_generate_password(self) -> None:
        result = runner.invoke(app, ["generate-key", "--type", "password"])
        assert result.exit_code == 0

    def test_generate_ed25519(self) -> None:
        result = runner.invoke(app, ["generate-key", "--type", "ed25519"])
        assert result.exit_code == 0
        assert "PRIVATE KEY" in result.output

    def test_generate_ecc(self) -> None:
        result = runner.invoke(app, ["generate-key", "--type", "ecc"])
        assert result.exit_code == 0
        assert "PRIVATE KEY" in result.output

    def test_generate_rsa(self) -> None:
        result = runner.invoke(app, ["generate-key", "--type", "rsa"])
        assert result.exit_code == 0
        assert "PRIVATE KEY" in result.output

    def test_generate_to_directory(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["generate-key", "--type", "ed25519", "--out", str(tmp_path)])
        assert result.exit_code == 0
        assert (tmp_path / "ed25519_private.pem").exists()
        assert (tmp_path / "ed25519_public.pem").exists()


class TestSignVerifyCli:
    @pytest.fixture()
    def key_dir(self, tmp_path: Path) -> Path:
        runner.invoke(app, ["generate-key", "--type", "ed25519", "--out", str(tmp_path)])
        return tmp_path

    def test_sign_and_verify(self, key_dir: Path) -> None:
        priv = key_dir / "ed25519_private.pem"
        pub = key_dir / "ed25519_public.pem"

        sign_result = runner.invoke(app, ["sign", "my message", "--key", str(priv)])
        assert sign_result.exit_code == 0
        sig = _extract_panel_value(sign_result.output)

        verify_result = runner.invoke(
            app, ["verify", "my message", "--sig", sig, "--key", str(pub)]
        )
        assert verify_result.exit_code == 0
        assert "VALID" in verify_result.output

    def test_verify_tampered_message_fails(self, key_dir: Path) -> None:
        priv = key_dir / "ed25519_private.pem"
        pub = key_dir / "ed25519_public.pem"

        sign_result = runner.invoke(app, ["sign", "original", "--key", str(priv)])
        sig = _extract_panel_value(sign_result.output)

        verify_result = runner.invoke(
            app, ["verify", "tampered", "--sig", sig, "--key", str(pub)]
        )
        assert verify_result.exit_code != 0


class TestEncryptDecryptFileCli:
    def test_encrypt_decrypt_file(self, tmp_path: Path) -> None:
        src = tmp_path / "plain.txt"
        enc = tmp_path / "plain.enc"
        dec = tmp_path / "plain.dec"
        src.write_bytes(b"file encryption test")

        key = generate_key(32).hex()
        enc_result = runner.invoke(app, ["encrypt-file", str(src), str(enc), "--key", key])
        assert enc_result.exit_code == 0

        dec_result = runner.invoke(app, ["decrypt-file", str(enc), str(dec), "--key", key])
        assert dec_result.exit_code == 0
        assert dec.read_bytes() == b"file encryption test"

    def test_wrong_key_fails(self, tmp_path: Path) -> None:
        src = tmp_path / "f.txt"
        enc = tmp_path / "f.enc"
        dec = tmp_path / "f.dec"
        src.write_bytes(b"data")
        key = generate_key(32).hex()
        runner.invoke(app, ["encrypt-file", str(src), str(enc), "--key", key])
        wrong = generate_key(32).hex()
        result = runner.invoke(app, ["decrypt-file", str(enc), str(dec), "--key", wrong])
        assert result.exit_code != 0


class TestRandomCli:
    def test_random_hex(self) -> None:
        result = runner.invoke(app, ["random", "--kind", "hex"])
        assert result.exit_code == 0

    def test_random_base64(self) -> None:
        result = runner.invoke(app, ["random", "--kind", "base64"])
        assert result.exit_code == 0

    def test_random_token(self) -> None:
        result = runner.invoke(app, ["random", "--kind", "token"])
        assert result.exit_code == 0

    def test_random_password(self) -> None:
        result = runner.invoke(app, ["random", "--kind", "password", "--length", "24"])
        assert result.exit_code == 0


class TestVersionCli:
    def test_version(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "1.0.0" in result.output


# ── Helpers ───────────────────────────────────────────────────────────────────

def _extract_panel_value(output: str) -> str:
    """Extract the value line from a Rich panel in CLI output.

    Rich panels look like:
        ╭─ Label ─╮
        │ value   │
        ╰─────────╯
    We grab the first non-border, non-empty line inside the panel.
    """
    lines = output.splitlines()
    for line in lines:
        stripped = line.strip().lstrip("│").strip()
        if stripped and not stripped.startswith("╭") and not stripped.startswith("╰"):
            # Skip the title line (contains label text in panel header)
            if "─" not in stripped:
                return stripped
    # Fallback: return last non-empty line
    return next((l.strip() for l in reversed(lines) if l.strip()), "")
