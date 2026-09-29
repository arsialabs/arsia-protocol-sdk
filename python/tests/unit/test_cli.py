# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Unit tests for ``arsia_protocol.__main__`` (the ``arsia`` CLI)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from arsia_protocol.__main__ import cli
from arsia_protocol.hazmat.primitives.ed25519 import (
    generate_keypair,
    public_key_to_jwk_dict,
)
from arsia_protocol.core.message import create_request, sign_message


@pytest.fixture()
def runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# version
# ---------------------------------------------------------------------------


class TestVersion:
    def test_version_option_prints_version(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "0." in result.output

    def test_version_command_json(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["version"])
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert "sdk_version" in body
        assert body["protocol_version"] == "1.0"


# ---------------------------------------------------------------------------
# keygen
# ---------------------------------------------------------------------------


class TestKeygen:
    def test_default_format_is_pem(self, runner: CliRunner) -> None:
        # Use mix_stderr=False so PEM bytes go to a buffer we can re-read.
        result = runner.invoke(cli, ["keygen"])
        assert result.exit_code == 0
        assert "-----BEGIN PRIVATE KEY-----" in result.output
        assert "-----END PRIVATE KEY-----" in result.output

    def test_pem_round_trip(self, runner: CliRunner, tmp_path: Path) -> None:
        """PEM output loads back via cryptography, signs, and verifies."""
        from cryptography.hazmat.primitives.serialization import (
            load_pem_private_key,
        )

        out = tmp_path / "agent.key"
        result = runner.invoke(cli, ["keygen", "--out", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        pem_bytes = out.read_bytes()
        assert pem_bytes.startswith(b"-----BEGIN PRIVATE KEY-----")
        priv = load_pem_private_key(pem_bytes, password=None)
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )

        assert isinstance(priv, Ed25519PrivateKey)
        pub = priv.public_key()
        signature = priv.sign(b"ping")
        pub.verify(signature, b"ping")

    def test_explicit_pem_matches_default(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        out = tmp_path / "agent.key"
        result = runner.invoke(
            cli, ["keygen", "--format", "pem", "--out", str(out)]
        )
        assert result.exit_code == 0
        assert out.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_json_format_preserves_legacy_shape(
        self, runner: CliRunner
    ) -> None:
        result = runner.invoke(
            cli, ["keygen", "--kid", "agent:acme.bot#k1", "--format", "json"]
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert set(body.keys()) == {
            "private_hex",
            "public_hex",
            "public_b64url",
            "jwk",
            "kid",
        }
        assert body["kid"] == "agent:acme.bot#k1"
        assert body["jwk"]["kty"] == "OKP"
        assert body["jwk"]["crv"] == "Ed25519"
        assert len(bytes.fromhex(body["private_hex"])) == 32

    def test_jwk_format(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli, ["keygen", "--kid", "agent:x.y#1", "--format", "jwk"]
        )
        assert result.exit_code == 0
        jwk = json.loads(result.output)
        assert jwk["kid"] == "agent:x.y#1"
        assert jwk["kty"] == "OKP"
        assert jwk["crv"] == "Ed25519"
        assert "x" in jwk

    def test_json_requires_kid(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["keygen", "--format", "json"])
        assert result.exit_code != 0
        assert "kid" in result.output.lower()

    def test_jwk_requires_kid(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["keygen", "--format", "jwk"])
        assert result.exit_code != 0
        assert "kid" in result.output.lower()

    def test_writes_pem_to_out_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        out = tmp_path / "agent.key"
        result = runner.invoke(cli, ["keygen", "--out", str(out)])
        assert result.exit_code == 0
        assert out.exists()
        assert out.read_bytes().startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_writes_json_to_out_file(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        out = tmp_path / "keys.json"
        result = runner.invoke(
            cli,
            [
                "keygen",
                "--kid",
                "agent:acme.bot#k1",
                "--format",
                "json",
                "--out",
                str(out),
            ],
        )
        assert result.exit_code == 0
        assert out.exists()
        body = json.loads(out.read_text())
        assert body["kid"] == "agent:acme.bot#k1"

    def test_invalid_format_rejected(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli, ["keygen", "--kid", "agent:a.b#1", "--format", "nope"]
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# verify
# ---------------------------------------------------------------------------


class TestVerify:
    def _write_signed(self, tmp_path: Path) -> tuple[Path, Path]:
        priv, pub = generate_keypair()
        jwk = public_key_to_jwk_dict(pub, "agent:acme.bot#k1")
        env = create_request(
            from_agent="agent:acme.bot",
            to_agent="agent:other.svc",
            payload_type="test.ping",
            args={"x": 1},
            capabilities=["test.ping"],
        )
        signed = sign_message(env, priv, "agent:acme.bot#k1")
        env_path = tmp_path / "envelope.json"
        jwk_path = tmp_path / "jwk.json"
        env_path.write_text(json.dumps(signed))
        jwk_path.write_text(json.dumps(jwk))
        return env_path, jwk_path

    def test_valid_signature_returns_0(self, runner: CliRunner, tmp_path: Path) -> None:
        env_path, jwk_path = self._write_signed(tmp_path)
        result = runner.invoke(
            cli,
            ["verify", str(env_path), "--jwk", str(jwk_path)],
        )
        assert result.exit_code == 0
        assert "VALID" in result.output

    def test_invalid_signature_returns_1(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        env_path, jwk_path = self._write_signed(tmp_path)
        envelope = json.loads(env_path.read_text())
        envelope["payload"]["args"]["x"] = 2  # Tamper after signing
        env_path.write_text(json.dumps(envelope))
        result = runner.invoke(
            cli,
            ["verify", str(env_path), "--jwk", str(jwk_path)],
        )
        assert result.exit_code == 1

    def test_wrong_key_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        env_path, _ = self._write_signed(tmp_path)
        _, other_pub = generate_keypair()
        other_jwk = public_key_to_jwk_dict(other_pub, "agent:acme.bot#k1")
        other_jwk_path = tmp_path / "other-jwk.json"
        other_jwk_path.write_text(json.dumps(other_jwk))
        result = runner.invoke(
            cli,
            ["verify", str(env_path), "--jwk", str(other_jwk_path)],
        )
        assert result.exit_code == 1

    def test_malformed_jwk_raises(self, runner: CliRunner, tmp_path: Path) -> None:
        env_path, _ = self._write_signed(tmp_path)
        bad_jwk = tmp_path / "bad.json"
        bad_jwk.write_text(json.dumps({"kty": "OKP"}))  # missing 'x'
        result = runner.invoke(
            cli,
            ["verify", str(env_path), "--jwk", str(bad_jwk)],
        )
        assert result.exit_code != 0
        assert "x" in result.output.lower()


# ---------------------------------------------------------------------------
# canonicalize
# ---------------------------------------------------------------------------


class TestCanonicalize:
    def test_canonicalizes_object(self, runner: CliRunner, tmp_path: Path) -> None:
        src = tmp_path / "doc.json"
        src.write_text(json.dumps({"b": 1, "a": 2}))
        result = runner.invoke(cli, ["canonicalize", str(src)])
        assert result.exit_code == 0
        # JCS sorts keys
        assert result.output.strip() == '{"a":2,"b":1}'

    def test_writes_to_out_file(self, runner: CliRunner, tmp_path: Path) -> None:
        src = tmp_path / "doc.json"
        out = tmp_path / "out.bin"
        src.write_text(json.dumps({"b": 1, "a": 2}))
        result = runner.invoke(cli, ["canonicalize", str(src), "--out", str(out)])
        assert result.exit_code == 0
        assert out.read_bytes() == b'{"a":2,"b":1}'

    def test_non_object_fails(self, runner: CliRunner, tmp_path: Path) -> None:
        src = tmp_path / "doc.json"
        src.write_text('"scalar"')
        result = runner.invoke(cli, ["canonicalize", str(src)])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# inspect
# ---------------------------------------------------------------------------


class TestInspect:
    def test_dumps_summary(self, runner: CliRunner, tmp_path: Path) -> None:
        priv, _pub = generate_keypair()
        env = create_request(
            from_agent="agent:acme.bot",
            to_agent="agent:other.svc",
            payload_type="test.ping",
            args={"x": 1},
            capabilities=["test.ping"],
        )
        signed = sign_message(env, priv, "agent:acme.bot#k1")
        path = tmp_path / "env.json"
        path.write_text(json.dumps(signed))
        result = runner.invoke(cli, ["inspect", str(path)])
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert body["summary"]["kid"] == "agent:acme.bot#k1"
        assert body["summary"]["intent"] == "request"
        assert body["l1_errors"] == []

    def test_reports_l1_errors(self, runner: CliRunner, tmp_path: Path) -> None:
        path = tmp_path / "env.json"
        path.write_text(json.dumps({"not": "an envelope"}))
        result = runner.invoke(cli, ["inspect", str(path)])
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert len(body["l1_errors"]) > 0

    def test_non_object_envelope_errors(
        self, runner: CliRunner, tmp_path: Path
    ) -> None:
        path = tmp_path / "env.json"
        path.write_text("[]")
        result = runner.invoke(cli, ["inspect", str(path)])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# schemas / vectors / profiles
# ---------------------------------------------------------------------------


class TestSchemas:
    def test_lists_schemas_default(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["schemas"])
        assert result.exit_code == 0
        assert result.output.strip() != ""
        assert ".json" in result.output
        assert "arsia-message.schema.json" in result.output

    def test_list_subcommand_equivalent(self, runner: CliRunner) -> None:
        default = runner.invoke(cli, ["schemas"])
        listed = runner.invoke(cli, ["schemas", "list"])
        assert default.exit_code == 0
        assert listed.exit_code == 0
        assert default.output == listed.output

    def test_show_existing_schema(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["schemas", "show", "arsia-message"])
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert isinstance(body, dict)
        # arsia-message is a JSON Schema — must declare $schema or type.
        assert "$schema" in body or "type" in body or "properties" in body

    def test_show_accepts_full_filename(self, runner: CliRunner) -> None:
        result = runner.invoke(
            cli, ["schemas", "show", "arsia-message.schema.json"]
        )
        assert result.exit_code == 0
        body = json.loads(result.output)
        assert isinstance(body, dict)

    def test_show_unknown_schema_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["schemas", "show", "no-such-schema-xyz"])
        assert result.exit_code == 1
        combined = result.output + (result.stderr if result.stderr_bytes else "")
        # Either the error message or the "Available schemas:" listing
        # must mention a real schema so the user can recover.
        assert "arsia-message" in combined or "Available" in combined


class TestVectors:
    def test_lists_vectors_default(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["vectors"])
        assert result.exit_code == 0
        assert ".json" in result.output

    def test_list_subcommand_equivalent(self, runner: CliRunner) -> None:
        default = runner.invoke(cli, ["vectors"])
        listed = runner.invoke(cli, ["vectors", "list"])
        assert default.exit_code == 0
        assert listed.exit_code == 0
        assert default.output == listed.output

    def test_run_passes_all_bundled_vectors(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["vectors", "run"])
        assert result.exit_code == 0, result.output
        assert " 0 failed" in result.output


class TestProfiles:
    def test_lists_profile_names(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["profiles"])
        assert result.exit_code == 0
        names = [ln for ln in result.output.splitlines() if ln.strip()]
        assert any("GDPR" in n or "gdpr" in n.lower() for n in names)

    def test_prints_named_profile(self, runner: CliRunner) -> None:
        list_result = runner.invoke(cli, ["profiles"])
        first_name = next(ln for ln in list_result.output.splitlines() if ln.strip())
        result = runner.invoke(cli, ["profiles", first_name])
        assert result.exit_code == 0
        body: Any = json.loads(result.output)
        assert isinstance(body, dict)

    def test_unknown_profile_errors(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["profiles", "no-such-profile-xyz"])
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# Top-level help
# ---------------------------------------------------------------------------


class TestHelp:
    def test_help_lists_subcommands(self, runner: CliRunner) -> None:
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        for cmd in (
            "keygen",
            "verify",
            "canonicalize",
            "inspect",
            "schemas",
            "vectors",
            "profiles",
            "version",
        ):
            assert cmd in result.output
