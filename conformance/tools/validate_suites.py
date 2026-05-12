# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Validate conformance suite YAML files against the suite schema."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import jsonschema
import yaml


def _load_schema() -> dict:
    schema_path = Path(__file__).resolve().parent.parent / "schemas" / "suite.schema.json"
    with schema_path.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def validate_suites(suites_dir: Path) -> tuple[int, int, dict[str, list[str]]]:
    schema = _load_schema()
    valid = 0
    invalid = 0
    errors: dict[str, list[str]] = {}
    for path in sorted(suites_dir.glob("*.yaml")):
        with path.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        file_errors: list[str] = []
        validator = jsonschema.Draft202012Validator(schema)
        for error in sorted(validator.iter_errors(data), key=lambda e: list(e.path)):
            file_errors.append(f"  {'.'.join(str(p) for p in error.absolute_path) or '(root)'}: {error.message}")
        if file_errors:
            invalid += 1
            errors[path.name] = file_errors
        else:
            valid += 1
    return valid, invalid, errors


def main() -> None:
    parser = argparse.ArgumentParser(description="Validate conformance suite YAML files.")
    parser.add_argument(
        "--suites-dir",
        type=Path,
        required=True,
        help="Directory containing suite YAML files.",
    )
    args = parser.parse_args()
    valid, invalid, errors = validate_suites(args.suites_dir)
    for name, file_errors in errors.items():
        print(f"INVALID: {name}")
        for e in file_errors:
            print(e)
    print(f"\n{valid} valid, {invalid} invalid")
    sys.exit(1 if invalid else 0)


if __name__ == "__main__":
    main()
