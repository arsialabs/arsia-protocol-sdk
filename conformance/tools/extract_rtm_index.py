#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Extract an RTM index from ARSIA RTM markdown files."""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def _parse_vector_ids(raw: str) -> list[str]:
    raw = raw.strip()
    if raw in ("—", "-", ""):
        return []
    return [v.strip() for v in raw.split(",") if v.strip()]


def _parse_schema_refs(raw: str) -> list[str]:
    raw = raw.strip()
    if raw in ("—", "-", ""):
        return []
    return [s.strip() for s in raw.split(",") if s.strip()]


def _parse_rtm_file(path: Path) -> dict:
    spec_name = path.stem.replace(".rtm", "")
    rows: list[dict] = []

    with open(path) as f:
        lines = f.readlines()

    for line in lines:
        if line.startswith("---") or "## Coverage Gaps" in line:
            break

        if not line.startswith("|"):
            continue

        parts = [p.strip() for p in line.split("|")]
        # split on | gives empty strings at start/end: ['', col1, col2, ..., col8, '']
        if len(parts) < 10:
            continue

        row_id = parts[1]
        # Skip header and separator rows
        if row_id in ("ID", "") or row_id.startswith("-"):
            continue

        section = parts[2]
        modal = parts[3]
        layer = parts[4]
        kind = parts[5]
        requirement = parts[6]
        schema_raw = parts[7]
        vector_raw = parts[8]

        vector_ids = _parse_vector_ids(vector_raw)
        schema_refs = _parse_schema_refs(schema_raw)

        rows.append(
            {
                "id": row_id,
                "section": section,
                "modal": modal,
                "layer": layer,
                "kind": kind,
                "requirement": requirement,
                "vector_ids": vector_ids,
                "schema_refs": schema_refs,
            }
        )

    return {"spec": spec_name, "total_rows": len(rows), "rows": rows}


def _build_summary(specs: dict[str, dict]) -> dict:
    total = 0
    by_layer: dict[str, int] = {}
    by_modal: dict[str, int] = {}
    with_vector = 0
    with_schema = 0
    with_either = 0
    neither = 0

    for spec_data in specs.values():
        for row in spec_data["rows"]:
            total += 1
            layer = row["layer"]
            modal = row["modal"]
            by_layer[layer] = by_layer.get(layer, 0) + 1
            by_modal[modal] = by_modal.get(modal, 0) + 1

            has_v = len(row["vector_ids"]) > 0
            has_s = len(row["schema_refs"]) > 0
            if has_v:
                with_vector += 1
            if has_s:
                with_schema += 1
            if has_v or has_s:
                with_either += 1
            else:
                neither += 1

    return {
        "total_rows": total,
        "by_layer": dict(sorted(by_layer.items(), key=lambda x: -x[1])),
        "by_modal": dict(sorted(by_modal.items(), key=lambda x: -x[1])),
        "with_vector": with_vector,
        "with_schema": with_schema,
        "with_either": with_either,
        "neither": neither,
    }


def extract_rtm_index(rtm_dir: Path) -> dict:
    specs: dict[str, dict] = {}

    for rtm_file in sorted(rtm_dir.glob("*.rtm.md")):
        parsed = _parse_rtm_file(rtm_file)
        specs[parsed["spec"]] = {
            "total_rows": parsed["total_rows"],
            "rows": parsed["rows"],
        }

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "source": str(rtm_dir),
        "specs": specs,
        "summary": _build_summary(specs),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract RTM index from ARSIA RTM files")
    parser.add_argument(
        "--rtm-dir",
        type=Path,
        default=Path("shared/rtm"),
        help="Path to RTM directory (default: shared/rtm/)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("conformance/tools/rtm_index.json"),
        help="Output JSON file path",
    )
    args = parser.parse_args()

    if not args.rtm_dir.is_dir():
        print(f"Error: RTM directory not found: {args.rtm_dir}", file=sys.stderr)
        sys.exit(1)

    index = extract_rtm_index(args.rtm_dir)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with open(args.output, "w") as f:
        json.dump(index, f, indent=2)

    # Print summary
    summary = index["summary"]
    print(f"RTM Index generated: {args.output}")
    print(f"  Specs: {len(index['specs'])}")
    print(f"  Total rows: {summary['total_rows']}")
    print(f"  By layer: {summary['by_layer']}")
    print(f"  By modal: {summary['by_modal']}")
    print(f"  With vector: {summary['with_vector']}")
    print(f"  With schema: {summary['with_schema']}")
    print(f"  With either: {summary['with_either']}")
    print(f"  Neither: {summary['neither']}")


if __name__ == "__main__":
    main()
