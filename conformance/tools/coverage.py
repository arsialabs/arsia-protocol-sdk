#!/usr/bin/env python3
# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Coverage validator: checks RTM requirements against test evidence."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml


def _load_vector_ids(vectors_file: Path) -> set[str]:
    with open(vectors_file) as f:
        data = json.load(f)
    return {v["id"] for v in data.get("vectors", [])}


def _load_suite_rtm_ids(suites_dir: Path) -> set[str]:
    rtm_ids: set[str] = set()
    for suite_file in sorted(suites_dir.glob("*.yaml")):
        with open(suite_file) as f:
            suite = yaml.safe_load(f)
        if not suite or "cases" not in suite:
            continue
        for case in suite["cases"]:
            for rid in case.get("rtm_ids", []):
                rtm_ids.add(rid)
    return rtm_ids


def _load_schema_names(schemas_dir: Path | None) -> set[str]:
    if schemas_dir is None or not schemas_dir.is_dir():
        return set()
    return {p.stem.replace(".schema", "") for p in schemas_dir.glob("*.schema.json")}


def run_coverage(
    rtm_index: dict,
    known_vectors: set[str],
    suite_rtm_ids: set[str],
    *,
    spec_filter: str | None = None,
    modal_filter: str | None = None,
    uncovered_only: bool = False,
) -> dict:
    results: dict[str, dict] = {}

    for spec_name, spec_data in rtm_index["specs"].items():
        if spec_filter and spec_name != spec_filter:
            continue

        sdk_rows: list[dict] = []
        sdk_enabled_rows: list[dict] = []

        for row in spec_data["rows"]:
            if row["layer"] == "sdk":
                sdk_rows.append(row)
            elif row["layer"] == "sdk_enabled":
                sdk_enabled_rows.append(row)

        covered_rows: list[dict] = []
        uncovered_rows: list[dict] = []

        for row in sdk_rows:
            if modal_filter and row["modal"] != modal_filter:
                continue

            has_vector = any(vid in known_vectors for vid in row["vector_ids"])
            has_schema = len(row["schema_refs"]) > 0
            has_case = row["id"] in suite_rtm_ids

            evidence: list[str] = []
            if has_vector:
                evidence.append("VECTOR")
            if has_schema:
                evidence.append("SCHEMA")
            if has_case:
                evidence.append("CASE")

            entry = {
                "id": row["id"],
                "section": row["section"],
                "modal": row["modal"],
                "kind": row["kind"],
                "requirement": row["requirement"],
                "evidence": evidence,
                "covered": len(evidence) > 0,
            }

            if entry["covered"]:
                covered_rows.append(entry)
            else:
                uncovered_rows.append(entry)

        total_sdk = len(covered_rows) + len(uncovered_rows)

        results[spec_name] = {
            "total_sdk": total_sdk,
            "covered": len(covered_rows),
            "uncovered": len(uncovered_rows),
            "pct": round(len(covered_rows) / total_sdk * 100, 1) if total_sdk else 0,
            "sdk_enabled_total": len(sdk_enabled_rows),
            "covered_rows": [] if uncovered_only else covered_rows,
            "uncovered_rows": uncovered_rows,
        }

    total_sdk = sum(r["total_sdk"] for r in results.values())
    total_covered = sum(r["covered"] for r in results.values())
    total_uncovered = sum(r["uncovered"] for r in results.values())

    all_uncovered = []
    for spec_result in results.values():
        all_uncovered.extend(spec_result["uncovered_rows"])

    uncovered_by_modal: dict[str, int] = {}
    for row in all_uncovered:
        m = row["modal"]
        uncovered_by_modal[m] = uncovered_by_modal.get(m, 0) + 1

    must_gaps = uncovered_by_modal.get("MUST", 0) + uncovered_by_modal.get("MUST_NOT", 0)

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "filters": {
            "spec": spec_filter,
            "modal": modal_filter,
            "uncovered_only": uncovered_only,
        },
        "per_spec": results,
        "totals": {
            "sdk_rows": total_sdk,
            "covered": total_covered,
            "uncovered": total_uncovered,
            "pct": round(total_covered / total_sdk * 100, 1) if total_sdk else 0,
        },
        "uncovered_by_modal": dict(
            sorted(uncovered_by_modal.items(), key=lambda x: -x[1])
        ),
        "critical_gaps": must_gaps,
    }


def _print_report(report: dict) -> None:
    print("\nARSIA Protocol — Coverage Report\n")

    for spec_name, spec_data in report["per_spec"].items():
        t = spec_data["total_sdk"]
        c = spec_data["covered"]
        u = spec_data["uncovered"]
        p = spec_data["pct"]
        print(f"  {spec_name + ':':<20s} {t:>4d} sdk rows | {c:>4d} covered ({p:>5.1f}%) | {u:>4d} uncovered")

    totals = report["totals"]
    print(
        f"\n  {'Total:':<20s} {totals['sdk_rows']:>4d} sdk rows | "
        f"{totals['covered']:>4d} covered ({totals['pct']:>5.1f}%) | "
        f"{totals['uncovered']:>4d} uncovered"
    )

    print("\n  Uncovered by modal:")
    for modal, count in report["uncovered_by_modal"].items():
        print(f"    {modal + ':':<16s} {count:>4d} rows")

    cg = report["critical_gaps"]
    print(f"\n  Critical gaps (MUST + MUST_NOT): {cg} rows")

    if report["filters"]["uncovered_only"]:
        print("\n  Uncovered rows:")
        for spec_name, spec_data in report["per_spec"].items():
            for row in spec_data["uncovered_rows"]:
                req = row["requirement"]
                if len(req) > 80:
                    req = req[:77] + "..."
                print(f"    {row['id']:<28s} {row['modal']:<10s} {req}")

    if not report["filters"]["uncovered_only"] and cg > 0:
        print("  → Run with --uncovered-only --modal MUST to see details")

    print()


def main() -> None:
    parser = argparse.ArgumentParser(description="ARSIA Protocol coverage validator")
    parser.add_argument(
        "--rtm-index",
        type=Path,
        default=Path("conformance/tools/rtm_index.json"),
        help="RTM index JSON file (from extract_rtm_index.py)",
    )
    parser.add_argument(
        "--suites-dir",
        type=Path,
        default=Path("conformance/suites"),
        help="Conformance suite directory",
    )
    parser.add_argument(
        "--vectors-file",
        type=Path,
        default=Path("shared/test-vectors/arsia-test-vectors.json"),
        help="Test vectors JSON file",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional output JSON file for full report",
    )
    parser.add_argument(
        "--spec",
        type=str,
        default=None,
        help="Filter to a single spec (e.g. ARSIA-Core)",
    )
    parser.add_argument(
        "--modal",
        type=str,
        default=None,
        help="Filter to a single modal keyword (e.g. MUST, MUST_NOT)",
    )
    parser.add_argument(
        "--uncovered-only",
        action="store_true",
        help="Show only uncovered rows",
    )
    args = parser.parse_args()

    if not args.rtm_index.is_file():
        print(f"Error: RTM index not found: {args.rtm_index}", file=sys.stderr)
        print("Run extract_rtm_index.py first.", file=sys.stderr)
        sys.exit(1)

    with open(args.rtm_index) as f:
        rtm_index = json.load(f)

    known_vectors = _load_vector_ids(args.vectors_file)
    suite_rtm_ids = _load_suite_rtm_ids(args.suites_dir)

    report = run_coverage(
        rtm_index,
        known_vectors,
        suite_rtm_ids,
        spec_filter=args.spec,
        modal_filter=args.modal,
        uncovered_only=args.uncovered_only,
    )

    _print_report(report)

    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Full report written to: {args.output}")


if __name__ == "__main__":
    main()
