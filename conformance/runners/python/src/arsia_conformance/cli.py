# SPDX-License-Identifier: BUSL-1.1
# Copyright 2025-2026 Arsia Labs (Arsia Tecnologia Unipessoal Lda)

"""Click CLI entry point for the ARSIA conformance runner.

Usage::

    python -m arsia_conformance [--suites-dir PATH] [--shared-dir PATH]
                                [--category NAME]... [--level core|compliance|full|all]
                                [--format text|json] [--verbose]

Exit codes:

- ``0`` — all tests passed (skipped tests do not fail the run)
- ``1`` — one or more tests failed or errored
- ``2`` — CLI usage error (click default)
"""

from __future__ import annotations

import logging
from pathlib import Path

import click

from arsia_conformance.context import ConformanceContext, ContextError
from arsia_conformance.loader import SuiteLoadError, load_suite_dir
from arsia_conformance.runner import TestRunner


@click.command()
@click.option(
    "--suites-dir",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=None,
    help="Directory containing suite YAML files. Auto-detected if omitted.",
)
@click.option(
    "--shared-dir",
    type=click.Path(file_okay=False, dir_okay=True, path_type=Path),
    default=None,
    help="Path to the repo-root shared/ directory. Auto-detected if omitted.",
)
@click.option(
    "--category",
    "categories",
    multiple=True,
    help="Filter by category (repeatable). Defaults to all categories.",
)
@click.option(
    "--level",
    type=click.Choice(["core", "compliance", "full", "all"], case_sensitive=False),
    default="all",
    help="Filter by conformance level.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"], case_sensitive=False),
    default="text",
    help="Report output format.",
)
@click.option("--verbose", is_flag=True, help="Print per-case results in text mode.")
def main(
    suites_dir: Path | None,
    shared_dir: Path | None,
    categories: tuple[str, ...],
    level: str,
    output_format: str,
    verbose: bool,
) -> None:
    """Run the ARSIA Protocol conformance suites against the installed SDK."""
    # Silence SDK loggers. The compliance module intentionally emits
    # warnings for R1 fallback and §4.3.7 retention floor hits — those are
    # deliberate signals to library consumers, not conformance output.
    # Keeping them out of stderr means JSON mode stays parseable when
    # callers do ``2>&1 | jq``.
    logging.getLogger("arsia_protocol").setLevel(logging.ERROR)

    try:
        context = ConformanceContext.resolve(
            suites_dir=suites_dir,
            shared_dir=shared_dir,
        )
    except ContextError as exc:
        raise click.ClickException(str(exc)) from exc

    try:
        suites = load_suite_dir(context.suites_dir)
    except (FileNotFoundError, SuiteLoadError) as exc:
        raise click.ClickException(str(exc)) from exc

    runner = TestRunner(context)
    category_list: list[str] | None = list(categories) if categories else None
    level_filter: str | None = None if level == "all" else level
    report = runner.run(suites, categories=category_list, level=level_filter)

    if output_format == "json":
        click.echo(report.to_json())
    else:
        click.echo(report.to_text(verbose=verbose), nl=False)

    raise SystemExit(report.exit_code)


__all__ = ["main"]
