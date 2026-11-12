"""umbra-sentry command line interface.

One command hardens a target; the report lands as JSON, and Sigma rules +
OCSF findings can be exported alongside it.

Critical findings raise ``QUARANTINE`` decisions that are never executed
unattended: an operator names the decision ids to approve with repeatable
``--approve <decision-id>`` (and gives ``--quarantine DIR`` as the
destination); every decision not approved on this invocation is denied, so
silence can never move a file.  Re-running is safe: decision ids are
deterministic, so the same critical event yields the same id to approve.

Usage::

    umbra-harden <target> [--out report.json] [--sigma rules/] [--ocsf ocsf/]
                 [--seed N] [--intensity stealth|balanced|maximum|bankrupt]
                 [--quarantine DIR] [--approve <decision-id>]... [--approver NAME]
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from adapters.ocsf_adapter import OcsfAdapter
from adapters.sigma_adapter import SigmaAdapter
from core.models import DecisionAction, HardeningReport
from core.pipeline import HardeningPipeline
from defense.exhaust import BudgetExhaustStrategy
from defense.hallucinate import ShadowLogicStrategy
from defense.native_strategies import NativeExhaustStrategy, NativePoisonStrategy
from defense.poison import CanaryPoisonStrategy
from gates.human_approval import ApprovalState, HumanApprovalGate
from response.bouncer import Bouncer
from response.event_bus import EventBus

__all__ = ["main"]


def _build_pipeline(args: argparse.Namespace) -> HardeningPipeline:
    strategies = [
        CanaryPoisonStrategy(),
        BudgetExhaustStrategy(),
        ShadowLogicStrategy(),
        # Polyglot stage: compiled artifacts go to the Rust kernel (or skip
        # with an audited event when it has not been built).
        NativePoisonStrategy(),
        NativeExhaustStrategy(),
    ]
    bus = EventBus()
    return HardeningPipeline(
        strategies,
        bus=bus,
        seed=args.seed,
        intensity=args.intensity,
        max_files=args.max_files,
        # getattr: programmatic callers may build a bare Namespace.
        quarantine_dir=getattr(args, "quarantine_dir", None),
    )


def _resolve_decisions(
    pipeline: HardeningPipeline,
    report: HardeningReport,
    approved_ids: list[str],
    approver_name: str,
) -> Bouncer:
    """Route every decision through the HITL gate; execute approved ones.

    The gate's approver is this invocation's ``--approve`` set: only a
    decision whose id was named on the command line is approved.  Everything
    else is denied — fail-closed, never fail-open.
    """
    approved = set(approved_ids)

    async def _approver(request) -> bool:
        return request.decision_id in approved

    gate = HumanApprovalGate(_approver)
    bouncer = Bouncer(gate)
    if pipeline.quarantine_dir is not None:
        bouncer.register_handler(
            DecisionAction.QUARANTINE,
            lambda decision: pipeline.quarantine(Path(decision.artifact_path), decision),
        )

    async def _drive() -> None:
        for decision in report.decisions:
            try:
                await bouncer.handle_decision(decision)
            except OSError as exc:
                # The executor failed before the bouncer could mark the
                # decision executed: report it and leave executed_at unset
                # rather than record a move that never happened.
                print(
                    f"error: executing {decision.decision_id} failed: {exc}",
                    file=sys.stderr,
                )
                continue
            request = gate.get(decision.decision_id)
            if (
                request is not None
                and request.state in (ApprovalState.APPROVED,
                                      ApprovalState.EXECUTED)
                and request.resolved_by == "approver"
            ):
                # The closure only answers yes/no; attribute the operator.
                request.resolved_by = approver_name
                decision.approved_by = approver_name

    asyncio.run(_drive())
    return bouncer


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="umbra-harden", description="Harden release artifacts against AI reverse-engineering agents."
    )
    parser.add_argument("target", help="file or directory to harden")
    parser.add_argument("--out", default="umbra-report.json", help="report output path (JSON)")
    parser.add_argument("--sigma", default=None, help="directory for Sigma YAML rules")
    parser.add_argument("--ocsf", default=None, help="directory for OCSF JSON findings")
    parser.add_argument("--seed", type=int, default=0, help="deterministic seed")
    parser.add_argument("--intensity", default="balanced", choices=["stealth", "balanced", "maximum", "bankrupt"])
    parser.add_argument("--max-files", type=int, default=64)
    parser.add_argument(
        "--quarantine",
        dest="quarantine_dir",
        default=None,
        metavar="DIR",
        help="destination directory for approved quarantine actions",
    )
    parser.add_argument(
        "--approve",
        action="append",
        default=[],
        metavar="DECISION_ID",
        help="approve one decision (repeatable); every other decision is denied",
    )
    parser.add_argument(
        "--approver",
        default="cli-operator",
        metavar="NAME",
        help="operator name recorded on approved decisions",
    )
    args = parser.parse_args(argv)

    if args.approve and not args.quarantine_dir:
        parser.error("--approve requires --quarantine DIR: an approved quarantine needs a destination")

    target = Path(args.target)
    if not target.exists():
        print(f"error: target does not exist: {target}", file=sys.stderr)
        return 2

    pipeline = _build_pipeline(args)
    report = pipeline.run(target)

    # HITL after the run and before serialization, so the report records the
    # approval attribution and execution timestamps.
    bouncer = _resolve_decisions(pipeline, report, args.approve, args.approver)

    report_json = report.model_dump(mode="json")
    out_path = Path(args.out)
    out_path.write_text(json.dumps(report_json, indent=2), encoding="utf-8")

    sigma_dir = Path(args.sigma) if args.sigma else None
    if sigma_dir is not None:
        adapter = SigmaAdapter()
        rules = adapter.from_artifact_events(report.events)
        sigma_dir.mkdir(parents=True, exist_ok=True)
        for rule in rules:
            (sigma_dir / f"{rule.rule_id}.yml").write_text(adapter.to_yaml(rule), encoding="utf-8")

    ocsf_dir = Path(args.ocsf) if args.ocsf else None
    if ocsf_dir is not None:
        oadapter = OcsfAdapter()
        batch = oadapter.report_to_batch(report)
        ocsf_dir.mkdir(parents=True, exist_ok=True)
        (ocsf_dir / "findings.json").write_text(json.dumps(batch, indent=2), encoding="utf-8")

    applied = len(report.applied_events)
    modified = len(report.modified_artifacts)
    print(f"umbra-sentry: {applied} events, {modified} artifacts modified, success={report.success}")
    print(f"report: {out_path}")
    if sigma_dir:
        print(f"sigma rules: {sigma_dir}")
    if ocsf_dir:
        print(f"ocsf findings: {ocsf_dir}")
    if report.decisions:
        executed = len(bouncer.executed)
        print(f"hitl: {executed} approved/executed, {len(report.decisions) - executed} denied")
        for decision in report.decisions:
            if decision.approved_by is None:
                print(f"  needs approval: {decision.decision_id} ({decision.action.value})")
    return 0 if report.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
