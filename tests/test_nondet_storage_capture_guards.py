from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FILES = (
    ROOT / "contracts" / "agentseal_assessment_evidence_evaluator.py",
    ROOT / "contracts" / "agentseal_challenge_evidence_evaluator.py",
)


def _class(tree: ast.Module) -> ast.ClassDef:
    return next(
        node
        for node in tree.body
        if isinstance(node, ast.ClassDef)
        and node.name in {
            "AgentSealAssessmentEvidenceEvaluator",
            "AgentSealChallengeEvidenceEvaluator",
        }
    )


def _nondet_web_calls(node: ast.AST) -> list[ast.Call]:
    calls = []
    for child in ast.walk(node):
        if not isinstance(child, ast.Call):
            continue
        f = child.func
        if not isinstance(f, ast.Attribute):
            continue
        if not isinstance(f.value, ast.Attribute):
            continue
        if not isinstance(f.value.value, ast.Attribute):
            continue
        if not isinstance(f.value.value.value, ast.Name):
            continue
        if (
            f.value.value.value.id == "gl"
            and f.value.value.attr == "nondet"
            and f.value.attr == "web"
        ):
            calls.append(child)
    return calls


def test_nondet_web_consensus_never_captures_contract_storage():
    for path in FILES:
        source = path.read_text(encoding="utf-8")
        tree = ast.parse(source)

        helper = next(
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef)
            and node.name == "_consensus_web_request"
        )

        nested = {
            node.name: node
            for node in helper.body
            if isinstance(node, ast.FunctionDef)
        }

        assert set(nested) == {"leader_fn", "validator_fn"}

        for name in ("leader_fn", "validator_fn"):
            fn = nested[name]
            names = {
                node.id
                for node in ast.walk(fn)
                if isinstance(node, ast.Name)
            }
            assert "self" not in names
            assert "PolicyRecord" not in names
            assert "AssessmentRecord" not in names
            assert len(_nondet_web_calls(fn)) >= 2

        consensus_call = next(
            node
            for node in ast.walk(helper)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Attribute)
            and isinstance(node.func.value.value, ast.Name)
            and node.func.value.value.id == "gl"
            and node.func.value.attr == "vm"
            and node.func.attr == "run_nondet_unsafe"
        )

        assert len(consensus_call.args) == 2
        assert isinstance(consensus_call.args[0], ast.Name)
        assert consensus_call.args[0].id == "leader_fn"
        assert isinstance(consensus_call.args[1], ast.Name)
        assert consensus_call.args[1].id == "validator_fn"

        contract = _class(tree)
        methods = {
            node.name: node
            for node in contract.body
            if isinstance(node, ast.FunctionDef)
        }

        assert "_evidence_once" not in methods
        assert not _nondet_web_calls(methods["_evidence_consensus"])

        assert "response.status_code" not in source
        assert source.count("int(response.status)") == 2
