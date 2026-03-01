"""Architecture contract tests — enforce v4 layer boundaries via AST analysis.

These tests prevent architectural drift by verifying that each layer only
imports from its allowed dependencies. Violations produce exact file:line
messages. Rules are data-driven: adding a rule = adding a dict entry.

Known cycles and wide dependency sets are documented with TODO markers.
As v4 transformation progresses, tighten rules and remove exceptions.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path

import pytest

BASILISK_ROOT = Path(__file__).resolve().parents[2] / "basilisk"

# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------


@dataclass
class ImportInfo:
    """A single import extracted from a Python source file."""

    module: str  # e.g. "basilisk.utils.http"
    names: list[str]  # e.g. ["AsyncHttpClient"] or ["*"]
    file: Path
    line: int
    in_type_checking: bool = False


@dataclass
class Violation:
    """A single boundary violation."""

    file: Path
    line: int
    imported_module: str
    message: str


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def collect_python_files(package_path: Path) -> list[Path]:
    """Recursively find all .py files under a package, excluding __pycache__."""
    return sorted(
        p for p in package_path.rglob("*.py") if "__pycache__" not in p.parts
    )


def _find_type_checking_ranges(tree: ast.Module) -> list[tuple[int, int]]:
    """Find line ranges of ``if TYPE_CHECKING:`` blocks."""
    ranges: list[tuple[int, int]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        is_tc = (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or (
            isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"
        )
        if not is_tc or not node.body:
            continue
        start = node.body[0].lineno
        end = max(
            getattr(child, "end_lineno", getattr(child, "lineno", start))
            for stmt in node.body
            for child in ast.walk(stmt)
        )
        ranges.append((start, end))
    return ranges


def _in_type_checking(line: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= line <= end for start, end in ranges)


def extract_imports(file_path: Path) -> list[ImportInfo]:
    """Parse a Python file and return all basilisk imports."""
    try:
        source = file_path.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(file_path))
    except (SyntaxError, UnicodeDecodeError):
        return []

    tc_ranges = _find_type_checking_ranges(tree)
    imports: list[ImportInfo] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.startswith("basilisk"):
                    imports.append(
                        ImportInfo(
                            module=alias.name,
                            names=[alias.asname or alias.name.rsplit(".", 1)[-1]],
                            file=file_path,
                            line=node.lineno,
                            in_type_checking=_in_type_checking(
                                node.lineno, tc_ranges
                            ),
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith("basilisk"):
                names = [a.name for a in (node.names or [])]
                imports.append(
                    ImportInfo(
                        module=node.module,
                        names=names,
                        file=file_path,
                        line=node.lineno,
                        in_type_checking=_in_type_checking(node.lineno, tc_ranges),
                    )
                )

    return imports


def _resolve_package(module: str) -> str | None:
    """Extract top-level basilisk package name.

    ``"basilisk.knowledge.entities"`` → ``"knowledge"``
    ``"basilisk.config"`` → ``"config"``
    ``"basilisk"`` → ``None``
    """
    parts = module.split(".")
    if len(parts) < 2 or parts[0] != "basilisk":
        return None
    return parts[1]


def _relative_path(file_path: Path) -> str:
    """Return path relative to repo root for readable messages."""
    try:
        return str(file_path.relative_to(BASILISK_ROOT.parent))
    except ValueError:
        return str(file_path)


# ---------------------------------------------------------------------------
# Test 1: Allowed Dependency Graph
#
# Documents the CURRENT state of the codebase. Any NEW dependency not listed
# here will fail the test. As v4 evolves, tighten by removing entries.
# ---------------------------------------------------------------------------

ALLOWED_DEPENDENCIES: dict[str, set[str]] = {
    # -- v4 foundation (strictest layers) --
    "domain": {"models"},
    "actor": {"utils"},  # wraps utils.http, utils.dns, utils.net
    "scenarios": {"domain", "models"},  # ONLY domain + Severity enum
    "models": set(),  # pure data, no deps
    "decisions": set(),  # pure model
    "events": set(),  # pure bus

    # -- bridge = sole v3↔v4 adapter --
    "bridge": {
        "capabilities",  # TODO(v4): extract; legacy_scenario uses mapping
        "config",  # TODO(v4): inject settings instead
        "core", "domain", "models",
    },

    # -- engine = composition root (assembles the full system) --
    # TODO(v4): engine should only depend on domain + scenarios + orchestrator.
    # Currently runner.py is a god-object wiring everything together.
    "engine": {
        "bridge", "campaign", "capabilities", "config", "core", "domain",
        "events", "knowledge", "logging", "memory", "models",
        "orchestrator", "reasoning", "scoring", "verification",
    },

    # -- knowledge spine --
    "knowledge": {
        "decisions", "models", "observations",
        "orchestrator",  # TODO(v4-cycle): graph.find_missing_knowledge → Planner
        "reasoning",  # TODO(v4-cycle): state → get_source_family
    },
    "observations": {"knowledge", "models"},

    # -- reasoning / scoring --
    "reasoning": {"knowledge"},
    "scoring": {
        "capabilities", "knowledge",
        "orchestrator",  # TODO(v4-cycle): scorer → attack_paths
    },
    "capabilities": {
        "bridge",  # TODO(v4-cycle): mapping → LegacyPluginScenario
        "core",
    },

    # -- orchestrator = central hub --
    "orchestrator": {
        "bridge", "capabilities", "decisions", "domain", "events",
        "knowledge", "models", "observations",
        "reasoning",  # loop.py → belief
        "scoring",
    },

    # -- supporting infrastructure --
    "memory": {"decisions"},
    "campaign": {"knowledge"},
    "storage": {"models"},
    "verification": set(),

    # -- training = composition root for validation mode --
    # TODO(v4-step3): merge into engine, reduce to {engine, domain}
    "training": {
        "capabilities", "config", "core", "events", "knowledge",
        "memory", "models", "orchestrator", "scoring", "utils",
    },

    "logging": {"events"},

    # -- v3 legacy leaf nodes --
    "utils": {"data", "models"},
    "plugins": {"core", "data", "models", "utils"},
    "core": {"models"},
    "data": set(),

    # -- config is a single file (basilisk/config.py) --
    "config": set(),
}

# Packages listed in the graph
_GOVERNED_PACKAGES = sorted(ALLOWED_DEPENDENCIES.keys())


def _collect_dependency_violations(package: str) -> list[Violation]:
    """Check every runtime import in *package* against allowed deps."""
    pkg_path = BASILISK_ROOT / package
    if not pkg_path.is_dir():
        return []

    allowed = ALLOWED_DEPENDENCIES[package]
    violations: list[Violation] = []

    for py_file in collect_python_files(pkg_path):
        for imp in extract_imports(py_file):
            if imp.in_type_checking:
                continue
            target_pkg = _resolve_package(imp.module)
            if target_pkg is None or target_pkg == package:
                continue
            if target_pkg not in allowed:
                violations.append(
                    Violation(
                        file=py_file,
                        line=imp.line,
                        imported_module=imp.module,
                        message=(
                            f"{_relative_path(py_file)}:{imp.line} "
                            f"imports {imp.module} (layer '{target_pkg}') "
                            f"but '{package}' allows only {sorted(allowed)}"
                        ),
                    )
                )
    return violations


class TestDependencyDirection:
    """Each layer may only import from its declared allowed dependencies."""

    @pytest.mark.parametrize("package", _GOVERNED_PACKAGES)
    def test_layer_boundary(self, package: str) -> None:
        violations = _collect_dependency_violations(package)
        if violations:
            report = "\n".join(f"  {v.message}" for v in violations)
            pytest.fail(
                f"Dependency violations in '{package}/' "
                f"({len(violations)} found):\n{report}"
            )


# ---------------------------------------------------------------------------
# Test 2: Scenario Purity (strictest layer)
# ---------------------------------------------------------------------------

_SCENARIO_ALLOWED_MODULES = {
    "basilisk.domain.finding",
    "basilisk.domain.scenario",
    "basilisk.domain.surface",
    "basilisk.domain.target",
    "basilisk.models.result",  # only Severity enum
}

_FORBIDDEN_ACTOR_CLASSES = {"CompositeActor", "HttpActor", "RecordingActor"}


class TestScenarioPurity:
    """Scenarios depend ONLY on domain types + models.result.Severity."""

    def test_scenario_imports_are_domain_only(self) -> None:
        pkg_path = BASILISK_ROOT / "scenarios"
        if not pkg_path.is_dir():
            pytest.skip("scenarios/ not found")

        violations: list[str] = []
        for py_file in collect_python_files(pkg_path):
            for imp in extract_imports(py_file):
                if imp.in_type_checking:
                    continue
                if not imp.module.startswith("basilisk."):
                    continue
                if imp.module not in _SCENARIO_ALLOWED_MODULES:
                    violations.append(
                        f"{_relative_path(py_file)}:{imp.line} "
                        f"imports {imp.module} (not in allowed set)"
                    )

        if violations:
            report = "\n".join(f"  {v}" for v in violations)
            pytest.fail(
                f"Scenario purity violations ({len(violations)}):\n{report}\n"
                f"  Allowed: {sorted(_SCENARIO_ALLOWED_MODULES)}"
            )

    def test_no_concrete_actor_classes(self) -> None:
        """Scenarios must not reference concrete actor classes, even for types."""
        pkg_path = BASILISK_ROOT / "scenarios"
        if not pkg_path.is_dir():
            pytest.skip("scenarios/ not found")

        violations: list[str] = []
        for py_file in collect_python_files(pkg_path):
            for imp in extract_imports(py_file):
                for name in imp.names:
                    if name in _FORBIDDEN_ACTOR_CLASSES:
                        violations.append(
                            f"{_relative_path(py_file)}:{imp.line} "
                            f"references concrete actor class '{name}'"
                        )

        if violations:
            report = "\n".join(f"  {v}" for v in violations)
            pytest.fail(
                f"Scenario actor coupling ({len(violations)}):\n{report}\n"
                f"  Use ActorProtocol or 'actor: Any' instead."
            )


# ---------------------------------------------------------------------------
# Test 3: Network Containment
# ---------------------------------------------------------------------------

_NETWORK_MODULES = {"aiohttp", "httpx", "requests", "socket"}

# Strict zone: network libs completely forbidden.
_NETWORK_STRICT = {
    "scenarios", "orchestrator", "engine", "knowledge", "scoring",
    "reasoning", "domain", "decisions", "events", "memory",
    "campaign", "verification", "logging", "observations",
    "capabilities",
}


def _is_network_import(imp: ImportInfo) -> bool:
    """Check if an import is a network library (not urllib.parse)."""
    mod = imp.module.split(".")[0]
    return mod in _NETWORK_MODULES


class TestNoNetworkOutsideActor:
    """Network I/O libraries only in actor/ and utils/."""

    def test_strict_zone_no_network(self) -> None:
        violations: list[str] = []
        for package in sorted(_NETWORK_STRICT):
            pkg_path = BASILISK_ROOT / package
            if not pkg_path.is_dir():
                continue
            for py_file in collect_python_files(pkg_path):
                for imp in extract_imports(py_file):
                    if imp.in_type_checking:
                        continue
                    if _is_network_import(imp):
                        violations.append(
                            f"{_relative_path(py_file)}:{imp.line} "
                            f"imports '{imp.module}' "
                            f"(network I/O forbidden in '{package}/')"
                        )

        if violations:
            report = "\n".join(f"  {v}" for v in violations)
            pytest.fail(
                f"Network containment violations ({len(violations)}):\n{report}\n"
                f"  Network libraries allowed only in actor/ and utils/."
            )


# ---------------------------------------------------------------------------
# Test 4: Finding Ownership
# ---------------------------------------------------------------------------

_FINDING_FORBIDDEN = {
    "orchestrator", "engine", "knowledge", "scoring", "reasoning",
    "campaign", "memory", "decisions", "events", "verification",
    "logging", "observations", "capabilities",
}


def _find_finding_instantiations(py_file: Path) -> list[tuple[int, str, str]]:
    """Find lines where Finding(...) or Finding.method(...) is called.

    Returns list of (line, call_text, finding_source_module).
    """
    try:
        source = py_file.read_text(encoding="utf-8")
        tree = ast.parse(source, filename=str(py_file))
    except (SyntaxError, UnicodeDecodeError):
        return []

    finding_aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names or []:
                if alias.name == "Finding":
                    key = alias.asname or "Finding"
                    finding_aliases[key] = node.module
                elif alias.name in ("V4Finding", "V3Finding"):
                    finding_aliases[alias.name] = node.module

    if not finding_aliases:
        return []

    results: list[tuple[int, str, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func = node.func
        name = None

        if isinstance(func, ast.Name) and func.id in finding_aliases:
            name = func.id
        elif (
            isinstance(func, ast.Attribute)
            and isinstance(func.value, ast.Name)
            and func.value.id in finding_aliases
            and func.attr in ("high", "critical", "medium", "low", "info")
        ):
            name = func.value.id

        if name:
            results.append((node.lineno, name, finding_aliases[name]))

    return results


class TestFindingOwnership:
    """Finding objects may only be instantiated in allowed layers."""

    @pytest.mark.parametrize("package", sorted(_FINDING_FORBIDDEN))
    def test_no_finding_creation(self, package: str) -> None:
        pkg_path = BASILISK_ROOT / package
        if not pkg_path.is_dir():
            pytest.skip(f"{package}/ not found")

        violations: list[str] = []
        for py_file in collect_python_files(pkg_path):
            for line, call_text, source_mod in _find_finding_instantiations(py_file):
                violations.append(
                    f"{_relative_path(py_file)}:{line} "
                    f"instantiates {call_text} (from {source_mod})"
                )

        if violations:
            report = "\n".join(f"  {v}" for v in violations)
            pytest.fail(
                f"Finding ownership violation in '{package}/' "
                f"({len(violations)}):\n{report}\n"
                f"  Finding creation forbidden in this layer."
            )

    def test_plugins_use_only_v3_finding(self) -> None:
        """Plugins must use models.result.Finding, never domain.finding.Finding."""
        pkg_path = BASILISK_ROOT / "plugins"
        if not pkg_path.is_dir():
            pytest.skip("plugins/ not found")

        violations: list[str] = []
        for py_file in collect_python_files(pkg_path):
            for line, call_text, source_mod in _find_finding_instantiations(py_file):
                if source_mod.startswith("basilisk.domain"):
                    violations.append(
                        f"{_relative_path(py_file)}:{line} "
                        f"uses v4 Finding from {source_mod} (must use models.result)"
                    )

        if violations:
            report = "\n".join(f"  {v}" for v in violations)
            pytest.fail(f"Plugin Finding version violations:\n{report}")

    def test_scenarios_use_only_v4_finding(self) -> None:
        """Scenarios must use domain.finding.Finding, never models.result.Finding."""
        pkg_path = BASILISK_ROOT / "scenarios"
        if not pkg_path.is_dir():
            pytest.skip("scenarios/ not found")

        violations: list[str] = []
        for py_file in collect_python_files(pkg_path):
            for line, call_text, source_mod in _find_finding_instantiations(py_file):
                if source_mod.startswith("basilisk.models"):
                    violations.append(
                        f"{_relative_path(py_file)}:{line} "
                        f"uses v3 Finding from {source_mod} (must use domain.finding)"
                    )

        if violations:
            report = "\n".join(f"  {v}" for v in violations)
            pytest.fail(f"Scenario Finding version violations:\n{report}")


# ---------------------------------------------------------------------------
# Test 5: No NEW Circular Dependencies
#
# Known cycles are legacy debt from v3→v4 migration. The test ensures no
# NEW cycles appear. As refactoring eliminates each cycle, remove it from
# _KNOWN_CYCLES and the test will enforce the fix permanently.
# ---------------------------------------------------------------------------

# Each frozenset = one known cycle edge (A imports B, B imports A).
_KNOWN_CYCLES: set[frozenset[str]] = {
    frozenset({"bridge", "capabilities"}),     # mapping ↔ legacy_scenario
    frozenset({"knowledge", "observations"}),  # state ↔ adapter/observation
    frozenset({"knowledge", "orchestrator"}),  # graph → Planner
    frozenset({"knowledge", "reasoning"}),     # state → get_source_family
    frozenset({"orchestrator", "scoring"}),    # scorer → attack_paths
}


def _build_dependency_graph() -> dict[str, set[str]]:
    """Build actual runtime dependency graph from all source files."""
    graph: dict[str, set[str]] = {}
    for package in _GOVERNED_PACKAGES:
        pkg_path = BASILISK_ROOT / package
        if not pkg_path.is_dir():
            continue
        deps: set[str] = set()
        for py_file in collect_python_files(pkg_path):
            for imp in extract_imports(py_file):
                if imp.in_type_checking:
                    continue
                target = _resolve_package(imp.module)
                if target and target != package:
                    deps.add(target)
        graph[package] = deps
    return graph


def _find_cycle_edges(graph: dict[str, set[str]]) -> set[frozenset[str]]:
    """Find all pairs (A, B) where A→B and B→A exist (direct mutual deps)."""
    edges: set[frozenset[str]] = set()
    for node, deps in graph.items():
        for dep in deps:
            if node in graph.get(dep, set()):
                edges.add(frozenset({node, dep}))
    return edges


class TestNoCircularTopLevel:
    """No NEW circular runtime dependencies between top-level packages."""

    def test_no_new_cycles(self) -> None:
        graph = _build_dependency_graph()
        actual_cycles = _find_cycle_edges(graph)
        new_cycles = actual_cycles - _KNOWN_CYCLES

        if new_cycles:
            formatted = "\n".join(
                f"  {sorted(c)[0]} ↔ {sorted(c)[1]}" for c in new_cycles
            )
            pytest.fail(
                f"NEW circular dependencies found ({len(new_cycles)}):\n"
                f"{formatted}\n"
                f"  Known cycles: {len(_KNOWN_CYCLES)}. "
                f"Do not add new ones — break the dependency instead."
            )

    def test_known_cycles_still_exist(self) -> None:
        """If a known cycle is fixed, remove it from _KNOWN_CYCLES."""
        graph = _build_dependency_graph()
        actual_cycles = _find_cycle_edges(graph)
        stale = _KNOWN_CYCLES - actual_cycles

        if stale:
            formatted = "\n".join(
                f"  {sorted(c)[0]} ↔ {sorted(c)[1]}" for c in stale
            )
            pytest.fail(
                f"Congratulations! {len(stale)} cycle(s) have been fixed.\n"
                f"Remove from _KNOWN_CYCLES:\n{formatted}"
            )
