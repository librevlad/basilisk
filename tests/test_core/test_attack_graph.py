"""Tests for basilisk.core.attack_graph — attack path synthesis."""

from __future__ import annotations

from basilisk.core.attack_graph import (
    AttackerState,
    AttackGraph,
    AttackPath,
    Edge,
    TransitionRule,
    _score_path,
)
from basilisk.models.result import Finding, PluginResult, Severity

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
_U = AttackerState.UNAUTHENTICATED
_INFO = AttackerState.INFO_DISCLOSURE
_CRED = AttackerState.CREDENTIAL_ACCESS
_AUTH = AttackerState.AUTHENTICATED
_ADMIN = AttackerState.ADMIN_ACCESS
_FREAD = AttackerState.FILE_READ
_SSRF = AttackerState.SSRF
_RCE = AttackerState.CODE_EXECUTION
_DATA = AttackerState.DATA_BREACH
_CLOUD = AttackerState.CLOUD_COMPROMISE


def _make_result(
    plugin: str,
    findings: list[Finding] | None = None,
    data: dict | None = None,
) -> PluginResult:
    return PluginResult.success(
        plugin=plugin,
        target="example.com",
        findings=findings or [],
        data=data or {},
    )


# ---------------------------------------------------------------------------
# 1. Empty results
# ---------------------------------------------------------------------------
def test_empty_results():
    graph = AttackGraph.from_results([])
    assert graph.edges == []
    assert graph.paths == []
    assert graph.to_report_chains() == []


# ---------------------------------------------------------------------------
# 2. Single SQLi finding → UNAUTH → DATA_BREACH
# ---------------------------------------------------------------------------
def test_single_sqli_finding():
    result = _make_result("sqli_basic", [
        Finding.high("SQL Injection in login", evidence="' OR 1=1--"),
    ])
    graph = AttackGraph.from_results([result])

    assert len(graph.edges) == 1
    edge = graph.edges[0]
    assert edge.source == _U
    assert edge.target == _DATA
    assert edge.plugin == "sqli_basic"

    assert len(graph.paths) >= 1
    path = graph.paths[0]
    assert path.goal == _DATA
    assert len(path.edges) == 1


# ---------------------------------------------------------------------------
# 3. SQLi → Data Breach → Credential Access (multi-step)
# ---------------------------------------------------------------------------
def test_sqli_to_creds_chain():
    """sqli_basic gives DATA_BREACH; with credentials in data → CREDENTIAL_ACCESS
    is not a default rule, but we test that 2 edges build a 2-step path when
    we set up a scenario where the graph has a DATA→CRED edge."""
    # For this test we need a rule that goes DATA→CRED. The current rules
    # don't have a generic DATA→CRED, but we can test that two separate
    # transitions produce a connected path.
    r1 = _make_result("sqli_basic", [
        Finding.high("SQL Injection", evidence="' OR 1=1--"),
    ])
    # js_secret_scan gives UNAUTH→CRED directly
    r2 = _make_result("js_secret_scan", [
        Finding.medium("API Key exposed in JS", evidence="sk_live_xxx"),
    ])
    graph = AttackGraph.from_results([r1, r2])

    # Both edges should exist independently
    assert len(graph.edges) == 2

    # Should find paths to both DATA_BREACH and CREDENTIAL_ACCESS
    data_paths = graph.find_paths(_DATA)
    cred_paths = graph.find_paths(_CRED)
    assert len(data_paths) >= 1
    assert len(cred_paths) >= 1


# ---------------------------------------------------------------------------
# 4. LFI → File Read → Credential Access (chained)
# ---------------------------------------------------------------------------
def test_lfi_to_creds_chain():
    r1 = _make_result("lfi_check", [
        Finding.high("LFI in file param", evidence="/etc/passwd content"),
    ])
    r2 = _make_result("lfi_check", [
        Finding.high("LFI credential harvest", evidence="root:x:0:0"),
    ], data={"credentials": ["root:password123"]})

    graph = AttackGraph.from_results([r1, r2])

    # Should have edges: UNAUTH→FILE_READ and FILE_READ→CREDENTIAL_ACCESS
    sources_targets = {(e.source, e.target) for e in graph.edges}
    assert (_U, _FREAD) in sources_targets
    assert (_FREAD, _CRED) in sources_targets

    # Should find a 2-step path to CREDENTIAL_ACCESS
    cred_paths = graph.find_paths(_CRED)
    assert len(cred_paths) >= 1
    assert len(cred_paths[0].edges) == 2
    assert cred_paths[0].goal == _CRED


# ---------------------------------------------------------------------------
# 5. SSRF → Cloud Compromise
# ---------------------------------------------------------------------------
def test_ssrf_to_cloud():
    r1 = _make_result("ssrf_check", [
        Finding.high("SSRF via url param", evidence="http://169.254.169.254/",
                     tags=["cloud-metadata"]),
    ])
    graph = AttackGraph.from_results([r1])

    sources_targets = {(e.source, e.target) for e in graph.edges}
    assert (_U, _SSRF) in sources_targets
    assert (_SSRF, _CLOUD) in sources_targets

    cloud_paths = graph.find_paths(_CLOUD)
    assert len(cloud_paths) >= 1
    assert cloud_paths[0].goal == _CLOUD
    assert len(cloud_paths[0].edges) == 2  # UNAUTH→SSRF→CLOUD


# ---------------------------------------------------------------------------
# 6. SSTI → direct RCE
# ---------------------------------------------------------------------------
def test_ssti_direct_rce():
    result = _make_result("ssti_check", [
        Finding.high("SSTI in template param", evidence="{{7*7}}=49"),
    ])
    graph = AttackGraph.from_results([result])

    assert len(graph.edges) == 1
    assert graph.edges[0].source == _U
    assert graph.edges[0].target == _RCE

    rce_paths = graph.find_paths(_RCE)
    assert len(rce_paths) == 1
    assert rce_paths[0].edges[0].plugin == "ssti_check"


# ---------------------------------------------------------------------------
# 7. No matching rules — INFO-only findings
# ---------------------------------------------------------------------------
def test_no_matching_rules():
    result = _make_result("tech_detect", [
        Finding.info("Technology detected: nginx"),
    ])
    graph = AttackGraph.from_results([result])

    assert graph.edges == []
    assert graph.paths == []


# ---------------------------------------------------------------------------
# 8. Scoring order — multiple paths sorted by risk_score descending
# ---------------------------------------------------------------------------
def test_scoring_order():
    r1 = _make_result("ssti_check", [
        Finding.high("SSTI RCE", evidence="{{7*7}}=49"),
    ])
    r2 = _make_result("sqli_basic", [
        Finding.high("SQL Injection", evidence="' OR 1=1--"),
    ])
    r3 = _make_result("js_secret_scan", [
        Finding.medium("API Key in JS", evidence="sk_live_xxx"),
    ])
    graph = AttackGraph.from_results([r1, r2, r3])

    assert len(graph.paths) >= 2
    # Paths should be sorted by risk_score descending
    for i in range(len(graph.paths) - 1):
        assert graph.paths[i].risk_score >= graph.paths[i + 1].risk_score

    # RCE path should be highest scored (RCE goal weight > DATA_BREACH)
    assert graph.paths[0].goal == _RCE


# ---------------------------------------------------------------------------
# 9. to_report_chains format matches template expectations
# ---------------------------------------------------------------------------
def test_to_report_chains_format():
    result = _make_result("sqli_basic", [
        Finding.high("SQL Injection", evidence="' OR 1=1--"),
    ])
    graph = AttackGraph.from_results([result])
    chains = graph.to_report_chains()

    assert len(chains) >= 1
    chain = chains[0]

    # Required keys
    assert "name" in chain
    assert "risk" in chain
    assert "steps" in chain
    assert "score" in chain
    assert "path_text" in chain

    assert isinstance(chain["name"], str)
    assert chain["risk"] in ("CRITICAL", "HIGH")
    assert isinstance(chain["score"], float)
    assert isinstance(chain["path_text"], str)
    assert "\u2192" in chain["path_text"]

    assert len(chain["steps"]) >= 1
    step = chain["steps"][0]
    assert "label" in step
    assert "count" in step
    assert "detail" in step


# ---------------------------------------------------------------------------
# 10. Max depth limit — prune long paths
# ---------------------------------------------------------------------------
def test_max_depth_limit():
    result = _make_result("ssrf_check", [
        Finding.high("SSRF", evidence="http://169.254.169.254/",
                     tags=["cloud-metadata"]),
    ])
    graph = AttackGraph.from_results([result])

    # With max_depth=1, the 2-step SSRF→CLOUD path should be pruned
    paths_depth_1 = graph.find_paths(_CLOUD, max_depth=1)
    assert len(paths_depth_1) == 0

    # With max_depth=2, it should be found
    paths_depth_2 = graph.find_paths(_CLOUD, max_depth=2)
    assert len(paths_depth_2) >= 1


# ---------------------------------------------------------------------------
# 11. TransitionRule matching — severity_ge, tag, has_data_key
# ---------------------------------------------------------------------------
class TestTransitionRuleMatching:
    def test_severity_ge_match(self):
        rule = TransitionRule("sqli_basic", _U, _DATA, severity_ge=Severity.HIGH)
        result = _make_result("sqli_basic", [Finding.high("SQLi", evidence="proof")])
        matched, title = rule.matches(result)
        assert matched is True
        assert title == "SQLi"

    def test_severity_ge_no_match(self):
        rule = TransitionRule("sqli_basic", _U, _DATA, severity_ge=Severity.HIGH)
        result = _make_result("sqli_basic", [Finding.low("Possible SQLi")])
        matched, _ = rule.matches(result)
        assert matched is False

    def test_tag_match(self):
        rule = TransitionRule("ssrf_check", _SSRF, _CLOUD, tag="cloud-metadata")
        result = _make_result("ssrf_check", [
            Finding.high("SSRF", evidence="proof", tags=["cloud-metadata"]),
        ])
        matched, _ = rule.matches(result)
        assert matched is True

    def test_tag_no_match(self):
        rule = TransitionRule("ssrf_check", _SSRF, _CLOUD, tag="cloud-metadata")
        result = _make_result("ssrf_check", [
            Finding.high("SSRF", evidence="proof", tags=["internal"]),
        ])
        matched, _ = rule.matches(result)
        assert matched is False

    def test_has_data_key_match(self):
        rule = TransitionRule("lfi_check", _FREAD, _CRED, has_data_key="credentials")
        result = _make_result("lfi_check", [
            Finding.high("LFI", evidence="proof"),
        ], data={"credentials": ["root:pass"]})
        matched, _ = rule.matches(result)
        assert matched is True

    def test_has_data_key_no_match(self):
        rule = TransitionRule("lfi_check", _FREAD, _CRED, has_data_key="credentials")
        result = _make_result("lfi_check", [Finding.high("LFI", evidence="proof")])
        matched, _ = rule.matches(result)
        assert matched is False

    def test_wrong_plugin_no_match(self):
        rule = TransitionRule("sqli_basic", _U, _DATA, severity_ge=Severity.HIGH)
        result = _make_result("xss_basic", [Finding.high("XSS", evidence="proof")])
        matched, _ = rule.matches(result)
        assert matched is False

    def test_error_result_no_match(self):
        rule = TransitionRule("sqli_basic", _U, _DATA, severity_ge=Severity.HIGH)
        result = PluginResult.fail("sqli_basic", "example.com", error="timeout")
        matched, _ = rule.matches(result)
        assert matched is False


# ---------------------------------------------------------------------------
# 12. Scoring function
# ---------------------------------------------------------------------------
def test_score_path_values():
    edge = Edge(_U, _RCE, "SSTI RCE", "ssti_check", "HIGH", "proof")
    path = AttackPath(edges=[edge], goal=_RCE)

    # HIGH (3/4) * 60 = 45, RCE goal_weight=0.95 * 30 = 28.5, brevity = (6-1)*2 = 10
    # Total = 45 + 28.5 + 10 = 83.5
    assert path.risk_score == 83.5

    # Empty path
    empty = AttackPath(edges=[], goal=_U, max_severity="INFO", risk_score=0.0)
    assert _score_path(empty) == 0.0


# ---------------------------------------------------------------------------
# 13. Complex multi-plugin scenario
# ---------------------------------------------------------------------------
def test_complex_scenario():
    """Multiple plugins produce a rich graph with several paths."""
    results = [
        _make_result("ssrf_check", [
            Finding.high("SSRF in url param", evidence="http://169.254.169.254/",
                         tags=["cloud-metadata"]),
        ]),
        _make_result("sqli_basic", [
            Finding.high("SQL Injection in search", evidence="' OR 1=1--"),
        ]),
        _make_result("ssti_check", [
            Finding.high("SSTI in name param", evidence="{{7*7}}=49"),
        ]),
        _make_result("git_exposure", [
            Finding.high("Git repository exposed", evidence="/.git/HEAD"),
        ]),
    ]
    graph = AttackGraph.from_results(results)

    # Should have edges for all plugins
    plugins = {e.plugin for e in graph.edges}
    assert "ssrf_check" in plugins
    assert "sqli_basic" in plugins
    assert "ssti_check" in plugins
    assert "git_exposure" in plugins

    # Should find paths to multiple goal states
    rce_paths = graph.find_paths(_RCE)
    data_paths = graph.find_paths(_DATA)
    cloud_paths = graph.find_paths(_CLOUD)
    cred_paths = graph.find_paths(_CRED)

    assert len(rce_paths) >= 1
    assert len(data_paths) >= 1
    assert len(cloud_paths) >= 1
    assert len(cred_paths) >= 1

    # All paths should be sorted by score
    for i in range(len(graph.paths) - 1):
        assert graph.paths[i].risk_score >= graph.paths[i + 1].risk_score
