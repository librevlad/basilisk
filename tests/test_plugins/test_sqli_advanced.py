"""Tests for sqli_advanced plugin."""

from __future__ import annotations

from basilisk.core.plugin import PluginCategory
from basilisk.plugins.pentesting.sqli_advanced import (
    DBMS_PROBES,
    ERROR_EXTRACT,
    SQL_ERROR_PATTERNS,
    SQLI_PARAMS,
    TIME_PAYLOADS,
    SqliAdvancedPlugin,
)
from basilisk.utils.payloads import DbmsType


class TestSqliAdvancedMeta:
    def test_meta_name(self):
        assert SqliAdvancedPlugin.meta.name == "sqli_advanced"

    def test_meta_category(self):
        assert SqliAdvancedPlugin.meta.category == PluginCategory.PENTESTING

    def test_depends_on_http_headers(self):
        assert "http_headers" in SqliAdvancedPlugin.meta.depends_on

    def test_produces(self):
        assert "sqli_results" in SqliAdvancedPlugin.meta.produces

    def test_timeout(self):
        assert SqliAdvancedPlugin.meta.timeout == 120.0


class TestSqliAdvancedData:
    def test_dbms_probes_non_empty(self):
        assert len(DBMS_PROBES) >= 5

    def test_dbms_probes_have_dbms_type(self):
        for _payload, _pattern, dbms in DBMS_PROBES:
            assert isinstance(dbms, DbmsType)

    def test_sql_error_patterns_compiled(self):
        assert len(SQL_ERROR_PATTERNS) >= 10
        for pat in SQL_ERROR_PATTERNS:
            assert hasattr(pat, "search")

    def test_time_payloads_major_dbms(self):
        assert DbmsType.MYSQL in TIME_PAYLOADS
        assert DbmsType.POSTGRES in TIME_PAYLOADS
        assert DbmsType.MSSQL in TIME_PAYLOADS
        assert DbmsType.SQLITE in TIME_PAYLOADS

    def test_time_payloads_non_empty(self):
        for dbms, payloads in TIME_PAYLOADS.items():
            assert len(payloads) > 0, f"No time payloads for {dbms}"

    def test_error_extract_major_dbms(self):
        assert DbmsType.MYSQL in ERROR_EXTRACT
        assert DbmsType.POSTGRES in ERROR_EXTRACT
        assert DbmsType.MSSQL in ERROR_EXTRACT

    def test_error_extract_non_empty(self):
        for dbms, payloads in ERROR_EXTRACT.items():
            assert len(payloads) > 0, f"No error extract for {dbms}"

    def test_sqli_params_non_empty(self):
        assert len(SQLI_PARAMS) >= 8
