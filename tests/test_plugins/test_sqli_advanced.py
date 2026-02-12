"""Tests for sqli_advanced plugin."""

from __future__ import annotations

from basilisk.core.plugin import PluginCategory
from basilisk.plugins.pentesting.sqli_advanced import (
    BOOLEAN_FALSE_PAYLOADS,
    BOOLEAN_TRUE_PAYLOADS,
    MAX_UNION_COLS,
    UNION_EXTRACT,
    SqliAdvancedPlugin,
)


class TestSqliAdvancedMeta:
    def test_meta_name(self):
        assert SqliAdvancedPlugin.meta.name == "sqli_advanced"

    def test_meta_category(self):
        assert SqliAdvancedPlugin.meta.category == PluginCategory.PENTESTING

    def test_depends_on_sqli_basic(self):
        assert "sqli_basic" in SqliAdvancedPlugin.meta.depends_on

    def test_produces(self):
        assert "sqli_advanced_findings" in SqliAdvancedPlugin.meta.produces

    def test_timeout(self):
        assert SqliAdvancedPlugin.meta.timeout == 60.0


class TestSqliAdvancedData:
    def test_union_extract_has_major_dbms(self):
        assert "MySQL" in UNION_EXTRACT
        assert "PostgreSQL" in UNION_EXTRACT
        assert "MSSQL" in UNION_EXTRACT
        assert "SQLite" in UNION_EXTRACT

    def test_union_extract_queries_non_empty(self):
        for dbms, queries in UNION_EXTRACT.items():
            assert len(queries) > 0, f"No UNION queries for {dbms}"

    def test_boolean_payloads(self):
        assert len(BOOLEAN_TRUE_PAYLOADS) >= 3
        assert len(BOOLEAN_FALSE_PAYLOADS) >= 3

    def test_max_union_cols(self):
        assert MAX_UNION_COLS == 20
