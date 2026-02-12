"""Tests for response diff engine."""

from __future__ import annotations

from basilisk.utils.diff import ResponseDiffer, ResponseSnapshot


class TestResponseSnapshot:
    def test_basic_properties(self):
        snap = ResponseSnapshot(
            status=200,
            headers={"Content-Type": "text/html"},
            body="<html><body>Hello World</body></html>",
            length=36,
        )
        assert snap.status == 200
        assert snap.words == 2  # "Hello World" splits across HTML tags
        assert snap.lines == 1
        assert snap.body_hash  # md5 hash exists

    def test_body_hash_consistency(self):
        a = ResponseSnapshot(status=200, headers={}, body="test", length=4)
        b = ResponseSnapshot(status=200, headers={}, body="test", length=4)
        assert a.body_hash == b.body_hash

    def test_different_body_different_hash(self):
        a = ResponseSnapshot(status=200, headers={}, body="aaa", length=3)
        b = ResponseSnapshot(status=200, headers={}, body="bbb", length=3)
        assert a.body_hash != b.body_hash


class TestResponseDiffer:
    def setup_method(self):
        self.differ = ResponseDiffer()

    def test_capture(self):
        snap = self.differ.capture(
            status=200,
            headers={"Content-Type": "text/html"},
            body="<h1>Test</h1>",
        )
        assert snap.status == 200
        assert snap.content_type == "text/html"
        assert snap.length == 13

    def test_identical_responses(self):
        snap = self.differ.capture(200, {}, "Same content")
        result = self.differ.compare(snap, snap)
        assert not result.status_changed
        assert result.similarity == 1.0
        assert result.length_delta == 0
        assert result.score == 0.0
        assert not result.is_significant
        assert not result.has_changes

    def test_different_status(self):
        base = self.differ.capture(200, {}, "OK")
        resp = self.differ.capture(500, {}, "OK")
        result = self.differ.compare(base, resp)
        assert result.status_changed
        assert result.score > 0.3
        assert result.is_significant

    def test_different_body(self):
        base = self.differ.capture(200, {}, "Original content here")
        resp = self.differ.capture(200, {}, "Completely different text")
        result = self.differ.compare(base, resp)
        assert result.similarity < 0.5
        assert result.is_significant

    def test_similar_body(self):
        base = self.differ.capture(
            200, {},
            "<html><body><h1>Welcome</h1><p>Content here.</p></body></html>"
        )
        resp = self.differ.capture(
            200, {},
            "<html><body><h1>Welcome</h1><p>Content here!</p></body></html>"
        )
        result = self.differ.compare(base, resp)
        assert result.similarity > 0.9
        assert not result.is_significant

    def test_header_changes(self):
        base = self.differ.capture(200, {"X-Custom": "old"}, "body")
        resp = self.differ.capture(200, {"X-Custom": "new"}, "body")
        result = self.differ.compare(base, resp)
        assert "X-Custom" in result.header_changes
        assert result.header_changes["X-Custom"] == ("old", "new")

    def test_length_delta(self):
        base = self.differ.capture(200, {}, "short")
        resp = self.differ.capture(200, {}, "a much longer response body text")
        result = self.differ.compare(base, resp)
        assert result.length_delta > 0
        assert result.length_ratio > 1.0

    def test_is_same_page(self):
        a = self.differ.capture(
            200, {},
            "<html><body><h1>Page</h1><p>Token: abc123</p></body></html>"
        )
        b = self.differ.capture(
            200, {},
            "<html><body><h1>Page</h1><p>Token: xyz789</p></body></html>"
        )
        assert self.differ.is_same_page(a, b, threshold=0.85)

    def test_is_same_page_different_status(self):
        a = self.differ.capture(200, {}, "body")
        b = self.differ.capture(404, {}, "body")
        assert not self.differ.is_same_page(a, b)

    def test_detect_reflection(self):
        base = self.differ.capture(200, {}, "<html>Normal page</html>")
        resp = self.differ.capture(
            200, {},
            "<html>Normal page<script>alert(1)</script></html>"
        )
        result = self.differ.detect_reflection(
            base, resp, "<script>alert(1)</script>"
        )
        assert result is not None
        assert "alert(1)" in result

    def test_detect_reflection_already_in_baseline(self):
        base = self.differ.capture(
            200, {},
            "<html><script>alert(1)</script></html>"
        )
        resp = self.differ.capture(
            200, {},
            "<html><script>alert(1)</script></html>"
        )
        result = self.differ.detect_reflection(
            base, resp, "<script>alert(1)</script>"
        )
        assert result is None

    def test_detect_error_pattern(self):
        base = self.differ.capture(200, {}, "<html>OK</html>")
        resp = self.differ.capture(
            200, {},
            "<html>SQL syntax error near 'test' Warning: mysqli_query()</html>",
        )
        result = self.differ.detect_error_pattern(base, resp)
        assert result is not None

    def test_detect_error_pattern_no_error(self):
        base = self.differ.capture(200, {}, "<html>OK</html>")
        resp = self.differ.capture(200, {}, "<html>Also OK</html>")
        result = self.differ.detect_error_pattern(base, resp)
        assert result is None

    def test_timing_anomaly(self):
        base = self.differ.capture(200, {}, "fast", elapsed=0.5)
        resp = self.differ.capture(200, {}, "slow", elapsed=5.5)
        assert self.differ.timing_anomaly(base, resp)

    def test_no_timing_anomaly(self):
        base = self.differ.capture(200, {}, "normal", elapsed=0.5)
        resp = self.differ.capture(200, {}, "normal", elapsed=0.7)
        assert not self.differ.timing_anomaly(base, resp)

    def test_csrf_normalization(self):
        """Dynamic tokens should be normalized for comparison."""
        base = self.differ.capture(
            200, {},
            '<input name="csrf_token" value="abc123">'
        )
        resp = self.differ.capture(
            200, {},
            '<input name="csrf_token" value="xyz789">'
        )
        result = self.differ.compare(base, resp)
        # After normalization, the bodies should be similar (short strings lose more ratio)
        assert result.similarity > 0.8

    def test_new_and_removed_content(self):
        base = self.differ.capture(
            200, {},
            "Line one. Line two. Line three."
        )
        resp = self.differ.capture(
            200, {},
            "Line one. Line four. Line three."
        )
        result = self.differ.compare(base, resp)
        assert len(result.new_content) > 0 or len(result.removed_content) > 0
