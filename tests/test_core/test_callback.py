"""Tests for OOB callback server."""

from __future__ import annotations

import struct

from basilisk.core.callback import CallbackServer


class TestCallbackServer:
    def test_generate_token(self):
        server = CallbackServer()
        token = server.generate_token("sqli_basic", "example.com", "sqli_blind")
        assert token.startswith("bsk")
        assert len(token) == 19  # "bsk" + 16 hex chars

    def test_unique_tokens(self):
        server = CallbackServer()
        tokens = {
            server.generate_token("plugin", "host", "type")
            for _ in range(100)
        }
        assert len(tokens) == 100

    def test_token_info(self):
        server = CallbackServer()
        token = server.generate_token(
            "ssrf_check", "target.com", "ssrf",
            description="Blind SSRF via image URL",
        )
        info = server.get_token_info(token)
        assert info is not None
        assert info.plugin == "ssrf_check"
        assert info.target == "target.com"
        assert info.payload_type == "ssrf"
        assert info.description == "Blind SSRF via image URL"

    def test_no_hits_initially(self):
        server = CallbackServer()
        token = server.generate_token("test", "host", "test")
        assert server.get_hits(token) == []
        assert not server.has_callback(token)

    def test_record_http_hit(self):
        server = CallbackServer()
        token = server.generate_token("sqli", "host.com", "blind")
        server._record_hit(
            token, "http", "1.2.3.4",
            {"method": "GET", "path": f"/{token}"},
        )
        hits = server.get_hits(token)
        assert len(hits) == 1
        assert hits[0].protocol == "http"
        assert hits[0].source_ip == "1.2.3.4"
        assert hits[0].token == token
        assert server.has_callback(token)

    def test_record_dns_hit(self):
        server = CallbackServer()
        token = server.generate_token("xxe", "host.com", "xxe_blind")
        server._record_hit(
            token, "dns", "5.6.7.8",
            {"domain": f"{token}.callback.local"},
        )
        hits = server.get_hits(token)
        assert len(hits) == 1
        assert hits[0].protocol == "dns"

    def test_multiple_hits(self):
        server = CallbackServer()
        token = server.generate_token("test", "host", "test")
        for i in range(5):
            server._record_hit(token, "http", f"1.1.1.{i}")
        assert len(server.get_hits(token)) == 5

    def test_unknown_token_ignored(self):
        server = CallbackServer()
        server._record_hit("unknown_token", "http", "1.2.3.4")
        assert server.get_all_hits() == {}

    def test_get_all_hits(self):
        server = CallbackServer()
        t1 = server.generate_token("p1", "h1", "t1")
        t2 = server.generate_token("p2", "h2", "t2")
        server._record_hit(t1, "http", "1.1.1.1")
        server._record_hit(t2, "dns", "2.2.2.2")
        all_hits = server.get_all_hits()
        assert t1 in all_hits
        assert t2 in all_hits

    def test_build_payload_url(self):
        server = CallbackServer(http_port=8880)
        token = server.generate_token("test", "host", "test")
        url = server.build_payload_url(token, "/exfil")
        assert token in url
        assert "/exfil" in url

    def test_build_dns_payload(self):
        server = CallbackServer(callback_domain="oob.attacker.com")
        token = server.generate_token("test", "host", "test")
        domain = server.build_dns_payload(token)
        assert token in domain
        assert "oob.attacker.com" in domain

    def test_domain_property(self):
        server = CallbackServer(
            callback_domain="callback.evil.com",
        )
        assert server.domain == "callback.evil.com"

    def test_domain_fallback(self):
        server = CallbackServer(http_port=9999)
        assert "9999" in server.domain

    def test_dns_query_parsing(self):
        """Test DNS query parser with a minimal valid DNS packet."""
        server = CallbackServer()
        token = server.generate_token("test", "host", "test")

        # Build a minimal DNS query for {token}.callback.local
        txn_id = b"\x12\x34"
        flags = struct.pack(">H", 0x0100)  # standard query
        counts = struct.pack(">HHHH", 1, 0, 0, 0)  # 1 question

        # QNAME: {token}.callback.local
        qname = b""
        for label in [token, "callback", "local"]:
            qname += bytes([len(label)]) + label.encode()
        qname += b"\x00"  # terminator

        qtype_class = struct.pack(">HH", 1, 1)  # A record, IN class
        packet = txn_id + flags + counts + qname + qtype_class

        response = server._handle_dns_query(packet, ("10.0.0.1", 12345))
        assert response is not None
        # Token should have been recorded
        assert server.has_callback(token)
        hits = server.get_hits(token)
        assert hits[0].source_ip == "10.0.0.1"
        assert hits[0].protocol == "dns"

    def test_dns_query_unknown_token(self):
        """DNS query with unknown token should still return response."""
        server = CallbackServer()
        txn_id = b"\xAB\xCD"
        flags = struct.pack(">H", 0x0100)
        counts = struct.pack(">HHHH", 1, 0, 0, 0)
        qname = b"\x07unknown\x05local\x00"
        qtype_class = struct.pack(">HH", 1, 1)
        packet = txn_id + flags + counts + qname + qtype_class

        response = server._handle_dns_query(packet, ("1.1.1.1", 53))
        assert response is not None  # still responds even for unknown tokens

    def test_http_url(self):
        server = CallbackServer(
            callback_domain="cb.test.com", http_port=8880,
        )
        assert server.http_url == "http://cb.test.com"
