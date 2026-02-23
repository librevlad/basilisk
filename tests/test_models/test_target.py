"""Tests for Target and TargetScope models."""

from basilisk.models.target import Target, TargetScope, TargetType


class TestTarget:
    def test_domain_factory(self):
        t = Target.domain("example.com")
        assert t.host == "example.com"
        assert t.type == TargetType.DOMAIN

    def test_subdomain_factory(self):
        t = Target.subdomain("api.example.com", parent="example.com")
        assert t.host == "api.example.com"
        assert t.type == TargetType.SUBDOMAIN
        assert t.parent == "example.com"

    def test_ip_factory(self):
        t = Target.ip("192.168.1.1")
        assert t.host == "192.168.1.1"
        assert t.type == TargetType.IP

    def test_equality(self):
        t1 = Target.domain("example.com")
        t2 = Target.domain("example.com")
        assert t1 == t2

    def test_inequality(self):
        t1 = Target.domain("example.com")
        t2 = Target.domain("other.com")
        assert t1 != t2

    def test_inequality_different_type_same_host(self):
        """Domain and subdomain with same host must NOT be equal."""
        domain = Target.domain("api.example.com")
        sub = Target.subdomain("api.example.com", parent="example.com")
        assert domain != sub

    def test_hash(self):
        t1 = Target.domain("example.com")
        t2 = Target.domain("example.com")
        assert hash(t1) == hash(t2)
        assert len({t1, t2}) == 1

    def test_hash_differs_by_type(self):
        """Same host with different type must have different hash."""
        domain = Target.domain("api.example.com")
        sub = Target.subdomain("api.example.com", parent="example.com")
        assert hash(domain) != hash(sub)
        assert len({domain, sub}) == 2

    def test_default_fields(self):
        t = Target.domain("example.com")
        assert t.ips == []
        assert t.parent is None
        assert t.ports == []
        assert t.meta == {}


class TestTargetScope:
    def test_add(self):
        scope = TargetScope()
        assert scope.add(Target.domain("a.com"))
        assert len(scope) == 1

    def test_add_duplicate(self):
        scope = TargetScope()
        scope.add(Target.domain("a.com"))
        assert not scope.add(Target.domain("a.com"))
        assert len(scope) == 1

    def test_add_same_host_different_type(self):
        """Domain and subdomain with same host are distinct targets."""
        scope = TargetScope()
        scope.add(Target.domain("api.example.com"))
        assert scope.add(Target.subdomain("api.example.com", parent="example.com"))
        assert len(scope) == 2

    def test_add_many(self):
        scope = TargetScope()
        added = scope.add_many([
            Target.domain("a.com"),
            Target.domain("b.com"),
            Target.domain("a.com"),  # duplicate
        ])
        assert added == 2
        assert len(scope) == 2

    def test_domains_property(self):
        scope = TargetScope()
        scope.add(Target.domain("a.com"))
        scope.add(Target.subdomain("sub.a.com", parent="a.com"))
        assert len(scope.domains) == 1
        assert scope.domains[0].host == "a.com"

    def test_subdomains_property(self):
        scope = TargetScope()
        scope.add(Target.domain("a.com"))
        scope.add(Target.subdomain("sub.a.com", parent="a.com"))
        assert len(scope.subdomains) == 1
        assert scope.subdomains[0].host == "sub.a.com"

    def test_hosts_property(self):
        scope = TargetScope()
        scope.add(Target.domain("a.com"))
        scope.add(Target.domain("b.com"))
        assert scope.hosts == ["a.com", "b.com"]

    def test_iteration(self):
        scope = TargetScope()
        scope.add(Target.domain("a.com"))
        scope.add(Target.domain("b.com"))
        hosts = [t.host for t in scope]
        assert hosts == ["a.com", "b.com"]
