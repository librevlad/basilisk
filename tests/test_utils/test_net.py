"""Tests for NetUtils — TCP port scanning and banner grabbing."""

from unittest.mock import AsyncMock, patch

from basilisk.models.types import PortState
from basilisk.utils.net import NetUtils


class TestNetUtilsInit:
    def test_default_timeout(self):
        net = NetUtils()
        assert net.timeout == 3.0

    def test_custom_timeout(self):
        net = NetUtils(timeout=5.0)
        assert net.timeout == 5.0


class TestCheckPort:
    async def test_open_port(self):
        net = NetUtils()
        mock_writer = AsyncMock()
        with patch("basilisk.utils.net.asyncio.wait_for", new_callable=AsyncMock) as m:
            m.return_value = (AsyncMock(), mock_writer)
            result = await net.check_port("example.com", 80)
        assert result.port == 80
        assert result.state == PortState.OPEN

    async def test_closed_port(self):
        net = NetUtils()
        with patch("basilisk.utils.net.asyncio.wait_for", new_callable=AsyncMock) as m:
            m.side_effect = ConnectionRefusedError()
            result = await net.check_port("example.com", 80)
        assert result.state == PortState.CLOSED

    async def test_filtered_port(self):
        net = NetUtils()
        with patch("basilisk.utils.net.asyncio.wait_for", new_callable=AsyncMock) as m:
            m.side_effect = TimeoutError()
            result = await net.check_port("example.com", 80)
        assert result.state == PortState.FILTERED

    async def test_custom_timeout(self):
        net = NetUtils(timeout=1.0)
        mock_writer = AsyncMock()
        with patch("basilisk.utils.net.asyncio.wait_for", new_callable=AsyncMock) as m:
            m.return_value = (AsyncMock(), mock_writer)
            await net.check_port("example.com", 80, timeout=5.0)
            # Verify wait_for was called (timeout arg passed through)
            m.assert_called_once()


class TestScanPorts:
    async def test_scan_multiple(self):
        net = NetUtils()
        with patch.object(net, "check_port", new_callable=AsyncMock) as m:
            from basilisk.models.types import PortInfo
            m.side_effect = [
                PortInfo(port=80, state=PortState.OPEN),
                PortInfo(port=443, state=PortState.CLOSED),
            ]
            results = await net.scan_ports("example.com", [80, 443])
        assert len(results) == 2
        assert results[0].state == PortState.OPEN
        assert results[1].state == PortState.CLOSED


class TestGrabBanner:
    async def test_success(self):
        net = NetUtils()
        mock_reader = AsyncMock()
        mock_reader.read = AsyncMock(return_value=b"SSH-2.0-OpenSSH_8.9\r\n")
        mock_writer = AsyncMock()

        with patch("basilisk.utils.net.asyncio.wait_for", new_callable=AsyncMock) as wait_mock:
            # First call: open_connection returns (reader, writer)
            # Second call: reader.read returns banner data
            wait_mock.side_effect = [
                (mock_reader, mock_writer),
                b"SSH-2.0-OpenSSH_8.9\r\n",
            ]
            banner = await net.grab_banner("example.com", 22)
        assert "SSH" in banner

    async def test_error_returns_empty(self):
        net = NetUtils()
        with patch("basilisk.utils.net.asyncio.wait_for", new_callable=AsyncMock) as m:
            m.side_effect = TimeoutError()
            banner = await net.grab_banner("example.com", 22)
        assert banner == ""


class TestResolveSync:
    def test_success(self):
        with patch("basilisk.utils.net.socket.getaddrinfo") as m:
            m.return_value = [
                (2, 1, 6, "", ("1.2.3.4", 0)),
                (2, 1, 6, "", ("5.6.7.8", 0)),
            ]
            ips = NetUtils.resolve_sync("example.com")
        assert set(ips) == {"1.2.3.4", "5.6.7.8"}

    def test_failure(self):
        import socket
        with patch("basilisk.utils.net.socket.getaddrinfo") as m:
            m.side_effect = socket.gaierror("not found")
            ips = NetUtils.resolve_sync("nonexistent.example.com")
        assert ips == []
