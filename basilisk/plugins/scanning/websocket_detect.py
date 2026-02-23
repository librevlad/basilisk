"""WebSocket endpoint detection."""

from __future__ import annotations

import logging
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

logger = logging.getLogger(__name__)


class WebSocketDetectPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="websocket_detect",
        display_name="WebSocket Detector",
        category=PluginCategory.SCANNING,
        description="Detects WebSocket endpoints and upgrade support",
        produces=["websocket_endpoints"],
        timeout=15.0,
    )

    WS_PATHS = [
        "/ws", "/websocket", "/ws/", "/socket", "/socket.io/",
        "/sockjs/", "/cable", "/hub", "/signalr", "/signalr/negotiate",
        "/graphql", "/subscriptions",
    ]

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        ws_endpoints: list[dict] = []
        base_url = ""

        # Use pre-probed scheme from autonomous mode when available
        _pre = ctx.state.get("http_scheme", {}).get(target.host)
        if _pre:
            base_url = f"{_pre}://{target.host}"

        if not base_url:
            for scheme in ("https", "http"):
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(
                            f"{scheme}://{target.host}/", timeout=5.0,
                        )
                        base_url = f"{scheme}://{target.host}"
                        break
                except Exception as e:
                    logger.debug("websocket_detect: %s probe failed: %s", scheme, e)
                    continue

        if not base_url:
            return PluginResult.success(
                self.meta.name, target.host,
                findings=[Finding.info("Host not reachable")],
                data={"websocket_endpoints": []},
            )

        # Check main page for WebSocket references
        try:
            async with ctx.rate:
                resp = await ctx.http.get(f"{base_url}/", timeout=8.0)
                body = await resp.text(encoding="utf-8", errors="replace")
                if "websocket" in body.lower() or "ws://" in body or "wss://" in body:
                    findings.append(Finding.info(
                        "WebSocket references found in page source",
                        tags=["scanning", "websocket"],
                    ))
        except Exception as e:
            logger.debug("websocket_detect: page source check failed: %s", e)

        # Probe known WebSocket paths
        ws_headers = {
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Version": "13",
            "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
        }

        for path in self.WS_PATHS:
            if ctx.should_stop:
                break
            url = f"{base_url}{path}"
            try:
                async with ctx.rate:
                    resp = await ctx.http.get(
                        url, headers=ws_headers, timeout=5.0,
                    )
                    if resp.status == 101:
                        ws_endpoints.append({"path": path, "status": 101})
                        findings.append(Finding.info(
                            f"WebSocket endpoint: {path}",
                            evidence=f"HTTP 101 Switching Protocols at {url}",
                            tags=["scanning", "websocket"],
                        ))
                    elif resp.status in (200, 400) and resp.headers.get(
                        "upgrade", ""
                    ).lower() == "websocket":
                        ws_endpoints.append({"path": path, "status": resp.status})
            except Exception as e:
                logger.debug("websocket_detect: WS probe %s failed: %s", url, e)
                continue

        if not findings:
            findings.append(Finding.info(
                "No WebSocket endpoints detected",
                tags=["scanning", "websocket"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data={"websocket_endpoints": ws_endpoints},
        )
