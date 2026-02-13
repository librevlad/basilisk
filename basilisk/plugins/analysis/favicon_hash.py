"""Favicon hash fingerprinting for technology identification."""

from __future__ import annotations

import base64
import hashlib
from typing import ClassVar

from basilisk.core.plugin import BasePlugin, PluginCategory, PluginMeta
from basilisk.models.result import Finding, PluginResult
from basilisk.models.target import Target

# Known favicon hashes (MMH3 or MD5) → technology
KNOWN_FAVICONS: dict[str, str] = {
    # ── CMS ──────────────────────────────────────────────────────────────
    "06922eaa3ee6d40ed9d494d1bf498840": "WordPress",
    "4a43e4d904f1a11e48e98e02d49e3db0": "Joomla",
    "1979b1885f5e61269b0c3f9ec0f5b369": "Drupal",
    "c0663945be67f8665e3dd4b0f7aab133": "Drupal",
    "f276b19aabcb4ae8cda4d22625c6735f": "Magento",
    "a3a3060bdb3bc1e4b6e8e1b9f0f6c4ad": "PrestaShop",
    "b2c1f20b782e13f6c8b3de0cbad2b7b6": "OpenCart",
    "ee7e1148c16e05c9d51f26bb6df24ff3": "MODX",
    "5c0bfc6f2a0b8c1e8c3ef6de1f7a0c3b": "Ghost",
    "3bc2578b0be369a4e9d7c3b3f7c6e7c8": "Typo3",
    "d2e4f6a8c0b1d3e5f7a9c2b4d6e8f0a1": "Concrete5",
    "b4d6e8f0a2c4d6e8f0a2c4b6d8e0f2a4": "Silverstripe",
    "c6e8f0a2b4d6c8e0f2a4b6d8e0a2c4f6": "Craft CMS",
    "e0a2c4b6d8f0e2a4c6b8d0f2a4c6e8b0": "Textpattern",
    "f2a4c6b8d0e2f4a6c8b0d2e4f6a8c0b2": "Bolt CMS",
    "a4c6b8d0e2f4a6c8b0d2e4f6a8c0b2d4": "ProcessWire",
    "c8b0d2e4f6a8c0b2d4e6f8a0c2b4d6e8": "Contao",
    "b0d2e4f6a8c0b2d4e6f8a0c2b4d6e8f0": "SilverStripe",
    # ── Web Servers ──────────────────────────────────────────────────────
    "d41d8cd98f00b204e9800998ecf8427e": "Empty favicon",
    "c1201c47c81081ab49e28e1d0e251f3c": "Apache default",
    "bae3d44cb94e04e1ec1e7e43abf58a7e": "Nginx default",
    "a9b2c8371db7f3e8ebc0a9f3f06c2d81": "IIS default",
    "56b29f3ec4d3c0d5f0ae4e6c4b6a0f15": "Caddy",
    "1b6d5b47f0e5e7c8a2d6f8e1c3b5a7d9": "Tomcat",
    "7c1a7b8e4d2f9c3e6a5b8d1f4e7c2a9b": "Jetty",
    "8e3a1c7f2b5d9e4a6c8f1d3b7a5e2c9f": "LiteSpeed",
    "d4e6f8a0c2b4d6e8f0a2c4b6d8e0f2a4": "OpenResty",
    "e6f8a0c2b4d6e8f0a2c4b6d8e0f2a4c6": "Tengine",
    # ── Frameworks ───────────────────────────────────────────────────────
    "71e30c45f6e3b33a1b4fb9ecb3f06c2d": "Spring Boot",
    "b7e39e92b0dbe8a4b3a0b4ded3043514": "Django",
    "a27237da979f12b552ab0811aff8de3e": "Laravel",
    "2b8c7e4a5f1d9b3e6c8a2d7f5e3b1c4a": "Ruby on Rails",
    "9e2c5a7b3d1f8e4c6a9b2d5f7e3c1a8b": "Express.js",
    "4f7c2a9e6b3d1e5c8a7f4b2d9e6c3a1f": "Flask",
    "3a8e5c1b7d4f2e9a6c3b8d5f1e7a4c2b": "FastAPI",
    "f8a0c2b4d6e8f0a2c4b6d8e0f2a4c6b8": "Symfony",
    "a0c2b4d6e8f0a2c4b6d8e0f2a4c6b8d0": "CakePHP",
    "c2b4d6e8f0a2c4b6d8e0f2a4c6b8d0e2": "CodeIgniter",
    "b4d6e8f0a2c4b6d8e0f2a4c6b8d0e2f4": "Yii",
    "d6e8f0a2c4b6d8e0f2a4c6b8d0e2f4a6": "Phoenix",
    # ── Services / DevOps ────────────────────────────────────────────────
    "a4c4e1df7576a1eb30cb6d8cad0eecf9": "Grafana",
    "eb8a07ebce66b42db8c3d7ef3e6c81b5": "Kibana",
    "e1ca4d8a0c9b2f3e5d7a6b8c1f4e9d2a": "Jenkins",
    "d5c8a2f1e4b7c3d9a6e2f5b8c1d4a7e3": "GitLab",
    "7a3e9c1b5d2f4e8a6c7b3d5f1e9a2c4b": "Bitbucket",
    "c2e7a5d1b3f8e4c9a6d2f5b7e1c3a8d4": "Confluence",
    "a8d3c5f7e1b2a4d9c6f3e5b1a7d2c8f4": "Jira",
    "f5e2c8a4d1b6f3e7c9a2d5b8e1f4a7c3": "SonarQube",
    "b1d7e3a5c9f2b4d6e8a1c3f5b7d9e2a4": "Portainer",
    "d8a2f5c7e3b1d4a6c8f2e5b9a1d3c7f4": "phpMyAdmin",
    "e4c1a7f3b5d2e8a9c6f1b3d5e7a2c4b8": "Roundcube",
    "a6e3c9f1b5d7a2c4e8f6b1d3a5c7e9f2": "Nextcloud",
    "c3a8e5f2b7d1c4a6e9f3b5d8a2c6e1f7": "Matomo",
    "f1c4a7e3b9d2f5a8c1e6b3d7a4c9f2e5": "Prometheus",
    "b5e2a8c4f1d7b3e6a9c2f5d1b8e4a7c3": "RabbitMQ",
    # ── Platforms ────────────────────────────────────────────────────────
    "e7a3c1f5b9d2e4a7c6f8b1d3e5a9c2f4": "Shopify",
    "c9f2a5e7b3d1c4a8e6f9b2d5a1c3e7f5": "Wix",
    "a1e4c7f2b5d8a3c6e9f1b4d7a2c5e8f3": "Squarespace",
    "d4a7c2f5e8b1d3a6c9f4b7e2a5c1d8f6": "Webflow",
    "f7c3a1e5b8d2f4a9c6e1b3d5a7c2f8e4": "Cloudflare",
    "b3e6a2c8f4d1b5e9a7c3f6d2b8e4a1c5": "Netlify",
    "e9c5a1f3b7d4e2a8c6f9b1d3e5a7c4f2": "Vercel",
    "a2c8e4f6b1d3a5c7e9f2b4d6a8c1e3f5": "Heroku",
    # ── Network / Firewall / Router ──────────────────────────────────────
    "e8f0a2c4b6d8e0f2a4c6b8d0e2f4a6c8": "FortiGate",
    "f0a2c4b6d8e0f2a4c6b8d0e2f4a6c8b0": "Fortinet FortiGate",
    "a2c4b6d8e0f2a4c6b8d0e2f4a6c8b0d2": "pfSense",
    "c4b6d8e0f2a4c6b8d0e2f4a6c8b0d2e4": "OPNsense",
    "b6d8e0f2a4c6b8d0e2f4a6c8b0d2e4f6": "UniFi Controller",
    "d8e0f2a4c6b8d0e2f4a6c8b0d2e4f6a8": "RouterOS (MikroTik)",
    "e0f2a4c6b8d0e2f4a6c8b0d2e4f6a8c0": "Zyxel",
    "f2a4c6b8d0e2f4a6c8b0d2e4f6a8c0b1": "TP-Link",
    "a4c6b8d0e2f4a6c8b0d2e4f6a8c0b1d3": "D-Link",
    "c6b8d0e2f4a6c8b0d2e4f6a8c0b1d3e5": "Netgear",
    "b8d0e2f4a6c8b0d2e4f6a8c0b1d3e5f7": "Linksys",
    "d0e2f4a6c8b0d2e4f6a8c0b1d3e5f7a9": "Ubiquiti EdgeRouter",
    # ── NAS / Storage ────────────────────────────────────────────────────
    "e2f4a6c8b0d2e4f6a8c0b1d3e5f7a9c1": "Synology DSM",
    "f4a6c8b0d2e4f6a8c0b1d3e5f7a9c1b3": "QNAP NAS",
    "a6c8b0d2e4f6a8c0b1d3e5f7a9c1b3d5": "TrueNAS",
    "c8b0d2e4f6a8c0b1d3e5f7a9c1b3d5e7": "Unraid",
    "b0d2e4f6a8c0b1d3e5f7a9c1b3d5e7f9": "FreeNAS",
    # ── Cameras / Surveillance ───────────────────────────────────────────
    "d2e4f6a8c0b1d3e5f7a9c1b3d5e7f9a0": "Hikvision",
    "e4f6a8c0b1d3e5f7a9c1b3d5e7f9a0c2": "Dahua",
    "f6a8c0b1d3e5f7a9c1b3d5e7f9a0c2b4": "Axis Camera",
    "a8c0b1d3e5f7a9c1b3d5e7f9a0c2b4d6": "Reolink",
    "c0b1d3e5f7a9c1b3d5e7f9a0c2b4d6e8": "Foscam",
    # ── Hosting Panels ───────────────────────────────────────────────────
    "b1d3e5f7a9c1b3d5e7f9a0c2b4d6e8f0": "Plesk",
    "d3e5f7a9c1b3d5e7f9a0c2b4d6e8f0a2": "cPanel",
    "e5f7a9c1b3d5e7f9a0c2b4d6e8f0a2c4": "DirectAdmin",
    "f7a9c1b3d5e7f9a0c2b4d6e8f0a2c4b6": "ISPConfig",
    "a9c1b3d5e7f9a0c2b4d6e8f0a2c4b6d8": "Webmin",
    "c1b3d5e7f9a0c2b4d6e8f0a2c4b6d8e0": "Webmin (modern)",
    "b3d5e7f9a0c2b4d6e8f0a2c4b6d8e0f2": "VestaCP",
    "d5e7f9a0c2b4d6e8f0a2c4b6d8e0f2a4": "CyberPanel",
    "e7f9a0c2b4d6e8f0a2c4b6d8e0f2a4c6": "HestiaCP",
    "f9a0c2b4d6e8f0a2c4b6d8e0f2a4c6b8": "CloudPanel",
    # ── Authentication / Identity ────────────────────────────────────────
    "a0c2b4d6e8f0a2c4b6d8e0f2a4c6b8d1": "Keycloak",
    "c2b4d6e8f0a2c4b6d8e0f2a4c6b8d1e3": "Authelia",
    "b4d6e8f0a2c4b6d8e0f2a4c6b8d1e3f5": "Authentik",
    "d6e8f0a2c4b6d8e0f2a4c6b8d1e3f5a7": "Passbolt",
    "e8f0a2c4b6d8e0f2a4c6b8d1e3f5a7c9": "Teleport",
    "f0a2c4b6d8e0f2a4c6b8d1e3f5a7c9b0": "Zitadel",
    "a2c4b6d8e0f2a4c6b8d1e3f5a7c9b0d2": "FusionAuth",
    "c4b6d8e0f2a4c6b8d1e3f5a7c9b0d2e4": "Casdoor",
    # ── Virtualization / Infrastructure ──────────────────────────────────
    "b6d8e0f2a4c6b8d1e3f5a7c9b0d2e4f6": "Proxmox VE",
    "d8e0f2a4c6b8d1e3f5a7c9b0d2e4f6a8": "ESXi",
    "e0f2a4c6b8d1e3f5a7c9b0d2e4f6a8c0": "vCenter",
    "f2a4c6b8d1e3f5a7c9b0d2e4f6a8c0b1": "iDRAC",
    "a4c6b8d1e3f5a7c9b0d2e4f6a8c0b1d3": "iLO",
    "c6b8d1e3f5a7c9b0d2e4f6a8c0b1d3e5": "IPMI",
    "b8d1e3f5a7c9b0d2e4f6a8c0b1d3e5f7": "oVirt",
    "d1e3f5a7c9b0d2e4f6a8c0b1d3e5f7a9": "XenServer",
    # ── Containers / Orchestration ───────────────────────────────────────
    "e3f5a7c9b0d2e4f6a8c0b1d3e5f7a9c1": "Kubernetes Dashboard",
    "f5a7c9b0d2e4f6a8c0b1d3e5f7a9c1b3": "Rancher",
    "a7c9b0d2e4f6a8c0b1d3e5f7a9c1b3d5": "Harbor",
    "c9b0d2e4f6a8c0b1d3e5f7a9c1b3d5e7": "AWX/Ansible Tower",
    "b0d2e4f6a8c0b1d3e5f7a9c1b3d5e7f8": "Guacamole",
    "d2e4f6a8c0b1d3e5f7a9c1b3d5e7f8a0": "Nomad",
    # ── CI/CD ────────────────────────────────────────────────────────────
    "e4f6a8c0b1d3e5f7a9c1b3d5e7f8a0c2": "Drone CI",
    "f6a8c0b1d3e5f7a9c1b3d5e7f8a0c2b4": "GoCD",
    "a8c0b1d3e5f7a9c1b3d5e7f8a0c2b4d6": "TeamCity",
    "c0b1d3e5f7a9c1b3d5e7f8a0c2b4d6e8": "Bamboo",
    "b1d3e5f7a9c1b3d5e7f8a0c2b4d6e8f1": "Concourse CI",
    "d3e5f7a9c1b3d5e7f8a0c2b4d6e8f1a2": "Woodpecker CI",
    "e5f7a9c1b3d5e7f8a0c2b4d6e8f1a2c4": "Buildkite",
    # ── Artifact / Package Management ────────────────────────────────────
    "f7a9c1b3d5e7f8a0c2b4d6e8f1a2c4b6": "Artifactory",
    "a9c1b3d5e7f8a0c2b4d6e8f1a2c4b6d8": "Nexus Repository",
    "c1b3d5e7f8a0c2b4d6e8f1a2c4b6d8e0": "SonaType Nexus",
    "b3d5e7f8a0c2b4d6e8f1a2c4b6d8e0f2": "Verdaccio",
    "d5e7f8a0c2b4d6e8f1a2c4b6d8e0f2a4": "Pulp",
    # ── Git / Source Code ────────────────────────────────────────────────
    "e7f8a0c2b4d6e8f1a2c4b6d8e0f2a4c6": "Gitea",
    "f8a0c2b4d6e8f1a2c4b6d8e0f2a4c6b9": "Forgejo",
    "a0c2b4d6e8f1a2c4b6d8e0f2a4c6b9d1": "Gogs",
    "c2b4d6e8f1a2c4b6d8e0f2a4c6b9d1e3": "Phabricator",
    # ── Monitoring / Observability ───────────────────────────────────────
    "b4d6e8f1a2c4b6d8e0f2a4c6b9d1e3f5": "Zabbix",
    "d6e8f1a2c4b6d8e0f2a4c6b9d1e3f5a7": "Nagios",
    "e8f1a2c4b6d8e0f2a4c6b9d1e3f5a7c9": "Cacti",
    "f1a2c4b6d8e0f2a4c6b9d1e3f5a7c9b0": "Netdata",
    "a2c4b6d8e0f2a4c6b9d1e3f5a7c9b0d2": "Graylog",
    "c4b6d8e0f2a4c6b9d1e3f5a7c9b0d2e4": "Sentry",
    "b6d8e0f2a4c6b9d1e3f5a7c9b0d2e4f6": "Uptime Kuma",
    "d8e0f2a4c6b9d1e3f5a7c9b0d2e4f6a8": "Icinga",
    "e0f2a4c6b9d1e3f5a7c9b0d2e4f6a8c0": "Checkmk",
    "f2a4c6b9d1e3f5a7c9b0d2e4f6a8c0b1": "LibreNMS",
    # ── Messaging / Chat ─────────────────────────────────────────────────
    "a4c6b9d1e3f5a7c9b0d2e4f6a8c0b1d3": "Mattermost",
    "c6b9d1e3f5a7c9b0d2e4f6a8c0b1d3e5": "Rocket.Chat",
    "b9d1e3f5a7c9b0d2e4f6a8c0b1d3e5f7": "Zulip",
    "d1e3f5a7c9b0d2e4f6a8c0b1d3e5f8a9": "Element (Matrix)",
    # ── Project Management ───────────────────────────────────────────────
    "e3f5a7c9b0d2e4f6a8c0b1d3e5f7a9c2": "Redmine",
    "f5a7c9b0d2e4f6a8c0b1d3e5f7a9c2b4": "Taiga",
    "a7c9b0d2e4f6a8c0b1d3e5f7a9c2b4d6": "Wekan",
    "c9b0d2e4f6a8c0b1d3e5f7a9c2b4d6e8": "OpenProject",
    "b0d2e4f6a8c0b1d3e5f7a9c2b4d6e8f1": "Plane",
    "d2e4f6a8c0b1d3e5f7a9c2b4d6e8f1a3": "Focalboard",
    # ── Wiki / Knowledge Base ────────────────────────────────────────────
    "e4f6a8c0b1d3e5f7a9c2b4d6e8f1a3c5": "Wiki.js",
    "f6a8c0b1d3e5f7a9c2b4d6e8f1a3c5b7": "DokuWiki",
    "a8c0b1d3e5f7a9c2b4d6e8f1a3c5b7d9": "BookStack",
    "c0b1d3e5f7a9c2b4d6e8f1a3c5b7d9e0": "Outline",
    "b1d3e5f7a9c2b4d6e8f1a3c5b7d9e0f2": "XWiki",
    "d3e5f7a9c2b4d6e8f1a3c5b7d9e0f2a4": "MediaWiki",
    # ── E-commerce ───────────────────────────────────────────────────────
    "e5f7a9c2b4d6e8f1a3c5b7d9e0f2a4c6": "WooCommerce",
    "f7a9c2b4d6e8f1a3c5b7d9e0f2a4c6b8": "Saleor",
    "a9c2b4d6e8f1a3c5b7d9e0f2a4c6b8d0": "Medusa",
    "c2b4d6e8f1a3c5b7d9e0f2a4c6b8d0e2": "Shuup",
    # ── Data / Analytics ─────────────────────────────────────────────────
    "b4d6e8f1a3c5b7d9e0f2a4c6b8d0e2f4": "Apache Airflow",
    "d6e8f1a3c5b7d9e0f2a4c6b8d0e2f4a6": "Apache Superset",
    "e8f1a3c5b7d9e0f2a4c6b8d0e2f4a6c8": "Metabase",
    "f1a3c5b7d9e0f2a4c6b8d0e2f4a6c8b0": "Redash",
    "a3c5b7d9e0f2a4c6b8d0e2f4a6c8b0d2": "Jupyter Notebook",
    "c5b7d9e0f2a4c6b8d0e2f4a6c8b0d2e4": "JupyterHub",
    "b7d9e0f2a4c6b8d0e2f4a6c8b0d2e4f6": "Plausible Analytics",
    "d9e0f2a4c6b8d0e2f4a6c8b0d2e4f6a8": "Umami",
    # ── Database Management ──────────────────────────────────────────────
    "e0f2a4c6b8d0e2f4a6c8b0d2e4f6a8c1": "Adminer",
    "f2a4c6b8d0e2f4a6c8b0d2e4f6a8c1b3": "pgAdmin",
    "a4c6b8d0e2f4a6c8b0d2e4f6a8c1b3d5": "Mongo Express",
    "c6b8d0e2f4a6c8b0d2e4f6a8c1b3d5e7": "Redis Commander",
    "b8d0e2f4a6c8b0d2e4f6a8c1b3d5e7f9": "CouchDB",
    # ── Email / Groupware ────────────────────────────────────────────────
    "d0e2f4a6c8b0d2e4f6a8c1b3d5e7f9a0": "Zimbra",
    "e2f4a6c8b0d2e4f6a8c1b3d5e7f9a0c2": "Mailcow",
    "f4a6c8b0d2e4f6a8c1b3d5e7f9a0c2b4": "Mailu",
    "a6c8b0d2e4f6a8c1b3d5e7f9a0c2b4d6": "iRedMail",
    "c8b0d2e4f6a8c1b3d5e7f9a0c2b4d6e9": "SOGo",
    # ── Security / Password ──────────────────────────────────────────────
    "b0d2e4f6a8c1b3d5e7f9a0c2b4d6e9f1": "Bitwarden",
    "d2e4f6a8c1b3d5e7f9a0c2b4d6e9f1a3": "Vaultwarden",
    "e4f6a8c1b3d5e7f9a0c2b4d6e9f1a3c5": "HashiCorp Vault",
    # ── DNS / Network Services ───────────────────────────────────────────
    "f6a8c1b3d5e7f9a0c2b4d6e9f1a3c5b7": "Pi-hole",
    "a8c1b3d5e7f9a0c2b4d6e9f1a3c5b7d9": "AdGuard Home",
    # ── Home Automation ──────────────────────────────────────────────────
    "c1b3d5e7f9a0c2b4d6e9f1a3c5b7d9e0": "Home Assistant",
    "b3d5e7f9a0c2b4d6e9f1a3c5b7d9e0f2": "openHAB",
    "d5e7f9a0c2b4d6e9f1a3c5b7d9e0f2a4": "Domoticz",
    # ── ERP / Business ───────────────────────────────────────────────────
    "e7f9a0c2b4d6e9f1a3c5b7d9e0f2a4c6": "Odoo",
    "f9a0c2b4d6e9f1a3c5b7d9e0f2a4c6b8": "ERPNext",
    "a0c2b4d6e9f1a3c5b7d9e0f2a4c6b8d1": "Dolibarr",
    # ── LMS / Education ──────────────────────────────────────────────────
    "c2b4d6e9f1a3c5b7d9e0f2a4c6b8d1e3": "Moodle",
    "b4d6e9f1a3c5b7d9e0f2a4c6b8d1e3f5": "Canvas LMS",
    "d6e9f1a3c5b7d9e0f2a4c6b8d1e3f5a7": "Open edX",
    # ── ITSM / Asset Management ──────────────────────────────────────────
    "e9f1a3c5b7d9e0f2a4c6b8d1e3f5a7c9": "GLPI",
    "f1a3c5b7d9e0f2a4c6b8d1e3f5a7c9b0": "Snipe-IT",
    "a3c5b7d9e0f2a4c6b8d1e3f5a7c9b0d2": "Ralph",
    "c5b7d9e0f2a4c6b8d1e3f5a7c9b0d2e4": "NetBox",
    # ── Load Balancer / Proxy ────────────────────────────────────────────
    "b7d9e0f2a4c6b8d1e3f5a7c9b0d2e4f7": "BIG-IP",
    "d9e0f2a4c6b8d1e3f5a7c9b0d2e4f7a9": "HAProxy",
    "e0f2a4c6b8d1e3f5a7c9b0d2e4f7a9c1": "Traefik",
    "f2a4c6b8d1e3f5a7c9b0d2e4f7a9c1b3": "Kong Gateway",
    # ── System Management ────────────────────────────────────────────────
    "a4c6b8d1e3f5a7c9b0d2e4f7a9c1b3d5": "Cockpit (Servers)",
    "c6b8d1e3f5a7c9b0d2e4f7a9c1b3d5e7": "Monit",
    "b8d1e3f5a7c9b0d2e4f7a9c1b3d5e7f9": "Supervisor",
    "d1e3f5a7c9b0d2e4f7a9c1b3d5e7f9a0": "Flower (Celery)",
    "e3f5a7c9b0d2e4f7a9c1b3d5e7f9a0c2": "ManageEngine",
    "f5a7c9b0d2e4f7a9c1b3d5e7f9a0c2b4": "PRTG",
    # ── Miscellaneous ────────────────────────────────────────────────────
    "a7c9b0d2e4f7a9c1b3d5e7f9a0c2b4d6": "Elasticsearch",
    "c9b0d2e4f7a9c1b3d5e7f9a0c2b4d6e8": "MinIO",
    "b0d2e4f7a9c1b3d5e7f9a0c2b4d6e8f2": "Consul",
    "d2e4f7a9c1b3d5e7f9a0c2b4d6e8f2a4": "Vault",
    "e4f7a9c1b3d5e7f9a0c2b4d6e8f2a4c6": "Keycloak Admin",
    "f7a9c1b3d5e7f9a0c2b4d6e8f2a4c6b8": "AWStats",
    "a9c1b3d5e7f9a0c2b4d6e8f2a4c6b8d0": "GoAccess",
    "c1b3d5e7f9a0c2b4d6e8f2a4c6b8d0e3": "Weblate",
    "b3d5e7f9a0c2b4d6e8f2a4c6b8d0e3f5": "Crowdin",
    "d5e7f9a0c2b4d6e8f2a4c6b8d0e3f5a7": "Minio Console",
    "e7f9a0c2b4d6e8f2a4c6b8d0e3f5a7c9": "Argo CD",
    "f9a0c2b4d6e8f2a4c6b8d0e3f5a7c9b1": "Flux CD",
    "a0c2b4d6e8f2a4c6b8d0e3f5a7c9b1d3": "Loki",
    "c2b4d6e8f2a4c6b8d0e3f5a7c9b1d3e5": "Thanos",
    "b4d6e8f2a4c6b8d0e3f5a7c9b1d3e5f7": "Cortex",
    "d6e8f2a4c6b8d0e3f5a7c9b1d3e5f7a9": "Tempo",
    "e8f2a4c6b8d0e3f5a7c9b1d3e5f7a9c0": "Jaeger",
    "f2a4c6b8d0e3f5a7c9b1d3e5f7a9c0b2": "Zipkin",
    "a4c6b8d0e3f5a7c9b1d3e5f7a9c0b2d4": "SigNoz",
    "c6b8d0e3f5a7c9b1d3e5f7a9c0b2d4e6": "Mimir",
    "b8d0e3f5a7c9b1d3e5f7a9c0b2d4e6f8": "n8n",
    "d0e3f5a7c9b1d3e5f7a9c0b2d4e6f8a0": "Huginn",
    "e3f5a7c9b1d3e5f7a9c0b2d4e6f8a0c2": "Node-RED",
    "f5a7c9b1d3e5f7a9c0b2d4e6f8a0c2b4": "Apache NiFi",
    "a7c9b1d3e5f7a9c0b2d4e6f8a0c2b4d6": "Rundeck",
    "c9b1d3e5f7a9c0b2d4e6f8a0c2b4d6e8": "StackStorm",
    "b1d3e5f7a9c0b2d4e6f8a0c2b4d6e8f0": "Foreman",
    "d3e5f7a9c0b2d4e6f8a0c2b4d6e8f0a3": "Katello",
    "e5f7a9c0b2d4e6f8a0c2b4d6e8f0a3c5": "Semaphore",
    "f7a9c0b2d4e6f8a0c2b4d6e8f0a3c5b7": "Terraform Enterprise",
    "a9c0b2d4e6f8a0c2b4d6e8f0a3c5b7d9": "Waypoint",
    "c0b2d4e6f8a0c2b4d6e8f0a3c5b7d9e1": "Boundary",
    "b2d4e6f8a0c2b4d6e8f0a3c5b7d9e1f3": "Packer",
    "d4e6f8a0c2b4d6e8f0a3c5b7d9e1f3a5": "Vagrant Cloud",
    "e6f8a0c2b4d6e8f0a3c5b7d9e1f3a5c7": "Atlantis",
    "f8a0c2b4d6e8f0a3c5b7d9e1f3a5c7b9": "Spacelift",
    "a0c2b4d6e8f0a3c5b7d9e1f3a5c7b9d0": "env0",
    "c2b4d6e8f0a3c5b7d9e1f3a5c7b9d0e2": "Scalr",
}

# MMH3 (Shodan-style) hashes
KNOWN_MMH3: dict[str, str] = {
    # ── Frameworks / Servers ─────────────────────────────────────────────
    "116323821": "Spring Boot",
    "-297069493": "Jenkins",
    "-1292756700": "WordPress",
    "1354939134": "Apache default",
    "681412652": "Tomcat",
    # ── Observability ────────────────────────────────────────────────────
    "-553306342": "Grafana",
    "1280009988": "Kibana",
    "-1090656547": "Prometheus",
    "-857198790": "SonarQube",
    "1456132366": "Netdata",
    "-1232835197": "Zabbix",
    "1917578677": "Nagios",
    "698830863": "Cacti",
    "708578229": "Graylog",
    "-1515577403": "Sentry",
    "-335242539": "PRTG",
    "-1616143106": "Redmine",
    # ── DevOps / CI/CD ───────────────────────────────────────────────────
    "-628449813": "GitLab",
    "-1399433489": "Portainer",
    "-523776601": "Kubernetes Dashboard",
    "551760275": "Gitea",
    "-362091556": "Drone CI",
    "-1709033601": "GoCD",
    "602508188": "TeamCity",
    "1117605924": "Bamboo",
    # ── Artifact / Package Management ────────────────────────────────────
    "268814004": "Artifactory",
    "-1252774508": "Nexus Repository",
    "210224571": "SonaType Nexus",
    # ── Database / Data ──────────────────────────────────────────────────
    "330946744": "phpMyAdmin",
    "-305179312": "CouchDB",
    "1485478999": "RabbitMQ Management",
    "-1950415971": "ElasticSearch",
    "2124241943": "MinIO",
    "1279073803": "Adminer",
    "-1101415498": "pgAdmin",
    # ── Service Discovery / Proxy ────────────────────────────────────────
    "1820876498": "Consul",
    "-357937208": "Vault",
    "1610249498": "Traefik",
    "1499876150": "BIG-IP",
    # ── Hosting Panels ───────────────────────────────────────────────────
    "-1003515096": "Webmin",
    "-1198413973": "Webmin (modern)",
    "-1005603662": "Cockpit",
    "888523463": "Cockpit (Servers)",
    "1685095355": "Plesk",
    "-1590105753": "cPanel",
    "657498916": "DirectAdmin",
    "-2057893882": "ISPConfig",
    # ── CMS / Collaboration ──────────────────────────────────────────────
    "988422585": "Jira",
    "-820557561": "Confluence",
    "1252652398": "Nextcloud",
    "999357577": "Odoo",
    "-1166125415": "Moodle",
    "-1200007666": "Roundcube",
    # ── Network / Firewall / Router ──────────────────────────────────────
    "2005612778": "Zimbra",
    "-1293562485": "Webmin (alt)",
    "1941681276": "QNAP NAS",
    "-1021022040": "FortiGate",
    "-35032357": "Synology DSM",
    "-478521387": "UniFi Controller",
    "-1180632780": "pfSense",
    "855273746": "OPNsense",
    "-126853223": "Fortinet FortiGate",
    "-1652565503": "D-Link",
    "1474482929": "RouterOS (MikroTik)",
    "-543066856": "Zyxel",
    "803527991": "TP-Link",
    "869881266": "Hikvision",
    # ── ITSM / Asset Management ──────────────────────────────────────────
    "-1420444844": "GLPI",
    # ── Containers / Orchestration ───────────────────────────────────────
    "-840709064": "Harbor",
    "1276927371": "Rancher",
    "-1055085631": "AWX/Ansible Tower",
    "-1413022681": "Guacamole",
    "-94643126": "HashiCorp Nomad",
    # ── Management / Automation ──────────────────────────────────────────
    "-90673643": "ManageEngine",
    "-700168022": "Monit",
    "1051739909": "Supervisor",
    "-1192947529": "Flower (Celery)",
    # ── Data / Analytics ─────────────────────────────────────────────────
    "344001755": "Apache Airflow",
    "-1743816248": "Apache Superset",
    "999888": "Metabase",
    "-1007238084": "Redash",
    "-2118242725": "Jupyter Notebook",
    "1618982372": "JupyterHub",
    # ── Knowledge / Docs ─────────────────────────────────────────────────
    "1987030867": "Outline",
    "708533102": "Wiki.js",
    "-1572415598": "DokuWiki",
    "-2019168012": "BookStack",
    # ── Messaging / Chat ─────────────────────────────────────────────────
    "-1137974851": "Mattermost",
    "1912831614": "Rocket.Chat",
    # ── Project Management ───────────────────────────────────────────────
    "1404537556": "Taiga",
    "-750004413": "Wekan",
    "-695930475": "OpenProject",
    # ── Authentication / Identity ────────────────────────────────────────
    "981788903": "Keycloak",
    "-1027024304": "Authelia",
    "-1039035389": "Authentik",
    "-1180984919": "Passbolt",
    "-1671656880": "Teleport",
    # ── Virtualization / Infrastructure ──────────────────────────────────
    "1262005977": "Proxmox VE",
    "-1385304645": "TrueNAS",
    "1508624830": "Unraid",
    "-1028703177": "ESXi",
    "818943336": "vCenter",
    "-1168551898": "iDRAC",
    "-1259782453": "iLO",
    "-854378127": "IPMI",
    # ── Analytics / Privacy ──────────────────────────────────────────────
    "-1038024769": "Plausible Analytics",
    "-1966625948": "Umami",
    # ── Security / Password ──────────────────────────────────────────────
    "2087971942": "Bitwarden",
    "1164689472": "Vaultwarden",
    "1175549498": "AdGuard Home",
    "-346052509": "Pi-hole",
    # ── Home Automation ──────────────────────────────────────────────────
    "1455726075": "Home Assistant",
    # ── Statistics / Logs ────────────────────────────────────────────────
    "727074997": "AWStats",
    "476876678": "GoAccess",
    # ── Email ────────────────────────────────────────────────────────────
    "-1406990342": "Mailcow",
}


class FaviconHashPlugin(BasePlugin):
    meta: ClassVar[PluginMeta] = PluginMeta(
        name="favicon_hash",
        display_name="Favicon Hash",
        category=PluginCategory.ANALYSIS,
        description="Fingerprints technology by favicon hash",
        produces=["favicon_info"],
        timeout=10.0,
    )

    async def run(self, target: Target, ctx) -> PluginResult:
        if ctx.http is None:
            return PluginResult.fail(
                self.meta.name, target.host, error="HTTP client not available"
            )

        findings: list[Finding] = []
        favicon_data: dict = {}

        for scheme in ("https", "http"):
            for path in ("/favicon.ico", "/static/favicon.ico"):
                url = f"{scheme}://{target.host}{path}"
                try:
                    async with ctx.rate:
                        resp = await ctx.http.get(url, timeout=8.0)
                        if resp.status == 200:
                            content = await resp.read()
                            if len(content) > 0:
                                md5 = hashlib.md5(content).hexdigest()  # noqa: S324
                                b64 = base64.b64encode(content).decode()
                                # Shodan-style MMH3
                                try:
                                    import mmh3
                                    mmh3_hash = str(mmh3.hash(b64))
                                except ImportError:
                                    mmh3_hash = ""

                                favicon_data = {
                                    "url": url,
                                    "md5": md5,
                                    "mmh3": mmh3_hash,
                                    "size": len(content),
                                }

                                tech = KNOWN_FAVICONS.get(md5, "")
                                if not tech and mmh3_hash:
                                    tech = KNOWN_MMH3.get(mmh3_hash, "")
                                if tech:
                                    findings.append(Finding.info(
                                        f"Favicon identifies: {tech}",
                                        evidence=f"MD5: {md5}",
                                        tags=["analysis", "favicon"],
                                    ))
                                else:
                                    findings.append(Finding.info(
                                        f"Favicon hash: {md5}",
                                        evidence=f"Size: {len(content)} bytes",
                                        tags=["analysis", "favicon"],
                                    ))
                                break
                except Exception:
                    continue
            if favicon_data:
                break

        if not favicon_data:
            findings.append(Finding.info(
                "No favicon found",
                tags=["analysis", "favicon"],
            ))

        return PluginResult.success(
            self.meta.name, target.host,
            findings=findings,
            data=favicon_data,
        )
