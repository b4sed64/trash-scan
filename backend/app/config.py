"""Application configuration.

All values are read from the environment (or an ``.env`` file) so that no secret
is baked into an image, per PRD section 20.
"""
from __future__ import annotations

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="TRASHSCAN_", env_file=".env", extra="ignore")

    # Database -----------------------------------------------------------------
    database_url: str = "postgresql+psycopg://trashscan:trashscan@db:5432/trashscan"

    # Sessions ---------------------------------------------------------------
    session_cookie_name: str = "trashscan_session"
    csrf_cookie_name: str = "trashscan_csrf"
    csrf_header_name: str = "X-CSRF-Token"
    # Cookies are marked Secure by default; set to false only for plain-HTTP localhost.
    session_cookie_secure: bool = True
    session_idle_minutes: int = 30
    session_absolute_hours: int = 12

    # Argon2id parameters (conservative defaults; tune per deployment) ---------
    argon2_time_cost: int = 3
    argon2_memory_cost_kib: int = 65536
    argon2_parallelism: int = 2

    # CORS: the Vite dev server origin during development.
    frontend_origin: str = "http://localhost:5173"

    # Behaviour flags --------------------------------------------------------
    # When true the app performs live DNS resolution for scope previews. Tests
    # and offline environments set this to false.
    enable_dns_resolution: bool = True

    environment: str = "development"

    # Queue / worker -------------------------------------------------------
    redis_url: str = "redis://redis:6379/0"
    celery_task_always_eager: bool = False
    # "real" invokes pinned CLI tools; "fake" uses deterministic stub adapters.
    scanner_mode: str = "real"
    # Directory for per-execution bounded result directories.
    result_root: str = "/app/artifacts/scans"
    # Internal DNS resolvers for the lab (comma-separated). Empty = system.
    dns_resolvers: str = ""

    # Concurrency / rate controls (conservative defaults; PRD §22) ----------
    max_global_executions: int = 2
    max_per_target_executions: int = 1
    max_parallel_stages: int = 2
    dns_queries_per_second: int = 20
    http_requests_per_second: int = 10
    nuclei_requests_per_second: int = 10
    retry_max: int = 1
    retry_backoff_seconds: int = 5
    max_response_bytes: int = 2_000_000
    max_evidence_bytes: int = 8_000

    # Time limits ---------------------------------------------------------
    approval_window_minutes: int = 120
    max_runtime_minutes: int = 120
    cancel_grace_seconds: int = 10

    # SYN scan, OS detection, and UDP scan all need raw-packet capability. Off
    # until the Phase 0 spike proves the minimum Docker capability (PRD §19.1 / §28).
    allow_raw_packet: bool = False

    # UDP scan (Standard active only, same allow_raw_packet gate as SYN/OS
    # detection) is scoped to a fixed, curated list of well-known business-network
    # UDP services rather than a broad sweep — DNS, DHCP, TFTP, NTP, NetBIOS, SNMP,
    # CLDAP, IPsec/ISAKMP, syslog, RIP, IPP, SSDP, IPsec NAT-T, mDNS — matching the
    # same "fixed, product-bounded set" approach as the TCP port lists below.
    standard_udp_ports: str = "53,67,68,69,123,137,138,161,162,389,500,514,520,631,1900,4500,5353"

    # External OSINT lookups (crt.sh Certificate Transparency, WHOIS/RDAP) send
    # the target domain to a third-party public service at scan time — a
    # different trust posture than the pinned CLI tool bundle. Off by default
    # (PRD §29 "broader OSINT providers", deferred until explicitly enabled).
    enable_external_osint: bool = False

    # Active-profile port sets (administrator-defined, product-bounded) --------
    safe_active_ports: str = "22,25,53,80,110,143,389,443,445,636,993,995,3306,3389,5432,8080,8443"
    standard_active_ports: str = (
        "1-1024,1433,1521,2049,2375,3000,3306,3389,5432,5900,5985,6379,8000,8080,8443,9200,11211,27017"
    )
    # Nmap timing template chosen from product options (never a raw flag).
    nmap_timing_safe: str = "T2"
    nmap_timing_standard: str = "T3"
    # httpx redirects are NOT followed by default; the Location header is
    # captured and scope-checked instead (PRD §12.4).
    httpx_max_redirects: int = 0
    httpx_follow_redirects: bool = False

    # katana crawl bounds (product-fixed, never a raw/user-supplied flag). Depth
    # varies by profile like Nmap's timing template; page count and time budget
    # are single global caps.
    katana_depth_safe: int = 1
    katana_depth_standard: int = 2
    katana_max_pages_per_host: int = 25
    katana_crawl_duration_seconds: int = 60

    def resolver_list(self) -> list[str]:
        return [r.strip() for r in self.dns_resolvers.split(",") if r.strip()]

    def ports_for_profile(self, profile: str) -> str:
        return self.standard_active_ports if profile == "STANDARD_ACTIVE" else self.safe_active_ports

    def timing_for_profile(self, profile: str) -> str:
        return self.nmap_timing_standard if profile == "STANDARD_ACTIVE" else self.nmap_timing_safe

    def katana_depth_for_profile(self, profile: str) -> int:
        return self.katana_depth_standard if profile == "STANDARD_ACTIVE" else self.katana_depth_safe


@lru_cache
def get_settings() -> Settings:
    return Settings()
