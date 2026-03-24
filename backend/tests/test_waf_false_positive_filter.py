import sys
import types
import os


# Permite importar app.graph.workflow sem depender do pacote langgraph no ambiente de teste.
langgraph_module = types.ModuleType("langgraph")
langgraph_graph_module = types.ModuleType("langgraph.graph")
langgraph_checkpoint_module = types.ModuleType("langgraph.checkpoint")
langgraph_checkpoint_memory_module = types.ModuleType("langgraph.checkpoint.memory")
celery_module = types.ModuleType("celery")


class _DummyStateGraph:
    def __init__(self, *args, **kwargs):
        pass


class _DummyMemorySaver:
    pass


class _DummyCelery:
    def __init__(self, *args, **kwargs):
        self.conf = self

    def update(self, **kwargs):
        return None

    def send_task(self, *args, **kwargs):
        raise RuntimeError("dummy celery send_task not available in unit test")


langgraph_graph_module.END = "END"
langgraph_graph_module.StateGraph = _DummyStateGraph
langgraph_checkpoint_memory_module.MemorySaver = _DummyMemorySaver
celery_module.Celery = _DummyCelery
celery_module.current_task = None

sys.modules.setdefault("langgraph", langgraph_module)
sys.modules.setdefault("langgraph.graph", langgraph_graph_module)
sys.modules.setdefault("langgraph.checkpoint", langgraph_checkpoint_module)
sys.modules.setdefault("langgraph.checkpoint.memory", langgraph_checkpoint_memory_module)
sys.modules.setdefault("celery", celery_module)

os.environ.setdefault("DATABASE_URL", "sqlite:///./test.db")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("CELERY_BROKER_URL", "redis://localhost:6379/0")
os.environ.setdefault("CELERY_RESULT_BACKEND", "redis://localhost:6379/0")

from app.graph.workflow import _suppress_waf_proxy_false_positives


def _finding(tool: str, **details):
    payload = {"tool": tool}
    payload.update(details)
    return {
        "title": f"{tool} finding",
        "severity": "info",
        "risk_score": 1,
        "source_worker": "analise_vulnerabilidade",
        "details": payload,
    }


def test_suppresses_nmap_vulscan_cve_when_waf_and_headers_indicate_cloudflare_proxy():
    findings = [
        _finding("wafw00f", waf_detected=True, waf_vendor="cloudflare"),
        _finding(
            "curl-headers",
            http_headers_raw="HTTP/1.1 200 OK\nServer: cloudflare\nCF-RAY: abc123",
        ),
        _finding(
            "nmap-vulscan",
            cve="CVE-2013-2961",
            evidence="Cloudflare http proxy in front of service",
        ),
    ]

    out = _suppress_waf_proxy_false_positives(
        findings,
        step_name="AnaliseVulnerabilidade",
        default_target="65.valid.com",
    )

    remaining_nmap_cves = [
        item
        for item in out
        if (item.get("details") or {}).get("tool") == "nmap-vulscan"
        and (item.get("details") or {}).get("cve")
    ]
    suppression_markers = [
        item
        for item in out
        if (item.get("details") or {}).get("suppressed_tool") == "nmap-vulscan"
    ]

    assert len(remaining_nmap_cves) == 0
    assert len(suppression_markers) == 1
    assert suppression_markers[0]["details"].get("suppressed_cve_count") == 1


def test_does_not_suppress_without_waf_detection():
    findings = [
        _finding(
            "curl-headers",
            http_headers_raw="HTTP/1.1 200 OK\nServer: cloudflare\nCF-RAY: abc123",
        ),
        _finding(
            "nmap-vulscan",
            cve="CVE-2013-2961",
            evidence="Cloudflare http proxy in front of service",
        ),
    ]

    out = _suppress_waf_proxy_false_positives(
        findings,
        step_name="AnaliseVulnerabilidade",
        default_target="65.valid.com",
    )

    remaining_nmap_cves = [
        item
        for item in out
        if (item.get("details") or {}).get("tool") == "nmap-vulscan"
        and (item.get("details") or {}).get("cve")
    ]

    assert len(remaining_nmap_cves) == 1


def test_does_not_suppress_when_headers_do_not_indicate_waf():
    findings = [
        _finding("wafw00f", waf_detected=True, waf_vendor="cloudflare"),
        _finding(
            "curl-headers",
            http_headers_raw="HTTP/1.1 200 OK\nServer: nginx",
        ),
        _finding(
            "nmap-vulscan",
            cve="CVE-2013-2961",
            evidence="Cloudflare http proxy in front of service",
        ),
    ]

    out = _suppress_waf_proxy_false_positives(
        findings,
        step_name="AnaliseVulnerabilidade",
        default_target="65.valid.com",
    )

    remaining_nmap_cves = [
        item
        for item in out
        if (item.get("details") or {}).get("tool") == "nmap-vulscan"
        and (item.get("details") or {}).get("cve")
    ]

    assert len(remaining_nmap_cves) == 1
