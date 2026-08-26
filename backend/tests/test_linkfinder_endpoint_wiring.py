"""linkfinder is a required P08 tool but its output never reached
OffensiveEndpoint (only Finding text blobs via findings_extractor) -- the
poll_scan_work_item completion hook that calls
js_endpoint_extractor.process_crawl_result only reacted to
katana/katana-js/gospider/hakrawler. Also: linkfinder emits bare relative
paths (e.g. "/rest/products/search"), not absolute URLs, so simply adding it
to that tool list isn't enough -- extract_endpoints_from_crawl only keeps
lines starting with http(s) and silently drops everything else.
"""
import inspect

from app.workers import tasks


def test_linkfinder_is_resolved_against_the_crawled_target():
    stdout = "\n".join([
        "/rest/products/search?q=test",
        "api/Login",
        "https://external.example.com/callback",
        "",
        "   ",
    ])

    resolved = tasks._resolve_linkfinder_stdout_to_absolute_urls(stdout, "http://target.local:3000")

    assert resolved.splitlines() == [
        "http://target.local:3000/rest/products/search?q=test",
        "http://target.local:3000/api/Login",
        "https://external.example.com/callback",
    ]


def test_linkfinder_is_registered_in_the_js_endpoint_extraction_hook():
    source = inspect.getsource(tasks.poll_scan_work_item)
    hook_pos = source.index("JS endpoint extraction + high-value probe seeding")
    tool_list_end = source.index(":", hook_pos)
    tool_list_segment = source[hook_pos:tool_list_end]

    assert '"linkfinder"' in tool_list_segment
    assert '"katana"' in tool_list_segment  # sanity: still covers the pre-existing crawlers
