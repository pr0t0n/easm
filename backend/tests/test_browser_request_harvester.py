"""browser_request_harvester.py drives the already-running browser_runner
Playwright server to capture real HTTP request/response bodies from actual
browser traffic -- unlike offensive_operator_runner.py's existing
discovered_parameterized_requests path, which scrubs real values into
synthetic placeholders (_safe_body_template) before persisting. These tests
mock Playwright itself (fake page/context/browser) and the inventory
service, matching this repo's fake-db unit-test convention rather than
hitting a real database.
"""
from types import SimpleNamespace

from app.services import browser_request_harvester as harvester


class _FakeResponse:
    def __init__(self, status=200, headers=None, text=""):
        self.status = status
        self.headers = headers or {}
        self._text = text

    def text(self):
        return self._text


class _FakeRequest:
    def __init__(self, method, url, resource_type, headers=None, post_data="", response=None):
        self.method = method
        self.url = url
        self.resource_type = resource_type
        self.headers = headers or {}
        self._post_data = post_data
        self._response = response

    def post_data(self):
        return self._post_data

    def response(self):
        return self._response


class _FakePage:
    def __init__(self, requests_to_fire):
        self._requests_to_fire = requests_to_fire
        self._handler = None
        self.goto_calls = []

    def on(self, event_name, handler):
        assert event_name == "requestfinished"
        self._handler = handler

    def goto(self, url, wait_until=None, timeout=None):
        self.goto_calls.append(url)
        for req in self._requests_to_fire:
            self._handler(req)

    def evaluate(self, script):
        return "{}"


class _FakeContext:
    def __init__(self, page, extra_http_headers=None):
        self.page = page
        self.extra_http_headers = extra_http_headers

    def new_page(self):
        return self.page

    def cookies(self):
        return []


class _FakeBrowser:
    def __init__(self, context):
        self.context = context
        self.closed = False

    def new_context(self, extra_http_headers=None):
        self.context.extra_http_headers = extra_http_headers
        return self.context

    def close(self):
        self.closed = True


class _FakeChromium:
    def __init__(self, browser=None, connect_error=None):
        self.browser = browser
        self.connect_error = connect_error
        self.connected_urls = []

    def connect(self, url):
        self.connected_urls.append(url)
        if self.connect_error:
            raise self.connect_error
        return self.browser


class _FakePlaywright:
    def __init__(self, chromium):
        self.chromium = chromium

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _FakeInventoryService:
    def __init__(self, db, scan):
        self.upsert_endpoint_calls = []
        self.upsert_parameter_calls = []

    def upsert_endpoint(self, url, **kwargs):
        self.upsert_endpoint_calls.append((url, kwargs))
        return SimpleNamespace(id=1, normalized_url=url)

    def upsert_parameter(self, endpoint, name, **kwargs):
        self.upsert_parameter_calls.append((name, kwargs))
        return SimpleNamespace(id=1)


class _FakeDb:
    def __init__(self):
        self.added = []

    def add(self, row):
        self.added.append(row)

    def flush(self):
        pass


def _patch_playwright(monkeypatch, requests_to_fire, connect_error=None):
    page = _FakePage(requests_to_fire)
    context = _FakeContext(page)
    browser = _FakeBrowser(context)
    chromium = _FakeChromium(browser=browser, connect_error=connect_error)
    fake_pw = _FakePlaywright(chromium)

    import playwright.sync_api as sync_api_module
    monkeypatch.setattr(sync_api_module, "sync_playwright", lambda: fake_pw)
    return page, context, browser, chromium


def test_disabled_flag_skips_without_touching_playwright(monkeypatch):
    monkeypatch.setattr(harvester.settings, "enable_browser_request_harvester", False)

    result = harvester.harvest_target(_FakeDb(), SimpleNamespace(id=1), "http://target.local")

    assert result == {"status": "skipped", "reason": "browser_request_harvester_disabled"}


def test_browser_runner_unreachable_returns_clean_error(monkeypatch):
    monkeypatch.setattr(harvester.settings, "enable_browser_request_harvester", True)
    _patch_playwright(monkeypatch, requests_to_fire=[], connect_error=RuntimeError("connection refused"))

    result = harvester.harvest_target(_FakeDb(), SimpleNamespace(id=1), "http://target.local")

    assert result["status"] == "error"
    assert "browser_runner_unreachable" in result["reason"]


def test_captures_real_body_and_upserts_endpoint(monkeypatch):
    monkeypatch.setattr(harvester.settings, "enable_browser_request_harvester", True)
    fake_response = _FakeResponse(status=200, headers={"content-type": "application/json"}, text='{"id": 42}')
    fake_request = _FakeRequest(
        method="POST",
        url="http://target.local/rest/login",
        resource_type="xhr",
        headers={"content-type": "application/json"},
        post_data='{"email": "real@user.com", "password": "hunter2"}',
        response=fake_response,
    )
    _patch_playwright(monkeypatch, requests_to_fire=[fake_request])
    fake_inv = _FakeInventoryService(None, None)
    monkeypatch.setattr(harvester, "OffensiveInventoryService", lambda db, scan: fake_inv)

    db = _FakeDb()
    result = harvester.harvest_target(db, SimpleNamespace(id=7), "http://target.local", identity_key="")

    assert result["status"] == "success"
    assert result["requests_captured"] == 1
    assert result["requests_persisted"] == 1
    assert len(fake_inv.upsert_endpoint_calls) == 1
    assert fake_inv.upsert_endpoint_calls[0][0] == "http://target.local/rest/login"
    body_params = {name for name, _ in fake_inv.upsert_parameter_calls}
    assert body_params == {"email", "password"}

    assert len(db.added) == 1
    observed = db.added[0]
    assert observed.method == "POST"
    assert observed.is_mutating is True
    assert observed.request_body == {"body": '{"email": "real@user.com", "password": "hunter2"}'}
    assert observed.status_code == 200
    assert observed.response_excerpt == '{"id": 42}'


def test_non_xhr_fetch_document_requests_are_not_captured(monkeypatch):
    monkeypatch.setattr(harvester.settings, "enable_browser_request_harvester", True)
    image_request = _FakeRequest(method="GET", url="http://target.local/logo.png", resource_type="image")
    _patch_playwright(monkeypatch, requests_to_fire=[image_request])
    fake_inv = _FakeInventoryService(None, None)
    monkeypatch.setattr(harvester, "OffensiveInventoryService", lambda db, scan: fake_inv)

    result = harvester.harvest_target(_FakeDb(), SimpleNamespace(id=1), "http://target.local")

    assert result["requests_captured"] == 0
    assert fake_inv.upsert_endpoint_calls == []


def test_response_body_not_captured_for_non_text_content_type(monkeypatch):
    monkeypatch.setattr(harvester.settings, "enable_browser_request_harvester", True)
    fake_response = _FakeResponse(status=200, headers={"content-type": "image/png"}, text="binary-garbage")
    fake_request = _FakeRequest(
        method="GET", url="http://target.local/api/avatar", resource_type="xhr", response=fake_response,
    )
    _patch_playwright(monkeypatch, requests_to_fire=[fake_request])
    fake_inv = _FakeInventoryService(None, None)
    monkeypatch.setattr(harvester, "OffensiveInventoryService", lambda db, scan: fake_inv)

    db = _FakeDb()
    harvester.harvest_target(db, SimpleNamespace(id=1), "http://target.local")

    assert db.added[0].response_excerpt is None


def test_identity_headers_are_passed_to_new_context(monkeypatch):
    monkeypatch.setattr(harvester.settings, "enable_browser_request_harvester", True)
    _, context, _, _ = _patch_playwright(monkeypatch, requests_to_fire=[])
    fake_inv = _FakeInventoryService(None, None)
    monkeypatch.setattr(harvester, "OffensiveInventoryService", lambda db, scan: fake_inv)
    fake_material = SimpleNamespace(valid=True, headers={"Authorization": "Bearer abc"}, cookies={"session": "xyz"})
    monkeypatch.setattr(
        harvester, "_resolve_identity_headers",
        lambda db, scan, identity_key: {"Authorization": "Bearer abc", "Cookie": "session=xyz"} if identity_key else {},
    )

    harvester.harvest_target(_FakeDb(), SimpleNamespace(id=1), "http://target.local", identity_key="user_a")

    assert context.extra_http_headers == {"Authorization": "Bearer abc", "Cookie": "session=xyz"}
