package easm.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.scanner.AuditConfiguration;
import burp.api.montoya.scanner.BuiltInAuditConfiguration;
import burp.api.montoya.scanner.CrawlConfiguration;
import burp.api.montoya.scanner.Crawl;
import burp.api.montoya.scanner.audit.Audit;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.http.message.requests.HttpRequest;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * EASM Scan Manager — Burp Suite Montoya API extension.
 *
 * Exposes an HTTP REST API (default port 8888) that allows programmatic
 * management of Burp Scanner tasks, including the ability to CANCEL
 * running scans via the Montoya {@code Task.delete()} method — something
 * the native Burp REST API (port 1337) does NOT support.
 *
 * Endpoints:
 *   POST   /scan              — Start a new crawl + audit for a URL
 *   GET    /scans             — List all tracked scans
 *   GET    /scan/{id}         — Poll scan status & metrics
 *   GET    /scan/{id}/issues  — Export discovered issues as JSON
 *   DELETE /scan/{id}         — Cancel/delete a running scan
 *   GET    /health            — Health check
 */
public class EasmScanManager implements BurpExtension {

    private MontoyaApi api;
    private HttpServer server;
    private final ConcurrentHashMap<Integer, ScanEntry> scans = new ConcurrentHashMap<>();
    private final AtomicInteger nextId = new AtomicInteger(1);

    // ── Internal scan tracking ───────────────────────────────────────────────

    static class ScanEntry {
        final int id;
        final String url;
        final Crawl crawl;   // content discovery (may be null if crawl failed)
        final Audit audit;   // vulnerability testing
        final long startTimeMs;
        volatile boolean deleted;

        ScanEntry(int id, String url, Crawl crawl, Audit audit) {
            this.id = id;
            this.url = url;
            this.crawl = crawl;
            this.audit = audit;
            this.startTimeMs = System.currentTimeMillis();
        }

        /**
         * Derive a machine-readable status from Burp's human-readable
         * statusMessage().  Returns: running | succeeded | failed |
         * cancelled | paused | unknown.
         */
        String scanStatus() {
            if (deleted) return "cancelled";
            try {
                String msg = audit.statusMessage();
                if (msg == null) return "running";
                String lower = msg.toLowerCase();
                if (lower.contains("complete") || lower.contains("finish")
                        || lower.contains("succeeded")) {
                    return "succeeded";
                }
                if (lower.contains("paused")) return "paused";
                if (lower.contains("fail")) return "failed";
                return "running";
            } catch (Exception e) {
                return deleted ? "cancelled" : "unknown";
            }
        }
    }

    // ── Extension lifecycle ──────────────────────────────────────────────────

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("EASM Scan Manager");

        int port = 8888;
        String portEnv = System.getenv("EASM_EXT_PORT");
        if (portEnv != null && !portEnv.isEmpty()) {
            try { port = Integer.parseInt(portEnv); } catch (NumberFormatException ignored) {}
        }

        try {
            server = HttpServer.create(new InetSocketAddress("0.0.0.0", port), 0);
            server.createContext("/scan", this::handleScanRoutes);
            server.createContext("/scans", this::handleListScans);
            server.createContext("/health", this::handleHealth);
            server.setExecutor(Executors.newFixedThreadPool(4));
            server.start();
            api.logging().logToOutput("[EASM] Scan Manager API ready on port " + port);
        } catch (IOException e) {
            api.logging().logToError("[EASM] HTTP server failed: " + e.getMessage());
            return;
        }

        api.extension().registerUnloadingHandler(() -> {
            if (server != null) {
                server.stop(1);
                api.logging().logToOutput("[EASM] Scan Manager API stopped.");
            }
        });
    }

    // ── Route handlers ───────────────────────────────────────────────────────

    private void handleHealth(HttpExchange ex) throws IOException {
        sendJson(ex, 200, "{\"status\":\"ok\",\"scans\":" + scans.size() + "}");
    }

    private void handleListScans(HttpExchange ex) throws IOException {
        if (!"GET".equalsIgnoreCase(ex.getRequestMethod())) {
            sendJson(ex, 405, "{\"error\":\"method_not_allowed\"}");
            return;
        }
        StringBuilder sb = new StringBuilder("[");
        boolean first = true;
        for (ScanEntry entry : scans.values()) {
            if (!first) sb.append(',');
            first = false;
            sb.append(buildScanSummaryJson(entry));
        }
        sb.append(']');
        sendJson(ex, 200, sb.toString());
    }

    private void handleScanRoutes(HttpExchange ex) throws IOException {
        String path = ex.getRequestURI().getPath();
        String method = ex.getRequestMethod().toUpperCase();

        // POST /scan → start new scan
        if ("POST".equals(method) && (path.equals("/scan") || path.equals("/scan/"))) {
            handleStartScan(ex);
            return;
        }

        // Parse ID from /scan/{id}[/issues]
        String[] segments = path.split("/");
        if (segments.length < 3) {
            sendJson(ex, 400, "{\"error\":\"missing_scan_id\"}");
            return;
        }
        int scanId;
        try {
            scanId = Integer.parseInt(segments[2]);
        } catch (NumberFormatException e) {
            sendJson(ex, 400, "{\"error\":\"invalid_scan_id\"}");
            return;
        }

        ScanEntry entry = scans.get(scanId);
        if (entry == null) {
            sendJson(ex, 404, "{\"error\":\"scan_not_found\"}");
            return;
        }

        boolean wantsIssues = segments.length >= 4 && "issues".equals(segments[3]);
        switch (method) {
            case "GET":
                if (wantsIssues) handleGetIssues(ex, entry);
                else handleGetScanStatus(ex, entry);
                break;
            case "DELETE":
                handleCancelScan(ex, entry);
                break;
            default:
                sendJson(ex, 405, "{\"error\":\"method_not_allowed\"}");
        }
    }

    // ── POST /scan ───────────────────────────────────────────────────────────

    private void handleStartScan(HttpExchange ex) throws IOException {
        String body = readBody(ex);
        String url = jsonStringValue(body, "url");
        if (url == null || url.isBlank()) {
            sendJson(ex, 400, "{\"error\":\"missing_url\"}");
            return;
        }
        try {
            int id = nextId.getAndIncrement();

            // 1) Start crawl for content discovery
            Crawl crawl = null;
            try {
                CrawlConfiguration crawlCfg = CrawlConfiguration.crawlConfiguration(url);
                crawl = api.scanner().startCrawl(crawlCfg);
            } catch (Exception ce) {
                api.logging().logToOutput("[EASM] Crawl failed, audit-only: " + ce.getMessage());
            }

            // 2) Start audit with active checks + seed request
            AuditConfiguration auditCfg = AuditConfiguration.auditConfiguration(
                    BuiltInAuditConfiguration.LEGACY_ACTIVE_AUDIT_CHECKS);
            Audit audit = api.scanner().startAudit(auditCfg);
            audit.addRequest(HttpRequest.httpRequestFromUrl(url));

            ScanEntry entry = new ScanEntry(id, url, crawl, audit);
            scans.put(id, entry);

            api.logging().logToOutput("[EASM] Scan " + id + " started → " + url);
            sendJson(ex, 201,
                    "{\"scan_id\":" + id + ",\"url\":\"" + esc(url) + "\"}");
        } catch (Exception e) {
            api.logging().logToError("[EASM] Start failed: " + e.getMessage());
            sendJson(ex, 500, "{\"error\":\"" + esc(e.getMessage()) + "\"}");
        }
    }

    // ── GET /scan/{id} ──────────────────────────────────────────────────────

    private void handleGetScanStatus(HttpExchange ex, ScanEntry e) throws IOException {
        sendJson(ex, 200, buildScanDetailJson(e));
    }

    // ── GET /scan/{id}/issues ────────────────────────────────────────────────

    private void handleGetIssues(HttpExchange ex, ScanEntry e) throws IOException {
        StringBuilder sb = new StringBuilder("[");
        try {
            List<AuditIssue> issues = e.audit.issues();
            for (int i = 0; i < issues.size(); i++) {
                if (i > 0) sb.append(',');
                sb.append(buildIssueJson(i, issues.get(i)));
            }
        } catch (Exception err) {
            api.logging().logToError("[EASM] Issues read error: " + err.getMessage());
        }
        sb.append(']');
        sendJson(ex, 200, sb.toString());
    }

    // ── DELETE /scan/{id} ────────────────────────────────────────────────────

    private void handleCancelScan(HttpExchange ex, ScanEntry e) throws IOException {
        e.deleted = true;
        if (e.crawl != null) {
            try { e.crawl.delete(); } catch (Exception ignored) {}
        }
        try { e.audit.delete(); } catch (Exception ignored) {}
        api.logging().logToOutput("[EASM] Scan " + e.id + " cancelled.");
        sendJson(ex, 200, "{\"scan_id\":" + e.id + ",\"status\":\"cancelled\"}");
    }

    // ── JSON builders ────────────────────────────────────────────────────────

    private String buildScanSummaryJson(ScanEntry e) {
        int reqs = safeInt(() -> e.audit.requestCount());
        int errs = safeInt(() -> e.audit.errorCount());
        int issues = safeInt(() -> e.audit.issues().size());
        return "{\"scan_id\":" + e.id
                + ",\"url\":\"" + esc(e.url)
                + "\",\"status\":\"" + e.scanStatus()
                + "\",\"request_count\":" + reqs
                + ",\"error_count\":" + errs
                + ",\"issue_count\":" + issues + "}";
    }

    /**
     * Returns status JSON in a format compatible with the native REST API
     * that the burp_cli_wrapper poll function expects:
     *   scan_metrics.scan_status, scan_metrics.audit_requests_made, etc.
     */
    private String buildScanDetailJson(ScanEntry e) {
        int auditReqs  = safeInt(() -> e.audit.requestCount());
        int auditErrs  = safeInt(() -> e.audit.errorCount());
        int insPoints  = safeInt(() -> e.audit.insertionPointCount());
        int issueCount = safeInt(() -> e.audit.issues().size());
        String auditMsg = safeStr(() -> e.audit.statusMessage());

        int crawlReqs = 0;
        int crawlErrs = 0;
        String crawlMsg = "n/a";
        if (e.crawl != null) {
            crawlReqs = safeInt(() -> e.crawl.requestCount());
            crawlErrs = safeInt(() -> e.crawl.errorCount());
            crawlMsg  = safeStr(() -> e.crawl.statusMessage());
        }

        String status = e.scanStatus();
        return "{\"scan_id\":" + e.id
                + ",\"url\":\"" + esc(e.url)
                + "\",\"scan_metrics\":{"
                + "\"scan_status\":\"" + status + "\""
                + ",\"audit_requests_made\":" + auditReqs
                + ",\"audit_queue_count\":0"
                + ",\"audit_errors\":" + auditErrs
                + ",\"crawl_requests_made\":" + crawlReqs
                + ",\"crawl_errors\":" + crawlErrs
                + ",\"insertion_point_count\":" + insPoints
                + ",\"issue_events\":" + issueCount
                + ",\"audit_status_message\":\"" + esc(auditMsg) + "\""
                + ",\"crawl_status_message\":\"" + esc(crawlMsg) + "\""
                + "}}";
    }

    private String buildIssueJson(int index, AuditIssue issue) {
        String name       = safeStr(() -> issue.name());
        String detail      = safeStr(() -> issue.detail());
        String remediation = safeStr(() -> issue.remediation());
        String severity    = safeStr(() -> issue.severity().name().toLowerCase());
        String confidence  = safeStr(() -> issue.confidence().name().toLowerCase());
        String baseUrl     = safeStr(() -> issue.baseUrl());

        return "{\"id\":\"" + index
                + "\",\"type\":\"issue_found\",\"issue\":{"
                + "\"name\":\"" + esc(name)
                + "\",\"severity\":\"" + esc(severity)
                + "\",\"confidence\":\"" + esc(confidence)
                + "\",\"origin\":\"" + esc(baseUrl)
                + "\",\"description\":\"" + esc(detail)
                + "\",\"remediation\":\"" + esc(remediation)
                + "\"}}";
    }

    // ── HTTP helpers ─────────────────────────────────────────────────────────

    private String readBody(HttpExchange ex) throws IOException {
        try (InputStream is = ex.getRequestBody()) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    private void sendJson(HttpExchange ex, int code, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }

    // ── Utility helpers ──────────────────────────────────────────────────────

    @FunctionalInterface
    interface IntSupplier { int get() throws Exception; }

    @FunctionalInterface
    interface StrSupplier { String get() throws Exception; }

    private static int safeInt(IntSupplier s) {
        try { return s.get(); } catch (Exception e) { return 0; }
    }

    private static String safeStr(StrSupplier s) {
        try { String v = s.get(); return v != null ? v : ""; }
        catch (Exception e) { return ""; }
    }

    /** Escape a string for safe embedding inside JSON double-quoted values. */
    private static String esc(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': sb.append("\\\\"); break;
                case '"':  sb.append("\\\""); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Minimal JSON string extractor — no external dependencies.
     * Finds the first occurrence of "key": "value" and returns value.
     */
    private static String jsonStringValue(String json, String key) {
        if (json == null || key == null) return null;
        String needle = "\"" + key + "\"";
        int ki = json.indexOf(needle);
        if (ki < 0) return null;
        int ci = json.indexOf(':', ki + needle.length());
        if (ci < 0) return null;
        int qi = json.indexOf('"', ci + 1);
        if (qi < 0) return null;
        int end = qi + 1;
        while (end < json.length()) {
            char ch = json.charAt(end);
            if (ch == '\\') { end += 2; continue; }
            if (ch == '"') break;
            end++;
        }
        if (end >= json.length()) return null;
        return json.substring(qi + 1, end)
                .replace("\\\"", "\"")
                .replace("\\\\", "\\");
    }
}
