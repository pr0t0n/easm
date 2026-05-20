---
skill_id: "skill.recon.surface_mapping"
name: "Complete Surface Mapping & Environment Analysis"
version: "1.0.0"
status: "approved"
category: "reconnaissance"
phase_ids: ["P01", "P02", "P03", "P04"]
supported_target_types: ["domain", "apex_domain", "subdomain", "url", "ip_address"]
risk_level: "low"
noise_level: "medium"
requires_authorization: true
required_tools:
  - httpx
  - curl
  - whatweb
  - katana
  - wafw00f
  - sslscan
optional_tools:
  - testssl
  - hakrawler
  - gospider
  - gau
  - waybackurls
  - theharvester
  - shodan
  - gitleaks
  - trufflehog
  - semgrep
fallback_tools:
  - curl
evidence_required:
  - tech_fingerprint
  - security_headers_audit
  - tls_certificate_profile
  - waf_detection_result
  - crawl_url_list
  - archive_url_list
  - js_endpoints_found
  - secrets_scan_result
exit_criteria:
  minimum_tools_attempted: 3
  minimum_evidence_items: 4
  validator_required: true
retry_policy:
  max_attempts: 2
  change_tool_on_retry: true
  reduce_rate_on_retry: true
allowed_execution_modes:
  - passive_recon
  - safe_validation
  - controlled_pentest
  - full_authorized_pentest
safety_rules:
  destructive_payloads_allowed: false
  scope_guard_required: true
  sensitive_data_redaction_required: true
  sast_output_collection_only: true
  no_code_execution_from_target: true
  secret_values_must_be_redacted: true
tags:
  - recon
  - fingerprinting
  - technology-detection
  - crawling
  - spidering
  - headers
  - tls
  - certificates
  - waf-detection
  - javascript-analysis
  - secret-scanning
  - sast
  - osint
  - surface-mapping
---

# Objective

Build a complete environmental profile of the target before any exploitation phase begins. This skill answers the question: **what is this target, how is it built, what does it expose, and what secrets has it leaked?** Output drives skill selection — you cannot choose the right vulnerability skill without knowing the technology stack, WAF presence, exposed attack surface, and historical endpoints.

# When To Use

Run this skill ONCE per target host/domain before any vulnerability testing phase. It is the mandatory prerequisite for:
- Choosing the correct injection payloads (tech stack determines SQLi syntax, SSTI engine, deserialization gadgets)
- Knowing whether a WAF is present (affects payload encoding strategy)
- Finding hidden endpoints that wordlist fuzzing alone misses (JS analysis, archives)
- Detecting already-leaked secrets in exposed repositories or JS bundles
- Understanding certificate scope for subdomain attack surface

Run AGAIN after significant new subdomains are discovered in P01.

# Preconditions

- Target host/URL is confirmed in scope
- At minimum one HTTP/HTTPS live URL available (from httpx_probe in P01/P02)
- Internet egress available from Kali runner

# Offensive Reasoning

Before attacking, a pentester needs to answer:

- **What technology runs here?** Ruby on Rails → mass assignment risk. PHP → type juggling, LFI. Java → deserialization. Node.js → prototype pollution. Python → SSTI with Jinja2.
- **What framework and version?** Known CVEs depend on exact version — Spring Boot 2.2.x has actuator exposure, WordPress 5.x has specific plugin CVEs.
- **Is there a WAF?** Cloudflare/Akamai/AWS WAF = payloads must be encoded differently. No WAF = raw payloads work.
- **What does the TLS certificate reveal?** SAN extensions expose ALL subdomains and internal hostnames. Certificate issuer reveals hosting provider.
- **What security headers are missing?** Missing CSP = XSS easier to exploit. Missing HSTS = downgrade possible. Missing X-Frame-Options = clickjacking viable.
- **What endpoints exist in JS bundles?** SPAs put API routes in JS — these are NOT found by directory brute-force.
- **What has been cached in Wayback Machine?** Old parameter names, deprecated endpoints, old API versions still running.
- **Are there secrets in exposed .git or JS bundles?** API keys, tokens, hardcoded passwords — immediate critical finding.
- **What does email/OSINT reveal?** Employee emails → credential stuffing, phishing, password reset attacks.

# Execution Strategy

## Phase A: Technology Fingerprinting

**HOW to fingerprint technology stack:**
```bash
TARGET="https://target.com"
HOST="target.com"

# Full HTTP probe with tech detection — most important single command
httpx -u "$TARGET" \
  -status-code -title -tech-detect -tls-probe \
  -server -content-type -web-server \
  -follow-redirects -no-color -json \
  -silent 2>/dev/null | tee /tmp/httpx_fingerprint.json
cat /tmp/httpx_fingerprint.json | python3 -m json.tool 2>/dev/null | \
  grep -E '"tech"|"server"|"title"|"status_code"|"webserver"'

# WhatWeb deep fingerprint (level 3 = aggressive — sends more probes)
whatweb --no-errors -a 3 --log-json=/tmp/whatweb.json "$TARGET" 2>/dev/null
cat /tmp/whatweb.json | python3 -m json.tool 2>/dev/null | \
  grep -A2 '"string"' | head -60

# Banner grab via curl — server header + X-Powered-By + framework hints
curl -sI "$TARGET" | grep -iE \
  "server:|x-powered-by:|x-aspnet|x-generator|x-drupal|x-wp|via:|x-varnish:|x-cache:"

# Identify CMS / framework from HTML meta tags and JS file names
curl -s "$TARGET" | grep -iE \
  'wordpress|drupal|joomla|laravel|django|rails|symfony|nextjs|nuxtjs|gatsby|react|angular|vue|wp-content|/wp-|Powered by' \
  | head -20
```

**HOW to detect server-side language and framework version:**
```bash
# Check generator meta tag
curl -s "$TARGET" | grep -i '<meta.*generator' | head -5

# PHP version disclosure (X-Powered-By: PHP/7.4.3)
curl -sI "$TARGET" | grep -i "php"

# ASP.NET version disclosure
curl -sI "$TARGET" | grep -iE "X-AspNet|X-AspNetMvc|__ViewState"

# WordPress version via readme.html or meta
curl -s "$TARGET/readme.html" | grep -i "version" | head -5
curl -s "$TARGET/?v=" | grep -io 'ver=[0-9.]*' | head -5

# Node.js / Express hints
curl -sI "$TARGET" | grep -iE "express|node|x-powered-by"

# Spring Boot actuator exposure (critical)
for path in /actuator /actuator/health /actuator/env /actuator/mappings /actuator/beans; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET$path")
  echo "Spring actuator $path: $status"
done

# Django debug mode (stack traces)
curl -s "$TARGET/DOESNOTEXIST_1337" | grep -i "django\|settings.py\|INSTALLED_APPS" | head -5
```

**HOW to detect CDN and hosting infrastructure:**
```bash
# CDN detection from response headers
curl -sI "$TARGET" | grep -iE \
  "cf-ray:|x-cache:|x-amz|cloudfront|fastly|akamai|x-sucuri|incapsula|x-cdn"

# Reverse DNS and hosting provider
dig +short "$HOST" | while read ip; do
  echo "IP: $ip"
  host "$ip" 2>/dev/null | grep -v "not found"
  # ASN lookup
  curl -s "https://ipinfo.io/${ip}" 2>/dev/null | python3 -m json.tool | grep -E '"org"|"asn"' || true
done
```

## Phase B: WAF Detection

**HOW to detect WAF and understand bypass requirements:**
```bash
# Primary WAF detection
wafw00f "$TARGET" 2>/dev/null | tee /tmp/waf_detection.txt
cat /tmp/waf_detection.txt | grep -iE "waf|firewall|detected|behind"

# Manual WAF detection via probe payloads (check if blocked)
# If WAF is present, these return 403/406/429/503 or WAF challenge page
WAF_PROBE='<script>alert(1)</script>'
status=$(curl -s -o /dev/null -w "%{http_code}" \
  "${TARGET}/?q=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${WAF_PROBE}')")")
echo "WAF probe response: $status"
# 200 = no WAF filtering; 403/406 = WAF present and blocking

# WAF fingerprint from error page
curl -s "${TARGET}/?q=%27%3Cscript%3E" | grep -iE \
  "cloudflare|sucuri|incapsula|imperva|barracuda|f5|fortiweb|modsecurity|akamai|fastly" | head -5

# Check rate limiting headers (WAF vs application-level)
curl -sI "$TARGET" | grep -iE "x-ratelimit|retry-after|x-sucuri|x-fw-|server:.*nginx" | head -10
```

## Phase C: HTTP Security Headers Audit

**HOW to perform complete security header audit:**
```bash
# Full header capture
curl -sI "$TARGET" -L | tee /tmp/response_headers.txt

# Parse each security header — presence and value
echo "=== SECURITY HEADERS AUDIT: $TARGET ==="

# HSTS
HSTS=$(grep -i "strict-transport-security" /tmp/response_headers.txt)
[ -n "$HSTS" ] && echo "[+] HSTS: $HSTS" || echo "[-] HSTS: MISSING — downgrade attack possible"

# Content-Security-Policy
CSP=$(grep -i "content-security-policy:" /tmp/response_headers.txt)
[ -n "$CSP" ] && echo "[+] CSP: $CSP" || echo "[-] CSP: MISSING — XSS exploitation easier"

# X-Frame-Options
XFO=$(grep -i "x-frame-options" /tmp/response_headers.txt)
[ -n "$XFO" ] && echo "[+] X-Frame-Options: $XFO" || echo "[-] X-Frame-Options: MISSING — clickjacking viable"

# X-Content-Type-Options
XCTO=$(grep -i "x-content-type-options" /tmp/response_headers.txt)
[ -n "$XCTO" ] && echo "[+] X-Content-Type-Options: $XCTO" || echo "[-] X-Content-Type-Options: MISSING"

# Permissions-Policy / Feature-Policy
PP=$(grep -i "permissions-policy\|feature-policy" /tmp/response_headers.txt)
[ -n "$PP" ] && echo "[+] Permissions-Policy: found" || echo "[-] Permissions-Policy: MISSING"

# Referrer-Policy
RP=$(grep -i "referrer-policy" /tmp/response_headers.txt)
[ -n "$RP" ] && echo "[+] Referrer-Policy: $RP" || echo "[-] Referrer-Policy: MISSING — token leakage in Referer"

# CORS headers (check if overly permissive)
CORS=$(grep -i "access-control-allow-origin" /tmp/response_headers.txt)
[ -n "$CORS" ] && echo "[!] CORS: $CORS — VERIFY if wildcard or arbitrary"

# Cache-Control on sensitive pages
CACHE=$(grep -i "cache-control" /tmp/response_headers.txt)
[ -n "$CACHE" ] && echo "[+] Cache-Control: $CACHE" || echo "[-] Cache-Control: check on authenticated endpoints"

# Cookie attributes — check login endpoint specifically
echo "=== COOKIE SECURITY ==="
curl -s -X POST "$TARGET/login" \
  -d "user=test&pass=test" \
  -D - -o /dev/null 2>/dev/null | grep -i "set-cookie" | while read -r ck; do
  echo "Cookie header: $ck"
  echo "$ck" | grep -qi "HttpOnly" || echo "  [!] MISSING HttpOnly — XSS session theft possible"
  echo "$ck" | grep -qi "Secure" || echo "  [!] MISSING Secure — cookie sent over HTTP"
  echo "$ck" | grep -qi "SameSite" || echo "  [!] MISSING SameSite — CSRF risk"
done
```

## Phase D: TLS and Certificate Analysis

**HOW to perform full TLS/certificate audit:**
```bash
# Protocol version and cipher suite audit
sslscan --no-colour "${HOST}:443" 2>/dev/null | tee /tmp/sslscan.txt
grep -E "SSL|TLS|WARN|FATAL|Accepted|Rejected" /tmp/sslscan.txt | head -30

# Key findings to flag:
grep -E "SSLv|TLSv1\.0|TLSv1\.1|RC4|DES|EXPORT|NULL|anon" /tmp/sslscan.txt && \
  echo "[!] WEAK PROTOCOL OR CIPHER DETECTED" || echo "[+] No deprecated protocols found"

# Certificate details — SAN = ALL SCOPE SUBDOMAINS
echo | openssl s_client -connect "${HOST}:443" -servername "$HOST" 2>/dev/null \
  | openssl x509 -noout -text 2>/dev/null \
  | grep -A5 "Subject Alternative Name\|Subject:\|Issuer:\|Not Before\|Not After\|DNS:" \
  | head -40

# Extract ALL SANs (Subject Alternative Names) — expands scope
echo | openssl s_client -connect "${HOST}:443" -servername "$HOST" 2>/dev/null \
  | openssl x509 -noout -text 2>/dev/null \
  | grep -oP 'DNS:[^,\s]+' | sort -u | tee /tmp/cert_sans.txt
echo "[+] Certificate SANs (potential scope expansion):"
cat /tmp/cert_sans.txt

# Certificate expiry
echo | openssl s_client -connect "${HOST}:443" -servername "$HOST" 2>/dev/null \
  | openssl x509 -noout -dates 2>/dev/null

# Full testssl audit (comprehensive — run if time allows)
testssl --fast --color 0 "$TARGET" 2>/dev/null | \
  grep -E "CRITICAL|HIGH|MEDIUM|WARN|OK " | head -40
```

## Phase E: Web Crawling and Spidering

**HOW to crawl and spider the application to discover all linked URLs:**
```bash
# Katana — JS-aware active crawler (most comprehensive)
# -jc: parse JavaScript; -kf all: find all forms; -d 3: depth 3
katana -u "$TARGET" -d 3 -jc -kf all -silent \
  -o /tmp/katana_urls.txt 2>/dev/null
echo "[+] Katana found $(wc -l < /tmp/katana_urls.txt) URLs"
cat /tmp/katana_urls.txt | sort -u | head -30

# Hakrawler — fast crawler (links, robots.txt, sitemap.xml, forms)
echo "$TARGET" | hakrawler -d 3 -u 2>/dev/null \
  | tee /tmp/hakrawler_urls.txt | wc -l | xargs echo "[+] Hakrawler found:"

# Gospider — form and sitemap spider
gospider -s "$TARGET" -d 3 -c 5 --quiet 2>/dev/null \
  | grep -oP 'https?://[^\s"]+' | sort -u \
  | tee /tmp/gospider_urls.txt | wc -l | xargs echo "[+] Gospider found:"

# Combine all crawler results
cat /tmp/katana_urls.txt /tmp/hakrawler_urls.txt /tmp/gospider_urls.txt 2>/dev/null \
  | grep -oP 'https?://[^\s"]+' | sort -u | tee /tmp/all_crawled_urls.txt
echo "[+] Total unique crawled URLs: $(wc -l < /tmp/all_crawled_urls.txt)"

# Identify interesting patterns in crawled URLs
echo "=== HIGH-INTEREST CRAWLED PATHS ==="
grep -iE "/admin|/api/|/graphql|/upload|/file|/download|/export|/backup|/config|\\.env|\\.git" \
  /tmp/all_crawled_urls.txt | sort -u

# Extract parameter names from crawled URLs (feeds parameter_discovery)
grep -oP '[\?&][a-zA-Z_0-9-]+=?' /tmp/all_crawled_urls.txt | \
  sed 's/[?&]//' | sed 's/=//' | sort | uniq -c | sort -rn | head -30
```

## Phase F: Archive URL Mining

**HOW to mine historical URLs from web archives:**
```bash
# GetAllURLs — mines Wayback, CommonCrawl, AlienVault OTX, URLScan
gau "$HOST" --threads 5 --subs 2>/dev/null \
  | tee /tmp/gau_urls.txt | wc -l | xargs echo "[+] GAU URLs found:"

# Wayback Machine specifically
waybackurls "$HOST" 2>/dev/null \
  | tee /tmp/wayback_urls.txt | wc -l | xargs echo "[+] Wayback URLs found:"

# Combine archive results
cat /tmp/gau_urls.txt /tmp/wayback_urls.txt 2>/dev/null \
  | sort -u | tee /tmp/all_archive_urls.txt
echo "[+] Total archive URLs: $(wc -l < /tmp/all_archive_urls.txt)"

# Find old API versions, deprecated endpoints (HIGH VALUE)
echo "=== DEPRECATED/OLD ENDPOINTS ==="
grep -iE "/api/v[0-9]|/v[0-9]/|/api/[0-9]|\.php\?|\.asp\?|\.aspx\?|\.jsp\?" \
  /tmp/all_archive_urls.txt | sort -u | head -20

# Find sensitive file types in archive
echo "=== SENSITIVE FILE TYPES IN ARCHIVES ==="
grep -iE "\.(sql|bak|backup|config|cfg|conf|env|log|key|pem|cert|zip|tar|gz|json|yaml|xml|csv|xls)" \
  /tmp/all_archive_urls.txt | sort -u | head -20

# Extract ALL historical parameter names (attack surface mapping)
echo "=== HISTORICAL PARAMETERS ==="
cat /tmp/all_archive_urls.txt | grep -oP '[?&][a-zA-Z0-9_-]+=' | \
  sed 's/[?&]//' | sed 's/=//' | sort | uniq -c | sort -rn | head -40

# Find subdomains in archived URLs (scope expansion)
grep -oP 'https?://[a-zA-Z0-9.-]+\.' /tmp/all_archive_urls.txt | \
  sed 's|https\?://||' | sed 's/\.//' | sort -u | \
  grep -v "^$" | tee /tmp/archive_subdomains.txt | head -20
```

## Phase G: JavaScript Analysis

**HOW to extract hidden endpoints, API routes, and secrets from JavaScript:**
```bash
# Step 1: Find all JS file URLs
JS_URLS=$(curl -s "$TARGET" | grep -oP '(src|href)="[^"]*\.js[^"]*"' | \
  sed 's/(src|href)="//;s/"//' | \
  grep -v "^//" | sed "s|^/|${TARGET%/}/|")
echo "[+] JS files found: $(echo "$JS_URLS" | wc -l)"
echo "$JS_URLS" | head -10

# Step 2: Download and analyze each JS file
mkdir -p /tmp/js_analysis
for jsurl in $(echo "$JS_URLS" | head -20); do
  filename=$(echo "$jsurl" | md5sum | cut -c1-8)
  curl -s "$jsurl" -o "/tmp/js_analysis/${filename}.js" 2>/dev/null
done

# Step 3: Extract API endpoints from JS bundles
echo "=== API ENDPOINTS IN JS ==="
grep -roP '("|'"'"')(/api/[a-zA-Z0-9/_-]+|/v[0-9]+/[a-zA-Z0-9/_-]+)("|'"'"')' \
  /tmp/js_analysis/ | grep -oP '/[a-zA-Z0-9/_-]+' | sort -u | head -40

# Step 4: Extract hardcoded secrets (API keys, tokens, passwords)
echo "=== POTENTIAL SECRETS IN JS ==="
grep -roiEh \
  '(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd|bearer|private[_-]?key)\s*[:=]\s*["\x27][a-zA-Z0-9+/=_-]{8,}' \
  /tmp/js_analysis/ | head -20
# IMPORTANT: Redact any real values before recording as evidence

# Step 5: Extract domain/host patterns (internal services, endpoints)
echo "=== HOSTS AND DOMAINS IN JS ==="
grep -roP 'https?://[a-zA-Z0-9._-]+\.[a-zA-Z]{2,}[/a-zA-Z0-9._-]*' \
  /tmp/js_analysis/ | grep -v "schemas\|example\.com\|w3\.org\|mozilla\|jquery\|google" | \
  sort -u | head -30

# Step 6: GraphQL schema patterns
echo "=== GRAPHQL PATTERNS ==="
grep -roiE 'query\s|mutation\s|subscription\s|__typename|gql`|graphql' \
  /tmp/js_analysis/ | head -10

# Alternative: use katana with JS crawl and extract API paths from output
katana -u "$TARGET" -jc -silent 2>/dev/null | \
  grep -E "^https?://$HOST" | \
  grep -iE "/api/|/graphql|/rpc|/v[0-9]" | sort -u | head -20
```

## Phase H: Secret Scanning

**HOW to scan for leaked secrets in exposed code repositories:**
```bash
# Check if .git is exposed
GIT_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$TARGET/.git/HEAD")
if [ "$GIT_STATUS" = "200" ]; then
  echo "[CRITICAL] .git/ EXPOSED — source code accessible"
  
  # Dump the repo config
  curl -s "$TARGET/.git/config" | head -20
  
  # Scan for secrets using trufflehog on the exposed git
  trufflehog git "$TARGET/.git/" --no-verification --json 2>/dev/null | \
    python3 -m json.tool | grep -A5 '"DetectorName"\|"Raw"' | head -40
  # IMPORTANT: Redact actual secret values in evidence
  
  # Scan with gitleaks if repo can be cloned
  git clone --depth 1 "$TARGET/.git/" /tmp/exposed_git_repo 2>/dev/null && \
    gitleaks detect --source /tmp/exposed_git_repo \
      --report-format json \
      --report-path /tmp/gitleaks_report.json \
      --no-git 2>/dev/null && \
    cat /tmp/gitleaks_report.json | python3 -m json.tool | \
      grep -E '"RuleID"|"File"|"Match"' | head -40
else
  echo "[+] .git/ not directly exposed (HTTP $GIT_STATUS)"
fi

# Scan downloaded JS files for secrets with trufflehog
trufflehog filesystem /tmp/js_analysis/ --no-verification --json 2>/dev/null | \
  python3 -m json.tool | grep -E '"DetectorName"|"SourceMetadata"' | head -20

# Scan for common secret patterns in all collected content
grep -rioEh \
  '(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36}|xoxb-[0-9]+-[a-zA-Z0-9]+|sk-[a-zA-Z0-9]{32,}|AIza[0-9A-Za-z_-]{35})' \
  /tmp/js_analysis/ /tmp/exposed_git_repo/ 2>/dev/null | head -10
# AWS AKIA: IAM key; ghp/ghr: GitHub token; xoxb: Slack; sk-: OpenAI; AIza: Google API
```

## Phase I: SAST on Exposed Source Code

**HOW to run SAST if source code is accessible:**
```bash
# Only run if .git was exposed or source code downloaded
if [ -d "/tmp/exposed_git_repo" ]; then
  echo "=== SAST SCAN ON EXPOSED SOURCE ==="
  
  # Semgrep: detect injection patterns, misconfigs, hardcoded secrets
  semgrep scan /tmp/exposed_git_repo \
    --config auto \
    --severity WARNING \
    --severity ERROR \
    --json \
    --output /tmp/semgrep_results.json \
    --quiet 2>/dev/null
  
  # Parse results: count by severity and category
  python3 -c "
import json, sys
try:
  data = json.load(open('/tmp/semgrep_results.json'))
  results = data.get('results', [])
  print(f'Total findings: {len(results)}')
  from collections import Counter
  cats = Counter(r['check_id'].split('.')[0] for r in results)
  for cat, count in cats.most_common(10):
    print(f'  {cat}: {count}')
  # Show top 5 HIGH severity
  high = [r for r in results if r.get('extra', {}).get('severity') in ['ERROR', 'WARNING']][:5]
  for r in high:
    print(f\"  [{r['extra']['severity']}] {r['check_id']}: {r['path']}:{r['start']['line']}\")
except Exception as e:
  print(f'SAST parse error: {e}')
" 2>/dev/null

  # Bandit for Python code
  bandit -r /tmp/exposed_git_repo \
    -f json \
    -o /tmp/bandit_results.json \
    --severity-level medium \
    --confidence-level medium \
    2>/dev/null
  python3 -c "
import json
try:
  data = json.load(open('/tmp/bandit_results.json'))
  issues = data.get('results', [])
  print(f'Bandit findings: {len(issues)}')
  for i in issues[:10]:
    print(f\"  [{i['issue_severity']}] {i['test_name']}: {i['filename']}:{i['line_number']}\")
except: pass
" 2>/dev/null
fi
```

## Phase J: OSINT Collection

**HOW to collect email and organizational OSINT:**
```bash
# theHarvester — emails, names, hosts from public sources
theharvester -d "$HOST" -b google,bing,linkedin,certspotter,crtsh \
  -l 100 -f /tmp/theharvester_results 2>/dev/null
cat /tmp/theharvester_results.json 2>/dev/null | python3 -m json.tool | \
  grep -E '"emails"|"hosts"' | head -30

# Extract emails for credential stuffing intelligence
python3 -c "
import json
try:
  data = json.load(open('/tmp/theharvester_results.json'))
  emails = data.get('emails', [])
  print(f'Emails found: {len(emails)}')
  for e in emails[:20]:
    print(f'  {e}')
except: pass
" 2>/dev/null

# Certificate Transparency for additional subdomains
curl -s "https://crt.sh/?q=%.${HOST}&output=json" 2>/dev/null | \
  python3 -c "
import json, sys
try:
  data = json.load(sys.stdin)
  names = sorted(set(
    name.strip().lstrip('*.')
    for entry in data
    for name in entry.get('name_value', '').split('\n')
    if '.' in name and not name.startswith('@')
  ))
  print(f'crt.sh subdomains: {len(names)}')
  for n in names[:30]: print(f'  {n}')
except Exception as e:
  print(f'crt.sh parse error: {e}')
" 2>/dev/null
```

## Phase K: Shodan OSINT

**HOW to query Shodan for infrastructure intelligence:**
```bash
# Initialize Shodan CLI with API key from environment (injected by docker-compose)
shodan init "$SHODAN_API_KEY" 2>/dev/null
shodan info 2>/dev/null | head -3  # Confirm key is valid and show plan/credits

# Resolve target IPs first (Shodan queries are IP or filter based)
TARGET_IPS=$(dig +short "$HOST" | grep -oP '^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
echo "[+] Resolved IPs for $HOST: $TARGET_IPS"
```

**HOW to get full host intelligence per IP:**
```bash
# Full Shodan host report — open ports, banners, vulns, ASN, org, geo
for IP in $TARGET_IPS; do
  echo "=== Shodan host: $IP ==="
  shodan host "$IP" 2>/dev/null | tee "/tmp/shodan_${IP}.txt"
  # Key sections in output:
  #   Organization: who owns this IP block
  #   OS: detected OS
  #   Ports: all open ports Shodan last saw
  #   Vulns: CVE IDs Shodan correlated (e.g. CVE-2021-44228)
  #   Data: service banners per port (HTTP headers, SSH banner, FTP banner)
done
```

**HOW to search Shodan by hostname and SSL certificate:**
```bash
# All Shodan-indexed hosts matching the domain (includes subdomains, CDN IPs)
echo "=== Shodan search: hostname:$HOST ==="
shodan search --fields ip_str,port,org,product,version "hostname:$HOST" 2>/dev/null \
  | tee /tmp/shodan_hostname.txt | head -30

# SSL certificate search — finds all hosts presenting certs for this domain
# This exposes infrastructure hidden behind CDN (real origin IPs)
echo "=== Shodan search: ssl.cert.subject.CN:$HOST ==="
shodan search --fields ip_str,port,org,ssl.cert.subject.cn \
  "ssl.cert.subject.CN:$HOST" 2>/dev/null \
  | tee /tmp/shodan_ssl.txt | head -20

# SAN-based search — finds wildcards and related certs
echo "=== Shodan search: ssl.cert.subject.CN:*.$HOST ==="
shodan search --fields ip_str,port,org,ssl.cert.subject.cn \
  "ssl.cert.subject.CN:*.$HOST" 2>/dev/null | head -20

# Count total results before downloading
shodan count "hostname:$HOST" 2>/dev/null | xargs echo "[+] Total Shodan results for hostname:"
```

**HOW to enumerate org infrastructure and ASN:**
```bash
# Get ASN from resolved IP
for IP in $TARGET_IPS; do
  ASN_INFO=$(shodan host "$IP" 2>/dev/null | grep -iE "ASN:|Organization:" | head -2)
  echo "IP $IP: $ASN_INFO"
  
  # Extract ASN number for broader infrastructure mapping
  ASN=$(shodan host "$IP" 2>/dev/null | grep -oP 'AS\d+')
  if [ -n "$ASN" ]; then
    echo "=== All hosts in $ASN (sample: top 20) ==="
    shodan search --fields ip_str,port,product,hostnames \
      "asn:$ASN" --limit 100 2>/dev/null | head -20
    shodan count "asn:$ASN" 2>/dev/null | xargs echo "[+] Total IPs in $ASN:"
  fi
done
```

**HOW to find exposed services and misconfigurations via Shodan:**
```bash
# Check for specific high-value exposed services on target IPs/org
ORG=$(shodan host $(echo $TARGET_IPS | awk '{print $1}') 2>/dev/null | grep "Organization:" | cut -d: -f2- | xargs)

if [ -n "$ORG" ]; then
  # Exposed databases (immediate critical finding)
  for DB_PORT in "3306" "5432" "27017" "6379" "9200" "9042"; do
    COUNT=$(shodan count "org:\"$ORG\" port:$DB_PORT" 2>/dev/null)
    [ "$COUNT" -gt 0 ] 2>/dev/null && \
      echo "[!] EXPOSED DB port $DB_PORT in org \"$ORG\": $COUNT hosts"
  done

  # Exposed admin interfaces
  for ADMIN in "8080" "8443" "9090" "9443" "4848" "15672" "5601"; do
    COUNT=$(shodan count "org:\"$ORG\" port:$ADMIN" 2>/dev/null)
    [ "$COUNT" -gt 0 ] 2>/dev/null && \
      echo "[!] Admin port $ADMIN in org: $COUNT hosts"
  done

  # RDP / VNC exposed
  shodan count "org:\"$ORG\" port:3389" 2>/dev/null | xargs echo "[!] RDP exposed:"
  shodan count "org:\"$ORG\" port:5900" 2>/dev/null | xargs echo "[!] VNC exposed:"
fi
```

**HOW to extract CVE intelligence from Shodan:**
```bash
# Shodan automatically correlates service banners to CVEs
for IP in $TARGET_IPS; do
  echo "=== CVEs for $IP ==="
  shodan host "$IP" 2>/dev/null | grep -A2 "Vulns:" | head -10
  # If CVEs appear: cross-reference with component_memory_corruption.md
  # Example output: CVE-2021-44228 (Log4Shell), CVE-2022-22965 (Spring4Shell)
done

# Search specifically for known-vulnerable products on org IPs
if [ -n "$ORG" ]; then
  shodan search --fields ip_str,port,product,version \
    "org:\"$ORG\" has_vuln:true" --limit 20 2>/dev/null | head -20
fi
```

**HOW to discover real origin IPs behind CDN/WAF:**
```bash
# Many targets use Cloudflare/Akamai but Shodan indexes the REAL origin
# Search for server header patterns that bypass CDN
echo "=== Origin IP detection via Shodan SSL ==="
shodan search --fields ip_str,port,org,ssl.cert.subject.cn,hostnames \
  "ssl.cert.subject.CN:$HOST -org:Cloudflare -org:Fastly -org:Akamai" 2>/dev/null \
  | head -10
# Any result NOT in CDN ASN = potential real origin IP

# Historical DNS via Shodan (shows past IPs before CDN migration)
shodan search --fields ip_str,port,hostnames,timestamp \
  "hostname:$HOST" 2>/dev/null | \
  awk '{print $1}' | sort -u | head -20
```

# Tool Mapping

| Tool | Purpose | Phase |
|------|---------|-------|
| httpx | HTTP probe + technology detection | A |
| whatweb | CMS/framework fingerprint | A |
| curl | Header audit, cookie check, manual probes | A, C, D |
| wafw00f | WAF/firewall vendor detection | B |
| sslscan | TLS protocol/cipher audit | D |
| testssl | Comprehensive TLS vulnerability scan | D |
| openssl | Certificate SAN extraction | D |
| katana | JS-aware active crawling | E |
| hakrawler | Fast link/form crawler | E |
| gospider | Sitemap/form/spider | E |
| gau | Archive URL mining (multi-source) | F |
| waybackurls | Wayback Machine URL extraction | F |
| gitleaks | Secret detection in git repos | H |
| trufflehog | Secret detection in git/filesystem | H |
| semgrep | SAST pattern scanning | I |
| bandit | Python-specific SAST | I |
| theharvester | Email/host OSINT (Google, LinkedIn, crtsh) | J |
| shodan | Infrastructure OSINT: open ports, CVEs, origin IPs, ASN, exposed services | K |

# Expected Evidence

- `tech_fingerprint`: technology stack from httpx/whatweb — CMS, framework, language, version, hosting provider
- `waf_detection_result`: WAF vendor (or "none detected") — affects all subsequent payload strategy
- `security_headers_audit`: table of present/absent security headers with severity impact
- `tls_certificate_profile`: protocol versions supported, weak ciphers, certificate expiry, SAN list
- `crawl_url_list`: unique URLs found by katana/hakrawler/gospider — count and high-interest paths
- `archive_url_list`: URLs from gau/wayback — old endpoints, deprecated API versions, historical parameters
- `js_endpoints_found`: API routes and hosts extracted from JS bundles
- `secrets_scan_result`: gitleaks/trufflehog findings — REDACTED values, only pattern types and locations
- `sast_findings`: semgrep/bandit result counts and categories (only if source accessible)
- `osint_emails`: email addresses found via theHarvester (feed credential attack intelligence)
- `cert_sans`: all Subject Alternative Names from TLS certificate (scope expansion)
- `shodan_host_report`: open ports, banners, OS, org, geo and Shodan-correlated CVEs per IP
- `shodan_origin_ips`: real origin IPs found behind CDN/WAF via SSL cert search
- `shodan_exposed_services`: databases/admin panels/RDP/VNC open on org ASN

# Validation Logic

**HOW to validate — step by step:**

1. **Tech fingerprint obtained**: httpx output contains at least `tech` array and `server` field.
2. **WAF status known**: wafw00f ran and reported either vendor or "no WAF detected" — both are valid.
3. **Security headers audited**: curl -I ran and output parsed for all 7 key headers.
4. **TLS audited**: sslscan ran on port 443; any deprecated protocols flagged.
5. **Crawl completed**: katana/hakrawler ran and produced URL list (even 0 results = valid for SPAs).
6. **Archives mined**: gau/waybackurls ran and output written.
7. **JS analyzed**: at least one JS file downloaded and scanned for endpoints and secrets.
8. **Secret scan ran**: gitleaks/trufflehog ran on any discovered code — even 0 findings is valid.
9. **theHarvester ran**: email/host collection attempted — even 0 emails is valid.
10. **Shodan queried**: `shodan host` ran on at least one resolved IP — confirms or expands Shodan-indexed surface.

Status decisions:
- `validated`: At least 3 of the 8 phases completed with evidence collected per phase.
- `partial`: Fewer than 3 phases completed; tool failures blocked key data collection.
- `inconclusive`: Target behind strict WAF blocking all probes; all tool timeouts.
- `blocked`: Target requires auth before any content visible — escalate to authenticated recon.

# Skill Selection Output

Based on surface mapping output, drive the following vulnerability skill selection:

| Finding | Recommended Next Skill |
|---------|----------------------|
| PHP detected | `sqli.md`, `path_traversal.md`, `command_injection.md` |
| Java/Spring detected | `deserialization.md`, `ssrf.md` (actuator), `ssti.md` |
| Node.js/Express detected | `ssti.md` (EJS), `prototype_pollution` |
| Python/Django/Flask detected | `ssti.md` (Jinja2), `sqli.md` |
| WordPress detected | `component_memory_corruption.md`, `sqli.md` |
| No CSP header | `xss.md`, `stored_xss_testing.md` (easier exploitation) |
| No X-Frame-Options | `clickjacking.md` |
| Missing HSTS | `crypto_storage.md` |
| Cookie without HttpOnly | `xss.md` → session theft viable |
| No WAF detected | All payload variants — no encoding needed |
| WAF detected (Cloudflare) | Use encoded/obfuscated payloads in all injection skills |
| `.git/` exposed | Immediate: `information_disclosure.md`, secret scan |
| `/actuator` 200 | `ssrf.md`, `information_disclosure.md` |
| GraphQL in JS | `graphql.md` |
| JWT in JS or headers | `jwt_oauth.md` |
| Old API versions in archive | Regression test with `api_security.md` |
| Emails found | Input to `account_takeover.md` credential stuffing path |
| Shodan CVEs on IP | `component_memory_corruption.md` (verify and exploit) |
| Shodan origin IP behind CDN | Re-test all skills directly on origin (bypasses WAF) |
| Shodan: DB port open on org | `auth_bypass.md` (unauthenticated DB access) |
| TLS 1.0/1.1 supported | `crypto_storage.md` (critical finding) |
| Weak cipher suite | `crypto_storage.md` |
| SAN reveals new subdomains | Re-run `subdomain_enumeration.md` with new scope |
| Secrets in JS/git | Immediate escalation to human review |

# Post-Execution Updates

Update `offensive_state`, `cross_phase_memory`, `hypothesis_engine`, `attack_path_engine`, and `phase_ledger`:

```json
{
  "cross_phase_memory.tech_stack": {
    "cms": "<WordPress|Drupal|custom>",
    "language": "<PHP|Java|Python|Node|Ruby>",
    "framework": "<Laravel|Spring|Django|Express|Rails>",
    "version": "<detected version or null>",
    "hosting": "<AWS|GCP|Azure|Cloudflare>"
  },
  "cross_phase_memory.waf": "<vendor or none>",
  "cross_phase_memory.security_headers": {
    "hsts": true,
    "csp": false,
    "x_frame_options": false
  },
  "cross_phase_memory.tls": {
    "weak_protocols": [],
    "weak_ciphers": [],
    "cert_expiry": "<date>",
    "san_list": []
  },
  "cross_phase_memory.crawled_endpoints": [],
  "cross_phase_memory.archive_params": [],
  "cross_phase_memory.js_api_routes": [],
  "cross_phase_memory.secrets_found": false,
  "cross_phase_memory.git_exposed": false,
  "cross_phase_memory.shodan": {
    "open_ports": [],
    "cves_found": [],
    "origin_ips_behind_cdn": [],
    "exposed_services_org": []
  },
  "active_hypotheses": [],
  "attack_paths": [],
  "phase_ledger.surface_mapping.status": "completed|partial|blocked",
  "phase_ledger.surface_mapping.evidence_ids": []
}
```

## Changelog

### 1.0.0
- Source: manual-seed + profiles/reconnaissance.yaml audit
- Change type: initial_skill
- Added: Complete 11-phase surface mapping covering technology fingerprinting, WAF detection, security headers audit, TLS/certificate analysis, web crawling/spidering, archive URL mining, JavaScript endpoint extraction, secret scanning, SAST on exposed code, theHarvester OSINT (email/host collection), and Shodan OSINT (IP intelligence, CVEs, origin IP discovery, exposed service enumeration per ASN/org).
- Gap addressed: Existing recon skills (subdomain_enumeration, port_service_discovery, endpoint_discovery, parameter_discovery) do NOT cover tech fingerprinting, WAF detection, JS analysis, secret scanning, SAST, or Shodan infrastructure intelligence — this skill fills those critical gaps.
- Shodan requires SHODAN_API_KEY env variable (injected via docker-compose from host environment).
- Approved by: human_review
- Approved at: 2026-05-20T00:00:00Z
