#!/bin/bash
# Configure Burp Suite Professional for advanced testing
# Handles Repeater for IDOR/SQLi and Intruder for fuzzing with wordlists
# Só para deploy

set -eu

BURP_HOME="${BURP_HOME:-/opt/burpsuite}"
WORDLIST_DIR="/opt/burp-wordlists"
CONFIG_DIR="/opt/burp-config"
LOG_FILE="/var/log/burp-config.log"

# Logging function
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

log "[*] Initializing Burp Suite Advanced Configuration"

# Ensure directories exist
mkdir -p "$WORDLIST_DIR" "$CONFIG_DIR" "$(dirname "$LOG_FILE")"

# 1. Download wordlists (if requests available)
if command -v python3 &> /dev/null; then
    log "[*] Downloading Burp wordlists..."
    if python3 /app/scripts/download_burp_wordlists.py >> "$LOG_FILE" 2>&1; then
        log "[✓] Wordlists downloaded successfully"
    else
        log "[!] Wordlist download failed (non-critical, continuing...)"
    fi
else
    log "[!] Python3 not available, skipping wordlist download"
fi

# 2. Create Burp Suite configuration file for macro/automation
log "[*] Creating Burp configuration files..."

# Config for Intruder-based fuzzing attacks
cat > "$CONFIG_DIR/intruder-attacks.yaml" << 'EOF'
# Burp Suite Intruder Attack Configurations
# Used for fuzzing, rate limiting tests, and parameter enumeration

attacks:
  - name: "Directory Discovery"
    type: "Sniper"
    wordlist: "/opt/burp-wordlists/discovery/directory_list_2.3_medium.txt"
    target_parameter: "path"
    threads: 10
    payload_encoding: "URL"
    result_filter: "status_code:!404"
    
  - name: "PHP Parameter Fuzzing"
    type: "Sniper"
    wordlist: "/opt/burp-wordlists/discovery/fuzz_php_special.txt"
    target_parameter: "param_name"
    threads: 8
    payload_encoding: "None"
    result_filter: "response_time:>1000"
    
  - name: "SQL Injection Testing"
    type: "Sniper"
    wordlist: "/opt/burp-wordlists/vulnerabilities/sql_inj.txt"
    target_parameter: "query"
    threads: 5
    payload_encoding: "URL"
    result_filter: "status_code:500|contains:error|contains:warning"
    
  - name: "XSS Payload Testing"
    type: "Sniper"
    wordlist: "/opt/burp-wordlists/vulnerabilities/xss.txt"
    target_parameter: "input"
    threads: 8
    payload_encoding: "HTML"
    result_filter: "response_content:contains:payload"
    
  - name: "LFI/RFI Testing"
    type: "Sniper"
    wordlist: "/opt/burp-wordlists/discovery/lfi_all.txt"
    target_parameter: "file"
    threads: 6
    payload_encoding: "URL"
    result_filter: "response_time:>500"
    
  - name: "SSTI Payload Testing"
    type: "Sniper"
    wordlist: "/opt/burp-wordlists/vulnerabilities/ssti.txt"
    target_parameter: "template"
    threads: 5
    payload_encoding: "None"
    result_filter: "response_content:contains:template_result"
    
  - name: "Rate Limit Testing"
    type: "Battering Ram"
    wordlist: "/opt/burp-wordlists/discovery/common.txt"
    target_parameter: "any"
    threads: 50
    payload_encoding: "None"
    result_filter: "status_code:429|contains:rate"
    timing_analysis: true

rate_limit_indicators:
  - "HTTP 429"
  - "Too many requests"
  - "rate limit"
  - "throttled"
  - "request limit"

EOF

log "[✓] Created intruder-attacks.yaml"

# Config for Repeater-based manual testing
cat > "$CONFIG_DIR/repeater-idor-sqli.yaml" << 'EOF'
# Burp Suite Repeater Manual Testing Guide
# For IDOR and SQL Injection vulnerabilities

repeater_testing:
  
  idor:
    description: "Insecure Direct Object Reference Testing"
    techniques:
      - name: "Sequential ID Testing"
        method: "Test consecutive numeric IDs"
        parameters: ["id", "user_id", "account_id", "object_id"]
        tools: "Repeater"
        steps:
          1: "Capture request with ID parameter"
          2: "Modify ID value to adjacent numbers (id=1, id=2, id=3, etc.)"
          3: "Check if unauthorized data is returned"
          4: "Vary ID format: hex, base64, UUID"
        
      - name: "Hash/UUID Enumeration"
        method: "Analyze and predict hash patterns"
        parameters: ["uuid", "token", "hash"]
        steps:
          1: "Capture multiple requests with different users"
          2: "Analyze ID patterns (sequential, random, deterministic)"
          3: "Attempt to predict next value"
          4: "Test with administrative accounts"
        
      - name: "Timestamp-based ID Prediction"
        method: "Time-based ID vulnerability"
        parameters: ["created_at", "timestamp", "created_id"]
        steps:
          1: "Create multiple objects with known timestamps"
          2: "Calculate ID generation method"
          3: "Predict IDs from other timestamps"
          4: "Validate against different user contexts"
    
    common_vulnerable_endpoints:
      - "/api/users/{id}"
      - "/api/accounts/{account_id}"
      - "/api/documents/{doc_id}"
      - "/account/profile/{user_id}"
      - "/api/orders/{order_id}"
      - "/admin/users/{id}"
    
    payload_examples:
      numeric: ["1", "100", "999", "9999"]
      hex: ["0x1", "0x64", "0x3e7"]
      uuid: ["550e8400-e29b-41d4-a716-446655440000"]
      wordlist: "/opt/burp-wordlists/discovery/common.txt"
  
  sqli:
    description: "SQL Injection Manual Testing in Repeater"
    techniques:
      - name: "Classic SQL Injection"
        vulnerability_types: ["In-band", "Error-based", "Union-based"]
        parameters: ["search", "id", "q", "filter", "username", "email"]
        test_payloads:
          - "' OR '1'='1"
          - "' OR 1=1 --"
          - "'; DROP TABLE users; --"
          - "' UNION SELECT NULL,NULL,NULL --"
        wordlist: "/opt/burp-wordlists/vulnerabilities/sql_inj.txt"
      
      - name: "Blind SQL Injection"
        vulnerability_types: ["Boolean-based", "Time-based"]
        parameters: ["id", "user_id", "page"]
        test_payloads:
          - "1' AND '1'='1"
          - "1' AND SLEEP(5) --"
          - "1'; WAITFOR DELAY '00:00:05' --"
        timing_expectations:
          - "Response delay indicates vulnerability"
      
      - name: "Time-based Blind SQLi"
        detection_method: "Response time analysis"
        steps:
          1: "Send normal request, note response time (baseline)"
          2: "Send SQLi payload with SLEEP/WAITFOR"
          3: "If response time increases, SQLi confirmed"
          4: "Use delay to exfiltrate data characters"
        tools: "Repeater with timing analysis"
    
    testing_workflow:
      1: "Identify input parameters (GET, POST, cookies)"
      2: "Test single quote injection: ' error?"
      3: "Test logic: ' OR '1'='1"
      4: "Test UNION: UNION SELECT version(),NULL,NULL"
      5: "Enumerate database: table_name, column_name"
      6: "Extract sensitive data"
    
    common_vulnerable_endpoints:
      - "/search?q=..."
      - "/product?id=..."
      - "/user?username=..."
      - "/api/filter?category=..."
      - "/login (POST)"

intruder_complement:
  description: "Use Intruder to automate parts of testing"
  fuzzing_payloads:
    sql: "/opt/burp-wordlists/vulnerabilities/sql.txt"
    xss: "/opt/burp-wordlists/vulnerabilities/xss.txt"
    all_attacks: "/opt/burp-wordlists/vulnerabilities/all_attacks.txt"

EOF

log "[✓] Created repeater-idor-sqli.yaml"

# 3. Create a Python helper script for Repeater macro handling
cat > "$CONFIG_DIR/burp_repeater_helper.py" << 'EOF'
#!/usr/bin/env python3
"""
Helper script for Burp Repeater manual testing.
Provides utilities to test IDOR and SQLi vulnerabilities systematically.
"""

import json
import sys
from pathlib import Path

class IDORTester:
    """IDOR vulnerability testing utilities"""
    
    def __init__(self, base_value: str):
        self.base_value = base_value
    
    def numeric_sequence(self, start: int = 1, count: int = 100) -> list:
        """Generate sequential numeric IDs"""
        return [str(i) for i in range(start, start + count)]
    
    def hash_variations(self, hash_value: str) -> list:
        """Generate hash variations for testing"""
        import hashlib
        variations = [hash_value]
        
        # Try with common modifications
        for mod in [
            f"{hash_value}0",
            f"{hash_value}1",
            hash_value[:-1],
        ]:
            variations.append(mod)
        
        return variations
    
    def uuid_patterns(self) -> list:
        """Common UUID patterns for testing"""
        return [
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-0000-0000-000000000001",
            "550e8400-e29b-41d4-a716-446655440000",
        ]

class SQLiTester:
    """SQL Injection testing utilities"""
    
    PAYLOADS = {
        "union": [
            "' UNION SELECT NULL --",
            "' UNION SELECT NULL,NULL --",
            "' UNION SELECT NULL,NULL,NULL --",
        ],
        "boolean": [
            "' AND '1'='1",
            "' AND '1'='2",
        ],
        "time": [
            "' AND SLEEP(5) --",
            "'; WAITFOR DELAY '00:00:05' --",
        ],
        "error": [
            "' AND extractvalue(rand(),concat(0x3a,version())) --",
            "' AND updatexml(rand(),concat(0x3a,version()),1) --",
        ]
    }
    
    def load_wordlist(self, path: str) -> list:
        """Load SQLi payloads from wordlist file"""
        try:
            with open(path, 'r') as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            return []
    
    def generate_payloads(self, param: str, attack_type: str = "all") -> list:
        """Generate SQLi payloads for a given parameter"""
        payloads = []
        
        if attack_type in ["all", "union"]:
            payloads.extend(self.PAYLOADS["union"])
        if attack_type in ["all", "boolean"]:
            payloads.extend(self.PAYLOADS["boolean"])
        if attack_type in ["all", "time"]:
            payloads.extend(self.PAYLOADS["time"])
        
        return payloads

def main():
    print("Burp Repeater Helper - IDOR & SQLi Testing")
    print("Usage: python3 burp_repeater_helper.py <command> [args]")
    print("\nCommands:")
    print("  idor <value>           - Generate IDOR test IDs")
    print("  sqli <param> [type]    - Generate SQLi payloads")

if __name__ == "__main__":
    main()
EOF

chmod +x "$CONFIG_DIR/burp_repeater_helper.py"
log "[✓] Created burp_repeater_helper.py"

# 4. Create summary document
cat > "$CONFIG_DIR/BURP_ADVANCED_TESTING.md" << 'EOF'
# Burp Suite Advanced Testing Configuration

## Overview
This setup enables advanced security testing using Burp Suite Professional with:
- **Repeater**: Manual IDOR and SQL Injection testing
- **Intruder**: Automated fuzzing, rate limiting tests, and payload enumeration

## Wordlist Organization

Wordlists are organized in `/opt/burp-wordlists/`:

### Discovery (Fuzzing & Enumeration)
- `directory_list_2.3_medium.txt` - Directory discovery
- `fuzz_php_special.txt` - PHP parameter fuzzing
- `lfi_all.txt` - Local File Inclusion tests
- `top_subdomains.txt` - Subdomain enumeration
- `common.txt` - Common paths/parameters
- `common_sql_tables.txt` - SQLi table names
- `apache_user_enum_2.0.txt` - User enumeration

### Vulnerabilities (Payload Wordlists)
- `sql_inj.txt` - SQL Injection payloads
- `xss.txt` - XSS payloads
- `ssti.txt` - Server-Side Template Injection
- `directory_traversal.txt` - Path traversal payloads
- `all_attacks.txt` - Combined attack payloads
- Platform-specific: jboss.txt, sap.txt, sharepoint.txt, weblogic.txt, websphere.txt

### Credentials
- `portuguese.txt` - Portuguese language wordlist (for password testing)
- `rockyou.txt` - Famous password list (extracted from rockyou.zip)

### Common
- `apache_user_enum_2.0.txt` - Apache user enumeration

## Using Repeater

### IDOR Testing Workflow
1. **Identify the parameter**: user_id, account_id, object_id, etc.
2. **Test sequential IDs**: Increment/decrement numeric IDs
3. **Test hash/UUID patterns**: Use provided UUID patterns
4. **Test timestamp-based IDs**: Predict based on time deltas
5. **Document findings**: Different user contexts showing unauthorized access

### SQL Injection Testing Workflow
1. **Identify injectable parameters**: search, id, filter, etc.
2. **Test basic injection**: ' OR '1'='1  
3. **Test UNION-based**: ' UNION SELECT version(),NULL,NULL --
4. **Test boolean-based blind**: ' AND '1'='1 (compare responses)
5. **Test time-based blind**: ' AND SLEEP(5) -- (measure response time)
6. **Enumerate database**: Extract table names, columns, data

## Using Intruder

### Setup Steps
1. **Capture Request**: Use Burp Proxy to capture HTTP request
2. **Send to Intruder**: Right-click → Send to Intruder
3. **Set Attack Type**: 
   - Sniper: Single parameter fuzzing
   - Battering Ram: Multiple parameters with same payload
   - Pitchfork: Multiple parameters with different payloads
   - Cluster Bomb: Cartesian product of multiple wordlists
4. **Select Wordlist**: Choose from `/opt/burp-wordlists/` categories
5. **Configure Options**:
   - Payload Encoding (URL, HTML, etc.)
   - Number of Threads
   - Response filters (status code, keywords, etc.)
6. **Start Attack**: Monitor results for interesting responses

### Recommended Intruder Attacks

#### Directory Discovery
- Wordlist: `/opt/burp-wordlists/discovery/directory_list_2.3_medium.txt`
- Attack Type: Sniper
- Filter: Status code != 404
- Threads: 10

#### PHP Fuzzing
- Wordlist: `/opt/burp-wordlists/discovery/fuzz_php_special.txt`
- Attack Type: Sniper
- Filter: Response time > 1000ms
- Threads: 8

#### SQL Injection (Automated)
- Wordlist: `/opt/burp-wordlists/vulnerabilities/sql_inj.txt`
- Attack Type: Sniper
- Filter: Status code 500 OR contains "error"
- Threads: 5

#### Rate Limiting Test
- Wordlist: `/opt/burp-wordlists/discovery/common.txt`
- Attack Type: Battering Ram (rapid requests)
- Filter: Status code 429 OR contains "rate"
- Threads: 50

#### XSS Testing
- Wordlist: `/opt/burp-wordlists/vulnerabilities/xss.txt`
- Attack Type: Sniper
- Filter: Response contains payload
- Threads: 8

## Helper Tools

### Python Helper (`burp_repeater_helper.py`)
```bash
python3 /opt/burp-config/burp_repeater_helper.py idor <value>
python3 /opt/burp-config/burp_repeater_helper.py sqli <param>
```

## Configuration Files

- `intruder-attacks.yaml` - Intruder attack configurations
- `repeater-idor-sqli.yaml` - Repeater testing guides
- `burp_repeater_helper.py` - Python helper script
- `burp-intruder-config.json` - JSON configuration reference

## Integration with Automated Scanning

The tool_adapters.py has been updated to:
1. Automatically use these wordlists for extended Burp scans
2. Support IDOR detection heuristics
3. Support blind SQLi detection via timing analysis
4. Generate Intruder attack configurations from templates

## Best Practices

1. **Start Manual**: Use Repeater to understand target behavior before automating
2. **Incremental Testing**: Test one vulnerability type at a time
3. **Monitor Resources**: Intruder with 50 threads consumes bandwidth; adjust for target capacity
4. **Validate Findings**: Manual confirmation is essential before reporting
5. **Use Filters**: Configure response filters to highlight interesting results
6. **Timing Analysis**: For blind SQLi, establish baseline response time first

## Troubleshooting

- **Wordlist not found**: Check `/opt/burp-wordlists/` directory permissions
- **Intruder too slow**: Reduce thread count, increase timeout
- **Rate limited**: Implement delays between requests in attack options
- **Unicode issues**: Ensure UTF-8 encoding is used for response analysis

EOF

log "[✓] Created BURP_ADVANCED_TESTING.md documentation"

# 5. Create environment variable export script
cat > "$CONFIG_DIR/burp-env.sh" << 'EOF'
#!/bin/bash
# Export Burp-related environment variables

export BURP_WORDLIST_DIR="/opt/burp-wordlists"
export BURP_CONFIG_DIR="/opt/burp-config"
export BURP_API_HOST="${BURP_API_HOST:-burp_rest}"
export BURP_API_PORT="${BURP_API_PORT:-1337}"
export BURP_INTRUDER_THREADS="${BURP_INTRUDER_THREADS:-10}"
export BURP_INTRUDER_TIMEOUT="${BURP_INTRUDER_TIMEOUT:-30}"

echo "[+] Burp environment variables loaded"
echo "  BURP_WORDLIST_DIR=$BURP_WORDLIST_DIR"
echo "  BURP_CONFIG_DIR=$BURP_CONFIG_DIR"
echo "  BURP_API_HOST=$BURP_API_HOST:$BURP_API_PORT"

EOF

chmod +x "$CONFIG_DIR/burp-env.sh"
log "[✓] Created burp-env.sh"

log "[✓] Burp Advanced Configuration Complete!"
log ""
log "Configuration Files:"
log "  - $CONFIG_DIR/intruder-attacks.yaml"
log "  - $CONFIG_DIR/repeater-idor-sqli.yaml"
log "  - $CONFIG_DIR/burp_repeater_helper.py"
log "  - $CONFIG_DIR/BURP_ADVANCED_TESTING.md"
log ""
log "Wordlists Directory: $WORDLIST_DIR"
log ""
log "Next Steps:"
log "  1. Configure Burp Suite Professional manually via UI"
log "  2. Import wordlists from $WORDLIST_DIR"
log "  3. Set up Repeater macros for IDOR/SQLi testing"
log "  4. Configure Intruder attack payloads"
log ""

exit 0
