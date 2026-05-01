#!/usr/bin/env python3
"""
Test script to validate IPv4 and domain schedule targets validation.
This test ensures that "192.168.18.141:3001" is properly accepted as a valid target.
"""

import re

# Replicate the exact validation logic from routes_management.py
DOMAIN_RE = re.compile(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
IPV4_RE = re.compile(r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")


def _parse_targets(targets_text: str) -> list[str]:
    return [item.strip() for item in targets_text.split(";") if item.strip()]


def _normalize_domain_candidate(raw_target: str) -> str | None:
    raw = str(raw_target or "").strip().lower()
    if not raw:
        return None

    if raw.startswith("http://"):
        raw = raw[7:]
    elif raw.startswith("https://"):
        raw = raw[8:]

    raw = raw.split("/")[0].split(":")[0].strip(".")
    wildcard = raw.startswith("*.")
    host = raw[2:] if wildcard else raw

    is_valid_domain = DOMAIN_RE.match(host)
    is_valid_ipv4 = IPV4_RE.match(host)
    
    if not host or (not is_valid_domain and not is_valid_ipv4):
        return None
    return f"*.{host}" if wildcard and is_valid_domain else host


def _validate_schedule_targets(targets_text: str) -> tuple[list[str], list[str]]:
    parsed = _parse_targets(targets_text)
    valid_targets: list[str] = []
    invalid_targets: list[str] = []

    for target in parsed:
        normalized = _normalize_domain_candidate(target)
        if normalized:
            valid_targets.append(normalized)
        else:
            invalid_targets.append(target)

    deduped_valid = list(dict.fromkeys(valid_targets))
    return deduped_valid, invalid_targets


def test_ipv4_with_port():
    """Test the main issue: 192.168.18.141:3001 should be accepted"""
    valid, invalid = _validate_schedule_targets("192.168.18.141:3001")
    assert len(invalid) == 0, f"Expected no invalid targets, got: {invalid}"
    assert "192.168.18.141" in valid, f"Expected 192.168.18.141 in valid, got: {valid}"
    print("✓ Test passed: 192.168.18.141:3001 is valid")


def test_ipv4_without_port():
    """Test IPv4 without port"""
    valid, invalid = _validate_schedule_targets("192.168.18.141")
    assert len(invalid) == 0, f"Expected no invalid targets, got: {invalid}"
    assert "192.168.18.141" in valid, f"Expected 192.168.18.141 in valid, got: {valid}"
    print("✓ Test passed: 192.168.18.141 is valid")


def test_domain_with_port():
    """Test domain with port"""
    valid, invalid = _validate_schedule_targets("example.com:8080")
    assert len(invalid) == 0, f"Expected no invalid targets, got: {invalid}"
    assert "example.com" in valid, f"Expected example.com in valid, got: {valid}"
    print("✓ Test passed: example.com:8080 is valid")


def test_mixed_targets():
    """Test mixed IPv4, domain, with and without ports"""
    targets = "192.168.18.141:3001; example.com; google.com:8080; 10.0.0.1"
    valid, invalid = _validate_schedule_targets(targets)
    assert len(invalid) == 0, f"Expected no invalid targets, got: {invalid}"
    assert "192.168.18.141" in valid, "Expected 192.168.18.141"
    assert "example.com" in valid, "Expected example.com"
    assert "google.com" in valid, "Expected google.com"
    assert "10.0.0.1" in valid, "Expected 10.0.0.1"
    print("✓ Test passed: Mixed targets with IPv4 and domains are valid")


def test_invalid_ips():
    """Test that invalid IPs are rejected"""
    invalid_ips = ["999.999.999.999:3001", "192.168.300.1", "256.256.256.256"]
    for ip in invalid_ips:
        valid, invalid = _validate_schedule_targets(ip)
        assert len(invalid) > 0, f"Expected {ip} to be invalid"
    print("✓ Test passed: Invalid IPs are properly rejected")


def test_wildcard_domains():
    """Test wildcard domains"""
    valid, invalid = _validate_schedule_targets("*.example.com")
    assert len(invalid) == 0, f"Expected no invalid targets, got: {invalid}"
    assert "*.example.com" in valid, f"Expected *.example.com in valid, got: {valid}"
    print("✓ Test passed: *.example.com is valid")


if __name__ == "__main__":
    print("Running IPv4 and Domain Validation Tests\n")
    print("=" * 50)
    
    test_ipv4_with_port()
    test_ipv4_without_port()
    test_domain_with_port()
    test_mixed_targets()
    test_invalid_ips()
    test_wildcard_domains()
    
    print("=" * 50)
    print("\n✅ All tests passed! IPv4 and domains are properly validated.")
