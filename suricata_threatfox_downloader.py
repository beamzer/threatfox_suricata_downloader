#!/usr/bin/env python3
"""
ThreatFox Suricata Rules Modifier

This script downloads ThreatFox Suricata rules and modifies the message fields to:
1. Always include the threatfox.abuse.ch URL
2. Include DNS query content when present in DNS rules

Author: Assistant
"""

import requests
import re
import sys
from urllib.parse import urlparse
import argparse

def download_rules(url):
    """Download rules from the given URL."""
    try:
        print(f"Downloading rules from {url}...")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        print(f"Successfully downloaded {len(response.text)} characters")
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error downloading rules: {e}")
        sys.exit(1)

def extract_dns_query_content(rule):
    """Extract the DNS query content from a DNS rule."""
    # Look for dns_query; content:"domain"; pattern
    pattern = r'dns_query;\s*content:"([^"]+)";'
    match = re.search(pattern, rule)
    if match:
        return match.group(1)
    return None

def extract_reference_url(rule):
    """Extract the reference URL from a rule."""
    pattern = r'reference:url,\s*([^;]+);'
    match = re.search(pattern, rule)
    if match:
        return match.group(1).strip()
    return None

def modify_rule_message(rule):
    """Modify the message field of a Suricata rule."""
    # Extract current message
    msg_pattern = r'msg:"([^"]+)";'
    msg_match = re.search(msg_pattern, rule)
    
    if not msg_match:
        return rule
    
    current_msg = msg_match.group(1)
    
    # Extract reference URL
    ref_url = extract_reference_url(rule)
    
    # Check if it's a DNS rule and extract DNS query content
    is_dns_rule = 'alert dns' in rule
    dns_query = None
    if is_dns_rule:
        dns_query = extract_dns_query_content(rule)
    
    # Build new message
    new_msg_parts = [current_msg]
    
    # Add ThreatFox URL if not already present
    if ref_url and 'threatfox.abuse.ch' in ref_url:
        if 'threatfox.abuse.ch' not in current_msg:
            new_msg_parts.append(f"ThreatFox: {ref_url}")
    
    # Add DNS query content if present
    if dns_query and dns_query not in current_msg:
        new_msg_parts.append(f"DNS Query: {dns_query}")
    
    # Create new message
    new_msg = " - ".join(new_msg_parts)
    
    # Replace the message in the rule
    modified_rule = re.sub(msg_pattern, f'msg:"{new_msg}";', rule)
    
    return modified_rule

def process_rules(rules_content):
    """Process all rules in the content."""
    lines = rules_content.split('\n')
    modified_lines = []
    
    rules_processed = 0
    rules_modified = 0
    
    for line in lines:
        # Skip comments and empty lines
        if line.strip().startswith('#') or not line.strip():
            modified_lines.append(line)
            continue
        
        # Check if this is a rule line
        if line.strip().startswith('alert '):
            rules_processed += 1
            modified_line = modify_rule_message(line)
            
            if modified_line != line:
                rules_modified += 1
                print(f"Modified rule SID: {extract_sid(line)}")
            
            modified_lines.append(modified_line)
        else:
            modified_lines.append(line)
    
    print(f"\nProcessing complete:")
    print(f"Total rules processed: {rules_processed}")
    print(f"Rules modified: {rules_modified}")
    
    return '\n'.join(modified_lines)

def extract_sid(rule):
    """Extract SID from a rule for logging purposes."""
    pattern = r'sid:(\d+);'
    match = re.search(pattern, rule)
    return match.group(1) if match else "unknown"

def save_rules(content, filename):
    """Save the modified rules to a file."""
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(content)
        print(f"Modified rules saved to {filename}")
    except IOError as e:
        print(f"Error saving rules: {e}")
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(description='Download and modify ThreatFox Suricata rules')
    parser.add_argument('--url', 
                       default='https://threatfox.abuse.ch/downloads/threatfox_suricata.rules',
                       help='URL to download rules from')
    parser.add_argument('--output', '-o',
                       default='modified_threatfox_suricata.rules',
                       help='Output filename for modified rules')
    parser.add_argument('--dry-run', action='store_true',
                       help='Show what would be modified without saving')
    
    args = parser.parse_args()
    
    # Download rules
    rules_content = download_rules(args.url)
    
    # Process rules
    modified_content = process_rules(rules_content)
    
    if args.dry_run:
        print("\n--- DRY RUN MODE - No files saved ---")
        print("First 5 modified rules preview:")
        lines = modified_content.split('\n')
        rule_count = 0
        for line in lines:
            if line.strip().startswith('alert ') and rule_count < 5:
                print(f"\n{line}")
                rule_count += 1
    else:
        # Save modified rules
        save_rules(modified_content, args.output)
    
    print("\nScript completed successfully!")

if __name__ == "__main__":
    main()

