# ThreatFox Rules Modifier

A Python script that downloads ThreatFox Suricata rules and enhances the alert messages with additional context.

## What it does

The script modifies ThreatFox Suricata rules to improve alert visibility by:
- Adding the ThreatFox URL to alert messages
- Including DNS query content in DNS rule messages

## Requirements

- Python 3.x
- `requests` library (`pip install requests`)

## Usage

```bash
# Basic usage - downloads and modifies rules
python threatfox_modifier.py

# Save to custom filename
python threatfox_modifier.py -o custom_rules.rules

# Preview changes without saving
python threatfox_modifier.py --dry-run
```

## Example

**Before:**
```
msg:"ThreatFox payload delivery (domain - confidence level: 100%)"
```

**After:**
```
msg:"ThreatFox payload delivery (domain - confidence level: 100%) - ThreatFox: threatfox.abuse.ch/ioc/1579000/ - DNS Query: nvk.toqyboe3.ru"
```

## Output

The script creates a modified rules file (default: `modified_threatfox_suricata.rules`) that can be used directly with Suricata.