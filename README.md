# ZER016 PAN-OS Security Advisor

```
 _____   __________  ____ ________
/__  /  / ____/ __ \/ __ <  / ___/
  / /  / __/ / /_/ / / / / / __ \
 / /__/ /___/ _, _/ /_/ / / /_/ /
/____/_____/_/ |_|\____/_/\____/

ZER016 PAN-OS CVE Security Assessment Tool
```

**Professional-grade PAN-OS vulnerability assessment and upgrade planning tool**

*Developed by Zero One Six Security, LLC (ZER016) - Enterprise Security for Every Enterprise*

---

## Overview

The ZER016 PAN-OS Security Advisor is an enterprise-grade command-line tool designed for IT security professionals who need comprehensive vulnerability analysis and strategic upgrade planning for Palo Alto Networks PAN-OS firewalls. This tool combines real-time CVE data analysis with End-of-Life (EOL) tracking to provide actionable security intelligence using **only official Palo Alto Networks data sources**.

### Key Value Propositions

- **Official PA Data Only**: Uses only Palo Alto Networks official sources for maximum accuracy
- **Smart Migration Analysis**: Evaluates CVE counts for migration targets across all supported families
- **Zero Phantom Versions**: Only recommends versions that actually exist
- **Multiple Migration Options**: Shows MIGRATE_11.1, MIGRATE_11.2, etc. with CVE analysis
- **Latest Version Intelligence**: Displays cutting-edge vs. recommended versions
- **Enterprise Reporting**: CSV exports with audit trails and ZER016 metadata

---

## Target Audience

- **IT Security Professionals** - Strategic vulnerability management
- **Network Security Engineers** - Firewall maintenance planning  
- **Compliance Officers** - Audit documentation and risk assessment
- **System Administrators** - Patch management and upgrade scheduling
- **Security Operations Centers (SOC)** - Threat intelligence and response
- **Enterprise Risk Management Teams** - Security posture assessment

---

## Features

### Core Capabilities
- **Real-time CVE Analysis** - Fetches latest vulnerability data from Palo Alto Networks security API
- **Official EOL Data** - Parses end-of-life information directly from PA's official EOL page
- **Smart Version Filtering** - Shows only applicable fixes for your current version
- **Multi-Family Migration Analysis** - Evaluates all supported families (11.1, 11.2, etc.) with CVE counts
- **Latest Version Display** - Shows cutting-edge versions by family (supported families only)
- **Professional Reporting** - Enterprise-ready CSV exports with ZER016 metadata

### Advanced Features
- **CVE-Aware Migration** - Checks CVE counts for migration targets before recommending
- **Family-Specific Strategies** - MIGRATE_11.1, MIGRATE_11.2 strategies with individual CVE analysis
- **Known CVEs Column** - Shows target version vulnerability counts
- **Clean vs. Bleeding Edge** - Avoids recommending untested latest versions when cleaner options exist
- **Zero Downgrade Protection** - Never suggests older versions
- **Official Source Validation** - All versions validated against PA's official datalist

---

## Requirements

### System Requirements
- **Python 3.7+** (recommended: Python 3.9+)
- **Internet connectivity** for API access
- **Command-line interface** (Windows, macOS, Linux)

### Python Dependencies
```bash
pip install -r requirements.txt
```

### Network Requirements
- Access to `security.paloaltonetworks.com` (CVE data and version datalist)
- Access to `www.paloaltonetworks.com` (official EOL table)

---

## Installation

### Direct Download
```bash
# Clone the repository
git clone https://github.com/zero16sec/panos-security-advisor.git
cd panos-security-advisor

#Activate or build a venv
python -m venv venv
-or-
venv/bin/activate

# Run directly
python main.py --help
```

---

## Usage

### Basic Usage
```bash
# Analyze a specific PAN-OS version
python main.py 10.2.11-h2

# Export results to CSV with Known CVEs column
python main.py 10.2.11-h2 --csv security_report.csv

# Show complete EOL analysis for all families
python main.py 10.2.11-h2 --show-eol

# Include expired versions in EOL data
python main.py 10.2.11-h2 --show-eol --show-expired
```

### Command-Line Arguments
```
positional arguments:
  version              PAN-OS version (e.g., 10.2.11-h2, 11.1.4-h7)

optional arguments:
  -h, --help           Show help message and exit
  --csv FILENAME       Export results to CSV file
  --show-eol           Display complete EOL summary table
  --show-expired       Include expired versions in EOL summary (requires --show-eol)
```

### Supported Version Formats
- `10.2.11-h2` (Full version with hotfix)
- `11.1.4-h7` (Major.Minor.Patch-Hotfix)
- `10.2.15` (Without hotfix)
- `11.2.6` (Latest versions)

---

## Output Examples

### Smart Upgrade Recommendations
```
ZER016 SMART UPGRADE RECOMMENDATION:
======================================================================
Current Version: 10.2.11-h2 (Family: 10.2)
Latest Available Overall: 11.2.6

LATEST VERSIONS BY FAMILY (Supported Only):
--------------------------------------------------
  10.2: 10.2.16-h1
  11.1: 11.1.10
  11.2: 11.2.6

Severity     CVE Count    Most Common Fix               
----------------------------------------------------------------------
CRITICAL     1            10.2.11-h6                    
HIGH         3            10.2.11-h12                   
MEDIUM       6            10.2.13-h7                    

ZER016 UPGRADE STRATEGY OPTIONS:
==============================================================================================================
Strategy        Version         CVEs Fixed   Known CVEs   Description                             
--------------------------------------------------------------------------------------------------------------
MIGRATE_11.2    11.2.6          18/18        0 CVEs       Migrate to 11.2 family
MIGRATE_11.1    11.1.10         18/18        1 CVE        Migrate to 11.1 family
COMPLETE        10.2.16-h1      18/18        N/A          Covers 100% of known CVEs for PAN-OS 10.2.11-h2
CONSERVATIVE    10.2.11-h12     8/18         N/A          Stays in 10.2.11 train                  
COMPREHENSIVE   10.2.11-h12     8/18         N/A          Most frequently recommended across all severities
SECURITY        10.2.11-h12     4/4          N/A          Prioritizes Critical/High severity CVEs only
==============================================================================================================
```

### CVE Analysis Report
```
ZER016 CVE REPORT for PAN-OS 10.2 family (showing fixes >= 10.2.11-h2):
===========================================================================================
CVE ID               Severity     Base Score  Fix Version                      Date        
-------------------------------------------------------------------------------------------
CVE-2025-0133        MEDIUM       6.1         10.2.13-h7                      2025-01-15  
CVE-2025-0108        HIGH         8.8         10.2.11-h12, 10.2.12-h6        2025-01-11  
CVE-2024-0012        CRITICAL     9.3         10.2.11-h6, 10.2.12-h2         2024-11-18  
```

### EOL Status Analysis
```
EOL STATUS FOR 10.2:
==================================================
STATUS: CRITICAL - 48 days until EOL
LATEST: 10.2.16-h1
EOL DATE: 2025-08-27
==================================================
```

---

## Data Sources

### Official Palo Alto Networks Sources Only
The tool uses **exclusively official PA sources** for maximum accuracy:

1. **CVE Data**: `https://security.paloaltonetworks.com/json/` - Official PA security API
2. **Version Validation**: `https://security.paloaltonetworks.com` - PA's official version datalist 
3. **EOL Information**: `https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary` - Official PA EOL table

### No Third-Party Dependencies
- **No endoflife.date**: Uses only PA's official EOL data
- **No Wikipedia scraping**: All data from authoritative sources
- **No community APIs**: Only PA-verified information

---

## Key Features Explained

### Migration CVE Analysis
The tool evaluates **actual CVE counts** for migration targets:
- Fetches real CVE data for 11.1.10, 11.2.6, etc.
- Shows "0 CVEs" for clean targets or "1 CVE" for targets with vulnerabilities
- Helps choose between families based on security posture

### Latest Version Intelligence
Displays what's available vs. what's recommended:
- **Latest Available Overall**: Shows cutting-edge version (e.g., 11.2.6)
- **Latest by Family**: Shows latest in each supported family
- **Supported Only**: Filters out EOL'd families (no 3.1, 4.0, etc.)

### Smart Strategy Naming
- **MIGRATE_11.1**: Specific migration to 11.1 family with CVE analysis
- **MIGRATE_11.2**: Specific migration to 11.2 family with CVE analysis
- **Known CVEs Column**: Shows vulnerability count in target version

---

## Upgrade Strategies Explained

### Migration Strategies (EOL Situations)
- **MIGRATE_11.1**: Move to 11.1 family (shows CVE count of 11.1.10)
- **MIGRATE_11.2**: Move to 11.2 family (shows CVE count of 11.2.6)
- **Purpose**: Long-term strategic migration from expiring families
- **CVE Consideration**: Picks cleanest option or warns about target CVEs

### Same-Family Strategies
- **COMPLETE**: Addresses 100% of known CVEs in current family
- **CONSERVATIVE**: Stays within current revision train (lowest risk)
- **COMPREHENSIVE**: Most frequently recommended across all severities  
- **SECURITY**: Prioritizes Critical/High severity vulnerabilities only

---

## CSV Export Format

### Standard Fields
- `CVE_ID` - Common Vulnerabilities and Exposures identifier
- `Severity` - Vulnerability severity level (Critical/High/Medium/Low)
- `Base_Score` - CVSS base score (0-10 scale)
- `Fix_Version` - Applicable fix versions for your PAN-OS family
- `Date` - CVE publication date

### ZER016 Enhanced Metadata
- `ZER016_Analysis_Date` - Timestamp of analysis execution
- `ZER016_Input_Version` - Original input version for audit trail
- `Updated` - Last CVE modification date

---

## Configuration

### Display Configuration
The script includes configurable column display options:

```python
# DISPLAY CONFIGURATION - Toggle columns on/off
SHOW_CVE_ID = True          # Show CVE ID column
SHOW_SEVERITY = True        # Show Severity column  
SHOW_THREAT_SCORE = False   # Show Threat Score column
SHOW_BASE_SCORE = True      # Show Base Score column
SHOW_FIX_VERSION = True     # Show Fix Version column
SHOW_TITLE = False          # Show Title column
SHOW_DATE = True            # Show Date column
```

---

## Troubleshooting

### Common Issues

#### Missing BeautifulSoup
```bash
# Install required dependency
pip install beautifulsoup4
```

#### Network Connectivity
```bash
# Test PA API connectivity
curl -I https://security.paloaltonetworks.com/
curl -I https://www.paloaltonetworks.com/
```

#### Version Format Errors
```
ZER016 ERROR: Invalid PAN-OS version format: xyz
```
**Solution**: Use proper format like `10.2.11-h2` or `11.1.4-h7`

#### No Migration Options
If no migration options appear, verify:
- Your version is approaching EOL (within 365 days)
- Network access to PA's EOL page
- BeautifulSoup is installed for HTML parsing

---

## Security Considerations

### Data Privacy
- **No Sensitive Data**: Tool only analyzes public CVE information
- **Official Sources Only**: All data from Palo Alto Networks
- **Local Processing**: All analysis performed locally
- **Audit Trail**: CSV exports include ZER016 analysis metadata

### Network Security
- **HTTPS Only**: All communications use encrypted connections
- **Official APIs Only**: Accesses only PA's public security data
- **No Configuration Data**: Your firewall configs never transmitted

---

## About Zero One Six Security, LLC

Zero One Six Security, LLC (ZER016) specializes in enterprise security solutions and professional-grade security tools. Our mission is to provide IT security professionals with the intelligence and tools needed to maintain robust security postures in complex enterprise environments.

### Contact Information
- **Website**: [https://zero16sec.com]
- **Email**: [Contact through website]
- **GitHub**: [@zer016-security](https://github.com/zer016-security)

---

## License

**ZER016 Custom Software License**

Copyright (c) 2025 Zero One Six Security, LLC. All rights reserved.

This software is licensed under a custom license that permits commercial and personal use while requiring attribution to Zero One Six Security, LLC and prohibiting removal of ZER016 branding.

---

## Acknowledgments

- **Palo Alto Networks** - For providing official CVE data APIs and EOL information
- **Security Community** - For feedback and continuous improvement
- **Enterprise Users** - For real-world testing and feature requests

---

*Enterprise Security for Every Enterprise*

**© 2025 Zero One Six Security, LLC. All rights reserved.**
