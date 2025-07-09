# ZER016 PAN-OS Security Advisor

```
 _____   __________  ____ ________
/__  /  / ____/ __ \/ __ <  / ___/
  / /  / __/ / /_/ / / / / / __ \
 / /__/ /___/ _, _/ /_/ / / /_/ /
/____/_____/_/ |_|\____/_/\____/

PAN-OS Security Advisor
```

**Professional-grade PAN-OS vulnerability assessment and upgrade planning tool**

*Developed by Zero One Six Security, LLC (ZER016) - https://zero16sec.com*

*Enterprise Security for Every Enterprise*

---

## Overview

The ZER016 PAN-OS Security Advisor is an enterprise-grade command-line tool designed for IT security professionals who need comprehensive vulnerability analysis and strategic upgrade planning for Palo Alto Networks PAN-OS firewalls. This tool combines real-time CVE data analysis with End-of-Life (EOL) tracking to provide actionable security intelligence.

### Key Value Propositions

- **Risk-Based Decision Making**: Multiple upgrade strategies based on your risk tolerance
- **Zero Downgrade Risk**: Only shows applicable fixes that won't force downgrades
- **EOL Intelligence**: Proactive warnings and migration paths for expiring versions
- **Enterprise Reporting**: CSV exports with audit trails for compliance documentation
- **Strategic Planning**: Long-term security roadmap recommendations

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
- **Real-time CVE Analysis** - Fetches latest vulnerability data from Palo Alto Networks
- **Smart Version Filtering** - Shows only applicable fixes for your current version
- **EOL Lifecycle Management** - Tracks version expiration and support status
- **Multi-Strategy Recommendations** - Tailored upgrade paths for different risk profiles
- **Severity-Based Grouping** - Organizes vulnerabilities by criticality (Critical/High/Medium/Low)
- **Professional Reporting** - Enterprise-ready CSV exports with metadata
- **Zero Downgrade Protection** - Prevents recommendations that could introduce risks

### Advanced Features
- **Automatic EOL Migration** - Recommends next supported version family
- **Comprehensive Analytics** - Frequency analysis across all severity levels
- **Security-Focused Options** - Prioritizes Critical/High severity vulnerabilities
- **Strategic Planning** - Long-term version lifecycle guidance
- **Enterprise Integration** - Designed for corporate security workflows

---

## Requirements

### System Requirements
- **Python 3.7+** (recommended: Python 3.9+)
- **Internet connectivity** for API access
- **Command-line interface** (Windows, macOS, Linux)

### Network Requirements
- Access to `security.paloaltonetworks.com`
- Access to `endoflife.date`

---

## Installation & Usage
```bash
# Clone the repository
git clone https://github.com/zero16sec/panos-security-advisor.git
cd panos-security-advisor

# Install local venv or activate your profile venv
python -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install dependencies
pip install requests

# Run directly
python main.py --help
```

---

```bash
# Analyze a specific PAN-OS version
python main.py 10.2.11-h2

# Export results to CSV
python main.py 10.2.11-h2 --csv security_report.csv

# Show complete EOL analysis
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
- `11.2.3` (Latest versions)

---

## Output Examples

### CVE Analysis Report
```
ZER016 CVE REPORT for PAN-OS 10.2 family (showing fixes >= 10.2.11-h2):
===========================================================================================
CVE ID               Severity     Base Score  Fix Version                      Date        
-------------------------------------------------------------------------------------------
CVE-2025-4230        MEDIUM       8.4         10.2.13-h7                      2025-06-11  
CVE-2025-0108        HIGH         8.8         10.2.11-h12, 10.2.12-h6        2025-06-11  
CVE-2024-0012        CRITICAL     9.3         10.2.11-h6, 10.2.12-h2         2024-11-18  
```

### EOL Status Analysis
```
ZER016 EOL STATUS FOR 10.2:
==================================================
ZER016 STATUS: WARNING - 234 days until EOL
ZER016 LATEST: 10.2.12-h2
ZER016 EOL DATE: 2025-08-15
==================================================
```

### Smart Upgrade Recommendations
```
ZER016 SMART UPGRADE RECOMMENDATION:
======================================================================
Severity     CVE Count    Most Common Fix               
----------------------------------------------------------------------
CRITICAL     1            10.2.11-h6                    
HIGH         3            10.2.11-h12                   
MEDIUM       6            10.2.13-h7                    
LOW          4            10.2.16-h1                    

ZER016 UPGRADE STRATEGY OPTIONS:
==========================================================================================
Strategy        Version         CVEs Fixed   Description                             
------------------------------------------------------------------------------------------
EOL_MIGRATION   11.1.5-h1       N/A          Migrate from EOL/expiring 10.2 family (ZER016 Recommended)
COMPLETE        10.2.16-h1      14/14        Covers 100% of known CVEs for PAN-OS 10.2.11-h2
CONSERVATIVE    10.2.11-h12     8/14         Stays in 10.2.11 train                  
COMPREHENSIVE   10.2.11-h12     8/14         Most frequently recommended across all severities
SECURITY        10.2.11-h12     4/4          Prioritizes Critical/High severity CVEs only
==========================================================================================
```

---

## Configuration

### Display Configuration
The script includes configurable column display options at the top of the file:

```python
# DISPLAY CONFIGURATION - Toggle columns on/off
SHOW_CVE_ID = True          # Show CVE ID column
SHOW_SEVERITY = True        # Show Severity column  
SHOW_THREAT_SCORE = False   # Show Threat Score column (default: False)
SHOW_BASE_SCORE = True      # Show Base Score column
SHOW_FIX_VERSION = True     # Show Fix Version column
SHOW_TITLE = False          # Show Title column (default: False)
SHOW_DATE = True            # Show Date column
```

### Customization Options
- **Column Visibility**: Enable/disable specific data columns
- **Output Format**: Modify table layouts and spacing
- **Color Coding**: Adjust EOL status color indicators
- **Export Fields**: Configure CSV output columns

---

## Upgrade Strategies Explained

### COMPLETE Strategy
- **Purpose**: Addresses 100% of known CVEs
- **Risk Level**: Medium
- **Use Case**: Comprehensive security posture improvement
- **Recommendation**: When security compliance requires complete coverage

### CONSERVATIVE Strategy  
- **Purpose**: Stays within current revision train
- **Risk Level**: Low
- **Use Case**: Minimal disruption maintenance windows
- **Recommendation**: Production environments with strict change control

### COMPREHENSIVE Strategy
- **Purpose**: Most frequently recommended across all severities
- **Risk Level**: Medium
- **Use Case**: Balanced approach to security and stability
- **Recommendation**: General-purpose upgrade planning

### SECURITY Strategy
- **Purpose**: Prioritizes Critical/High severity vulnerabilities only
- **Risk Level**: Medium-Low
- **Use Case**: Rapid response to critical threats
- **Recommendation**: Emergency security updates

### EOL_MIGRATION Strategy
- **Purpose**: Migrate to next supported version family
- **Risk Level**: High (major version change)
- **Use Case**: End-of-life version replacement
- **Recommendation**: Long-term strategic planning

---

## CSV Export Format

### Standard Fields
- `CVE_ID` - Common Vulnerabilities and Exposures identifier
- `Severity` - Vulnerability severity level (Critical/High/Medium/Low)
- `Base_Score` - CVSS base score (0-10 scale)
- `Fix_Version` - Applicable fix versions for your PAN-OS family
- `Date` - CVE publication date
- `Updated` - Last modification date

### ZER016 Metadata Fields
- `ZER016_Analysis_Date` - Timestamp of analysis execution
- `ZER016_Input_Version` - Original input version for audit trail

### Enterprise Integration
CSV exports are designed for integration with:
- **SIEM Systems** - Security Information and Event Management
- **GRC Platforms** - Governance, Risk, and Compliance tools
- **Ticketing Systems** - Change management workflows
- **Asset Management** - IT inventory and tracking systems

---

## Troubleshooting

### Common Issues

#### Network Connectivity
```bash
# Test API connectivity
curl -I https://security.paloaltonetworks.com/
curl -I https://endoflife.date/api/panos.json
```

#### Version Format Errors
```
ZER016 ERROR: Invalid PAN-OS version format: xyz
```
**Solution**: Use proper format like `10.2.11-h2` or `11.1.4-h7`

#### No CVE Data Retrieved
```
ZER016 WARNING: No CVE data retrieved
```
**Possible Causes**:
- Network connectivity issues
- Invalid version format
- API rate limiting
- Firewall blocking outbound HTTPS

### Debug Mode
For troubleshooting, examine the API URLs displayed:
```
ZER016 STATUS: Fetching CVE data for version: 10.2.11-h2
API URL: https://security.paloaltonetworks.com/json/?version=PAN-OS+10.2.11-h2&sort=-date
```

---

## Security Considerations

### Data Privacy
- **No Sensitive Data**: Tool only analyzes public CVE information
- **No Credentials**: No authentication required for public APIs
- **Local Processing**: All analysis performed locally
- **Audit Trail**: CSV exports include analysis metadata

### Network Security
- **HTTPS Only**: All API communications use encrypted connections
- **Public APIs**: Accesses only publicly available security data
- **No Data Transmission**: Your firewall configurations are not transmitted

---

## Contributing

### Development Guidelines
We welcome contributions from the security community! Please follow these guidelines:

1. **Fork the repository** and create a feature branch
2. **Maintain ZER016 branding** in all contributions
3. **Follow Python PEP 8** style guidelines
4. **Add unit tests** for new functionality
5. **Update documentation** for any new features

### Code Standards
- Python 3.7+ compatibility
- Type hints for new functions
- Comprehensive error handling
- Professional logging and output

### Reporting Issues
- Use GitHub Issues for bug reports
- Include PAN-OS version and error output
- Provide steps to reproduce the issue
- Check existing issues before creating new ones

---

## License

**ZER016 Custom Software License**

Copyright (c) 2025 Zero One Six Security, LLC. All rights reserved.

This software is licensed under a custom license that:
- Permits commercial and personal use
- Allows modifications and distribution  
- Requires attribution to Zero One Six Security, LLC
- Prohibits removal of ZER016 branding
- Prohibits claiming ownership or creation

See the [LICENSE](LICENSE) file for complete terms and conditions.

---

## About Zero One Six Security, LLC

Zero One Six Security, LLC (ZER016) specializes in enterprise security solutions and professional-grade security tools. Our mission is to provide IT security professionals with the intelligence and tools needed to maintain robust security postures in complex enterprise environments.

### Contact Information
- **Website**: https://zero16sec.com
- **Email**: sales@zero16sec.com
- **GitHub**: https://github.com/zero16sec

### Professional Services
- Enterprise Security Assessments
- Automation and Tool Development
- Security & Infrastructure Architecture Consulting
- Compliance and Audit Support
- Asset Procurement
- Professional Services
- Adaptive Operations Partner / Daily Operations Management

---

## Acknowledgments

- **Palo Alto Networks** - For providing public CVE data APIs
- **endoflife.date** - For comprehensive EOL tracking data
- **Security Community** - For feedback and continuous improvement
- **Open Source Contributors** - For code reviews and enhancements

---

*Enterprise Security for Every Enterprise*

**© 2025 Zero One Six Security, LLC. All rights reserved.**
