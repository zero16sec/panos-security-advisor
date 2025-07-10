# main.py
r"""
================================================================================
ZER016 PAN-OS CVE Security Assessment Tool
================================================================================

ENTERPRISE SECURITY MANAGEMENT SOLUTION
Developed by Zero One Six Security, LLC (ZER016)

OVERVIEW:
This comprehensive security assessment tool provides enterprise-grade analysis 
of PAN-OS firewall vulnerabilities and intelligent upgrade recommendations. 
The tool integrates CVE data analysis with End-of-Life (EOL) tracking to 
deliver strategic security planning capabilities for IT security professionals.

KEY FEATURES:
• CVE Analysis: Fetches real-time vulnerability data from Palo Alto Networks
• Smart Filtering: Shows only applicable fixes for your current version
• EOL Management: Tracks version lifecycle and expiration dates  
• Upgrade Strategy: Provides multiple upgrade paths based on risk tolerance
• Export Capabilities: Generates CSV reports for compliance documentation
• Version Intelligence: Prevents downgrade recommendations
• Severity Analysis: Groups vulnerabilities by criticality levels

CORE FUNCTIONALITY:
The tool takes a PAN-OS version as input (e.g., 10.2.11-h2), fetches current 
CVE data from Palo Alto Networks security API, and displays affected CVEs with 
their severity ratings and applicable fix versions. Only shows fix versions 
that are equal to or newer than your input version, preventing downgrade 
scenarios that could introduce additional security risks.

UPGRADE STRATEGIES:
• COMPLETE: Covers 100% of known CVEs with minimum version jump
• CONSERVATIVE: Stays within current revision train (lowest risk)
• COMPREHENSIVE: Most frequently recommended across all severity levels
• SECURITY: Prioritizes Critical/High severity vulnerabilities
• MIGRATE_X.Y: Migration to newer family with CVE analysis

TARGET AUDIENCE:
• IT Security Professionals
• Network Security Engineers  
• Compliance Officers
• System Administrators
• Security Operations Centers (SOC)
• Enterprise Risk Management Teams

COMPLIANCE & REPORTING:
Supports enterprise compliance requirements with detailed CSV exports 
including ZER016 analysis metadata, timestamps, and version tracking 
for audit trails and security documentation.

 _____   __________  ____ ________
/__  /  / ____/ __ \/ __ <  / ___/
  / /  / __/ / /_/ / / / / / __ \
 / /__/ /___/ _, _/ /_/ / / /_/ /
/____/_____/_/ |_|\____/_/\____/

Copyright (c) 2025 Zero One Six Security, LLC. All rights reserved.
Enterprise Security Solutions - Professional Grade Tools
================================================================================
"""

import re
import sys
import csv
import json
import requests
import argparse
from urllib.parse import quote
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple

try:
    from bs4 import BeautifulSoup
    BS4_AVAILABLE = True
except ImportError:
    BS4_AVAILABLE = False

# ============================================================================
# ZER016 BRANDING
# ============================================================================
ZER016_BANNER = r"""
 _____   __________  ____ ________
/__  /  / ____/ __ \/ __ <  / ___/
  / /  / __/ / /_/ / / / / / __ \
 / /__/ /___/ _, _/ /_/ / / /_/ /
/____/_____/_/ |_|\____/_/\____/

ZER016 PAN-OS CVE Security Assessment Tool
"""

# ============================================================================
# DISPLAY CONFIGURATION - Toggle columns on/off
# ============================================================================
SHOW_CVE_ID = True          # Show CVE ID column
SHOW_SEVERITY = True        # Show Severity column  
SHOW_THREAT_SCORE = False   # Show Threat Score column
SHOW_BASE_SCORE = True      # Show Base Score column
SHOW_FIX_VERSION = True     # Show Fix Version column
SHOW_TITLE = False          # Show Title column
SHOW_DATE = True            # Show Date column

# ============================================================================
# COLOR CONFIGURATION 
# ============================================================================
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
RESET = "\033[0m"

class PanOSVersion:
    """Class to handle PAN-OS version parsing and comparison."""
    
    def __init__(self, version_str: str):
        self.original = version_str.replace("PAN-OS ", "").strip()
        self.major, self.minor, self.patch, self.hotfix = self._parse_version(self.original)
        self.family = f"{self.major}.{self.minor}"
    
    def _parse_version(self, version: str) -> Tuple[int, int, int, int]:
        """Parse PAN-OS version string into components."""
        version = re.sub(r'^>=?\s*', '', version).strip()
        
        match = re.match(r'^(\d+)\.(\d+)\.(\d+)(?:-h(\d+))?', version)
        if not match:
            simple_match = re.match(r'^(\d+)\.(\d+)$', version)
            if simple_match:
                return int(simple_match.group(1)), int(simple_match.group(2)), 0, 0
            raise ValueError(f"Invalid PAN-OS version format: {version}")
        
        major = int(match.group(1))
        minor = int(match.group(2))
        patch = int(match.group(3))
        hotfix = int(match.group(4)) if match.group(4) else 0
        
        return major, minor, patch, hotfix
    
    def _version_tuple(self):
        """Return version as tuple for comparison."""
        return (self.major, self.minor, self.patch, self.hotfix)
    
    def __ge__(self, other):
        if not isinstance(other, PanOSVersion):
            return NotImplemented
        return self._version_tuple() >= other._version_tuple()
    
    def __gt__(self, other):
        if not isinstance(other, PanOSVersion):
            return NotImplemented
        return self._version_tuple() > other._version_tuple()
    
    def __le__(self, other):
        if not isinstance(other, PanOSVersion):
            return NotImplemented
        return self._version_tuple() <= other._version_tuple()
    
    def __lt__(self, other):
        if not isinstance(other, PanOSVersion):
            return NotImplemented
        return self._version_tuple() < other._version_tuple()
    
    def __eq__(self, other):
        if not isinstance(other, PanOSVersion):
            return NotImplemented
        return self._version_tuple() == other._version_tuple()
    
    def __ne__(self, other):
        if not isinstance(other, PanOSVersion):
            return NotImplemented
        return self._version_tuple() != other._version_tuple()
    
    def __str__(self):
        if self.hotfix > 0:
            return f"{self.major}.{self.minor}.{self.patch}-h{self.hotfix}"
        return f"{self.major}.{self.minor}.{self.patch}"

def get_available_panos_versions():
    """Get all available PAN-OS versions from the security portal datalist."""
    if not BS4_AVAILABLE:
        print("ZER016 ERROR: BeautifulSoup not available. Install with: pip install beautifulsoup4")
        return []
    
    try:
        url = "https://security.paloaltonetworks.com"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        version_datalist = soup.find('datalist', {'id': 'dl-version'})
        if not version_datalist:
            print("ZER016 WARNING: Could not find version datalist on PA security portal")
            return []
        
        available_versions = []
        version_options = version_datalist.find_all('option')
        
        for option in version_options:
            version_value = option.get('value', '')
            if version_value.startswith('PAN-OS '):
                clean_version = version_value.replace('PAN-OS ', '').strip()
                if clean_version and clean_version not in ['', 'undefined']:
                    available_versions.append(clean_version)
        
        return sorted(set(available_versions))
        
    except Exception as e:
        print(f"ZER016 ERROR: Unable to fetch available versions: {e}")
        return []

def get_latest_version_for_family(version_family: str, available_versions: List[str]) -> str:
    """Get the latest version for a given family from available versions list."""
    try:
        family_versions = []
        
        for version_str in available_versions:
            try:
                parsed_ver = PanOSVersion(version_str)
                if parsed_ver.family == version_family:
                    family_versions.append(parsed_ver)
            except ValueError:
                continue
        
        if family_versions:
            latest = max(family_versions, key=lambda v: (v.major, v.minor, v.patch, v.hotfix))
            return str(latest)
        else:
            return f"{version_family}.x"
            
    except Exception:
        return f"{version_family}.x"

def parse_panos_eol_data():
    """Parse PAN-OS End of Life data from official Palo Alto Networks EOL page."""
    if not BS4_AVAILABLE:
        print("ZER016 ERROR: BeautifulSoup not available. Install with: pip install beautifulsoup4")
        return []
    
    try:
        url = "https://www.paloaltonetworks.com/services/support/end-of-life-announcements/end-of-life-summary"
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        eol_data = []
        
        tables = soup.find_all('table')
        panos_table = None
        
        for table in tables:
            header_text = table.get_text()
            if 'PAN-OS' in header_text and 'Panorama' in header_text:
                panos_table = table
                break
        
        if not panos_table:
            print("ZER016 WARNING: Could not find PAN-OS EOL table on PA website")
            return []
        
        rows = panos_table.find_all('tr')
        
        for row in rows:
            cells = row.find_all(['td', 'th'])
            if len(cells) >= 3:
                cell_texts = [cell.get_text().strip() for cell in cells]
                
                if not cell_texts[0] or cell_texts[0] in ['Version', 'PAN-OS & Panorama', '']:
                    continue
                
                version_text = cell_texts[0]
                if not re.match(r'^\d+\.\d+', version_text):
                    continue
                
                version = re.sub(r'\+.*$', '', version_text)
                release_date = cell_texts[1] if len(cell_texts) > 1 else ''
                eol_date = cell_texts[2] if len(cell_texts) > 2 else ''
                
                try:
                    if release_date:
                        parsed_release = datetime.strptime(release_date, "%B %d, %Y")
                        release_iso = parsed_release.strftime("%Y-%m-%d")
                    else:
                        release_iso = ''
                    
                    if eol_date:
                        parsed_eol = datetime.strptime(eol_date, "%B %d, %Y")
                        eol_iso = parsed_eol.strftime("%Y-%m-%d")
                    else:
                        eol_iso = ''
                    
                    eol_data.append({
                        'cycle': version,
                        'release_date': release_iso,
                        'eol': eol_iso,
                        'latest': ''
                    })
                    
                except ValueError:
                    continue
        
        return eol_data
        
    except requests.exceptions.RequestException as e:
        print(f"ZER016 ERROR: Unable to fetch EOL data from PA website: {e}")
        return []
    except Exception as e:
        print(f"ZER016 ERROR: Unable to parse EOL data from PA website: {e}")
        return []

def check_version_eol_status(input_version: PanOSVersion):
    """Check if the input version is approaching or past EOL."""
    eol_data = parse_panos_eol_data()
    if not eol_data:
        return None
    
    available_versions = get_available_panos_versions()
    today = datetime.now(timezone.utc).date()
    input_family = input_version.family
    
    for entry in eol_data:
        version_cycle = entry.get('cycle', '')
        if version_cycle == input_family:
            eol_str = entry.get('eol')
            if eol_str:
                eol_date = datetime.strptime(eol_str, "%Y-%m-%d").date()
                days_left = (eol_date - today).days
                
                latest = get_latest_version_for_family(input_family, available_versions)
                entry['latest'] = latest
                
                return {
                    'version': version_cycle,
                    'latest': latest,
                    'eol_date': eol_date,
                    'days_left': days_left,
                    'is_expired': days_left < 0,
                    'is_warning': days_left <= 365
                }
    
    return None

def display_eol_summary(show_expired=False):
    """Display PAN-OS EOL summary table."""
    eol_data = parse_panos_eol_data()
    if not eol_data:
        print("ZER016 WARNING: Could not fetch official PANW EOL data.")
        return
    
    available_versions = get_available_panos_versions()
    today = datetime.now(timezone.utc).date()
    
    print(f"\nZER016 PAN-OS END OF LIFE ANALYSIS (Official PANW Data):")
    print("=" * 80)
    print(f"{'Version':<10} {'Latest':<20} {'EOL Date':<12} {'Days Left':<11} {'Status':<15}")
    print("-" * 80)
    
    for entry in eol_data:
        version = entry.get('cycle', 'N/A')
        
        latest = get_latest_version_for_family(version, available_versions)
        entry['latest'] = latest
        
        eol_str = entry.get('eol')
        
        if eol_str:
            eol_date = datetime.strptime(eol_str, "%Y-%m-%d").date()
            days_left = (eol_date - today).days
            
            if days_left < 0:
                if not show_expired:
                    continue
                status = "EXPIRED"
                color = RED
                days_display = f"{days_left}"
            elif days_left <= 90:
                status = "CRITICAL"
                color = RED
                days_display = f"{days_left}"
            elif days_left <= 365:
                status = "WARNING"
                color = YELLOW
                days_display = f"{days_left}"
            else:
                status = "SUPPORTED"
                color = GREEN
                days_display = f"{days_left}"
        else:
            eol_date = 'Unknown'
            days_display = 'Unknown'
            status = "UNKNOWN"
            color = RESET
        
        print(f"{color}{version:<10} {latest:<20} {str(eol_date):<12} {days_display:<11} {status:<15}{RESET}")
    
    print("=" * 80)

def fetch_cve_data(version: str) -> List[Dict]:
    """Fetch CVE data from Palo Alto Networks security API."""
    encoded_version = quote(f"PAN-OS {version}")
    url = f"https://security.paloaltonetworks.com/json/?version={encoded_version}&sort=-date"
    
    try:
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        data = response.json()
        return data if isinstance(data, list) else []
        
    except requests.exceptions.RequestException as e:
        print(f"ZER016 ERROR: Unable to fetch CVE data from API: {e}")
        return []
    except json.JSONDecodeError as e:
        print(f"ZER016 ERROR: Unable to parse JSON response: {e}")
        return []

def parse_fix_versions(fix_string: str) -> List[str]:
    """Parse fix version string and extract individual versions."""
    if not fix_string or fix_string in ["All", "None"]:
        return [fix_string]
    
    versions = []
    parts = [part.strip() for part in fix_string.split(',')]
    
    for part in parts:
        if part.startswith('< '):
            continue
        
        clean_part = re.sub(r'\s*\[ETA:.*?\]', '', part)
        clean_part = re.sub(r'^>=?\s*', '', clean_part).strip()
        
        if clean_part and clean_part not in ["All", "None"]:
            versions.append(clean_part)
    
    return versions if versions else [fix_string]

def find_applicable_fix_version(cve_data: Dict, version_family: str, input_version: PanOSVersion) -> List[str]:
    """Find applicable fix versions that are >= input version for the given PAN-OS family."""
    try:
        versions = cve_data.get('version', [])
        fixed_versions = cve_data.get('fixed', [])
        
        family_pattern = f"PAN-OS {version_family}"
        
        for i, ver in enumerate(versions):
            if ver == family_pattern and i < len(fixed_versions):
                fix_info = fixed_versions[i]
                
                if fix_info == "All":
                    return ["Not affected"]
                elif fix_info == "None":
                    return ["No fix available"]
                
                fix_versions = parse_fix_versions(fix_info)
                applicable_versions = []
                
                for fix_ver in fix_versions:
                    if fix_ver in ["All", "None"]:
                        applicable_versions.append(fix_ver)
                        continue
                    
                    try:
                        fix_version_obj = PanOSVersion(fix_ver)
                        if (fix_version_obj.family == input_version.family and 
                            fix_version_obj >= input_version):
                            applicable_versions.append(str(fix_version_obj))
                    except ValueError:
                        applicable_versions.append(fix_ver)
                
                return applicable_versions if applicable_versions else ["No applicable fix (version too old)"]
        
        return ["Version family not found"]
        
    except Exception as e:
        return [f"Error parsing fix data: {e}"]

def evaluate_cve_score_for_version(version_str: str) -> Dict:
    """Evaluate CVE score for a specific version by fetching its CVE data."""
    try:
        cve_data = fetch_cve_data(version_str)
        
        if not cve_data:
            return {'score': 0, 'description': '0 CVEs', 'details': []}
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0}
        details = []
        
        for cve in cve_data:
            severity = cve.get('severity', 'UNKNOWN').upper()
            if severity in severity_counts:
                severity_counts[severity] += 1
                details.append({
                    'id': cve.get('ID', 'Unknown'),
                    'severity': severity,
                    'score': cve.get('baseScore', 'N/A')
                })
        
        total_cves = sum(severity_counts.values())
        if total_cves == 0:
            description = '0 CVEs'
        else:
            desc_parts = []
            for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
                if severity_counts[severity] > 0:
                    desc_parts.append(f"{severity_counts[severity]} {severity}")
            description = ', '.join(desc_parts)
        
        return {
            'score': total_cves,
            'description': description,
            'details': details,
            'severity_counts': severity_counts
        }
        
    except Exception as e:
        return {'score': 999, 'description': f'Error: {e}', 'details': []}

def generate_eol_migration_analysis(current_version: PanOSVersion) -> List[Dict]:
    """Generate comprehensive EOL migration analysis and return migration options."""
    try:
        eol_data = parse_panos_eol_data()
        available_versions = get_available_panos_versions()
        
        if not eol_data or not available_versions:
            return []
        
        today = datetime.now(timezone.utc).date()
        
        supported_families = []
        for entry in eol_data:
            version_cycle = entry.get('cycle', '')
            eol_str = entry.get('eol')
            
            if eol_str and version_cycle:
                try:
                    major, minor = map(int, version_cycle.split('.'))
                    eol_date = datetime.strptime(eol_str, "%Y-%m-%d").date()
                    days_left = (eol_date - today).days
                    
                    if (major > current_version.major or 
                        (major == current_version.major and minor > current_version.minor)) and days_left > 365:
                        
                        latest_version = get_latest_version_for_family(version_cycle, available_versions)
                        
                        supported_families.append({
                            'family': version_cycle,
                            'major': major,
                            'minor': minor,
                            'latest_version': latest_version,
                            'eol_date': eol_date,
                            'days_left': days_left
                        })
                except (ValueError, AttributeError):
                    continue
        
        if not supported_families:
            return []
        
        supported_families.sort(key=lambda x: (x['major'], x['minor']))
        
        migration_options = []
        
        for family_info in supported_families:
            latest_ver = family_info['latest_version']
            if latest_ver.endswith('.x'):
                continue
                
            cve_analysis = evaluate_cve_score_for_version(latest_ver)
            
            migration_options.append({
                'family': family_info['family'],
                'latest_version': latest_ver,
                'cve_score': cve_analysis['score'],
                'cve_description': cve_analysis['description'],
                'eol_date': family_info['eol_date'],
                'days_left': family_info['days_left'],
                'severity_counts': cve_analysis.get('severity_counts', {}),
                'details': cve_analysis.get('details', [])
            })
        
        migration_options.sort(key=lambda x: (x['cve_score'], -x['days_left']))
        
        return migration_options
        
    except Exception as e:
        print(f"ZER016 ERROR: Unable to perform EOL migration analysis: {e}")
        return []

def generate_upgrade_recommendation(cve_list: List[Dict], version_family: str, input_version: PanOSVersion, eol_status: Optional[Dict] = None) -> str:
    """Generate smart upgrade recommendation based on severity analysis and common fix versions."""
    try:
        available_versions = get_available_panos_versions()
        eol_data = parse_panos_eol_data()
        
        all_versions = []
        for version_str in available_versions:
            try:
                parsed_ver = PanOSVersion(version_str)
                all_versions.append(parsed_ver)
            except ValueError:
                continue
        
        latest_overall = max(all_versions, key=lambda v: (v.major, v.minor, v.patch, v.hotfix))
        
        # Get EOL status for filtering
        today = datetime.now(timezone.utc).date()
        eol_families = {}
        for entry in eol_data:
            version_cycle = entry.get('cycle', '')
            eol_str = entry.get('eol')
            if eol_str and version_cycle:
                eol_date = datetime.strptime(eol_str, "%Y-%m-%d").date()
                days_left = (eol_date - today).days
                eol_families[version_cycle] = {
                    'eol_date': eol_date,
                    'days_left': days_left,
                    'is_expired': days_left < 0
                }
        
        # Find latest version for each family, but only include non-expired families
        family_latest = {}
        for version in all_versions:
            family = version.family
            # Only include families that are not expired
            if family in eol_families and not eol_families[family]['is_expired']:
                if family not in family_latest or version > family_latest[family]:
                    family_latest[family] = version
        
        severity_groups = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        all_fix_versions = []
        
        for cve in cve_list:
            severity = cve.get('severity', 'UNKNOWN').upper()
            fix_versions = find_applicable_fix_version(cve, version_family, input_version)
            
            valid_fixes = []
            for fix_ver in fix_versions:
                if (fix_ver not in ["Not affected", "No fix available", "Version family not found", 
                                   "No applicable fix (version too old)"] and 
                    not fix_ver.startswith("Error")):
                    valid_fixes.append(fix_ver)
                    all_fix_versions.append(fix_ver)
            
            if valid_fixes and severity in severity_groups:
                severity_groups[severity].append({
                    'cve_id': cve.get('ID', 'Unknown'),
                    'fixes': valid_fixes,
                    'base_score': cve.get('baseScore', 0)
                })
        
        if not all_fix_versions:
            return "No specific upgrade recommendations available."
        
        version_frequency = {}
        parsed_versions = []
        
        for fix_ver in all_fix_versions:
            try:
                parsed_ver = PanOSVersion(fix_ver)
                if parsed_ver.family == input_version.family:
                    version_str = str(parsed_ver)
                    version_frequency[version_str] = version_frequency.get(version_str, 0) + 1
                    parsed_versions.append(parsed_ver)
            except ValueError:
                continue
        
        sorted_by_frequency = sorted(version_frequency.items(), key=lambda x: (-x[1], x[0]))
        
        recommendations = []
        recommendations.append("ZER016 SMART UPGRADE RECOMMENDATION:")
        recommendations.append("=" * 70)
        recommendations.append(f"Current Version: {input_version} (Family: {input_version.family})")
        recommendations.append(f"Latest Available Overall: {latest_overall}")
        recommendations.append("")
        
        recommendations.append("LATEST VERSIONS BY FAMILY:")
        recommendations.append("-" * 50)
        sorted_families = sorted(family_latest.items(), key=lambda x: (int(x[0].split('.')[0]), int(x[0].split('.')[1])))
        for family, latest_ver in sorted_families:
            recommendations.append(f"  {family}: {latest_ver}")
        recommendations.append("")
        
        recommendations.append(f"{'Severity':<12} {'CVE Count':<12} {'Most Common Fix':<30}")
        recommendations.append("-" * 70)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            if severity_groups[severity]:
                count = len(severity_groups[severity])
                
                severity_fixes = []
                for cve_info in severity_groups[severity]:
                    severity_fixes.extend(cve_info['fixes'])
                
                severity_freq = {}
                for fix in severity_fixes:
                    try:
                        parsed_ver = PanOSVersion(fix)
                        if parsed_ver.family == input_version.family:
                            version_str = str(parsed_ver)
                            severity_freq[version_str] = severity_freq.get(version_str, 0) + 1
                    except ValueError:
                        continue
                
                if severity_freq:
                    most_common_fix = max(severity_freq.items(), key=lambda x: x[1])
                    recommendations.append(f"{severity:<12} {count:<12} {most_common_fix[0]:<30}")
        
        recommendations.append("")
        
        def count_fixed_cves(target_version_str):
            try:
                target_version = PanOSVersion(target_version_str)
            except ValueError:
                return 0
            
            fixed_count = 0
            for cve in cve_list:
                fix_versions = find_applicable_fix_version(cve, version_family, input_version)
                for fix_ver in fix_versions:
                    try:
                        parsed_fix = PanOSVersion(fix_ver)
                        if parsed_fix <= target_version:
                            fixed_count += 1
                            break
                    except ValueError:
                        continue
            return fixed_count
        
        complete_version = None
        if parsed_versions:
            all_unique_versions = list(set([str(v) for v in parsed_versions]))
            all_unique_versions.sort(key=lambda v: PanOSVersion(v).major * 10000 + 
                                                  PanOSVersion(v).minor * 1000 + 
                                                  PanOSVersion(v).patch * 100 + 
                                                  PanOSVersion(v).hotfix)
            
            for version_str in all_unique_versions:
                if count_fixed_cves(version_str) == len(cve_list):
                    complete_version = version_str
                    break
        
        strategies = []
        
        if eol_status and (eol_status['is_expired'] or eol_status['is_warning']):
            migration_options = generate_eol_migration_analysis(input_version)
            
            for option in migration_options:
                fixed_count = len(cve_list)
                
                strategies.append({
                    'strategy': f'MIGRATE_{option["family"]}',
                    'version': option['latest_version'],
                    'fixed': f'{fixed_count}/{len(cve_list)}',
                    'known_cves': option['cve_description'],
                    'description': f'Migrate to {option["family"]} family'
                })
        
        if complete_version:
            complete_count = count_fixed_cves(complete_version)
            strategies.append({
                'strategy': 'COMPLETE',
                'version': complete_version,
                'fixed': f"{complete_count}/{len(cve_list)}",
                'known_cves': 'N/A',
                'description': f'Covers 100% of known CVEs for PAN-OS {input_version}'
            })
        
        same_revision_fixes = [v for v in parsed_versions if v.patch == input_version.patch]
        if same_revision_fixes:
            highest_same_revision = max(same_revision_fixes, key=lambda v: v.hotfix)
            fixed_count = count_fixed_cves(str(highest_same_revision))
            
            strategies.append({
                'strategy': 'CONSERVATIVE',
                'version': str(highest_same_revision),
                'fixed': f"{fixed_count}/{len(cve_list)}",
                'known_cves': 'N/A',
                'description': f"Stays in {input_version.major}.{input_version.minor}.{input_version.patch} train"
            })
        
        if sorted_by_frequency:
            most_comprehensive = sorted_by_frequency[0][0]
            comprehensive_count = count_fixed_cves(most_comprehensive)
            
            strategies.append({
                'strategy': 'COMPREHENSIVE',
                'version': most_comprehensive,
                'fixed': f"{comprehensive_count}/{len(cve_list)}",
                'known_cves': 'N/A',
                'description': 'Most frequently recommended across all severities'
            })
        
        critical_high_fixes = []
        for severity in ['CRITICAL', 'HIGH']:
            for cve_info in severity_groups[severity]:
                critical_high_fixes.extend(cve_info['fixes'])
        
        if critical_high_fixes:
            critical_high_freq = {}
            for fix in critical_high_fixes:
                try:
                    parsed_ver = PanOSVersion(fix)
                    if parsed_ver.family == input_version.family:
                        version_str = str(parsed_ver)
                        critical_high_freq[version_str] = critical_high_freq.get(version_str, 0) + 1
                except ValueError:
                    continue
            
            if critical_high_freq:
                critical_focus = max(critical_high_freq.items(), key=lambda x: x[1])[0]
                
                critical_high_count = 0
                total_critical_high = len(severity_groups['CRITICAL']) + len(severity_groups['HIGH'])
                
                for severity in ['CRITICAL', 'HIGH']:
                    for cve_info in severity_groups[severity]:
                        for fix_ver in cve_info['fixes']:
                            try:
                                parsed_fix = PanOSVersion(fix_ver)
                                parsed_focus = PanOSVersion(critical_focus)
                                if parsed_fix <= parsed_focus:
                                    critical_high_count += 1
                                    break
                            except ValueError:
                                continue
                
                if total_critical_high > 0:
                    strategies.append({
                        'strategy': 'SECURITY',
                        'version': critical_focus,
                        'fixed': f"{critical_high_count}/{total_critical_high}",
                        'known_cves': 'N/A',
                        'description': 'Prioritizes Critical/High severity CVEs only'
                    })
        
        recommendations.append("ZER016 UPGRADE STRATEGY OPTIONS:")
        recommendations.append("=" * 110)
        recommendations.append(f"{'Strategy':<15} {'Version':<15} {'CVEs Fixed':<12} {'Known CVEs':<12} {'Description':<40}")
        recommendations.append("-" * 110)
        
        for strategy in strategies:
            recommendations.append(f"{strategy['strategy']:<15} {strategy['version']:<15} {strategy['fixed']:<12} {strategy['known_cves']:<12} {strategy['description']:<40}")
        
        recommendations.append("=" * 110)
        
        return "\n".join(recommendations)
        
    except Exception as e:
        return f"Error generating recommendation: {e}"

def display_cve_table(cve_list: List[Dict], version_family: str, input_version: PanOSVersion):
    """Display CVE information in a formatted table based on configuration flags."""
    if not cve_list:
        print("ZER016 RESULT: No CVEs found for the specified version.")
        return
    
    headers = []
    formats = []
    total_width = 0
    
    if SHOW_CVE_ID:
        headers.append("CVE ID")
        formats.append("20")
        total_width += 22
    
    if SHOW_SEVERITY:
        headers.append("Severity")
        formats.append("12")
        total_width += 14
    
    if SHOW_THREAT_SCORE:
        headers.append("Threat Score")
        formats.append("12")
        total_width += 14
    
    if SHOW_BASE_SCORE:
        headers.append("Base Score")
        formats.append("11")
        total_width += 13
    
    if SHOW_FIX_VERSION:
        headers.append("Fix Version")
        formats.append("40")
        total_width += 42
    
    if SHOW_DATE:
        headers.append("Date")
        formats.append("12")
        total_width += 14
    
    if SHOW_TITLE:
        headers.append("Title")
        formats.append("45")
        total_width += 47
    
    print(f"\nZER016 CVE REPORT for PAN-OS {version_family} family (showing fixes >= {input_version}):")
    print("=" * total_width)
    
    header_format = " ".join([f"{{:<{fmt}}}" for fmt in formats])
    print(header_format.format(*headers))
    print("-" * total_width)
    
    for cve in cve_list:
        row_data = []
        
        if SHOW_CVE_ID:
            row_data.append(cve.get('ID', 'N/A'))
        
        if SHOW_SEVERITY:
            row_data.append(cve.get('severity', 'N/A'))
        
        if SHOW_THREAT_SCORE:
            row_data.append(str(cve.get('threatScore', 'N/A')))
        
        if SHOW_BASE_SCORE:
            row_data.append(str(cve.get('baseScore', 'N/A')))
        
        if SHOW_FIX_VERSION:
            fix_versions = find_applicable_fix_version(cve, version_family, input_version)
            fix_version = ", ".join(fix_versions)
            row_data.append(fix_version)
        
        if SHOW_DATE:
            date = cve.get('date', 'N/A')
            if date != 'N/A' and 'T' in date:
                date = date.split('T')[0]
            row_data.append(date)
        
        if SHOW_TITLE:
            title = cve.get('title', 'N/A')
            if len(title) > 42:
                title = title[:39] + "..."
            row_data.append(title)
        
        print(header_format.format(*row_data))

def export_to_csv(cve_list: List[Dict], version_family: str, input_version: PanOSVersion, filename: str):
    """Export CVE data to CSV file based on configuration flags."""
    try:
        fieldnames = []
        
        if SHOW_CVE_ID:
            fieldnames.append('CVE_ID')
        if SHOW_SEVERITY:
            fieldnames.append('Severity')
        if SHOW_THREAT_SCORE:
            fieldnames.append('Threat_Score')
        if SHOW_BASE_SCORE:
            fieldnames.append('Base_Score')
        if SHOW_FIX_VERSION:
            fieldnames.append('Fix_Version')
        if SHOW_DATE:
            fieldnames.append('Date')
        if SHOW_TITLE:
            fieldnames.append('Title')
        
        fieldnames.extend(['Updated', 'ZER016_Analysis_Date', 'ZER016_Input_Version'])
        
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            analysis_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            for cve in cve_list:
                row_data = {}
                
                if SHOW_CVE_ID:
                    row_data['CVE_ID'] = cve.get('ID', 'N/A')
                if SHOW_SEVERITY:
                    row_data['Severity'] = cve.get('severity', 'N/A')
                if SHOW_THREAT_SCORE:
                    row_data['Threat_Score'] = cve.get('threatScore', 'N/A')
                if SHOW_BASE_SCORE:
                    row_data['Base_Score'] = cve.get('baseScore', 'N/A')
                if SHOW_FIX_VERSION:
                    fix_versions = find_applicable_fix_version(cve, version_family, input_version)
                    row_data['Fix_Version'] = ", ".join(fix_versions)
                if SHOW_DATE:
                    row_data['Date'] = cve.get('date', 'N/A')
                if SHOW_TITLE:
                    row_data['Title'] = cve.get('title', 'N/A')
                
                row_data['Updated'] = cve.get('updated', 'N/A')
                row_data['ZER016_Analysis_Date'] = analysis_date
                row_data['ZER016_Input_Version'] = str(input_version)
                
                writer.writerow(row_data)
        
        print(f"\nZER016 SUCCESS: CVE data exported to: {filename}")
        
    except Exception as e:
        print(f"ZER016 ERROR: Unable to export to CSV: {e}")

def main():
    """Main function to run the ZER016 CVE checker."""
    print(ZER016_BANNER)
    
    parser = argparse.ArgumentParser(
        description='ZER016 PAN-OS CVE Checker - Check CVEs for PAN-OS versions and find applicable fixes',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
ZER016 Examples:
  python panos_cve_checker.py 10.2.11-h2
  python panos_cve_checker.py 10.2.11-h2 --csv output.csv
  python panos_cve_checker.py 11.1.4-h7 --csv /path/to/report.csv
  python panos_cve_checker.py 10.2.11-h2 --show-eol
  python panos_cve_checker.py 10.2.11-h2 --show-eol --show-expired

Developed by ZER016 for enterprise security management.
        """
    )
    
    parser.add_argument('version', help='PAN-OS version (e.g., 10.2.11-h2)')
    parser.add_argument('--csv', metavar='FILENAME', help='Export results to CSV file')
    parser.add_argument('--show-eol', action='store_true', help='Display complete EOL summary table')
    parser.add_argument('--show-expired', action='store_true', help='Include expired versions in EOL summary (requires --show-eol)')
    
    args = parser.parse_args()
    
    try:
        input_version = PanOSVersion(args.version)
        version_family = input_version.family
        
        print(f"Checking CVEs for PAN-OS version: {args.version}")
        print(f"Version family: {version_family}")
        print(f"Parsed version: {input_version}")
        
        cve_data = fetch_cve_data(args.version)
        
        if not cve_data:
            print("No CVE data retrieved. Please check the version format and try again.")
            return
        
        display_cve_table(cve_data, version_family, input_version)
        
        print(f"\nTotal CVEs found: {len(cve_data)}")
        
        eol_status = check_version_eol_status(input_version)
        if eol_status:
            print(f"\nEOL STATUS FOR {input_version.family}:")
            print("=" * 50)
            
            if eol_status['is_expired']:
                color = RED
                status_msg = f"EXPIRED ({abs(eol_status['days_left'])} days ago)"
            elif eol_status['days_left'] <= 90:
                color = RED
                status_msg = f"CRITICAL - {eol_status['days_left']} days until EOL"
            elif eol_status['days_left'] <= 365:
                color = YELLOW
                status_msg = f"WARNING - {eol_status['days_left']} days until EOL"
            else:
                color = GREEN
                status_msg = f"SUPPORTED - {eol_status['days_left']} days until EOL"
            
            print(f"{color}STATUS: {status_msg}{RESET}")
            print(f"LATEST: {eol_status['latest']}")
            print(f"EOL DATE: {eol_status['eol_date']}")
            print("=" * 50)
        
        recommendation = generate_upgrade_recommendation(cve_data, version_family, input_version, eol_status)
        print(f"\n{recommendation}")
        
        if args.show_eol:
            display_eol_summary(show_expired=args.show_expired)
        
        if args.csv:
            export_to_csv(cve_data, version_family, input_version, args.csv)
        
    except ValueError as e:
        print(f"ZER016 ERROR: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"ZER016 UNEXPECTED ERROR: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()