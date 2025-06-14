"""
Domain Extractor - A simple tool to find valid domains in text files.

This script extracts potential domain names from a text file, validates their format,
and outputs all valid-format domains to a file. For domains that resolve to an IP address,
the IP address is included in the output.

Usage:
    python domain_extractor.py input.txt output.txt

"""

import re
import socket
import sys
from typing import List, Tuple, Optional
import requests  # Add VirusTotal API support


def extract_domains(text: str) -> List[str]:
    """
    Extract potential domains from text.

    Args:
        text: Input text to search for domains

    Returns:
        List of potential domain names found in the text
    """
    # Find anything that looks like a domain
    domain_pattern = r"[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]+"
    candidates = re.findall(domain_pattern, text)

    # Basic cleaning
    cleaned = []
    seen = set()  # Track duplicates

    for domain in candidates:
        # Remove surrounding punctuation and convert to lowercase
        domain = domain.lower().strip(".-\"'()[]{},:;<>?!#$%^&*_=+`~")

        # Skip duplicates
        if domain in seen:
            continue

        # Check domain format
        if is_valid_domain_format(domain):
            cleaned.append(domain)
            seen.add(domain)

    return cleaned


def is_valid_domain_format(domain: str) -> bool:
    """
    Check if domain has valid format according to DNS rules.

    Args:
        domain: Domain name to validate

    Returns:
        True if the domain format is valid, False otherwise
    """
    # Must have at least one dot and valid length
    if "." not in domain or len(domain) > 253:
        return False

    # Check labels
    labels = domain.split(".")
    if len(labels) < 2:  # Need at least two labels (hostname and TLD)
        return False

    for label in labels:
        # Each label must follow DNS rules
        if not (0 < len(label) <= 63):
            return False
        if label[0] == "-" or label[-1] == "-":
            return False
        if not re.match(r"^[a-z0-9-]+$", label):
            return False

    # Validate TLD format (alphabetic or IDN)
    tld = labels[-1]
    return tld.startswith("xn--") or tld.isalpha()


def get_domain_ip(domain: str, timeout: float = 1.0) -> Optional[str]:
    """
    Try to resolve a domain to an IP address.

    Args:
        domain: Domain name to resolve
        timeout: Timeout in seconds for DNS resolution

    Returns:
        IP address as string if resolved, None otherwise
    """
    # Set the default timeout
    original_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)

    try:
        # Try to resolve the domain
        return socket.gethostbyname(domain)
    except socket.error:
        # Try one more time with 'www.' prefix for domains that might require it
        if not domain.startswith("www."):
            try:
                return socket.gethostbyname(f"www.{domain}")
            except socket.error:
                return None
        return None
    finally:
        # Restore original timeout
        socket.setdefaulttimeout(original_timeout)


def check_domain_virustotal(domain: str, api_key: str) -> Optional[str]:
    """
    Check if a domain is malicious using the VirusTotal API.
    Returns 'malicious', 'suspicious', 'clean', or None on error.
    """
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}
    try:
        resp = requests.get(url, headers=headers, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            stats = (
                data.get("data", {})
                .get("attributes", {})
                .get("last_analysis_stats", {})
            )
            return (
                "malicious" if stats.get("malicious", 0) > 0
                else "suspicious" if stats.get("suspicious", 0) > 0
                else "clean"
            )
        else:
            print(f"VirusTotal API error for {domain}: {resp.status_code}")
            return None
    except Exception as e:
        print(f"Error querying VirusTotal for {domain}: {e}")
        return None


def get_asn_info(ip: str) -> Optional[str]:
    """
    Get very detailed ASN info for an IP address using bgpview.io (no API key required).
    Returns a string with ASN, org, country, prefix, registry, allocation date, ASN description, type, website, and more if available.
    """
    def format_asn_info(asn_info_dict, prefix_info):
        asn_fields = [
            ("AS", f"AS{asn_info_dict.get('asn', '')}"),
            ("ASNName", asn_info_dict.get("name", "")),
            ("ASNDescShort", asn_info_dict.get("description_short", "")),
            ("ASNDescLong", asn_info_dict.get("description", "")),
            ("ASNCountry", asn_info_dict.get("country_code", "")),
            ("ASNType", asn_info_dict.get("type", "")),
            ("ASNWebsite", asn_info_dict.get("website", "")),
            ("ASNLG", asn_info_dict.get("looking_glass", "")),
            ("ASNIRR", asn_info_dict.get("irr_as_set", "")),
            ("RIR", asn_info_dict.get("rir_allocation", {}).get("rir_name", "")),
            ("AllocDate", asn_info_dict.get("rir_allocation", {}).get("allocation_date", "")),
            ("OrgWebsite", asn_info_dict.get("org", {}).get("website", "")),
        ]
        prefix_fields = [
            ("Prefix", prefix_info.get("prefix", "")),
            ("PrefixName", prefix_info.get("name", "")),
            ("PrefixDesc", prefix_info.get("description", "")),
            ("PrefixCountry", prefix_info.get("country_code", "")),
            ("PrefixParent", prefix_info.get("parent", "")),
        ]
        return " | ".join(
            f"{k}:{v}" for k, v in asn_fields + prefix_fields if v and (k != "AS" or asn_info_dict.get("asn", ""))
        )

    try:
        resp = requests.get(f"https://api.bgpview.io/ip/{ip}", timeout=3)
        if resp.status_code == 200:
            data = resp.json()
            if asn_data := data.get("data", {}).get("prefixes", []):
                prefix_info = asn_data[0]
                asn_info_dict = prefix_info.get("asn", {})
                asn_info = format_asn_info(asn_info_dict, prefix_info)
                return asn_info or None
        return None
    except Exception as e:
        print(f"Error getting ASN for {ip}: {e}")
        return None


def process_file(
    input_file: str, output_file: str, vt_api_key: Optional[str] = None
) -> None:
    """
    Process input file and write domains to output file.
    All valid-format domains are included, with IP addresses when available.

    Args:
        input_file: Path to input text file
        output_file: Path to output file for domains
        vt_api_key: Optional VirusTotal API key for checking maliciousness
    """
    try:
        # Read input file
        with open(input_file, "r", encoding="utf-8") as f:
            text = f.read()
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)

    # Extract domains with valid format
    potential_domains = extract_domains(text)
    results = []

    print(f"Found {len(potential_domains)} potential domains. Checking...")

    for domain in potential_domains:
        ip_address = get_domain_ip(domain)
        vt_status = check_domain_virustotal(domain, vt_api_key) if vt_api_key else None

        # print statusAdd commentMore actions
        status_msg = (
            f"RESOLVES TO {ip_address}" if ip_address else "VALID FORMAT (NO IP)"
        )
        vt_msg = f" VT: {vt_status}" if vt_status else ""
        print(f"Checking {domain}... {status_msg}{vt_msg}")

        line_parts = [domain]

        if ip_address:
            line_parts.append(ip_address)
        else:
            line_parts.append("")  # keep column order

        if vt_status:
            line_parts.append(f"VT:{vt_status}")

        if ip_address and (asn_info := get_asn_info(ip_address)):
            line_parts.append(f"ASN:{asn_info}")

        # Join only non-empty parts with a space
        line = " ".join(part for part in line_parts if part)
        results.append(line)

    try:
        # Write all domains to output file
        with open(output_file, "w", encoding="utf-8") as f:
            for result in results:
                f.write(result + "\n")
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)

    # Count domains with IPs
    domains_with_ip = sum(" " in r for r in results)

    print(f"Complete! Found {len(results)} valid domains.")
    print(f"- {domains_with_ip} domains resolve to an IP address")
    print(f"- {len(results) - domains_with_ip} domains have valid format but no IP")


def main():
    """Main function to handle command line arguments and run the script."""
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print(
            "Usage: python domain_extractor.py input.txt output.txt [virustotal_api_key]"
        )
        sys.exit(1)

    input_file = sys.argv[1]
    output_file = sys.argv[2]
    vt_api_key = sys.argv[3] if len(sys.argv) == 4 else None

    process_file(input_file, output_file, vt_api_key)


if __name__ == "__main__":
    main()
