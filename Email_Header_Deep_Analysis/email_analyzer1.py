#!/usr/bin/env python3

import argparse
import re
from email import policy
from email.parser import BytesParser
from colorama import Fore, Style, init

init(autoreset=True)


# =====================================================
# IOC Utilities (Defanging + Extraction)
# =====================================================

def defang_ip(ip: str) -> str:
    """Defang an IP address"""
    return ip.replace(".", "[.]")



def extract_ips(text: str):
    """Extract IPv4 addresses based on specific patterns"""

    ips = set()

    # -------------------------------
    # 1. Extract IP after "Sender IP is"
    # -------------------------------
    sender_ip_pattern = r"Sender IP is\s*((?:\d{1,3}\.){3}\d{1,3})"
    sender_ips = re.findall(sender_ip_pattern, text)
    ips.update(sender_ips)

    # -------------------------------
    # 2. Extract IPs inside parentheses
    # -------------------------------
    bracket_ip_pattern = r"\(((?:\d{1,3}\.){3}\d{1,3})\)"
    bracket_ips = re.findall(bracket_ip_pattern, text)
    ips.update(bracket_ips)

    return list(ips)




def extract_and_defang_ips(text: str):
    """Extract and return defanged IPs"""
    raw_ips = extract_ips(text)
    return [defang_ip(ip) for ip in raw_ips]


# =====================================================
# Email Helpers
# =====================================================

def get_header(msg, name):
    return msg.get(name, "N/A")


def attachment_exists(msg):
    """Check if any attachment is present"""
    for part in msg.walk():
        if part.get_filename():
            return True
    return False


# =====================================================
# Header Authentication Checks
# =====================================================

def analyze_authentication(headers):
    spf = headers.get("Received-SPF", "Not Found")
    dkim = headers.get("DKIM-Signature", "Not Found")
    dmarc = headers.get("Authentication-Results", "Not Found")

    return spf, dkim, dmarc


# =====================================================
# Originating IP Detection
# =====================================================

def get_originating_ip(headers):
    """
    Last IP in Received chain is usually closest to sender
    """
    received_headers = headers.get_all("Received", [])

    ips = []
    for line in received_headers:
        ips.extend(extract_ips(line))

    if not ips:
        return "Not Found"

    return defang_ip(ips[-1])


# =====================================================
# Main Analyzer
# =====================================================

def analyze_email(file_path):

    with open(file_path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = msg
    raw_headers = str(headers)

    print(Fore.CYAN + "\n================ EMAIL ANALYSIS REPORT ================\n")

    # -------------------------------------------------
    # Basic Metadata
    # -------------------------------------------------

    print(Fore.YELLOW + "[ Basic Information ]")

    print("From        :", get_header(headers, "From"))
    print("To          :", get_header(headers, "To"))
    print("Reply-To    :", get_header(headers, "Reply-To"))
    print("Delivered-To    :", get_header(headers, "Delivered-To"))
    print("Subject     :", get_header(headers, "Subject"))
    print("Date        :", get_header(headers, "Date"))
    print("Message-ID  :", get_header(headers, "Message-ID"))

    print("Attachments :", "Yes" if attachment_exists(msg) else "No")

    # -------------------------------------------------
    # IP Extraction (Defanged)
    # -------------------------------------------------

    print(Fore.YELLOW + "\n[ Extracted IPs (Defanged) ]")

    defanged_ips = extract_and_defang_ips(raw_headers)

    if defanged_ips:
        for ip in defanged_ips:
            print(" -", ip)
    else:
        print("None Found")

    # -------------------------------------------------
    # Header Authentication
    # -------------------------------------------------

    print(Fore.YELLOW + "\n[ Header Authentication ]")

    spf, dkim, dmarc = analyze_authentication(headers)

    print("SPF   :", spf)
    print("DKIM  :", "Present" if dkim != "Not Found" else "Missing")
    print("DMARC :", dmarc)

    # -------------------------------------------------
    # Originating IP
    # -------------------------------------------------

    print(Fore.YELLOW + "\n[ Originating IP ]")
    print(get_originating_ip(headers))

    print(Fore.GREEN + "\n================ ANALYSIS COMPLETE ====================\n")


# =====================================================
# CLI Entry
# =====================================================

def main():
    parser = argparse.ArgumentParser(
        description="Linux Email Header Analyzer (SOC-safe with IOC defanging)"
    )

    parser.add_argument("file", help="Path to .eml file")

    args = parser.parse_args()

    analyze_email(args.file)


if __name__ == "__main__":
    main()

