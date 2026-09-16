#!/bin/bash
# ==============================================================================
# Script: phish_campaign.sh
# Project: P7 — Phishing Email Investigation with Splunk
# Description: Emulates real-world adversary email campaigns and benign corporate
#              noise by transmitting authentic SMTP traffic over TCP 25 to Postfix.
# Target: Ubuntu P3 Mail Gateway (192.168.100.9:25)
# Author: Natto Chakma
# MITRE ATT&CK: T1566 (Phishing), T1566.001 (Attachment), T1566.002 (Link)
# ==============================================================================

TARGET="192.168.100.9"

echo "[+] ========================================================="
echo "[+] Starting Live Phishing & Benign Telemetry Campaign"
echo "[+] Target Mail Gateway: $TARGET:25"
echo "[+] ========================================================="

# Prepare simulated test attachment artifacts
echo "MZP....SIMULATED_BINARY_HEADER" > /tmp/Shipping_Manifest.pdf.exe
echo "PK.....SIMULATED_MACRO_XLSM" > /tmp/INVOICE_OCT2026.xlsm
echo "CD001..SIMULATED_ISO_IMAGE" > /tmp/DocuSign_Contract_Review.iso
echo "%PDF-1.4 SIMULATED_BENIGN_PDF" > /tmp/Statement_Sept2026.pdf

# --- BENIGN TRAFFIC (Corporate Baseline Noise) ---
echo "[*] [1/14] Benign: GitHub Issue Notification..."
swaks --server "$TARGET" --to "natto@company.com" --from "notifications@github.com" \
  --header "Subject: [NATTOMR/splunk-soc-threat-hunting-lab] Issue #8 assigned" \
  --body "A new issue has been assigned to you in the threat hunting lab repository." --hide-all

echo "[*] [2/14] Benign: Monthly Vendor Statement (PDF Attachment)..."
swaks --server "$TARGET" --to "accounts@company.com" --from "billing@trusted-vendor.com" \
  --header "Subject: Monthly Services Statement - September 2026" \
  --attach /tmp/Statement_Sept2026.pdf \
  --body "Attached is the monthly services breakdown for September." --hide-all

echo "[*] [3/14] Benign: Slack Daily Digest..."
swaks --server "$TARGET" --to "team@company.com" --from "notifications@slack.com" \
  --header "Subject: Daily Digest: SOC Incident Response Channel" \
  --body "Here are today's top discussions from #soc-incidents." --hide-all

echo "[*] [4/14] Benign: Zoom Standup Meeting Invite..."
swaks --server "$TARGET" --to "all-hands@company.com" --from "no-reply@zoom.us" \
  --header "Subject: Meeting Invitation: Weekly Engineering Standup" \
  --body "Join URL: https://zoom.us/j/982341908" --hide-all

echo "[*] [5/14] Benign: AWS CloudWatch Budget Alert..."
swaks --server "$TARGET" --to "devops@company.com" --from "no-reply-aws@amazon.com" \
  --header "Subject: AWS Budget Alert: Actual Spend Exceeded Forecast" \
  --body "Your AWS account budget alert threshold has triggered." --hide-all

# --- ATTACK 1: Credential Harvester Links (T1566.002) ---
echo "[!] [6/14] ATTACK: Microsoft 365 Credential Harvester..."
swaks --server "$TARGET" --to "sarah.connor@company.com" --from "admin@micros0ft-support.com" \
  --header "Subject: [CRITICAL] Microsoft 365 Password Expiration Notice - Action Required" \
  --body "Your password expires in 2 hours. Reset immediately: http://login-micros0ft-verify.com/auth/login.php?user=sarah" --hide-all

echo "[!] [7/14] ATTACK: SharePoint Token Stealer..."
swaks --server "$TARGET" --to "elizabeth.vane@company.com" --from "sharepoint-noreply@onedrive-secure-docs.info" \
  --header "Subject: Confidential Financial Review shared with you on SharePoint" \
  --body "Access document at: http://194.26.29.112:8080/sharepoint/token?auth=98a7" --hide-all

# --- ATTACK 2: Weaponized Attachments (T1566.001) ---
echo "[!] [8/14] ATTACK: Macro-Enabled Spreadsheet (.xlsm)..."
swaks --server "$TARGET" --to "finance@company.com" --from "orders@quick-invoices-secure.org" \
  --header "Subject: URGENT: Overdue Remittance & Payment Invoice #99824" \
  --attach /tmp/INVOICE_OCT2026.xlsm \
  --body "Please find the overdue remittance attached. Enable macros to review details." --hide-all

echo "[!] [9/14] ATTACK: Double-Extension Executable (.pdf.exe)..."
swaks --server "$TARGET" --to "john.doe@company.com" --from "courier@dhl-express-tracking-portal.com" \
  --header "Subject: Delivery Notification: Package on Hold - Confirm Address Immediately" \
  --attach /tmp/Shipping_Manifest.pdf.exe \
  --body "Your shipment is on hold. Open attached manifest to confirm address." --hide-all

echo "[!] [10/14] ATTACK: Disk Image Container (.iso) DocuSign Lure..."
swaks --server "$TARGET" --to "legal@company.com" --from "documents@docusign-docs.online" \
  --header "Subject: DocuSign Completed: NDA Signature Verification Pending" \
  --attach /tmp/DocuSign_Contract_Review.iso \
  --body "Review and sign the attached legal contract container." --hide-all

# --- ATTACK 3: Whaling / BEC (Business Email Compromise) ---
echo "[!] [11/14] ATTACK: CEO Impersonation (Wire Transfer Fraud)..."
swaks --server "$TARGET" --to "cfo@company.com" --from "ceo.corporate.exec77@gmail.com" \
  --header "Subject: URGENT CONFIDENTIAL: Wire Transfer Authorization Required for Acquisition" \
  --body "I am in a confidential board meeting. Wire $145,000 to the attached escrow account today." --hide-all

# --- ATTACK 4: Multi-Recipient Spraying (HR Phishing Lure) ---
echo "[!] [12/14] ATTACK: HR Spray (Target 1 - Alice)..."
swaks --server "$TARGET" --to "alice.smith@company.com" --from "humanresources@hr-internal-portal.net" \
  --header "Subject: Action Required: Mandatory Q3 Security & Employee Policy Acknowledgment" \
  --body "Mandatory compliance review: http://hr-internal-portal.net/update" --hide-all

echo "[!] [13/14] ATTACK: HR Spray (Target 2 - Bob)..."
swaks --server "$TARGET" --to "bob.miller@company.com" --from "humanresources@hr-internal-portal.net" \
  --header "Subject: Action Required: Mandatory Q3 Security & Employee Policy Acknowledgment" \
  --body "Mandatory compliance review: http://hr-internal-portal.net/update" --hide-all

echo "[!] [14/14] ATTACK: HR Spray (Target 3 - Charlie)..."
swaks --server "$TARGET" --to "charlie.davis@company.com" --from "humanresources@hr-internal-portal.net" \
  --header "Subject: Action Required: Mandatory Q3 Security & Employee Policy Acknowledgment" \
  --body "Mandatory compliance review: http://hr-internal-portal.net/update" --hide-all

echo "[+] ========================================================="
echo "[+] Campaign Finished! All 14 emails transmitted successfully."
echo "[+] ========================================================="
