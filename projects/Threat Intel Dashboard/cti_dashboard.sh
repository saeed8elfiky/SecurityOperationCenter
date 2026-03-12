#!/bin/bash

# =========================================
# Threat Intel Dashboard CLI
# Author: Saeed
# GitHub: github.com/saeed
# Created: 2026
# =========================================

# ---------- API Keys ----------
VT_API_KEY="YOUR_VT_KEY"
ABUSE_KEY="YOUR_ABUSE_KEY"

# ---------- Threshold ----------
MIN_ABUSE_SCORE=50

# ---------- Read input ----------
read -p "Enter IP or Domain: " target
echo -e "\n Gathering Threat Intelligence for: $target\n"

# ---------- VirusTotal Lookup ----------
vt_json=$(curl -s -X GET "https://www.virustotal.com/api/v3/ip_addresses/$target" \
     -H "x-apikey: $VT_API_KEY")

vt_malicious=$(echo "$vt_json" | jq '.data.attributes.last_analysis_stats.malicious')
vt_suspicious=$(echo "$vt_json" | jq '.data.attributes.last_analysis_stats.suspicious')
vt_reputation=$(echo "$vt_json" | jq '.data.attributes.reputation')

# ---------- VirusTotal descriptions (High-Risk only) ----------
vt_desc=$(echo "$vt_json" | jq -r '.data.attributes.last_analysis_results 
    | to_entries[] 
    | select(.value.category=="malicious" or .value.category=="suspicious") 
    | "\(.key): \(.value.result)"')

# ---------- AbuseIPDB Lookup ----------
abuse_json=$(curl -s "https://api.abuseipdb.com/api/v2/check?ipAddress=$target&maxAgeInDays=90&verbose=true" \
     -H "Key: $ABUSE_KEY" -H "Accept: application/json")

abuse_score=$(echo "$abuse_json" | jq '.data.abuseConfidenceScore')
abuse_reports=$(echo "$abuse_json" | jq '.data.totalReports')
abuse_country=$(echo "$abuse_json" | jq -r '.data.countryCode')

# ---------- AbuseIPDB descriptions (High Confidence Only) ----------
abuse_desc=$(echo "$abuse_json" | jq -r ".data.reports[] 
    | select(.abuseConfidenceScore >= $MIN_ABUSE_SCORE) 
    | \"- [\(.reportedAt)] \(.comment) (Score: \(.abuseConfidenceScore))\"")

# ---------- Color functions ----------
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

color_score() {
    score=$1
    if [ "$score" -ge 50 ]; then
        echo -e "${RED}$score${NC}"
    elif [ "$score" -ge 10 ]; then
        echo -e "${YELLOW}$score${NC}"
    else
        echo -e "${GREEN}$score${NC}"
    fi
}

# ---------- Dashboard Output ----------
echo "======================================================================"
echo "                       Threat Intel Dashboard"
echo "        Author: Saeed Elfiky (GitHub: https://github.com/saeed8elfiky)"
echo "======================================================================"
echo "Target: $target"
echo ""

# ---------- VirusTotal ----------
echo "VirusTotal:"
if [ "$vt_malicious" -eq 0 ] && [ "$vt_suspicious" -eq 0 ]; then
    echo "  Clean / Safe"
else
    echo "  Malicious: $(color_score $vt_malicious)"
    echo "  Suspicious: $(color_score $vt_suspicious)"
    echo "  Reputation: $vt_reputation"
    if [ -n "$vt_desc" ]; then
        echo "  High-Risk Vendors:"
        echo "$vt_desc" | sed 's/^/    /'
    fi
fi
echo ""

# ---------- AbuseIPDB ----------
echo "AbuseIPDB:"
if [ "$abuse_score" -lt $MIN_ABUSE_SCORE ] && [ "$abuse_reports" -eq 0 ]; then
    echo "  Clean / Safe "
else
    echo "  Abuse Confidence Score: $(color_score $abuse_score)"
    echo "  Total Reports: $abuse_reports"
    echo "  Country: $abuse_country"
    if [ -n "$abuse_desc" ]; then
        echo "  High Confidence Reports:"
        echo "$abuse_desc" | sed 's/^/    /'
    fi
fi
echo "=============================="
echo ""
