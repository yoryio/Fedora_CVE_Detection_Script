#!/bin/bash

# Function to fetch CVE information from NVD API
get_cve_info() {
  local cve_id="$1"
  local nvd_url="https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=$cve_id"

  # Use curl to make the API request
  local cve_info=$(curl -s "$nvd_url")

  # Extract relevant information (e.g., CVSS score and description)
  local cvss=$(echo "$cve_info" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseScore')
  local severity=$(echo "$cve_info" | jq -r '.vulnerabilities[0].cve.metrics.cvssMetricV31[0].cvssData.baseSeverity')
  local cwe=$(echo "$cve_info" | jq -r '.vulnerabilities[0].cve.weaknesses[0].description[0].value')
  # Check if CVSS is a valid numeric value
  if [[ "$cvss" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    # local description=$(echo "$cve_info" | jq -r '.vulnerabilities[0].cve.descriptions[0].value')

    # Print the information
    echo "CVE: $cve_id"
    echo "CVSS Score: $cvss"
    echo "Severity: $severity"
    echo "CWE: $cwe"
    # echo "Description: $description"
  else
    echo "Error fetching information for CVE $cve_id"
  fi
}

# Run your command and store the output in a variable
output=$(dnf updateinfo info --security)

# Use a regular expression to extract CVEs from the output
cve_list=$(echo "$output" | grep -oP 'CVE-\d{4}-\d{4,7}')

# Declare an associative array to store unique CVEs
declare -A unique_cves

# Loop through the CVE list and add to the associative array
for cve in $cve_list; do
  unique_cves["$cve"]=1
done

# Loop through the unique CVEs and fetch information from NVD
for cve in "${!unique_cves[@]}"; do
  get_cve_info "$cve"
  echo "------------------------"
done
