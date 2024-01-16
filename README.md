# Fedora CVE detection Script

Bash script to detect CVEs to be patched in Fedora systems and give you more information about the CVE like CVSS, Severity and CWE.

Usage: `chmod u+x && ./cves.sh`

Script version: 1.0

The information is gathered through the NVD API version 2.0, for more information please refer to: [CVE API](https://nvd.nist.gov/developers/vulnerabilities).

If you are interested in adding more information to the script, please check the following JSON example: [CVE-2019-1010218](https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218)
