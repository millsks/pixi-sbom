# KEV fixture

A two-entry excerpt in the shape of CISA's Known Exploited Vulnerabilities catalog
(`https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`): one real entry
(CVE-2025-39964, with `knownRansomwareCampaignUse` set to `Known` for the test) and one **synthetic** entry for
CVE-2021-33503 (urllib3), which is not in the real catalog and is here only so the recorded OSV fixtures in
`../osv/` have a known-exploited match.
