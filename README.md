# Maple Phish

Canadian-brand phishing signals, with evidence kept in context. Open https://coolcode.ca/maplephish/.

<!-- coolcode:guide -->
Choose a brand to inspect derived phishing counts, report-month groups and hosting-ASN groups. Import a PhishStats JSON array or URLhaus response locally to inspect defanged URLs, report dates and supplied registrar data. Brand-token matches are unverified candidates; URLhaus malware is always separate from phishing.
<!-- /coolcode:guide -->

## Source coverage and permissions

The daily collector queries six configured names: Interac, RBC / Royal Bank, Canada Post, Scotiabank, CIBC and Desjardins. Each PhishStats query fetches one newest result page of at most 100 rows (`_p=0`, verified against actual API behavior; the documentation’s pagination prose is inconsistent). Server search is broad; a local case-insensitive token check excludes embedded acronyms. Matches can still be unrelated and are **not confirmed brand impersonation**. Counts overlap across brands. Zero is only no matching observation in the selected source page, not zero fraud or an exhaustive all-time total. PhishStats does not supply registrar fields in the observed response; local imports display an explicit registrar only if supplied, otherwise Not supplied. Hosting country does not identify victim location.

Current PhishStats documentation allows anonymous access (50 requests/day/IP; approximate burst 20/min), with an optional `PHISHSTATS_API_KEY` in `X-API-Key` (free registered: 150/day). This collector makes six daily queries and respects bounded Retry-After. Its terms prohibit raw-feed redistribution without written permission. Consequently public snapshots contain **derived aggregate counts only**, without URLs, source IDs, page titles, exact report dates or other reconstructable raw records. Month and ASN groups under three are pooled. URL-level imports remain in tab memory.

URLhaus requires `URLHAUS_AUTH_KEY` in the `Auth-Key` request header. It queries recent additions, at most 1,000 across the preceding three days, once daily. These are **malware distribution reports, not phishing reports**. Matching uses the same brand-token rule and publishes aggregate counts only. Missing credentials are explicitly missing coverage; a bad configured response fails collection and preserves the previous deployment. Commercial uses may require an abuse.ch/Spamhaus agreement. Source data is not relabelled as MIT or CC0.

Primary documentation and policies verified 2026-11-22:

- https://www.phishstats.info/api-docs
- https://www.phishstats.info/terms (June 2026; section 5 redistribution)
- https://urlhaus-api.abuse.ch/ (recent endpoint and required header)
- https://urlhaus.abuse.ch/api/ (community fair use)
- https://abuse.ch/terms-of-use/ (updated 2026-10-21)

## Evidence workbench and privacy

Paste a PhishStats JSON array or URLhaus response, or select a JSON file up to 15 MB / 10,000 records. Local imports can be filtered by brand, classification, URL/title or ASN, opened for detail and exported as spreadsheet-safe CSV. Repeated IDs are deduplicated. URLs are defanged and never made navigable. No indicator is visited, rendered in an iframe or executed. Only validated source evidence pages may be linked. Query values, credentials and fragments are removed; paths may still contain sensitive content, so review exports. There is no automatic browser storage. Clear or reload to discard imports.

No pasted evidence or filter value leaves the browser. Scheduled collection contacts the named providers from GitHub Actions. Provider keys are environment secrets, never browser inputs, URLs, logs or site artifacts. The shared CoolCode metrics script counts aggregate opens and excludes tool inputs. Related tools: FraudPulse Canada, RegistrarWatch and ScamTrace.

## Collection, history and operation

Schedule: **daily at 14:23 UTC** (`23 14 * * *`), best effort. Scheduled/manual runs collect, validate, test and deploy. Pushes rebuild saved observations offline unless there is no saved baseline or the manifest explicitly needs pending credentials. Configure `URLHAUS_AUTH_KEY` as a repository Actions secret. `PHISHSTATS_API_KEY` is optional; it is not needed for this six-query daily schedule. Optional `HEALTHCHECKS_PING_URL` reports collection status.

`data/current.json` is the latest public aggregate. `data/index.json` is small hub-readable metadata. `data/history.json` indexes immutable JSON snapshots in `archive/YYYY-MM/` with SHA-256 checksums. The first snapshot is a baseline, never invented history. An unchanged observation updates the check timestamp without adding a snapshot. Source report month and collector capture/check times are separate. Archived aggregate datasets can be downloaded from the observation diary. They are retained in Git, independent of Actions artifact expiry.

```sh
node --test tests/*.test.mjs
python3 -m unittest discover -s tests -v
python3 scripts/build.py        # offline
python3 scripts/collect.py      # explicit provider refresh
```

The Python app/collector uses only the standard library. CI installs Playwright as a test-only dependency and runs desktop/mobile import, safe rendering, filtering, CSV and source-classification checks. Failed collection or validation never commits replacement data or deploys. Application code is MIT licensed. Upstream data and services retain their own terms.
