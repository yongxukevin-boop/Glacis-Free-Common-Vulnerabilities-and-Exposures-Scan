# Glacis CVE Scanner

A dependency-free GitHub Pages dashboard backed by ProjectDiscovery Nuclei on GitHub Actions. The website lives in `docs/index.html`, `docs/app.js`, `docs/utils.mjs` and `docs/styles.css`. No scanner or Go installation is needed on the visitor's computer.

## Deploy

1. Create a GitHub repository and upload `.github/`, `docs/`, `scripts/`, `tests/` and this README to its **default branch**. Do not upload the unrelated local `download/` or `tools/` directories. Repository dispatch workflows must exist on the default branch.
2. Under **Settings → Pages**, select **Deploy from a branch**, the default branch and `/docs`. Save and wait for the Pages deployment.
3. Under **Settings → Secrets and variables → Actions → Variables**, create `ALLOWED_SCAN_HOSTS`: a comma-separated list of exact authorised hostnames, for example `app.example.com,staging.example.com`. No schemes, paths or wildcard hostnames. Missing configuration fails closed.
4. Ensure repository rules permit `github-actions[bot]` to push result commits to the default branch. The publication job requests Contents write permission. If branch protection prevents pushes, publication fails; reports remain available as run artifacts.
5. Create a fine-grained PAT restricted to this repository with **Contents: read and write** (dispatch and report access) and **Actions: read** (polling). A classic token uses `public_repo` for public repositories or `repo` for private repositories. **`workflow` scope alone does not authorise repository dispatch.** Org approval or SSO may also be required.
6. Set `owner` and `name` once in `docs/config.mjs` to your GitHub repository owner and name, then commit that configuration. Visitors cannot change the repository through the dashboard.
7. Open the Pages URL, enter the target and PAT, confirm authorisation/publication, then start a scan.

The PAT is sent only to `api.github.com`, retained in memory while polling, then cleared; never stored in cookies, localStorage, URLs, repository files or dispatch payloads. Refreshing the page stops browser monitoring, but not the workflow. Use GitHub Actions and Load latest report to recover. Keep this site and its origin trusted: a browser PAT is accessible to any script compromised on the same page.

## Results and limitations

The workflow runs the requested `go install ...@latest`, installs current templates, and invokes Nuclei with `-u`, `-json-export results.json` and `-severity low,medium,high,critical`. It also limits concurrency and rate, disables redirects and Interactsh, and has a 20-minute scanner deadline. These choices reduce coverage; scans are template matches, not exhaustive assessments. Current Nuclei flags are documented at https://docs.projectdiscovery.io/opensource/nuclei/running.

The runner validates the URL and exact hostname server-side and rejects private/local DNS answers and IPv6. Shell execution is disabled; the target is passed as a single process argument. This DNS precheck is not a network sandbox and cannot eliminate DNS rebinding or all template-initiated traffic. Only allow hosts you control. The scanner job has read-only GitHub permissions and no persisted checkout credential; the separate publication job has write permission.

Each scan creates `public/latest_scan.json` and `public/scans/<scan-id>.json`. The dashboard fetches these through the GitHub Contents API, so commits made by `GITHUB_TOKEN` do not need to trigger a Pages rebuild. UUID-based run titles and report/run checks prevent cross-scan mixups. “Latest” is the most recently published report; use the unique scan file for reliable historical lookup. Concurrent pushes retry with rebase.

**Reports and raw HTTP snippets are committed to repository history. In a public repository they are public, potentially including sensitive response content.** Snippets are truncated, not redacted. Use only targets whose results you intend to publish. Full raw output is a short-lived Actions artifact. Do not assume a private repository's Pages website is private; Pages availability/access depends on your GitHub plan and configuration.

Light reports include at most 60 findings, bounded descriptions/extractions and 2,000 characters per HTTP request/response; truncation is shown in the dashboard. Full output remains in the raw artifact for three days. JSON/CSV exports contain the currently filtered findings. CSV neutralises formula prefixes. Findings render as text, never HTML. CVE IDs link to NVD; templates without CVE metadata still appear by name. Info is supported by the renderer but excluded from the default scan.

A valid empty JSON array is a no-match result. Missing/malformed output, failed scans, timeout, API errors and failed publication are not reported as clean scans. Installation or validation failures may have no report artifact; open the run logs. Reports do not prove target reachability or successful execution of every template. A workflow that fails after producing a partial report remains failed in the browser.

## Local checks

With Node.js 22 or newer: `node --test tests/scan.test.mjs` and `node --check docs/app.js`. Serve `docs/` using a local HTTP server to preview it. GitHub Actions execution and Pages deployment must be verified after pushing to your own repository; no live scan is performed by the tests.

Official API reference: https://docs.github.com/en/rest/repos/repos#create-a-repository-dispatch-event

## Recommended scan profile

Scans now use ProjectDiscovery's recommended profile (nuclei -profile recommended), with progress statistics every 15 seconds in the Actions log. Reports record profile: recommended. Existing severity filters, rate limit (10 requests/second), concurrency (5), disabled redirects/Interactsh and the 20-minute scanner timeout remain. This narrows the template selection but does not guarantee completion within 15 minutes; installation and queue time are additional. Start a new dashboard scan after this update. See https://github.com/projectdiscovery/nuclei-templates/blob/main/profiles/recommended.yml.


## Current scan configuration: prebuilt binary and KEV

The workflow now downloads the official Nuclei v3.11.1 Linux amd64 binary and verifies its SHA-256 against the release checksums before installation. No Go compilation is required. Templates are updated before each scan. The previous recommended-profile configuration above is superseded by -profile kev, targeting Nuclei templates tagged for CISA Known Exploited Vulnerabilities. Coverage is narrower and does not establish whether a particular website is currently being attacked. Existing severity filters, 10 requests/second, concurrency 5, progress every 15 seconds and 20-minute execution limit remain. Setup still requires downloads; there is no fixed completion-time guarantee. Official profile: https://github.com/projectdiscovery/nuclei-templates/blob/main/profiles/kev.yml.


IPv4 validation now requests only DNS A records, matching Nuclei's explicit -ip-version 4. A site's additional IPv6 records no longer reject an otherwise valid public IPv4 target. Private/local IPv4 addresses remain blocked; IPv6-only or unresolvable targets receive a DNS-specific error.


## KEV plus informational findings

The current scan selects templates with the condition contains(tags, 'kev') OR severity == 'info', replacing the KEV-only profile. All five displayed severities are allowed. This adds informational observations such as service identification and missing headers without enabling every non-KEV vulnerability check. Info findings are not confirmed CVEs. Existing default template exclusions remain; more checks can increase runtime. Findings are prioritised by severity before the light report's 60-finding cap; full output remains in the raw artifact. Start a new scan to generate these findings; historical reports are unchanged.

