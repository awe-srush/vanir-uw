# Patch-Gap Analysis: Code-Level vs Metadata-Level Vulnerability Detection in the Python Ecosystem

## 1. Objective

This analysis evaluates how code-level vulnerability detection (Vanir) and metadata-level vulnerability detection (OSV Scanner) perform when applied to the Python (PyPI) open-source ecosystem. We document the end-to-end process, present findings from both tools, and identify the operational characteristics of each approach.

## 2. Repository and Vulnerability Selection

### 2.1 Package Selection Criteria

We targeted well-known, widely-used Python open-source packages with documented security vulnerabilities in the OSV database. Packages were selected to span multiple domains:

- **Web frameworks**: Django, Flask, FastAPI, Starlette, Tornado, Sanic
- **HTTP libraries**: requests, urllib3, aiohttp, httpx
- **Templating/markup**: Jinja2, Mako, Pygments
- **Security-critical**: cryptography, paramiko, PyJWT, certifi
- **Data/ML**: NumPy, SciPy, Transformers
- **Infrastructure**: Ansible, Scrapy, Twisted, Celery, pip, setuptools
- **Image processing**: Pillow
- **XML processing**: lxml
- **Validation**: Pydantic

### 2.2 Vulnerability Survey

We queried the OSV database for all 35 candidate packages using the OSV API (`https://api.osv.dev/v1/`), filtering for PyPI ecosystem entries that contain **GIT-type ranges** with fix commit references. GIT ranges are required because Vanir's signature generation relies on extracting code diffs from fix commits.

Out of 35 packages surveyed:

| Metric | Value |
|--------|-------|
| Total packages queried | 35 |
| Total vulnerabilities found | 1,654 |
| Vulnerabilities with GIT fix commits | 335 |
| Packages with at least 1 usable vulnerability | 28 |
| Packages with 0 usable vulnerabilities | 7 |

Packages excluded due to zero GIT fix commits: httpx, SQLAlchemy, Celery, Gunicorn, Sanic, pandas, PyYAML.

TensorFlow (235 GIT-fix vulns) was excluded from the analysis as its vulnerabilities are predominantly in C/C++ code and its scale would disproportionately dominate the dataset.

### 2.3 Final Dataset

27 packages were selected for analysis. Flask was later excluded during signature generation due to merge-commit extraction failures, leaving **26 packages** with usable results.

| Package | Vulnerabilities Tested | Vanir Signatures Generated |
|---------|:---:|:---:|
| django | 10 | 76 |
| pillow | 20 | 55 |
| urllib3 | 7 | 41 |
| aiohttp | 7 | 39 |
| transformers | 4 | 24 |
| ansible | 8 | 71 |
| cryptography | 4 | 14 |
| twisted | 5 | 13 |
| scrapy | 4 | 12 |
| werkzeug | 5 | 5 |
| lxml | 4 | 10 |
| requests | 3 | 5 |
| starlette | 1 | 15 |
| tornado | 1 | 8 |
| numpy | 2 | 32 |
| jinja2 | 2 | 8 |
| setuptools | 2 | 4 |
| fastapi | 2 | 7 |
| scipy | 1 | 8 |
| pydantic | 1 | 5 |
| pygments | 1 | 7 |
| pyjwt | 1 | 7 |
| paramiko | 1 | 3 |
| certifi | 1 | 1 |
| pip | 1 | 3 |
| mako | 1 | 4 |
| **Total** | **98** | **467** |

## 3. Methodology

### 3.1 Vanir Signature Generation

For each of the 26 packages:

1. Full vulnerability records were downloaded from the OSV database in OSV schema JSON format.
2. These were fed to Vanir's signature generator (`sign_generator_runner`) running inside a Docker container with Python 3.11 and Bazel 8.0.
3. For each vulnerability, Vanir's pipeline:
   - Cloned the source repository referenced in the GIT range
   - Identified the fix commit and its parent commit
   - Extracted the pre-patch and post-patch versions of modified files
   - Parsed the Python source using tree-sitter
   - Normalized tokens (abstracting variable names, function names, data types)
   - Generated function-based signatures (hashed normalized function bodies) and line-based signatures (n-gram hashes of normalized code lines)
   - Refined signatures by testing them against the patched version and discarding any that matched patched code (false-positive removal)
4. Output: per-package signature JSON files containing vulnerability metadata and Vanir signatures.

### 3.2 Vanir Detection Scanning

For each vulnerability with a GIT fix commit:

1. The package's source repository (already cloned during signature generation) was checked out at two states:
   - **Pre-fix commit** (`fix_commit~1`): represents the vulnerable state
   - **Fix commit** (`fix_commit`): represents the patched state
2. Vanir's detector (`detector_runner`) was run against each checkout using `all_files` target selection strategy.
3. The detector parsed all Python files in the repository, normalized them, generated hashes, and compared them against the package's signature file.
4. Output: JSON and HTML reports listing detected missing patches (unpatched vulnerabilities) for each scan.

### 3.3 Vanir Result Classification

For each vulnerability scan pair (pre-fix and post-fix), we checked whether the **specific CVE under test** appeared in the detection results:

- **True Positive**: The vulnerability's CVE was detected in the pre-fix scan and absent in the post-fix scan. Vanir correctly identified the vulnerable code and confirmed the fix.
- **Not Detected**: The vulnerability's CVE was not detected in either scan. Vanir did not have a matching signature for this vulnerability.
- **Persistent**: The vulnerability's CVE was detected in both pre-fix and post-fix scans. The signature matched code patterns that survived the patch.
- **Error**: The scan could not complete.

### 3.4 OSV Scanner Metadata Scanning

For each vulnerability:

1. The **last affected version** and the **fixed version** were extracted from the OSV vulnerability record's ECOSYSTEM range (e.g., for PYSEC-2019-140 affecting werkzeug: last affected = `0.15.2`, fixed = `0.15.3`).
2. A `requirements.txt` file was created containing a single pinned dependency (e.g., `werkzeug==0.15.2`).
3. Google's OSV Scanner (`osv-scanner` v2.3.8) was run against this lockfile:
   ```
   osv-scanner scan source --lockfile=requirements.txt --format json
   ```
4. This was repeated for both the last affected version (should be flagged) and the fixed version (should not be flagged).
5. Output: JSON reports listing all vulnerabilities OSV Scanner associates with that package version.

### 3.5 OSV Scanner Result Classification

For each vulnerability:

- **Correct**: OSV Scanner flagged the last affected version and did not flag the fixed version for this specific vulnerability.
- **Still Flags**: OSV Scanner flagged both the affected and fixed versions (metadata may not yet reflect the fix).
- **Not Found**: OSV Scanner did not flag either version.
- **Error**: No fixed version available in the OSV record.

## 4. Vanir Detection Results

### 4.1 Overall Results

| Classification | Count | Percentage | Description |
|---------------|:---:|:---:|-------------|
| True Positive | 75 | 78.1% | Detected in vulnerable, clean in fixed |
| Not Detected | 19 | 19.8% | Not detected in either version |
| Persistent | 2 | 2.1% | Detected in both versions |
| Error | 1 | — | Scan failure (scipy) |
| **Total** | **97** | | |

**Detection rate**: 75 out of 96 valid scans (78.1%).

**Precision**: Of the 77 scans where Vanir produced a detection, 75 correctly distinguished vulnerable from fixed code (97.4%).

### 4.2 Per-Package Results

15 out of 26 packages achieved a 100% detection rate:

| Package | Tested | Detected | Rate |
|---------|:---:|:---:|:---:|
| django | 10 | 10 | 100% |
| urllib3 | 7 | 7 | 100% |
| transformers | 4 | 4 | 100% |
| cryptography | 3 | 3 | 100% |
| numpy | 2 | 2 | 100% |
| jinja2 | 2 | 2 | 100% |
| setuptools | 2 | 2 | 100% |
| certifi | 1 | 1 | 100% |
| paramiko | 1 | 1 | 100% |
| tornado | 1 | 1 | 100% |
| starlette | 1 | 1 | 100% |
| pydantic | 1 | 1 | 100% |
| pyjwt | 1 | 1 | 100% |
| pygments | 1 | 1 | 100% |
| pip | 1 | 1 | 100% |
| mako | 1 | 1 | 100% |

Packages with partial detection:

| Package | Tested | Detected | Rate |
|---------|:---:|:---:|:---:|
| aiohttp | 7 | 6 | 86% |
| ansible | 7 | 5 | 83% |
| lxml | 4 | 3 | 75% |
| pillow | 20 | 14 | 74% |
| requests | 3 | 2 | 67% |
| scrapy | 4 | 2 | 50% |
| fastapi | 2 | 1 | 50% |
| werkzeug | 5 | 2 | 40% |
| twisted | 5 | 1 | 20% |

### 4.3 Cross-Vulnerability Detection

In 47 out of 97 scans (48.5%), Vanir detected additional unpatched vulnerabilities beyond the specific one being tested. When scanning a repository at a historical commit, all vulnerabilities that had not yet been fixed at that point in time are detectable.

For example, when scanning Django at the pre-fix commit for CVE-2015-8213 (PYSEC-2015-11), Vanir also detected 4 additional unpatched CVEs: CVE-2016-6186, CVE-2022-41323, CVE-2016-2512, and CVE-2016-2513.

### 4.4 Analysis of Not-Detected Vulnerabilities

All 19 not-detected vulnerabilities were investigated. The root causes were determined by examining signature generation logs and signature files.

#### 4.4.1 Merge Commit Extraction Failure (14 of 19)

The dominant cause of detection failure. The following vulnerabilities had fix commits that were **git merge commits** (two parent commits):

| Package | Vuln ID | CVE | Fix Commit Message |
|---------|---------|-----|--------------------|
| aiohttp | PYSEC-2021-76 | CVE-2021-21330 | Merge commit |
| requests | PYSEC-2018-28 | CVE-2018-18074 | Merge commit |
| scrapy | PYSEC-2024-162 | CVE-2024-1892 | Merge commit |
| scrapy | PYSEC-2024-258 | CVE-2024-1968 | Merge commit |
| twisted | PYSEC-2022-195 | CVE-2022-24801 | Merge commit |
| twisted | PYSEC-2022-27 | CVE-2022-21712 | Merge commit |
| twisted | PYSEC-2024-75 | CVE-2024-41810 | Merge commit |
| werkzeug | PYSEC-2022-203 | CVE-2022-29361 | Merge commit |
| werkzeug | PYSEC-2023-57 | CVE-2023-23934 | Merge commit |
| werkzeug | PYSEC-2023-58 | CVE-2023-25577 | Merge commit |
| pillow | OSV-2022-715 | — | Merge commit |
| pillow | PYSEC-2020-78 | CVE-2020-10379 | Merge commit |
| pillow | PYSEC-2022-42979 | CVE-2022-45198 | Merge commit |
| pillow | PYSEC-2022-42980 | CVE-2022-45199 | Merge commit |

Vanir's `GitCodeExtractor` computes a patch by diffing a commit against its single parent. When a commit has two parents (a merge commit), the extractor cannot determine which parent to diff against and skips the commit. This is a consequence of Vanir's design for the Android ecosystem, where security patches are cherry-picked as single-parent commits. Python projects predominantly use GitHub's PR merge workflow, which creates merge commits. See **Section 6.6** for a detailed explanation of why this affects Python but not Android, with a walkthrough example.

Flask (PYSEC-2023-62, CVE-2023-30861) was excluded entirely from the analysis for the same reason — both of its fix commits were merge commits, so no signatures could be generated.

#### 4.4.2 Git Command Failure (2 of 19)

Two vulnerabilities failed during the git diff operation:

| Package | Vuln ID | CVE |
|---------|---------|-----|
| pillow | PYSEC-2016-19 | CVE-2016-2533 |
| lxml | PYSEC-2021-852 | CVE-2021-43818 |

The error was `Failed to run git command` during the clone/diff process. For lxml PYSEC-2021-852, signatures were generated from an alternative fix commit reference but did not match the code at the scanned vulnerable commit (6 signatures generated, 0 matched).

#### 4.4.3 Signatures Refined Away (2 of 19)

Two vulnerabilities had signatures successfully generated, but Vanir's false-positive refiner removed them:

| Package | Vuln ID | CVE |
|---------|---------|-----|
| ansible | PYSEC-2020-202 | CVE-2014-4660 |
| twisted | PYSEC-2022-160 | CVE-2022-21716 |

Vanir's refiner tests generated signatures against the patched version of the code. If a signature matches both the vulnerable and patched code, it is discarded to prevent false positives. In these cases, the fix may have been a behavioral change (e.g., changing a default value, adding a conditional check) where the surrounding code structure remained largely the same.

#### 4.4.4 Persistent Detections (2 of 97)

Two vulnerabilities were detected in both the vulnerable and fixed versions:

| Package | Vuln ID | CVE |
|---------|---------|-----|
| ansible | PYSEC-2017-3 | CVE-2015-6240 |
| pillow | PYSEC-2025-61 | CVE-2025-48379 |

In these cases, the generated signature matched code patterns that persisted after the fix was applied. This indicates the signature was too broad — matching structural code patterns rather than the specific vulnerable logic.

## 5. OSV Scanner Metadata Results

### 5.1 Overall Results

| Classification | Count | Percentage | Description |
|---------------|:---:|:---:|-------------|
| Correct | 95 | 97.9% | Flags affected version, clears fixed version |
| Still Flags | 2 | 2.1% | Flags both affected and fixed versions |
| Error | 2 | — | No fixed version in ecosystem range |
| **Total** | **99** | | |

OSV Scanner correctly identified 95 out of 97 valid vulnerability-version pairs.

### 5.2 Still-Flagged Cases

Two vulnerabilities were flagged by OSV Scanner in both the affected and fixed versions:

| Package | Vuln ID | CVE | Affected Version | Fixed Version |
|---------|---------|-----|:---:|:---:|
| scrapy | PYSEC-2024-258 | CVE-2024-1968 | Flagged | Flagged |
| transformers | PYSEC-2025-40 | CVE-2025-2099 | Flagged | Flagged |

This indicates that the OSV database metadata for these vulnerabilities may not have been updated to reflect the fix at the time of scanning, or the fixed version in the ECOSYSTEM range does not exactly correspond to the resolution.

### 5.3 Per-Package Results

All 26 packages achieved 100% correct identification except:

| Package | Tested | Correct | Still Flags | Error | Rate |
|---------|:---:|:---:|:---:|:---:|:---:|
| scrapy | 4 | 3 | 1 | 0 | 75% |
| transformers | 4 | 3 | 1 | 0 | 75% |
| pillow | 20 | 18 | 0 | 2 | 90%* |

\* Pillow's two error cases (OSV-2022-1074, OSV-2022-715) had no ECOSYSTEM-type range with a fixed version, making it impossible to construct a fixed-version lockfile for comparison. Excluding errors, Pillow was 18/18 (100%).

All other 23 packages achieved 100% correct identification.

### 5.4 How OSV Scanner Works

OSV Scanner does not examine source code. It reads a lockfile (e.g., `requirements.txt` with `werkzeug==0.15.2`), extracts the package name and version number, and queries the OSV database for any vulnerability records whose affected version ranges include that version. If the version falls within a known vulnerable range (e.g., `introduced: 0` → `fixed: 0.15.3`), the vulnerability is reported.

This means:
- OSV Scanner is only as accurate as the version range metadata in the OSV database.
- It cannot detect vulnerabilities for which no ECOSYSTEM range exists (only GIT ranges).
- It cannot distinguish between two source states that share the same version number (e.g., pre-fix and post-fix within `0.15.2`).
- It requires no language parsing, no signature generation, and no access to source code.

### 5.5 OSV Scanner Limitations Observed

1. **Same-version ambiguity**: Between a fix commit and the next version release, the code is patched but the version number is unchanged. OSV Scanner would report the version as vulnerable during this window. Vanir correctly distinguishes these states by examining the code itself.

2. **Metadata lag**: Two vulnerabilities (PYSEC-2024-258, PYSEC-2025-40) were flagged on both the affected and fixed versions, suggesting the OSV database's ECOSYSTEM range had not been updated to reflect the fix at scan time.

3. **Missing ECOSYSTEM ranges**: Two Pillow vulnerabilities had only GIT-type ranges (commit hashes) with no ECOSYSTEM version ranges, making metadata-based scanning impossible for those entries.

## 6. Vanir vs OSV Scanner: Operational Characteristics

### 6.1 What Each Tool Examines

| Aspect | Vanir | OSV Scanner |
|--------|-------|-------------|
| **Input** | Source code files | Package version number |
| **Detection basis** | Code-level signature matching | Version-range lookup in OSV database |
| **Requires** | Patch diff for signature generation | Version number and OSV database |
| **Language parsing** | Yes (tree-sitter / ANTLR4) | No |

### 6.2 Performance on Known Versions

When evaluating against known affected and fixed versions from the OSV database:

| Metric | Vanir | OSV Scanner |
|--------|:---:|:---:|
| Correct identifications | 75/96 (78.1%) | 95/97 (97.9%) |
| Not detected / Not found | 19 | 0 |
| False positives on fixed version | 2 | 2 |
| Errors | 1 | 2 |

### 6.3 Behavior at Fix Commit Boundaries

During Vanir scanning, we checked out the actual git commits (pre-fix and post-fix). At these commit boundaries, the package version number in the source code is typically **unchanged** — the version bump occurs in a subsequent release commit, not in the fix commit itself.

For example, for werkzeug PYSEC-2019-140 (CVE-2019-14806):
- Pre-fix commit (`fix~1`): source version = `0.15.2`
- Fix commit: source version = `0.15.2`
- Next release: `0.15.3`

At the fix commit, the code is patched but the version still reads `0.15.2`:
- **Vanir**: Detects the vulnerability at `fix~1`, does not detect it at the fix commit. Correctly identifies the code change.
- **OSV Scanner**: If given version `0.15.2`, would flag it as vulnerable at both commits. Cannot distinguish between pre-fix and post-fix states within the same version number.

This characteristic applies to the majority of the scanned vulnerabilities, as fix commits and version-bump commits are typically separate events in the Python ecosystem.

### 6.4 Vanir's Signature Generation Pipeline for Python

Of the 97 vulnerability scan pairs attempted:

| Outcome | Count | Percentage |
|---------|:---:|:---:|
| Signatures generated and matched correctly | 75 | 77.3% |
| Signature generation failed (merge commits) | 14 | 14.4% |
| Signature generation failed (git errors) | 2 | 2.1% |
| Signatures refined away | 2 | 2.1% |
| Signatures generated but did not match | 1 | 1.0% |
| Signatures too broad (persistent detection) | 2 | 2.1% |
| Scan error | 1 | 1.0% |

When Vanir successfully generated signatures (78 out of 97 cases), it correctly detected the vulnerability and confirmed the fix in 75 cases (96.2%).

### 6.5 Merge Commit Impact on Python Ecosystem Coverage

The merge commit limitation accounted for 14 out of 19 (73.7%) of Vanir's detection failures and the complete exclusion of 1 package (Flask). This limitation originates from Vanir's design for the Android ecosystem, where security patches are applied as cherry-picked single-parent commits.

Python open-source projects predominantly use GitHub's pull request merge workflow, producing merge commits with two parents. The fix commits recorded in OSV vulnerability entries for PyPI packages are frequently these merge commits.

The patch information is present in these merge commits — it is the diff between the first parent (main branch) and the merge commit. Vanir's `GitCodeExtractor` currently requires a single-parent commit and does not attempt first-parent diffing.

### 6.6 Why Merge Commits Are Not an Issue for Android (Vanir's Original Use Case)

Vanir was originally built for the Android Open Source Project (AOSP). The Android security patch workflow differs fundamentally from the typical Python open-source workflow:

**Android (cherry-pick workflow):**
```
upstream:    ... ── A ── B ── C (fix commit) ── D ── ...

AOSP branch: ... ── X ── Y ── C' (cherry-picked fix, single parent)
```

In the Android ecosystem, security fixes are developed upstream and then **cherry-picked** onto the AOSP branch. A cherry-pick creates a new commit (`C'`) that has a single parent (`Y`). The diff between `Y` and `C'` cleanly shows the security fix. The commit recorded in Android Security Bulletins is this cherry-picked single-parent commit, which Vanir's `GitCodeExtractor` handles correctly.

**Python open-source (PR merge workflow):**
```
main:        ... ── M ── N ──────────── P (merge commit, two parents)
                                       /
PR branch:          ── fix1 ── fix2 ──
```

In the Python ecosystem, developers submit pull requests on GitHub. When the PR is merged, GitHub creates a **merge commit** (`P`) that has two parents: the main branch tip (`N`) and the PR branch tip (`fix2`). The fix commit recorded in the OSV database is this merge commit.

Vanir's `GitCodeExtractor` computes a diff by calling `git diff <parent>..<commit>`. For a single-parent commit, there is exactly one parent, so the diff is unambiguous. For a merge commit, there are two parents, and the extractor does not know which one to diff against. It reports:

```
Failed to determine parent commit for <url>. Expected 1 parent commit,
got ['<parent1>', '<parent2>']. Is this a git-merge?
```

The correct approach for merge commits would be to diff against the **first parent** (`git diff <first_parent>..<merge_commit>`), which produces the same diff that the PR introduced into the main branch. This is equivalent to `git diff --first-parent` and is how tools like `git log -p --first-parent` display merge commit changes.

**Concrete example — werkzeug PYSEC-2023-58 (CVE-2023-25577):**

The OSV record lists fix commit `517cac5a`, which is a merge commit ("Merge pull request from GHSA-xg9f-g7g7-2323"):

```
main:        ... ── cf275f42 ──────────── 517cac5a (merge commit, recorded in OSV)
                                         /
PR branch:         ── babc8d9e ──────────
                      (actual fix code)
```

This commit has two parents:
- `cf275f42` — the main branch before the merge (first parent)
- `babc8d9e` — the PR branch tip (second parent)

The security patch is the diff between the first parent and the merge commit (`git diff cf275f42..517cac5a`), showing changes across 3 Python source files (60 insertions, 18 deletions in `formparser.py`, `multipart.py`, and `request.py`). This diff is available and usable, but Vanir's extractor does not attempt it because it sees two parents and aborts.

In the Android workflow, this same fix would have been cherry-picked as a single-parent commit, and Vanir would process it without issue.

This design choice in Vanir is not a bug — it is an intentional simplification that works well for Android's cherry-pick model. However, it means that Vanir cannot generate signatures for the majority of Python open-source projects that use GitHub's merge workflow, unless the OSV record references the actual PR branch commit rather than the merge commit.

### 6.7 How OSV Scanner Handles Vanir's Missed Cases

OSV Scanner's metadata-based approach is unaffected by merge commits entirely, since it does not examine source code or git history. It only checks whether a declared package version falls within a known vulnerable range.

For the 19 vulnerabilities that Vanir did not detect:

| Root Cause | Count | OSV Scanner Result |
|-----------|:---:|------------|
| Merge commit (no Vanir signature) | 14 | 13 correctly identified, 1 flagged both versions |
| Git command failure | 2 | 2 correctly identified |
| Signatures refined away | 2 | 2 correctly identified |
| Signature did not match | 1 | 1 correctly identified |

OSV Scanner correctly identified 18 out of 19 of the vulnerabilities that Vanir missed. The one exception (PYSEC-2024-258, scrapy) was flagged by OSV Scanner on both the affected and fixed versions, indicating an OSV database metadata issue rather than a tool limitation.

This illustrates a key complementarity: metadata-based detection is immune to code extraction and parsing challenges, while code-level detection can identify vulnerabilities regardless of version numbering accuracy.

## 7. Detailed Results Tables

### 7.1 Vanir True Positives (75)

| Package | Vuln ID | CVE | Cross-detections |
|---------|---------|-----|:---:|
| aiohttp | PYSEC-2023-246 | CVE-2023-47627 | 3 |
| aiohttp | PYSEC-2023-247 | CVE-2023-47641 | 4 |
| aiohttp | PYSEC-2023-250 | CVE-2023-49081 | 2 |
| aiohttp | PYSEC-2023-251 | CVE-2023-49082 | 3 |
| aiohttp | PYSEC-2024-24 | CVE-2024-23334 | 0 |
| aiohttp | PYSEC-2024-26 | CVE-2024-23829 | 1 |
| ansible | PYSEC-2017-2 | CVE-2014-3498 | 3 |
| ansible | PYSEC-2018-41 | CVE-2017-7481 | 1 |
| ansible | PYSEC-2020-203 | CVE-2014-4678 | 4 |
| ansible | PYSEC-2020-204 | CVE-2014-4966 | 2 |
| ansible | PYSEC-2020-205 | CVE-2014-4967 | 2 |
| certifi | PYSEC-2024-230 | CVE-2024-39689 | 0 |
| cryptography | PYSEC-2017-8 | CVE-2016-9243 | 0 |
| cryptography | PYSEC-2023-254 | CVE-2023-49083 | 1 |
| cryptography | PYSEC-2024-225 | CVE-2024-26130 | 0 |
| django | PYSEC-2012-7 | CVE-2012-4520 | 1 |
| django | PYSEC-2013-19 | CVE-2013-4249 | 2 |
| django | PYSEC-2013-21 | CVE-2013-6044 | 2 |
| django | PYSEC-2014-7 | CVE-2014-0483 | 3 |
| django | PYSEC-2015-11 | CVE-2015-8213 | 4 |
| django | PYSEC-2016-15 | CVE-2016-2512 | 3 |
| django | PYSEC-2016-16 | CVE-2016-2513 | 2 |
| django | PYSEC-2016-2 | CVE-2016-6186 | 0 |
| django | PYSEC-2020-35 | CVE-2020-7471 | 1 |
| django | PYSEC-2022-304 | CVE-2022-41323 | 0 |
| fastapi | PYSEC-2021-100 | CVE-2021-32677 | 0 |
| jinja2 | PYSEC-2014-82 | CVE-2014-0012 | 1 |
| jinja2 | PYSEC-2019-220 | CVE-2016-10745 | 0 |
| lxml | PYSEC-2018-12 | CVE-2018-19787 | 1 |
| lxml | PYSEC-2021-19 | CVE-2021-28957 | 2 |
| lxml | PYSEC-2022-230 | CVE-2022-2309 | 0 |
| mako | PYSEC-2022-260 | CVE-2022-40023 | 0 |
| numpy | PYSEC-2018-33 | CVE-2014-1858 | 1 |
| numpy | PYSEC-2018-34 | CVE-2014-1859 | 1 |
| paramiko | PYSEC-2018-19 | CVE-2018-7750 | 0 |
| pillow | OSV-2022-1074 | — | 0 |
| pillow | PYSEC-2014-10 | CVE-2014-3589 | 3 |
| pillow | PYSEC-2014-22 | CVE-2014-1932 | 4 |
| pillow | PYSEC-2014-23 | CVE-2014-1933 | 4 |
| pillow | PYSEC-2016-5 | CVE-2016-0740 | 2 |
| pillow | PYSEC-2016-6 | CVE-2016-0775 | 2 |
| pillow | PYSEC-2016-7 | CVE-2016-4009 | 3 |
| pillow | PYSEC-2020-77 | CVE-2020-10378 | 0 |
| pillow | PYSEC-2020-81 | CVE-2020-5310 | 1 |
| pillow | PYSEC-2020-82 | CVE-2020-5311 | 2 |
| pillow | PYSEC-2020-83 | CVE-2020-5312 | 2 |
| pillow | PYSEC-2020-84 | CVE-2020-5313 | 3 |
| pillow | PYSEC-2021-317 | CVE-2021-23437 | 0 |
| pillow | PYSEC-2023-227 | CVE-2023-44271 | 0 |
| pip | PYSEC-2020-173 | CVE-2019-20916 | 0 |
| pydantic | PYSEC-2021-47 | CVE-2021-29510 | 0 |
| pygments | PYSEC-2021-141 | CVE-2021-27291 | 0 |
| pyjwt | PYSEC-2022-202 | CVE-2022-29217 | 0 |
| requests | PYSEC-2015-17 | CVE-2015-2296 | 0 |
| requests | PYSEC-2023-74 | CVE-2023-32681 | 0 |
| scrapy | PYSEC-2021-363 | CVE-2021-41125 | 1 |
| scrapy | PYSEC-2022-159 | CVE-2022-0577 | 0 |
| setuptools | PYSEC-2022-43012 | CVE-2022-40897 | 0 |
| setuptools | PYSEC-2025-49 | CVE-2025-47273 | 0 |
| starlette | PYSEC-2023-48 | CVE-2023-30798 | 0 |
| tornado | PYSEC-2020-213 | CVE-2014-9720 | 0 |
| transformers | PYSEC-2023-299 | CVE-2023-2800 | 2 |
| transformers | PYSEC-2023-300 | CVE-2023-6730 | 2 |
| transformers | PYSEC-2023-301 | CVE-2023-7018 | 2 |
| transformers | PYSEC-2025-40 | CVE-2025-2099 | 0 |
| twisted | PYSEC-2019-128 | CVE-2019-12387 | 0 |
| urllib3 | PYSEC-2020-148 | CVE-2020-26137 | 2 |
| urllib3 | PYSEC-2020-149 | CVE-2020-7212 | 0 |
| urllib3 | PYSEC-2021-108 | CVE-2021-33503 | 1 |
| urllib3 | PYSEC-2021-59 | CVE-2021-28363 | 2 |
| urllib3 | PYSEC-2023-192 | CVE-2023-43804 | 0 |
| urllib3 | PYSEC-2023-207 | CVE-2018-25091 | 0 |
| urllib3 | PYSEC-2023-212 | CVE-2023-45803 | 0 |
| werkzeug | PYSEC-2019-140 | CVE-2019-14806 | 0 |
| werkzeug | PYSEC-2023-221 | CVE-2023-46136 | 0 |

### 7.2 Vanir Not Detected (19)

| Package | Vuln ID | CVE | Root Cause |
|---------|---------|-----|------------|
| aiohttp | PYSEC-2021-76 | CVE-2021-21330 | Merge commit |
| ansible | PYSEC-2020-202 | CVE-2014-4660 | Signatures refined away |
| fastapi | PYSEC-2024-38 | CVE-2024-24762 | Merge commit |
| lxml | PYSEC-2021-852 | CVE-2021-43818 | Git command failure; signatures did not match |
| pillow | OSV-2022-715 | — | Merge commit |
| pillow | PYSEC-2016-19 | CVE-2016-2533 | Git command failure |
| pillow | PYSEC-2020-78 | CVE-2020-10379 | Merge commit |
| pillow | PYSEC-2022-42979 | CVE-2022-45198 | Merge commit |
| pillow | PYSEC-2022-42980 | CVE-2022-45199 | Merge commit |
| requests | PYSEC-2018-28 | CVE-2018-18074 | Merge commit |
| scrapy | PYSEC-2024-162 | CVE-2024-1892 | Merge commit |
| scrapy | PYSEC-2024-258 | CVE-2024-1968 | Merge commit |
| twisted | PYSEC-2022-160 | CVE-2022-21716 | Signatures refined away |
| twisted | PYSEC-2022-195 | CVE-2022-24801 | Merge commit |
| twisted | PYSEC-2022-27 | CVE-2022-21712 | Merge commit |
| twisted | PYSEC-2024-75 | CVE-2024-41810 | Merge commit |
| werkzeug | PYSEC-2022-203 | CVE-2022-29361 | Merge commit |
| werkzeug | PYSEC-2023-57 | CVE-2023-23934 | Merge commit |
| werkzeug | PYSEC-2023-58 | CVE-2023-25577 | Merge commit |

## 8. Environment

| Component | Version |
|-----------|---------|
| Vanir | Latest (commit 8663090) with Python tree-sitter support |
| Python | 3.11 (Docker container) |
| Bazel | 8.0.0 |
| OSV Scanner | 2.3.8 |
| Platform | linux/amd64 (Docker on macOS host) |
| OSV Database | Queried live during May–June 2026 |
