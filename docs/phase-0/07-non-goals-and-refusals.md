> **Phase 0 design artifact — no implementation code.** This document is part of the Phase 0 requirements & threat-model package for an *authorized, non-destructive* defensive web-application security assessment platform. It is subordinate to the safety model: every control described here is intended to be enforced **technically**, not by warning.

# Explicit Boundaries — Non-Goals & Refusal/Safe-Alternative Map (Phase 0)

This document is the authoritative boundary definition for the platform. It exists so that every downstream phase (scope engine, check engine, tool adapters, validation workflow, reporting) can be traced back to a fixed answer on *what we will never do*. Non-goals here are **product invariants**, not configuration options: they cannot be toggled on by an operator, an engagement setting, a plugin, or a scanner's output.

---

## 1) Explicit Non-Goals

Grouped by theme. Each item is something the platform will **deliberately not do**, with the reason it is excluded.

### A. Destructive exploitation & data integrity

| # | Non-Goal | Why |
|---|----------|-----|
| A1 | **No destructive exploitation** (weaponized payloads that alter target behavior or state). | The mission is evidence-based *detection*, not proof-by-damage; damage is never an acceptable side effect of an assessment. |
| A2 | **No data modification, deletion, corruption, or write operations** to prove a flaw. | A non-destructive platform must be safe to run on production; a single altered row is an outage or a data-integrity incident. |
| A3 | **No database dumping or bulk data extraction.** | Extraction converts a finding into a breach; single-row metadata is sufficient to evidence SQLi/IDOR. |
| A4 | **No retrieval of secrets, tokens, keys, credentials, or user/PII records as "proof."** | Retrieving sensitive data as evidence *is* the harm we assess for; it violates redaction and data-minimization guarantees. |
| A5 | **No destructive race conditions or resource-exhaustion "tests."** | These validate a flaw by causing instability; the risk to availability outweighs the evidentiary value. |
| A6 | **No sensitive-OS-file retrieval** (e.g. reading `/etc/passwd`, key material, config secrets) to demonstrate traversal/LFI. | A benign canary path proves the traversal primitive without exposing sensitive host data. |

### B. Access, persistence & post-exploitation

| # | Non-Goal | Why |
|---|----------|-----|
| B1 | **No persistence, implants, backdoors, or scheduled footholds** on any target. | Persistence outlives the engagement window and authorization; it is indistinguishable from a real compromise. |
| B2 | **No reverse shells, bind shells, or OS/command execution on the target.** | Command execution is the exploitation step we detect *indicators* of, never perform. |
| B3 | **No Command-and-Control (C2), beaconing, or agent deployment.** | C2 is offensive infrastructure with no defensive-assessment use case. |
| B4 | **No lateral movement, privilege escalation, or pivoting** to other hosts. | Movement inevitably leaves the authorized scope and touches infrastructure we were not permitted to test. |
| B5 | **No uploading of executables, web shells, or active content** (even to prove an upload flaw). | Upload-validation weakness is proven by an inert harmless file; live payloads create a real backdoor. |
| B6 | **No cryptomining, tasking, or use of target compute.** | Any use of target resources is abuse regardless of intent. |

### C. Authentication & account attacks

| # | Non-Goal | Why |
|---|----------|-----|
| C1 | **No brute force, password/credential spraying, or dictionary attacks.** | These trip lockouts, create noise, risk locking out real users, and are trivially destructive to availability. |
| C2 | **No MFA bypass, session fixation exploitation, or account takeover (ATO).** | Taking over an account is unauthorized access to a real (or test) user's data, not a detection. |
| C3 | **No credential harvesting or credential-store scraping.** | Harvesting credentials is theft; the platform never collects live credentials as output. |
| C4 | **No password/hash cracking** of any recovered material. | We report weak-storage *indicators* from observable behavior; cracking is offensive and out of scope. |
| C5 | **No defeating of authentication controls.** | The platform uses *operator-supplied* sessions and test accounts; it never breaks auth to gain access. |

### D. Availability & aggression

| # | Non-Goal | Why |
|---|----------|-----|
| D1 | **No Denial-of-Service** of any kind (network, application, algorithmic, or "stress to prove availability risk"). | DoS is the one outcome that is always destructive; conservative rate limits and circuit breakers make it structurally impossible. |
| D2 | **No high-volume / aggressive / flooding scan modes.** | Aggression risks availability and evades the per-engagement request budget the safety model mandates. |
| D3 | **No unbounded fuzzing intended to crash the target.** | Crash-oriented fuzzing is a DoS by another name; fuzzing here is bounded, structural, and non-crashing. |

### E. Evasion, stealth & bypass

| # | Non-Goal | Why |
|---|----------|-----|
| E1 | **No WAF bypass or evasion.** | A WAF is a defensive control; the platform reports its presence as a positive signal and never circumvents it. |
| E2 | **No CAPTCHA solving or bypass.** | CAPTCHA is an anti-automation control; defeating it is exactly the abuse we protect targets from. |
| E3 | **No rate-limit / anti-automation bypass.** | Missing rate limits are *reported as a finding*; existing ones are respected, never overrun. |
| E4 | **No stealth, anti-forensics, log evasion, or timing games to avoid detection.** | Legitimate authorized testing is transparent; evasion only serves illegitimate access. |
| E5 | **No tamper-evident-audit-trail suppression.** | The audit trail is a safety invariant; the platform cannot be operated "quietly." |

### F. Scope, targeting & third parties

| # | Non-Goal | Why |
|---|----------|-----|
| F1 | **No testing of any target without an explicit, current scope + authorization record.** | Deny-by-default is the core invariant: no scope, no traffic. |
| F2 | **No scanning of infrastructure discovered *during* testing** (newly found subdomains, linked hosts, IP ranges). | Discovery is not authorization; discovered assets require a new scope entry with its own written approval. |
| F3 | **No third-party / shared infrastructure targeting** (CDNs, payment processors, SSO/identity providers, SaaS APIs) unless individually allowlisted with authorization. **Cloud metadata endpoints are NOT in this category** — they are Tier A (§SI-006/network guard) and remain **unreachable by any means**: no allowlist entry, elevated flag, or authorization can ever reach them. | We have no right to test infrastructure the client does not own or control; metadata endpoints are a separate, absolute network-guard hard-deny, not an authorization question. |
| F4 | **No SSRF pivoting to cloud metadata, RFC1918, link-local, or localhost.** SSRF-class checks confirm the primitive only via approved controlled-callback infra, never by reaching a real internal host. | These are the DNS-rebinding / SSRF targets the platform blocks. *Direct* testing of an **authorized internal** RFC1918/ULA/link-local application is a separate, legitimate path permitted only under the two-tier network guard's **elevated dual approval** (Tier B); cloud metadata and Tier A remain unreachable by any means. |
| F5 | **No mass/internet-wide scanning or opportunistic targeting.** | The platform is engagement-scoped; it is not a mass-scanner. |
| F6 | **No continued testing after authorization expiry or outside the testing window.** | Authorization is time-bound; auto-expiration and window enforcement are hard stops. |

### G. Autonomy & operator-effort limits (the "minimal effort ≠ no control" line)

| # | Non-Goal | Why |
|---|----------|-----|
| G1 | **No one-click "attack everything" / autonomous exploitation.** | Minimal operator effort applies to setup and triage, never to unleashing intrusive actions unattended. |
| G2 | **No automatic intrusive validation.** | Every intrusive step is approval-gated with an explicit plan; the platform never self-authorizes impact. |
| G3 | **No self-escalation past its own approval gates or safety classifications.** | The gates are the product; a system that can bypass them has no safety model. |
| G4 | **The platform is not a replacement for a professional pentester.** | Automated results are decision support; every report states they require expert review. |

### H. Tooling & extensibility

| # | Non-Goal | Why |
|---|----------|-----|
| H1 | **No arbitrary shell command execution from the UI or API.** | An arbitrary-command surface is a supply-chain and RCE risk to the platform itself and its operators. |
| H2 | **No exploit frameworks or offensive C2 integrations** (Metasploit, Cobalt Strike, Sliver, `sqlmap --dump`, etc.). | These are weaponization tools; only curated, non-destructive adapters are permitted. |
| H3 | **No user-supplied CLI arguments reaching a shell** in any tool adapter. | Adapters are parameterized and sandboxed; a shell-arg passthrough is command injection by design. |
| H4 | **No unsafe/destructive scanner templates or plugin options** (Nuclei/ZAP intrusive/DoS/exploit categories disabled and pinned). | Untrusted templates can turn a scan into an attack or a supply-chain vector. |
| H5 | **No unpinned or unverified tool/template versions.** | Version drift is a supply-chain compromise vector for one of the ten named threats. |

### I. Output, reporting & privacy

| # | Non-Goal | Why |
|---|----------|-----|
| I1 | **No inclusion of raw secrets, cookies, `Authorization` headers, API keys, passwords, PII, or sensitive bodies in logs, evidence, or reports.** | Report-data exposure is a named threat; redaction is enforced at capture, not at export. |
| I2 | **No long-term retention of raw sensitive response data.** | Data minimization limits blast radius if the platform itself is compromised. |
| I3 | **No cross-tenant / cross-engagement data visibility.** | Tenant isolation is a hard invariant; one client's findings are never reachable from another's context. |
| I4 | **No deanonymization, tracking, or profiling of real end-users** of the target. | Real users are non-consenting bystanders; the platform interacts with operator-provided test identities only. |

### J. Social & out-of-domain

| # | Non-Goal | Why |
|---|----------|-----|
| J1 | **No phishing, social engineering, or awareness "tests" against client staff.** | This is not a web-application assessment function and involves non-consenting humans. |
| J2 | **No physical, wireless, or non-web attack surfaces.** | Out of the platform's defined web-app domain and safety envelope. |
| J3 | **No offering the platform as an attack service to third parties** or against targets the operator cannot prove they own/are authorized for. | Authorization-first means the *operator's* right to test is verified, not assumed. |

---

## 2) Refusal & Safe-Alternative Map

For each category of request that conflicts with the authorization/safety model, the platform issues a **structured refusal** (it does not silently no-op) and offers the **non-destructive defensive alternative** it *does* provide. Refusals are enforced technically — the offending action cannot be scheduled or executed even if requested.

### Exploitation / proof-by-impact

| Operator asks for… | Refusal | Safe alternative the platform offers |
|---|---|---|
| "Get me a reverse shell / prove RCE." | No command execution or shell on any target. | Record a **command-injection indicator** via inert differential (e.g. benign math/delay marker in a controlled parameter), then produce an **approval-gated, non-executing validation plan** showing the exact request and expected inert response — no OS interaction. |
| "Dump the database to prove the SQLi." | No DB dumping or bulk extraction. | **Non-destructive boolean/timing differential** to confirm injectability, plus **single-row, non-sensitive metadata** (e.g. DB version banner, one benign column count) as redacted evidence. Never row data. |
| "Read `/etc/passwd` / a config secret to prove path traversal." | No sensitive-file retrieval. | **Bounded traversal to a benign canary path** the platform controls or to a known non-sensitive marker, evidencing the traversal *primitive* only; sensitive content is never fetched. |
| "Upload a web shell to prove the upload bypass." | No executable/active-content upload. | **Inert harmless file** with a controlled extension/content-type mismatch to evidence the *validation gap*; the file cannot execute and is cleaned up. |
| "Pop `alert(document.cookie)` / steal a cookie to prove XSS." | No exfiltration payloads. | **Inert reflection marker** (unique non-executing token) plus **output-context and encoding analysis** to establish reflected/stored XSS with confidence, no data theft. |
| "Fire the SSRF at `169.254.169.254` / the internal service." | The SSRF check never uses metadata/private/link-local/localhost as its interaction target. Tier A (metadata/loopback/…) is unreachable by any means; authorized internal ranges are tested only *directly* under elevated dual approval, never via SSRF pivot. | **Approved controlled-callback (canary) infrastructure only**: an inert out-of-band token confirms the SSRF primitive (blind indicator) without touching any real internal target. |
| "Prove the deserialization RCE with a working gadget." | No code-execution PoC. | **Inert probe / error-signature indicator** to flag unsafe deserialization, escalated only via an approval-gated validation plan that still does not execute code. |
| "Pull everything via GraphQL introspection + batching." | No bulk data harvesting. | **Report introspection-enabled and batching indicators** as findings; collect schema-shape evidence, not the underlying data. |

### Authentication / account attacks

| Operator asks for… | Refusal | Safe alternative |
|---|---|---|
| "Brute force / spray the login." | No brute force or spraying. | **Auth & session configuration checks** (lockout policy presence, credential-transport, session-cookie attributes) observed *without triggering* lockouts, plus **operator-supplied test accounts** for authorization-consistency testing. |
| "Bypass MFA / take over this account." | No MFA bypass or ATO. | **Session-attribute and access-control indicator analysis** using operator-provided accounts (e.g. horizontal/vertical authz consistency between two test users), never unauthorized access to a real account. |
| "Crack these hashes we found." | No credential cracking. | **Weak-storage indicators** derived from observable behavior/config; the finding notes the risk without recovering credentials. |
| "Enumerate all valid usernames." | No enumeration that abuses missing rate limits. | **Report username-enumeration and missing-anti-automation indicators** (differential responses, absent lockout) as findings, without mass-enumerating real accounts. |

### Evasion / control-bypass

| Operator asks for… | Refusal | Safe alternative |
|---|---|---|
| "Bypass the WAF so we can reach the app." | No WAF evasion. | **Report the WAF as a defense-in-depth control**; test only the in-scope, explicitly allowlisted origin/app through normal paths. |
| "Solve the CAPTCHA to test the flow behind it." | No CAPTCHA defeat. | Use an **operator-provided authenticated/post-CAPTCHA session** so the control is respected while the downstream flow is still assessed. |
| "Bypass rate limiting to speed things up." | No rate-limit bypass. | **Flag missing or weak rate limiting as a finding**; the platform itself stays within conservative per-engagement budgets. |
| "Run quietly so we don't show up in their logs." | No stealth/anti-forensics. | Transparent, **rate-limited, fully audit-logged** testing; the operator can coordinate a testing window with the client instead. |

### Scope / targeting

| Operator asks for… | Refusal | Safe alternative |
|---|---|---|
| "Also scan this /24 (or subdomain) we just discovered." | No auto-scanning of discovered infrastructure. | **Surface the discovery as an inventory item** and prompt the operator to add it to scope **with a new authorization record**; until then it receives zero traffic. |
| "Test the payment processor / SSO / CDN it talks to." | No third-party infrastructure testing. | Test **only client-owned, allowlisted assets**; recommend the operator obtain separate written authorization for any third party they actually control. |
| "Keep testing — the window/authorization just expired." | No testing past expiry or outside the window. | **Window close** only *pauses* execution (the engagement stays `active`, requests are denied at the gate until a window re-opens — it is **not** a terminal state). **Authorization expiry/revocation** is terminal: the platform stops and offers to resume only after a **fresh authorization** is recorded. |
| "Just point it at the target; skip the scope setup." | No operation without an explicit scope + authorization. | **Guided setup**: create engagement → attach authorization → define scope → verify scope (DNS/redirect/rebinding checks) → then run. Deny-by-default until complete. |

### Autonomy / validation

| Operator asks for… | Refusal | Safe alternative |
|---|---|---|
| "One-click attack everything." | No autonomous "attack everything." | **Mode selection** (Passive → Safe Active → Approval-Gated Validation) with a **request-volume estimate and budget indicators** before anything runs. |
| "Auto-validate every finding for me." | No automatic intrusive validation. | For each candidate, generate a **validation plan** (exact request, why needed, potential impact, scope check, required test account, expected response, evidence retained, cleanup, stop conditions) that executes **only after explicit operator approval**. |
| "Crawl and submit all the forms." | No auto-submission of state-changing actions. | **Record forms, parameters, and provenance** in the attack-surface map; avoid logout/delete/payment/account-change/messaging actions; state-changing forms are catalogued, never auto-submitted. |

### Availability

| Operator asks for… | Refusal | Safe alternative |
|---|---|---|
| "Crank up concurrency / load-test to prove they can't handle it." | No DoS or load generation. | **Rate-limit and resilience *configuration* analysis** (headers, throttling behavior observed passively) within strict budgets; availability risk is reported, not demonstrated by impact. |
| "Fuzz it until something crashes." | No crash-oriented fuzzing. | **Bounded, structural input testing** (parser/URL edge cases) that is explicitly non-crashing, with circuit breakers if the target shows instability. |

### Tooling / extensibility

| Operator asks for… | Refusal | Safe alternative |
|---|---|---|
| "Run Metasploit / `sqlmap --dump` / my exploit script." | No exploit frameworks or destructive tool modes. | **Curated non-destructive adapters** (Nuclei with an allowlisted safe-template set, ZAP baseline/controlled, TestSSL, SCA/secret scanners) run in **isolated, egress-restricted containers** with pinned versions and unsafe options disabled. |
| "Give me a shell / let me pass custom CLI args to the scanner." | No arbitrary shell and no user args reaching a shell. | **Parameterized, validated check modules only**; adapters expose a fixed safe option surface, and tool output is parsed as **untrusted structured data**, never as trusted console text. |
| "Add this random third-party template/plugin and run it." | No unverified/unsafe templates or plugins. | Templates/plugins must be **version-pinned, verified, classified non-destructive, and allowlisted**; unsafe categories (DoS/exploit/intrusive) are disabled by construction. |

### Reporting / privacy

| Operator asks for… | Refusal | Safe alternative |
|---|---|---|
| "Put the actual token/cookie/PII in the report so they see it's real." | No raw secrets/PII in logs, evidence, or reports. | **Redacted evidence** (masked value + type + location reference) backed by a secured evidence store; the finding conveys severity without leaking the secret. |
| "Show me another engagement's findings for comparison." | No cross-tenant/engagement visibility. | Findings stay **isolated per engagement/tenant**; comparison is limited to the operator's own authorized engagements via explicit, permissioned exports. |
| "Retrieve a sample of real user records as evidence." | No user-data extraction. | **Count- or metadata-level evidence** (e.g. "response differential confirms IDOR; 1 non-sensitive identifier observed, redacted") establishes the flaw without exposing user data. |

### Out-of-domain

| Operator asks for… | Refusal | Safe alternative |
|---|---|---|
| "Phish their employees / run a social-engineering test." | Not a function of this platform. | Recommend a **separately scoped, separately authorized** engagement type; the platform stays on the authorized web-application surface only. |
| "Persist a marker so we can prove access later." | No persistence. | **Ephemeral, cleaned-up test artifacts** only; every intrusive validation defines its cleanup action and leaves no foothold. |

---

**Invariant summary:** every refusal above degrades gracefully into a *detection*, an *indicator*, an *operator-supplied-credential path*, or an *approval-gated non-executing validation* — never into impact, extraction, persistence, evasion, or unauthorized reach. If a requested capability cannot be reduced to one of those safe forms, the platform refuses and does not offer a workaround.
