# electronic_senate_voting_system

Zak Valente

COMP SCI 4024 Secure Software Engineering: Electronic Senate Voting System.

* **Frontend:** `frontend/`, React + TypeScript.
* **Backend:** six FastAPI services (auth, ballot, count, recount, audit, pdp) behind Nginx, with separate PostgreSQL databases, run with Docker.

The backend serves the frontend's API contract (`frontend/src/api/client.ts`) directly. See "Frontend API" below.

---

## Run it

Needs Docker Desktop, Python 3.11 or newer, and Node 20 or newer.

```bash
# 1. Prepare the Python environment once
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

# 2. Build the frontend, create fresh demo data, and start everything
bash scripts/presentation_setup.sh --reset-env --reset-data
```

The setup script creates `.env`, generates keys, builds `frontend/dist`, resets the database volumes, starts Nginx and all backend services, and prints the demo official passwords and live MFA codes. Keep its terminal open so the codes remain visible.

Open **https://localhost:8443**. The certificate comes from the project's development CA, so accept the browser warning once, or trust `keys/nginx/ca.crt`.

To start over with fresh presentation data, run the same `presentation_setup.sh --reset-env --reset-data` command again.

**Optional frontend development:** `cd frontend && npm run dev` gives `http://localhost:5173` and proxies `/api` to the Docker stack. For the presentation, use `https://localhost:8443`, where Nginx serves the production build and secure cookies work correctly.

---

## Demo accounts

**Voters** (election `senate-2026`). Passwords are for the demo only.

| Voter ID | Password | State |
|---|---|---|
| SA-0001 … SA-0005 | sa-voter-0001 … sa-voter-0005 | SA |
| VIC-0002 | vic-voter-0002 | VIC (refused on the SA ballot page) |

**Officials.** `scripts/demo_officials.py` prints each username, its password and its live one-time code.

| Username | Role | Scope |
|---|---|---|
| `eo.sa` | ELECTION_OFFICIAL | senate-2026 / SA |
| `co.sa` | COUNT_OPERATOR | senate-2026 / SA |
| `rd.sa` | RECOUNT_DELEGATE | senate-2026 / SA |
| `multi.sa` | COUNT_OPERATOR + RECOUNT_DELEGATE (one active per session) | senate-2026 / SA |
| `aud.demo` | AUDITOR | read-only, all |

**Court orders** (supporting evidence IDs), signed with the court key by `scripts/gen_keys.py`:

| Evidence ID | Excludes |
|---|---|
| HC-2026-17 | CAND-041, senate-2026 SA |
| HC-2026-18 | CAND-052, senate-2026 VIC |

Add more with `.venv/bin/python scripts/sign_exclusion.py --order HC-2026-19 --election senate-2026 --state SA --exclude CAND-063 --issued-on 2026-11-10 --register`.

---

## Demo walkthrough

1. **GR01 and GR02, voting.** Open *Voter flow*, sign in as SA-0001, choose a candidate and submit. You get a receipt. Signing in as SA-0001 again is refused with "A vote is already recorded against this enrolment".
2. **Close voting and count.** The frontend has no screen for these steps yet. This script signs in as `eo.sa` and `co.sa`, with a step-up code for the count, through Nginx:
   ```bash
   .venv/bin/python scripts/close_and_count.py
   ```
   (`scripts/demo_election.py` is the original narrated walkthrough. It runs the separate SEN2028 / NSW election.)
3. **GR03, recount.** Sign in as `rd.sa` (Recount delegate), open the recount workflow, and use evidence `HC-2026-17` with a **new** one-time code. The exclusion is approved, and the recount result no longer elects CAND-041. Try the following:
   * CAND-052 (VIC) is rejected because it is not named in the SA court order.
   * A made-up evidence ID is rejected because it can't be verified.
   * A wrong one-time code ends the session (Milestone 2, Table 11).
4. **GR05, audit.** Sign in as `aud.demo` (Auditor) and open *Audit*. The page shows the hash-chained events and "Chain: VALID". Other roles get "Auditor access required".
5. **GR04, availability.** Rapid repeated requests get `429 RATE_LIMITED` with `Retry-After: 60`. The *Resilience* page explains how the UI handles it.

---

## Frontend API

These are the paths in `frontend/src/api/client.ts`, as served through Nginx.

| Frontend call | Endpoint | Backend |
|---|---|---|
| obtainElectorAuthorisation | `POST /api/auth/elector/authorisation` `{state, voterId, password, electionId}` → `{authorisationToken, state, expiresAt}` | auth |
| getBallotConfig | `GET /api/ballots/config?state&electionId` → `{electionId, state, configurationVersion, candidates[{candidateId, displayName, party}]}` | ballot |
| submitBallot | `POST /api/ballots` `{authorisationToken, electionId, state, selections[{candidateId, rank}], configurationVersion}` → `{submissionId, status, submittedAt}` | ballot |
| officialLogin / officialLogout | `POST /api/auth/officials/login`, `POST /api/auth/officials/logout` | auth |
| getOfficialSession | `GET /api/auth/session` → `{role, sessionExpiresAt, scope{state, electionId, countId}, csrfToken}` | auth |
| submitExclusion | `POST /api/recount/exclusions` `{electionId, state, candidateId, recountPhase, exclusionGround, supportingEvidenceId, stepUpCode}` → `{status, exclusionId, auditEventId, reason}` | recount |
| getAuditEvents | `GET /api/audit/events?limit=50` → `{events[AuditEvent], chainStatus}` | audit |

Errors always look like `{"error": {"code", "message"}}`. Codes include `AUTHENTICATION_REQUIRED`, `SCOPE_DENIED`, `ALREADY_VOTED`, `AUTHORISATION_REPLAY`, `CONFIGURATION_CHANGED`, `STEP_UP_TIMEOUT`, `RATE_LIMITED` (with `Retry-After`) and `SERVICE_UNAVAILABLE`.

**Where the frontend changed to keep the security requirements:**
* The voter page asks for a voter ID and password. Without them anyone could get a ballot, which would break GR01.
* There is an official sign-in page (`/official/login`), because officials need a password and a one-time code.
* The recount form asks for a step-up one-time code, because the exclusion is irreversible (Milestone 2, Table 7).
* The API client sends the session cookie and the `X-CSRF-Token` header on state-changing requests.

**Simplifications** (state these in the report):
* A ballot with a single ranked candidate counts as formal. Real Senate rules need at least 1 group above the line or 6 candidates below it, and the original `/api/ballot/ballots` endpoint still enforces those rules.
* A court order excludes the candidates it names. Exclusions from different orders are not combined into one recount.

**Fixed while adapting:** previously a voter could get one authorisation per *made-up* election ID and vote several times. Auth now issues authorisations only for running elections (`SV_ACTIVE_ELECTIONS`).

---

## Tests

```bash
.venv/bin/python -m pytest                                    # 70 unit tests, no Docker needed
.venv/bin/python tests/e2e/frontend_contract_test.py          # frontend endpoints, through Nginx (fresh stack)
SMOKE_COMPOSE_PROJECT=electronic-senate-voting PYTHONPATH=shared \
  .venv/bin/python tests/e2e/smoke_test.py                    # original full-election test (fresh stack)
cd frontend && npm run build                                  # TypeScript type-check + build
```
