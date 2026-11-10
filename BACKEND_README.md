# Senate Voting

A Senate election system built as six small FastAPI services behind Nginx, with four separate PostgreSQL databases. It runs with one Docker Compose command.

The design follows the group's Milestone 2 document (Authentication and Authorisation Design); section numbers below refer to it.

| Requirement | Main controls | Where |
|---|---|---|
| **GR01** Eligibility and single-use authorisation | Voter ID + password checked against the roll for the chosen state (§2.2). One `issuances` row per elector per election (409 "vote already recorded"). The capability carries a random 128-bit `authorisationNonce`; its primary key in `used_nonces` makes it single use, consumed in the same transaction as the ballot | `services/auth`, `services/ballot`, `common/tokens.py` |
| **GR02** Ballot secrecy | Capability holds only the envelope, nonce and state (Table 5). Roll and ballots in separate databases on separate networks. Ballots sealed to the **Count** key with no elector, nonce or time. `QUERY_BALLOT_BY_ELECTOR_ID` denied for everyone and logged. Audit families share no field; times kept to the minute (§2.7) | `common/ballot_crypto.py`, `db/roll`, `db/ballot`, `services/audit` |
| **GR03** Scoped recount authority | `RECOUNT_DELEGATE` scoped to one election and state; exact scope match in the PDP. Step-up bound to `ENTER_MANUAL_EXCLUSION` and the exact candidates. Court-signed grounds. Recount phase opens only after a published count | `services/pdp/app/rules.py`, `services/recount` |
| **GR04** Availability and DoS | Nginx rate limits per IP (stricter on login and voting), body size and timeouts. Stateless signature check on the voting path. **No elector lockout** (§4.4); officials locked after 5 failures. 64 KB body cap and nesting guard everywhere | `nginx/nginx.conf`, `services/auth/app/lockout.py`, `common/app_factory.py` |
| **GR05** Tamper-evident audit | Hash chain plus Ed25519 signature per entry, record families from Table 13. DB user has INSERT/SELECT only and a trigger blocks UPDATE/DELETE. Every official action attributed to an `operatorId`. Chain re-verified after every count and recount; result withheld if it fails (Figure 2) | `common/audit_chain.py`, `services/audit`, `services/count` |

### Authentication model (Milestone 2 Section 2)

- **Token envelope (Table 4):** `iss` = `aec-auth`, `aud` = `senate-voting-api`, `kid` header, EdDSA only, `principalType`, `iat`/`nbf`/`exp`.
- **Electors:** no session, no cookie. A 15-minute single-use capability in the `Authorization` header.
- **Officials:** password + TOTP, **one active role per session** (chosen at sign-in). Server-side session in Auth (30 min idle, 8 h absolute, revoked on logout or a failed step-up) behind an `HttpOnly; Secure; SameSite=Strict` `__Host-` cookie, with a CSRF synchroniser token on every change. Other services confirm the session with Auth on each request.
- **Step-up (Table 7):** only `COMMIT_NOMINATIONS`, `FIX_PARTY_ORDER`, `START_COUNT`, `ENTER_MANUAL_EXCLUSION`. Bound to the action and resource, valid 2 minutes, usable once (408 if expired, 403 on mismatch or reuse).
- **Contest lifecycle:** `nominations → nominations_committed → order_fixed → open → closed → counted` (counted = recount phase open).

## Layout

```
docker-compose.yml        services, databases and the network isolation between them
.env.example              copy to .env (never committed)
nginx/nginx.conf          HTTPS, routing /api/<service>/, rate limits, mTLS to services, blocks /internal/
shared/common/            code every service uses
  settings.py             SV_* environment variables; production is the default
  keys.py                 loads keys from the service's own /run/keys folder
  tokens.py               EdDSA session, ballot and service tokens
  audit_chain.py          hash chain + signatures (GR05)
  ballot_crypto.py        X25519 + AES-GCM ballot sealing (GR02)
  clients.py              mTLS calls to Audit and PDP (both fail closed)
  security.py             FastAPI dependencies: official, ballot token, service caller, PDP check
  app_factory.py          shared app setup: no docs in prod, body cap, safe 500s, headers
  db.py                   SQLAlchemy engine + per-request transaction
  run.py                  starts uvicorn with mutual TLS
services/<name>/app/      auth, ballot, count (+ stv.py), recount (+ grounds.py), audit, pdp (+ rules.py)
services/Dockerfile       one image recipe, SERVICE build arg picks the service
db/<name>/                01-schema.sql + 02-app-role.sh (least-privilege DB user)
scripts/gen_keys.py       all keys and certificates, one folder per service
scripts/sign_exclusion.py plays the court: signs exclusion grounds for a recount
tests/                    unit tests (no Docker needed)
tests/e2e/smoke_test.py   full election through Nginx against the running stack
```

## First run

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt
cp .env.example .env                 # then replace every change-me with a random value
.venv/bin/python scripts/gen_keys.py
docker compose up -d --build
.venv/bin/python tests/e2e/smoke_test.py     # expects fresh databases
```

The app is at **https://localhost:8443**. The certificate comes from the project's own development CA; trust `keys/nginx/ca.crt`, or accept the browser warning.

Linux hosts only: the containers run as uid 10001. If a service can't read its keys, run `sudo chown -R 10001 keys/{auth,ballot,count,recount,audit,pdp}`.

## Everyday commands

| Command | What it does |
|---|---|
| `docker compose up -d --build` | Build and start everything |
| `docker compose ps` | What's running |
| `docker compose logs -f auth` | Follow one service's log |
| `docker compose down` | Stop (data kept) |
| `docker compose down -v` | Stop and **delete all databases** (fresh start) |
| `.venv/bin/python -m pytest` | Unit tests |
| `.venv/bin/bandit -r shared services scripts` | Static security scan |
| `.venv/bin/pip-audit` | Known-vulnerable dependency scan |

Set `SV_ENVIRONMENT=development` in `.env` to turn on `/docs` for each service, e.g. `https://localhost:8443/api/ballot/docs`.

## Creating officials

Officials can only be created inside the Auth container, because it's the only one that can reach the auth database. Every role except `AUDITOR` is scoped to one election and one state:

```bash
docker compose exec auth python -m app.manage create-official --username eo.nsw --role ELECTION_OFFICIAL --election SEN2028 --state NSW
docker compose exec auth python -m app.manage create-official --username co.nsw --role COUNT_OPERATOR --election SEN2028 --state NSW
docker compose exec auth python -m app.manage create-official --username rd.nsw --role RECOUNT_DELEGATE --election SEN2028 --state NSW
docker compose exec auth python -m app.manage create-official --username aud.kim --role AUDITOR
docker compose exec auth python -m app.manage add-role --username co.nsw --role RECOUNT_DELEGATE --election SEN2028 --state NSW
```

You're prompted for the password. The command prints an `otpauth://` link once: add it to an authenticator app. For demos, `scripts/demo_officials.py` creates a set of accounts and shows their live codes.

## API (through Nginx)

Official requests carry the session cookie automatically; state-changing ones also need the `X-CSRF-Token` header from the login response.

| Method and path | Who | Notes |
|---|---|---|
| `POST /api/auth/electors/authorise` | elector | `{voter_id, password, state, election_id}` returns a voting capability (once per election) |
| `POST /api/ballot/ballots` | elector capability | `{above_the_line: ["B","A"]}` or `{below_the_line: [6+ ids]}` returns `{receipt}` |
| `GET  /api/ballot/elections/{id}/contests/{state}` | public | Ballot paper and lifecycle status |
| `GET  /api/ballot/elections/{id}/receipts/{state}` | public, after close | Voters check their receipt is included |
| `POST /api/auth/officials/login` | official | `{username, password, otp, role}` sets the session cookie, returns `csrfToken` |
| `GET  /api/auth/officials/session` | official | Current session (used after a page reload) |
| `POST /api/auth/officials/step-up` | official | `{otp, action, resource: {election_id, state, candidates?}}` |
| `POST /api/auth/officials/logout` | official | Revokes the session |
| `POST /api/ballot/elections/{id}/contests/{state}/nominations/commit` | ELECTION_OFFICIAL + step-up | |
| `POST /api/ballot/elections/{id}/contests/{state}/party-order` | ELECTION_OFFICIAL + step-up | `{group_order: ["B","A","C"]}` |
| `POST /api/ballot/elections/{id}/contests/{state}/open` and `/close` | ELECTION_OFFICIAL | |
| `POST /api/count/counts` | COUNT_OPERATOR + step-up | `{election_id, state}` returns the STV result, released after chain verification |
| `POST /api/recount/recounts` | RECOUNT_DELEGATE + step-up | Body from `scripts/sign_exclusion.py` |
| `GET  /api/ballot/ballots/by-elector/{id}` | nobody | Always 403, logged as `QUERY_REFUSED` |
| `GET  /api/audit/events`, `GET /api/audit/verify` | AUDITOR | `?after_seq=&limit=` |

`/internal/*` endpoints are for service-to-service calls only. Nginx returns 404 for them.

## Frontend (React + Vite)

`frontend/` has the voter screens (enrolment check, ballot paper, review, receipt, receipt check) and one
dashboard per official role (open/close, count, court-ordered recount, audit log and chain verification).
Tokens are kept in memory only, never in browser storage.

```bash
docker compose down -v && docker compose up -d     # fresh election in 'draft'
.venv/bin/python scripts/demo_officials.py         # eo.nsw, co.nsw, rd.nsw, aud.demo, ...: passwords + live codes
cd frontend && npm install && npm run dev          # http://localhost:5190 (API proxied to Nginx)
```

Walkthrough: sign in as `eo.nsw` (Election official) to commit nominations, fix the party order and open voting;
vote as the sample electors (voter IDs and passwords are on the home page); close voting; count as `co.nsw`
(Count operator); check receipts; enter a court-ordered exclusion as `rd.nsw`; verify the audit log as `aud.demo`.

- **Production:** `npm run build` writes `frontend/dist`. Set `FRONTEND_DIST=./frontend/dist` in `.env` and
  restart Nginx; it serves the app at https://localhost:8443 on the same origin, so no CORS is needed. The build
  has no inline scripts or styles, so it runs under Nginx's strict Content-Security-Policy.

## Known simplifications and differences from the Milestone 2 design (state these in the report)

- `stv.py` is a teaching STV: Droop quota and weighted inclusive Gregory method, but no bulk exclusion or AEC rounding rules.
- TOTP secrets are stored in plain text in the auth DB. Encrypt them at rest for production.
- Services identify each other by mutual TLS **plus** a signed service token, rather than by certificate fingerprint alone (Table 9). The CA-signed certificate is required, but there is no per-fingerprint allowlist and no 90-day rotation.
- Ballot, Count, Recount and Audit call Auth to confirm official sessions. Table 10 doesn't list these calls; they are what makes server-side sessions and single-use step-up possible.
- The Nonce Store is a table in the ballot database rather than a separate store, so the nonce can be consumed in the same transaction as the ballot is written.
- `AUTHORISATION_CONSUMED` is written as a NonceRecord by the Ballot service. Table 13 lists it as an AuthorisationRecord with the enrolment, but the Ballot service never knows the enrolment.
- `SERVICE_AUTHENTICATED` / `SERVICE_CERT_REFUSED` aren't logged: refused certificates fail in the TLS handshake before the application sees them.
- Count scope is the contest (election + state); there is no separate `countId`.
- Nominations are loaded from the seed data; there is no screen for entering candidates.
- If an elector's capability expires unused, a new one can't be issued (the roll records one issuance per election). Add a supervised re-issue process.
- In this setup the court key is generated locally (`keys/offline/`). In reality only the court would hold it.
