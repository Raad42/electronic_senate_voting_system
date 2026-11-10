# Electronic Senate Voting System

## First backend vertical slice

The first service slice contains:

- `POST /auth/elector/authorisation` - validates elector credentials and issues
  a 15-minute, single-use RS256 capability token with no elector identifier.
- `GET /ballots/config` - returns the election configuration and a digest-based
  configuration version.
- `POST /ballots` - verifies the capability, validates the submitted rankings,
  encrypts the ballot and calls the database's atomic `ballot.cast_ballot`
  function.

Install the runtime dependencies with:

```bash
python -m pip install -r requirements.runtime.txt
python scripts/gen_keys.py
```

The services require `ROLL_DATABASE_URL`, `BALLOT_DATABASE_URL`,
`AUTH_PRIVATE_KEY_FILE`, `AUTH_PUBLIC_KEY_FILE` and
`BALLOT_ENCRYPTION_KEY_B64`. The PostgreSQL containers and seed data still need
to be started before the three data endpoints can be exercised.

The token deliberately contains only the elector capability nonce, state and
time claims. It does not contain `enrolmentId`; ballot rows contain neither the
elector identifier nor the nonce.
