# for downlaoding all the dependencioes
```bash
cd frontend
npm install
cp .env.example .env
npm run dev
```

Open <http://localhost:5173>.

The default configuration uses mock API responses so the interface can be
developed before the backend services are connected. Set
`VITE_USE_MOCK_API=false` when the API is available through the configured
`VITE_API_BASE_URL`.

## Build check

```bash
npm run build
```

## Current routes

- `/` - prototype overview
- `/voter/ballot` - voter ballot flow (GR01 and GR02)
- `/official` - official operations console
- `/official/recount` - scope-limited recount workflow (GR03)
- `/audit` - tamper-evident audit events (GR05)

The frontend does not enforce authorisation. It presents backend decisions and
handles loading, validation, conflict, rate-limit and unavailable states as the
API contract is integrated.
