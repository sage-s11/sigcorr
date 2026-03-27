# nfault

**Structured network error classification for Node.js.**

Every networking library surfaces raw OS error codes when a connection fails. You get `ECONNREFUSED`, `ETIMEDOUT`, or `certificate has expired` — without layer classification, cause analysis, retryability guidance, or escalation signals. The result is fragile string-matching, inconsistent retry logic, and delayed alerting.

`nfault` converts any raw network error into a structured, typed object with actionable fields.

```
╔══ NetworkError ────────────────────────────────────────────────
  code              tls/cert_expired
  layer             TLS
  fault             remote
  causeConfidence   ● high

  safeRetryable     false
  safeMaxRetries    0
  escalateAfter     true

  host              api.payments.internal:443

  hint              TLS certificate has expired. Ops must renew immediately.
                    Add expiry monitoring at 30/14/7 days.

  ── Possible causes ──────────────────────────────────────────
  1. cert_not_renewed  ✕
     Certificate not renewed before expiry
     → Alert ops and security team immediately.

  2. autorenewal_failed  ✕
     Auto-renewal job (certbot/ACME) failed silently
     → Check auto-renewal logs. Manual renewal required.

  3. clock_skew  ✕
     Client/server clocks out of sync (NTP failure)
     → Check system time against NTP.
╚════════════════════════════════════════════════════════════════
```

## Key design insight

> **Transience is a property of the *cause*, not the symptom.**
> The same `dns/timeout` has causes that are fully self-healing, partially self-healing, or permanently broken. A single `transient: boolean` collapses this distinction and leads to infinite retries on non-recoverable failures. `nfault` exposes possible causes with per-cause retryability flags.

## Install

```bash
npm install nfault
```

## Usage

### Core — works with any error

```ts
import { classify } from 'nfault';

try {
  await fetch('https://api.example.com/data');
} catch (err) {
  const e = classify(err as Error, { host: 'api.example.com', method: 'GET' });

  console.log(e.code);           // 'tls/cert_expired'
  console.log(e.safeRetryable);  // false
  console.log(e.hint);
  console.log(e.escalateAfter);  // true

  if (e.isSecurityEvent) alertSecurityTeam(e);
  if (e.escalateAfter)   pagerduty.trigger(e);
}
```

### With axios

```ts
import axios from 'axios';
import { createAxiosInterceptor, formatSummary } from 'nfault';

const client = axios.create({ baseURL: 'https://api.example.com' });

client.interceptors.response.use(null, createAxiosInterceptor({
  onError: (e) => {
    logger.error(formatSummary(e));
    if (e.escalateAfter)   pagerduty.trigger(e);
    if (e.isSecurityEvent) securityChannel.alert(e);
  }
}));
```

### With fetch

```ts
import { fetchWithClassification } from 'nfault';

try {
  const res = await fetchWithClassification('https://api.example.com', {
    method: 'POST'
  });
} catch (e) {
  console.log(e.requiresIdempotencyCheck); // true — don't auto-retry POST
  console.log(e.code);                     // 'tcp/reset'
}
```

### With Winston / Pino

```ts
import winston from 'winston';
import { classify, createWinstonErrorHandler } from 'nfault';

const logger = winston.createLogger({
  transports: [new winston.transports.Console()],
  format: winston.format.json(),
});

const handleError = createWinstonErrorHandler(logger, {
  onSecurityEvent: (e) => securityChannel.alert(e),
  onEscalate:      (e) => pagerduty.trigger(e),
});

try {
  await fetch('https://api.example.com');
} catch (err) {
  const e = classify(err as Error, { host: 'api.example.com' });
  handleError(e);
}
```

### With native node:http / node:https

```ts
import { requestWithClassification } from 'nfault';

try {
  const { body } = await requestWithClassification('https://api.example.com/data');
} catch (e) {
  console.log(e.code, e.hint);
}
```

### DNS rolling-window detector

```ts
import { classify, DnsFailureDetector } from 'nfault';

const detector = new DnsFailureDetector({ windowMs: 60000, minDistinctHosts: 3 });

const e = classify(err, { host });
const result = detector.record(e);
// If 3+ distinct hosts fail within 60s:
// result.causeConfidence → 'high'
// result.possibleCauses[0].id → 'resolver_unreachable'
// result.safeRetryable → false
```

## CLI

```bash
npx nfault diagnose api.example.com
npx nfault diagnose api.example.com 5432
npx nfault diagnose api.example.com --tls
npx nfault diagnose api.example.com --dns
npx nfault diagnose api.example.com --tls --watch
npx nfault diagnose api.example.com --tls --watch --interval 30
npx nfault explain tls/cert_expired
npx nfault list
npx nfault check api.example.com
```

## Output modes

```ts
import { formatNetworkError, formatSummary, formatCompact } from 'nfault';

// Full verbose — CLI / debugging only
console.log(formatNetworkError(e));

// Single line — safe for production logs, won't flood
console.log(formatSummary(e));
// → [nfault] tls/cert_expired | conf:high | fault:remote | retry:no | ↑escalate | api.example.com

// JSON — for Datadog, Splunk, ELK pipelines
console.log(formatCompact(e));
// → {"code":"tls/cert_expired","layer":"tls","fault":"remote",...}
```

## NetworkError schema

| Field | Description | Example |
|---|---|---|
| `.code` | Namespaced error identifier | `"tls/cert_expired"` |
| `.layer` | Stack layer where failure occurred | `"dns" \| "tcp" \| "tls" \| "http"` |
| `.causeConfidence` | How certain we are about root cause | `"high" \| "medium" \| "low"` |
| `.possibleCauses[]` | Ordered causes with per-cause retryability | `[{ id, retryable, delay, action }]` |
| `.fault` | Who is responsible | `"remote" \| "network" \| "config" \| "client"` |
| `.safeRetryable` | Conservative retry flag | `true \| false` |
| `.safeMaxRetries` | Max retries before mandatory escalation | `0 \| 1 \| 2 \| 3` |
| `.safeDelay` | Suggested backoff in ms | `1000 \| 5000 \| null` |
| `.escalateAfter` | Alert ops if retries exhausted? | `true \| false` |
| `.isSecurityEvent` | Route to security team, not ops queue | `true \| false` |
| `.requiresIdempotencyCheck` | Non-idempotent request — caller decides retry | `true \| false` |
| `.hint` | Human-readable remediation hint | `"Check /etc/resolv.conf..."` |

## Error coverage — v1.0

| Code | Layer | Confidence | Notes |
|---|---|---|---|
| `dns/timeout` | DNS | low → high* | *upgrades via rolling-window detector |
| `dns/nxdomain` | DNS | high | |
| `dns/servfail` | DNS | medium | |
| `dns/refused` | DNS | high | |
| `tcp/refused` | TCP | medium | |
| `tcp/timeout` | TCP | low | |
| `tcp/reset` | TCP | medium | |
| `tls/cert_expired` | TLS | high | |
| `tls/handshake_failed` | TLS | high | |
| `tls/hostname_mismatch` | TLS | high | `isSecurityEvent: true` |
| `tls/untrusted_cert` | TLS | medium | |
| `tls/cert_revoked` | TLS | high | `isSecurityEvent: true` |
| `http/rate_limited` | HTTP | high | Parses `Retry-After` header |
| `http/auth_failure` | HTTP | medium | 401 retryable, 403 not |
| `http/request_timeout` | HTTP | medium | 408 + 504 |
| `http/server_error` | HTTP | medium | 500 + 502 + 503 |
| `http/not_found` | HTTP | high | |

## Security event routing

`isSecurityEvent: true` is set on errors that should go to a security channel, not the ops queue:

- `tls/cert_revoked` — certificate explicitly revoked by CA
- `tls/hostname_mismatch` — could indicate man-in-the-middle

## Non-idempotent request protection

For POST, PUT, PATCH, DELETE, `nfault` sets `requiresIdempotencyCheck: true` even when the transport error would normally be retryable. A lost TCP connection mid-POST could mean the request was processed or not — retrying could cause duplicate charges or double writes. The library surfaces this flag and leaves the retry decision to the application layer.

## Research basis

The taxonomy behind this library is grounded in research on DNS-over-QUIC downgrade attacks and protocol fallback behavior (Computers & Security, Elsevier, 2026). The cause-confidence model and per-cause retryability flags emerged from classifying real attack-induced error surfaces across five DNS client implementations.

## Roadmap

- **v1.1** — Python port (`pip install nfault`)
- **v1.2** — QUIC/HTTP3 error classification (DoQ error taxonomy from research)
- **v1.3** — gRPC status codes, WebSocket close codes

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md). New error types must be proposed in the taxonomy spec first — see [docs/taxonomy.md](./docs/taxonomy.md).

## License

MIT
