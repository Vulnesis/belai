# vLLM broker

`belai-broker` puts an OpenAI-compatible API in front of a vLLM server. It
launches and supervises vLLM, authenticates clients with their own keys,
serves Belai's nonce endpoint and verifies sealed blocks the way the Vulnetix
AI Firewall does, and writes one analytics row per request to SQLite or
Postgres without adding latency to the request. Belai, the OpenAI SDKs and
anything else that speaks `/v1/chat/completions` connect to it unchanged.

```
client (Belai, openai SDK) --https--> belai-broker :8000 --loopback--> vllm :8001
                                          |
                                          +-- analytics writer --> SQLite / Postgres
```

## Install and run

```sh
go build -o belai-broker ./cmd/belai-broker     # or: just broker-build
belai-broker keygen                             # prints a client key and its sha256
cp cmd/belai-broker/broker.example.yaml broker.yaml
# paste the sha256 into keys[0].sha256, adjust the vllm block
belai-broker print-args -config broker.yaml     # shows the exact vllm argv
belai-broker serve -config broker.yaml
```

The example config reproduces this command:

```sh
vllm serve Qwen/Qwen3.8-27B-AWQ --quantization awq_marlin --dtype float16 \
  --gpu-memory-utilization 0.92 --max-model-len 4096 --max-num-seqs 16 \
  --enable-prefix-caching
```

with two differences: vLLM binds `127.0.0.1:8001`, not `0.0.0.0:8000`, so
the broker is the only way in, and it gets `--served-model-name` when
`served_model_name` is set.

## Endpoints

| Method and path | Auth | What it does |
| --- | --- | --- |
| `GET /healthz` | none | The broker is up. |
| `GET /readyz` | none | `200` when vLLM is ready, else `503`, with `{"state": …}`. |
| `GET /v1/nonces?count=N` | key | Belai nonce endpoint (below). Answers while vLLM is still loading. |
| `GET /v1/models` | key | Proxied. |
| `POST /v1/chat/completions` | key | Nonce gate, then proxied; streams pass through event by event. |
| `POST /v1/completions` | key | Same. |
| `POST /v1/responses` | key | Same. |
| `POST /v1/embeddings` | key | Same. |
| `GET /broker/stats` | key | Model server state, restarts, analytics written, dropped and failed. |

Any other path is `404`. A key is sent as `Authorization: Bearer <key>` or
`X-Api-Key`. The config stores only each key's SHA-256; `belai-broker
hash-key < keyfile` prints one. Errors use the OpenAI error shape, so SDKs
raise their usual exceptions. A request that arrives while vLLM is loading
waits up to `ready_wait`, then gets `503` with `Retry-After: 30`.

## Managing vLLM

The supervisor builds the argv from the config only (`vllm.Args`), runs it in
its own process group with the scrubbed environment plus the names in
`pass_env`, and gives it a fresh random key per launch through
`VLLM_API_KEY` in its environment, never in argv. `extra_args` may add any
vLLM flag except `--host`, `--port`, `--api-key`, `--model` and
`--served-model-name`, which the broker owns.

- `start: eager` launches at boot. `start: on_demand` launches on the first
  request, and with `idle_stop` stops vLLM again after that long without a
  request, which frees the GPU.
- Readiness is vLLM's `GET /health`. Startup may take `startup_timeout`
  (default 30m, for a first download). Three failed checks in a row while
  ready, or an exit, restart it with exponential backoff from
  `restart_backoff` to `max_backoff`.
- On `SIGTERM` or `SIGINT` the broker stops accepting requests, lets open
  streams finish for up to 30 s, sends `SIGTERM` to vLLM's process group,
  waits `stop_grace`, then `SIGKILL`s it, and finally flushes analytics.
- `external_url` proxies to a vLLM the broker does not start (for example one
  run by systemd or Kubernetes). `external_key_env` names the variable that
  holds its `--api-key`.

## Nonce protocol

The broker implements the issuer and gateway halves of
[nonce-endpoint-spec.md](nonce-endpoint-spec.md).

**Issuing.** `GET /v1/nonces` returns
`{"nonces": […], "count": N, "expires_at": "…", "modes": ["observe", "enforce", "canonical"]}`.
`count` is clamped to 1 to 64 and defaults to 16. A nonce is 16 random bytes,
an 8-byte expiry and a 16-byte HMAC-SHA256 tag, hex encoded. The HMAC key is
derived from the master secret and the key's name in the config, so a nonce
issued to one client never verifies for another, and replicas that share the
secret verify each other's nonces with nothing stored. The secret is
`nonce.secret_env` (hex) or `nonce.secret_file`, created with mode `0600` on
first start; a file readable by group or others is refused.

**Verifying.** Every string under `messages`, `prompt`, `input` and
`instructions` in a request body goes through `delimiters.Gateway`, which
shares Belai's own tag grammar (`internal/delimiters`). Each known-kind block
is *verified* (nonce issued to this client and unexpired, integrity hash
matches), *unknown* (no nonce, or not one of ours) or *tampered* (hash
mismatch, or a missing hash on `attachment`, `directive` or `diagnostics`).
`tools`, `response_format` and the sampling fields pass unchanged.

**Modes.** A client's `X-Vulnetix-Nonce-Mode` header picks the mode; an
unrecognised value is `observe`. Without the header, `nonce.default_mode`
applies:

| Mode | Unknown and tampered blocks | Verified blocks |
| --- | --- | --- |
| `observe` | kept | kept |
| `enforce` | stripped | kept |
| `canonical` | stripped | forwarded as `<kind integrity="H">`, nonce removed |
| `auto` (default) | kept | canonical when every block in the request verified, else kept |

`auto` exists because Belai sends the mode header only to the Vulnetix
firewall. It gives vLLM's prefix cache identical bytes for every Belai session
seeded here, which is the point of `--enable-prefix-caching`, and it never
strips anything from a client that minted its own nonces. Set
`default_mode: enforce` or `canonical` when every client fetches nonces from
the broker.

Every gated response carries
`X-Vulnetix-Firewall-Nonce: mode=…;verified=…;unknown=…;tampered=…;stripped=…`
(plus `;canonical=N` in canonical mode).

## Analytics

Each request produces one row in `broker_requests`: time, request id, client
name, route, model id, status, stream flag, total latency, time to the first
upstream byte, time spent waiting for vLLM, request and response bytes,
prompt, completion and cached tokens, nonce mode and counts, and an error
class. A row holds no prompt, completion, header value or key; the model id
and request id are reduced to identifier characters.

The handler calls `Recorder.Record` after the response is written. Record is
a non-blocking send into a buffered channel (`buffer`, default 8192); when the
channel is full the row is dropped and counted, so a slow database never
holds a request. One writer goroutine batches rows (`batch_size`, default
256, or every `flush_interval`, default 1 s) into a single transaction.
`/broker/stats` reports written, dropped and failed counts.

For streamed chat and completions requests that did not set
`stream_options`, the broker adds `"stream_options":{"include_usage":true}`
so vLLM reports token counts, and removes the usage-only chunk before it
reaches the client. Set `stream_usage: false` to forward streams untouched
(their token columns are then 0).

SQLite (pure Go, WAL mode) is the default. For a shared database:

```yaml
analytics:
  driver: postgres
  dsn_env: BELAI_BROKER_PG_DSN   # postgres://broker:…@db/analytics
```

Example query:

```sql
SELECT principal, COUNT(*), SUM(prompt_tokens), SUM(cached_tokens),
       AVG(ttfb_ms), SUM(nonce_canonical)
FROM broker_requests WHERE ts > now() - interval '1 day'
GROUP BY principal;
```

## Connecting Belai

Add a provider profile pointing at the broker, then store the key you
generated as that provider's credential:

```json
{
  "providers": {
    "vllm-broker": {
      "base_url": "https://broker.example.internal:8000/v1",
      "api": "openai-chat",
      "auth": "bearer",
      "kind": "openai-compatible"
    }
  },
  "provider_labels": { "vllm-broker": "Qwen on vLLM" }
}
```

```sh
belai -provider vllm-broker -model qwen3.8-27b
```

With no firewall in front, Belai asks the provider's own base URL for nonces
with its Bearer key (`agent.nonceEndpoints`), so its pool is seeded by the
broker and the default `auto` mode canonicalises its blocks. Belai caches a
`401` from the nonce endpoint as unsupported for 7 days, so fix a wrong key
and clear `~/.vulnetix/belai/cache/nonce-unsupported.json`, or the session
mints locally and its blocks are only observed.

## Other clients

```python
from openai import OpenAI
client = OpenAI(base_url="https://broker.example.internal:8000/v1", api_key="sk-belai-…")
client.chat.completions.create(model="qwen3.8-27b", messages=[{"role": "user", "content": "hi"}])
```

## Testing

`go test -race ./internal/broker/... ./cmd/belai-broker/` covers the
gateway rules, the issuer, the recorder (including that a stuck database
never blocks `Record`), the proxy with streaming, and the supervisor
launching, health-checking and stopping a real child process
(`internal/broker/fakevllm` turns the test binary into a fake vLLM).
