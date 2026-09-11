# Validate an evidenced FastCGI interaction

Read this only when current authorized service evidence suggests FastCGI and the
next question requires distinguishing transport, protocol and application behavior.

Retrieve `tool_search(name="system_fastcgi_request")`, then call the exposed native
`system_fastcgi_request` function with its exact schema. Derive host, port and server-side path from current evidence. Do not copy
historical defaults, invent paths, add configuration overrides or write another client.
If the necessary parameter is unknown, record that missing prerequisite first.

Interpret the existing tool's response in separate layers:

- bytes_received/raw_response describe actual socket reads, including framing and
  incomplete records. Local diagnostic strings are not server bytes. Do not add
  raw and parsed lengths together; they describe the same response.
- stdout/stderr contain parsed stream data; partial raw bytes do not establish a
  valid complete record. Inspect the available raw evidence before blaming the app.
- transport describes connect/send/receive termination. Timeout, EOF, reset and
  local_stop are not application rejection; local_stop is a client-side stop.
- app_status/protocol_status are not HTTP status codes. Inspect application output
  separately. A complete protocol response or ok=true alone is not business success.
- Incomplete responses with outcome_unknown do not prove the operation never ran.
  Do not replay an operation merely to recover output or assume it had no effect.

Validate a minimal known control if one is available. After readiness or client
conditions change, recheck only the affected premise. Preserve exact response/read
refs, tested conditions and uncertainty. Stop when the layer/question is identified
or a prerequisite/control is unavailable; do not turn zero bytes or failed parsing
into a global negative conclusion.
