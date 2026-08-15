# Web direction

## Recognize

Strong signals include explicit SQL injection, XSS, SSRF, XXE, SSTI, path
traversal, file upload, JWT, OAuth, CORS, WebSocket, GraphQL, API authorization,
or server-side template terminology. Medium signals include a web framework,
HTML forms, cookies, sessions, routes, or a browser-facing application combined
with an input or authorization objective.

HTTP, HTTPS, HTML, login pages, and ports 80/443/8080 are access evidence only.
If the page is a chat/model application, prefer AI. If the endpoint returns EVM
JSON-RPC or is paired with Solidity/ABI/chain evidence, prefer blockchain.

## First information channels

Keep tasks independent and small:

1. Establish the HTTP baseline and technology stack.
2. Identify functional inputs, authentication, sessions, and authorization
   boundaries.
3. Inspect exposed source, static assets, API descriptions, or configuration.
4. Validate one concrete input/behavior hypothesis only after evidence selects it.

Do not combine broad path discovery, deep fingerprinting, exploit testing, and
flag extraction in one task.
