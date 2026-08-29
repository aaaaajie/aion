# Golden case: object-scope differential

Fixture: two authorized test roles can use the same application, and one object
identifier is visible in a normal request. The test environment provides a
control object for each role.

Expected path:

1. Activate `execution/src-auth-business-logic`.
2. Write the actor/role/object/state matrix before making an altered request.
3. Capture the normal request, replace exactly one object identifier, and keep
   the session and other fields constant.
4. Compare status, response body, side effect, and server-side audit evidence.
5. Submit one `execution_report` with the request sequence, impact object,
   differential result, and false-positive exclusion; use `inconclusive` when the
   response difference is not an authorization or business effect.

Acceptance: no candidate is submitted from a client-side flag or status-code
change alone.
