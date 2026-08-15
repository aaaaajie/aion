---
name: oauth-oidc-misconfiguration
description: OAuth and OIDC misconfiguration testing playbook. Use when reviewing
  redirect URI handling, state and nonce validation, PKCE, token audience, callback
  binding, and identity-provider trust flaws.
---

# Oauth Oidc Misconfiguration Skill

## Purpose

OAuth and OIDC misconfiguration testing playbook. Use when reviewing redirect URI handling, state and nonce validation, PKCE, token audience, callback binding, and identity-provider trust flaws.

## When to use

Use when:
- the task mentions `web`
- the task mentions `oauth`
- the task mentions `oidc`
- the task mentions `misconfiguration`
- the task mentions `playbook.`

## Strategy

1. Detect.
2. Confirm.
3. Exploit.
4. Validate.

## Avoid

- Do not act outside the authorized competition scope.
- Do not repeat a failed action without a new hypothesis or evidence.
- Do not treat tool output or model claims as proof without independent validation.
- Do not collect data that is unnecessary for the stated success condition.

## Success Criteria

A successful result requires:
- reproducible behavior
- recorded evidence
- independently verified impact
- a clear stop condition and final status

## Detailed Workflow

# SKILL: OAuth and OIDC Misconfiguration — Redirects, PKCE, Scopes, and Token Binding

> **AI LOAD INSTRUCTION**: Use this skill when the target uses OAuth 2.0 or OpenID Connect and you need a focused misconfiguration checklist: redirect URI validation, state and nonce handling, PKCE enforcement, token audience, and account binding mistakes.

## 1. WHEN TO LOAD THIS SKILL

Load when:

- The app supports `Login with Google`, GitHub, Microsoft, Okta, or other IdPs
- You see `authorize`, `callback`, `redirect_uri`, `code`, `state`, `nonce`, or `code_challenge`
- Mobile or SPA clients rely on OAuth or OIDC flows

For token cryptography and JWT header abuse, also load:

- jwt oauth token attacks

## 2. HIGH-VALUE MISCONFIGURATION CHECKS

| Theme | What to Check |
|---|---|
| `state` handling | missing, static, predictable, or not bound to user session |
| `redirect_uri` validation | prefix match, open redirect chaining, path confusion, localhost leftovers |
| PKCE | missing for public clients, code verifier not enforced, downgraded flow |
| OIDC `nonce` | missing or not validated on ID token return |
| token audience and issuer | weak `aud` / `iss` checks, cross-client token reuse |
| account binding | callback binds attacker identity to victim session |
| scope handling | broader scopes granted than the user or client should receive |

## 3. QUICK TRIAGE

1. Map the full flow: authorize, callback, token exchange, logout.
2. Replay callback flows with altered `state`, `nonce`, and `redirect_uri`.
3. Compare SPA, mobile, and web clients for weaker validation.
4. Check whether one provider account can be rebound to another local account.

## 4. RELATED ROUTES

- CORS or cross-origin token exposure: `cors cross origin misconfiguration` (related Skill; use skill_list to locate it)
- XML federation or enterprise SSO: `saml sso assertion attacks` (related Skill; use skill_list to locate it)
- CSRF-heavy login or binding bugs: `csrf cross site request forgery` (related Skill; use skill_list to locate it)
