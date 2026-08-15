---
name: ghost-bits-cast-attack
description: Java "Ghost Bits" / Cast Attack playbook (Black Hat Asia 2026). Use when
  attacking Java services where 16-bit char is silently narrowed to 8-bit byte to
  bypass WAF/IDS for SQL injection, deserialization RCE, file upload (Webshell), path
  traversal, CRLF injection, request smuggling, and SMTP injection. Affects Tomcat,
  Spring, Jetty, Undertow, Vert.x, Jackson, Fastjson, Apache Commons BCEL, Apache
  HttpClient, Angus Mail, JDK HttpServer, Lettuce, Jodd, XMLWriter and re-enables
  many "patched" CVEs through WAF bypass.
---

# Ghost Bits Cast Attack Skill

## Purpose

Java "Ghost Bits" / Cast Attack playbook (Black Hat Asia 2026). Use when attacking Java services where 16-bit char is silently narrowed to 8-bit byte to bypass WAF/IDS for SQL injection, deserialization RCE, file upload (Webshell), path traversal, CRLF injection, request smuggling, and SMTP injection. Affects Tomcat, Spring, Jetty, Undertow, Vert.x, Jackson, Fastjson, Apache Commons BCEL, Apache HttpClient, Angus Mail, JDK HttpServer, Lettuce, Jodd, XMLWriter and re-enables many "patched" CVEs through WAF bypass.

## When to use

Use when:
- the task mentions `web`
- the task mentions `ghost`
- the task mentions `bits`
- the task mentions `cast`
- the task mentions `attack`

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

Read `references/detailed-workflow.md` only after the Skill is selected and the current evidence matches this vulnerability family. Read only the relevant section; keep the current atomic task, tool budget, evidence target, and stop condition unchanged.
