# AI Application and Product Security Program

This directory turns the 2026+ roadmap into small, reviewable engagements.
Each engagement must produce a control, test, configuration, or runbook.

## Current engagement

`ENG-0001` establishes the Phase 0 safety boundary. GitHub issue
[#15](https://github.com/amaw535353-ai/piloteproject/issues/15) tracks the work.

### What

Create and validate the authorization and scope record for this Onyx fork.

### Where

- Record: `engagements/ENG-0001/authorization-scope.json`
- Validator: `../../scripts/security/validate_scope.py`
- Tests: `../../scripts/security/test_validate_scope.py`
- Target: a local clone at commit `1d86f5f8f94af7845bffbee61460665838ecc905`

### Why

The record prevents testing from moving to public systems, real data, or paid
services. The validator fails closed when a required safety rule is missing.

### When

Run the validator before every test session. Run it again after each scope
change and before release approval.

### How

From the repository root, run:

```bash
python scripts/security/validate_scope.py \
  docs/security-program/engagements/ENG-0001/authorization-scope.json
python -m unittest scripts/security/test_validate_scope.py
```

The first command loads one JSON record and checks its safety controls. The
second command runs positive and negative tests without network access.

### Who

Ahmed, GitHub user `amaw535353-ai`, owns, performs, reviews, and approves this
self-study engagement. AI assistance can draft and review work. Ahmed makes
scope, safety, evidence, and risk decisions.

## Prerequisites

- Python 3.11 or newer
- A local clone of this repository
- No real data, credentials, accounts, or production backups
- Local mock LLM and MCP services when later tests need them

## Safety boundary

Only loopback endpoints and local containers are in scope. The record blocks
public targets, third-party services, external APIs, and billable resources.
Stop when the next action is uncertain or any stop condition occurs.

## Prediction

The committed record will pass. A record with an external endpoint, missing
control, real-data permission, or unbounded limit will fail.

## Expected result

The validator prints `scope validation passed` and exits with status `0`.
The test runner reports four passing tests.

## Actual result

At `2026-09-13T09:44:03Z`, the validator passed and all four tests passed.
The pull request records the commands and tested base commit. Do not add
unsanitized runtime logs to this public repository.

## Security interpretation

A pass means the record contains the minimum Phase 0 controls. It does not
prove that the application is secure or that runtime network isolation exists.

## Troubleshooting

Read each reported field path. Correct the record only after Ahmed confirms the
new value is authorized. Do not weaken the validator to make a record pass.

## Rollback

Close the pull request or revert its commit. No application or database state
changes in this engagement.

## Completion criteria

- The scope record is approved and pinned to one commit.
- The validator and all tests pass locally.
- The pull request links issue #15 and contains sanitized evidence.
- Ahmed confirms the boundary before Phase 1 starts.

## Learning score

This step is not scored until Ahmed explains the boundary and interprets one
rejected unsafe record in his own words.
