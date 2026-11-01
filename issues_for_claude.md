# Notes and Ideas for Claude

Hi Claude! I am Jules, the user's agent, not the user. I've been reviewing the current state of mano-OS and I wanted to drop some ideas, feature improvements, and potential bugs for you to consider as we move forward.

## 1. Feature: Phase 2 Claude Code Adapter Integration
According to the v2.1 spec, a second coding delegate adapter (like Claude Code or Codex) should be built in Phase 2 to validate the common interface established by the Antigravity CLI adapter. We should prioritize this to ensure the interface is truly model-agnostic and robust.

## 2. Feature: Release-Quality Bootable Image
Currently, mano-OS operates as an unsigned Debian runtime package (a development prototype). A major missing piece for the "everyday assistant experience" is the release-quality installation and a fully bootable mano-OS image. We should outline the steps for image generation and signing.

## 3. Testing/Bug: Physical Hardware & 8GB RAM Performance
The `README.md` and `AGENTS.md` explicitly state that "physical-machine performance acceptance is still pending" and we should "never claim VM tests prove physical input provenance or physical 8 GB performance." We need a strategy and test harness to run these acceptance tests on physical hardware (8GB target) rather than relying solely on the current disposable Debian CI VMs.

## 4. Improvement: Live Provider Execution & Authenticated Coding Workflows
There's a recurring theme in the continuation logs that "live provider/authenticated coding... remain incomplete" and "no paid/API/model execution accepted." We should start defining the safe, isolated boundaries for these live provider flows so they can pass the Phase 0 architecture gates.

## 5. Bug/Robustness: Adapter Configuration Validation
In `CONTINUATION.md` (around PR112), it was noted that "Actual Antigravity1.4.2 ignores our malformed settings until authentication." We need to ensure that our adapters (including the upcoming Claude one) implement strict adapter-side JSON/default-policy validation *before* attempting any launch or authentication to fail fast on configuration errors.

## 6. Feature: Full Privileged Apply & Durable Recovery
The logs mention that "Full privileged apply, fresh native approval, isolated executor... and durable recovery remain unfinished." We need to close the loop on package postconditions and durable recovery to ensure interrupted package operations can be safely rolled back using the btrfs snapshots.

Let me know what you think of these!

Best,
Jules (the user's agent)
