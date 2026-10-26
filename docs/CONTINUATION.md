# mano-OS continuation

Original v2.1 phases 0-7 remain active and incomplete; Phase 8 is optional.
The frozen spec is docs/spec-v2.1.md (SHA256
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace).
Repository: https://github.com/We-build-AI-Stuff/mano-os. PR #134 remains open.
Use merge commits only after every exact-head check and security gate passes.
Admin reviewer override is authorized, not failed-CI or branch-protection bypass.
Assess CodeRabbit findings on merit: fix valid findings; explain dismissed ones
on the PR. No human review notifications or proactive subagents are authorized.
Root/Linux/VM/AppArmor work runs only in disposable Debian CI, never this Mac.
No local VM/model downloads, paid-provider/key experiments or silent deletion.
Warn below 20 GiB free or above 90% disk use; stop large downloads below 10 GiB.
The agent has no /compact tool; keep this handoff current without claiming one.

## Latest accepted native baseline

Head20e4fe1a854e8b77bd0155445ae5e945ab64d096, run40223650928 ALL THREE SUCCESS:
quality121260375217, security-lab121260375376, merge-gate121265986120.
Artifact12611276738,22947547bytes,SHA256
868e40f6cc94d09be2c30c1807b40751f9b02c05a5925e20f6b3df211ecdff85.
Outputs pr134-tree-observation-security.json/.zip and acceptance log preserved.
Full independent 54 hashes/45 flags plus prior package/PAM/Stop/recovery/ELF/
staging/container/payload/read-only baseline and new tree checks PASS.
Fresh six GUI originals inspected; receipt acceptance-pr134-tree-observation/
inspection.json. Before900/after120 fully visible. Headless only, physical null.
Collector admission and actual baseline/candidate/baseline scans passed:62778 to
62821 entries,43 additions,23 modifications,0 removals. Baseline unchanged and
no unseen hardlink aliases reported. SYS_ADMIN remains trusted collector TCB;
this is not adversarial sandbox or independently acquired filesystem proof.

## Prepared follow-up: full-record database invariant

Remote348474423a99b06f2f6f1120452e19661617257b CI40257481990 is still running;
quality121362341635 passed and security121362341485 was confirmed live.
Follow-up source retains all dpkg fields and checks complete unapproved records,
not just state/version. Receipt schema unchanged for historical recovery records.
692 local tests:637passed/55skipped; lint/compilation pass. Independent historical
checks cover four native status transitions and four metadata mutation denials.
Keep this follow-up LOCAL until the existing CI is terminal; pushing cancels it.
Then accept that run for its exact remote3484744 source, not this follow-up.
Fresh subsequent CI is required for the stronger database checks.

## Current combined payload gate

package_candidate_policy.validate_payloads checks the combined authenticated
payload closure against baseline/candidate observations. Rejects collisions,
metadata/content/timestamp drift, shared directory security changes and unlisted
hardlink aliases. All unlisted changes and directory timestamp changes remain
unresolved. No path-name whitelist or generated-state/publication authority.
Integrated into CI-only probe_staged_package.py after candidate drainage.
689 local tests:634passed/55skipped; Ruff and compilation passed. Twelve new
attack regressions. Offline against accepted20e4 observations:44 distinct payload
paths validated,40 changes unresolved. Independent output helper plus seven
altered-report rejections PASS. This is not new-source native evidence.
Fresh CI must also require --staged-payload-closure, dependent on tree option,
in addition to all prior acceptance options. Do not apply new option to20e4.

## Remaining production work

Complete generated/conffile/dpkg/cache state and unlisted mutation validation,
protected trusted runtime upgrade policy, production staging guard/PAM/Stop,
coherent publication/activation with crash/ENOSPC/recovery/no replay, broader
package compatibility and full registry reprobe. Existing production package
execution still lacks full privileged-runtime closure; do not merge or claim
completion on the strength of the CI-only staging prototype. Live-provider/model
repair/coding/apps/connectors/profiles, physical input/8GB, signed OS installation/
update/recovery and all other original spec requirements remain active.

Preserve three unrelated untracked duplicates: architecture0109 document,
mano-package2.slice and probe_root_package_stop2.py. Main last verified65fdfc02.
Current source/CI status and exact commands are in outputs/CONTINUATION.md;
older evidence details remain in Git history and output continuation archives.
