# mano-OS current continuation

## Scope and rules
Original v2.1 phases0–7 remain ACTIVE/incomplete; Phase8optional. The frozen spec
is docs/spec-v2.1.md, SHA256
6d320e79ad62a44afea04fcf305432ec56dcdc5061e6cfcef55d113b7101eace.
Repository: https://github.com/We-build-AI-Stuff/mano-os.
PR134 is the only open PR, ready/isDraft=false, attached to this chat.
PR122/124/123 already merged; main65fdfc02e3dbb18f791a92374a24690ae4e1ba87.
Use merge commits. Admin reviewer override is authorized; never bypass CI,
security evidence or branch protection. Do not notify reviewers or other chats.
No proactive subagents. Native/Root/VM/AppArmor execution ONLY in disposable Debian
CI, never this Mac. No paid providers, key/auth experiments, local VM/model
images or silent deletion. Warn below20GiB or above90percent disk; stop new large
downloads below10GiB. Last disk about19GiB/91percent, warned.
The /compact agent tool is unavailable; this handoff is condensed instead.
Prior detail is retained in Git history and workspace output archives.

## Current source and running CI
Pushed headfc9e01da051e529c3ab9de7eb83bcbc09d59b5a6, CI40162914482:
quality SUCCESS, security-lab IN_PROGRESS at last check. Poll SAME run; do not
restart on observation timeout. The workflow cancels older runs on a new push,
so let this run become terminal before pushing the prepared commits.
Local4638073 adds direct ELF search candidates;38575d3 adds fixed ELF name rules.
Both are unpushed and native-unverified. The full local suite on prepared code
passed584tests/48Linux-only skips, plus Ruff/compileall/all-shell/diff checks.
No native tests ran locally. Preserve the unrelated untracked duplicates:
- docs/architecture/0109-privileged-package-stop-domain 2.md
- packaging/systemd/mano-package 2.slice
- scripts/probe_root_package_stop 2.py

fc9 corrects a pre-effect IPC probe failure from483c04c CI40162256102. Python's
socket timeout wrapper waited for readiness before the negative accept syscall.
Negative operations now stay blocking; only positive pair traffic uses a timeout.
Nine IPC regressions pass. Strict EPERM and native filters were not relaxed.
Current worker denies named socket/connect/bind/listen/accept/accept4; only AF_UNIX
protocol0 stream socketpairs are allowed. It rejects inherited socketfds and
requires exact bidirectional bytes. Native APT/dpkg compatibility awaits fc9 CI.

## Last accepted evidence
Head6d308fa4b10bed265262f3a8c06708f66fd83ab7, CI40160330966 ALL3SUCCESS.
Artifact12586393657,13343314bytes, SHA256
dd8cbf51100544e337740f1b3ef5cd90453221b500347c3296241f81dc79e1cf.
outputs/pr134-helper-policy-security.json/.zip independently passed54hashes and
45flags plus real/installed worker policy label,17helper/keyring name denials,
signed payload/full database plans, actual dpkg Stop, separate Broker death,
successful-COMMIT reply loss, normal installed PAM/cancel, recovery/removal domain.
Six fresh originals and four numeric crops ACTUALLY viewed and hash-preserved in
outputs/acceptance-pr134-helper-policy/inspection.json. Pending/effective900
before and120after are fully visible: the headless display correction is observed.
Accessible text buffers were unavailable; no GTK root-cause or physical proof.
The kernel policy remains after removal once the managed Root domain drains.
Do not claim full kernel cleanup or complete trusted runtime closure.

Failed483c04c artifact12586903178,1908600bytes, SHA256
c37c6b67a7963f2f2d8ef56e732605af9b682c107326e89a3d90781c5d352af5,
is byte-verified in outputs/pr134-483c04c-native-failure.zip. ONLY its static ELF
inventory component passed independent inspection:22roots/49extensions/124files,
with libsystemd-shared-257.so missing from cache candidates. Three systemd tools
record a private RUNPATH; the target is observed in outside init maps, not proven
as those helpers' actual resolution. See pr134-483c04c-elf-inspection.json and
pr134-483c04c-elf-runpath-gap.json. Raw failed log is preserved; gh job-log API
needs --allow-escape-sequences. This is not full CI or package acceptance.

## Prepared changes needing fresh CI
Direct-search collector follows own absolute RPATH/RUNPATH and canonical-object
ORIGIN candidates; RUNPATH takes precedence. Empty/relative/unknown tokens remain
explicitly unsupported. Inherited RPATH, hwcaps, actual loader selection, plugin
closure and write protection stay unverified. All observed candidates join the
bounded graph. Cache-only unresolved names remain distinct from combined missing
names. Twelve parser/search tests pass. No target execution to infer dependencies;
the fixed readelf and ldconfig-p tools do execute.

The profile protects52observed SONAME families plus the private systemd-shared
family, including future suffixes under lib/lib64 trees. Architecture/systemd/
lib64 directory anchors are included. Current prepared profile SHA256:
cc0aa58e44abf1f9124d129135d7ecd3de700fe7d4573ce161e3741bc3e525d0.
The ownership/content binding tests pass. A private namespace uses54dummy library
name files plus one absent future name, requiring55write denials and four alias/
metadata denials. Real shared libraries remain RO; no real library writes occur.
These filename rules do not prove all inode aliases, loader-cache/plugin coverage
or protected-runtime upgrade compatibility. The preload-name rule and its three
private synthetic/etc probes from fc9 also need successful native acceptance.

## Independent acceptance
Run outputs/accept_ci_artifact.py FROM THE REPO cwd, with45positional flags from
outputs/package-archives-acceptance-flags.json and all prior package/runtime/UI/
recovery/Stop/archive/postcondition options. OMIT obsolete --dirty-root-recovery.
Always verify completed exact-head ALL3SUCCESS and fresh server artifact digest;
reuse a verified ZIP with --cached-artifact and the same report basename.
outputs/download_ci_artifact.py is a read-only digest-verifying downloader; it
does not accept or merge. Store raw evidence, inspect all six fresh GUI originals
and four crops, and preserve a hash receipt. Headless evidence is not physical.

For currentfc9 full acceptance add exactly:
--package-ipc --package-elf-inventory --package-preload-policy.
For the next prepared head add ALSO:
--package-elf-direct-search --package-elf-name-policy.
Do not use the last two on fc9 or older reports. The independent helpers require
three IPC flags, direct graph/tag checks, exact-head AST-literal ELF_LEAVES53safe
names and55errnos/four alias denials, separate policy SHA, and actual package/
installed-PAM evidence. Inventory source_revision is the actual PR merge-checkout
revision matching runtime build/artifact name; outer run metadata binds PR head.

## Remaining gates
No merge eligibility yet. Complete shared ELF/library/loader-cache/persistence
closure, broader upgrade/remove/predepends/conffile/ENOSPC/adversarial compatibility
and full tool-registry reprobe remain required. Catalog refresh is not that registry.
Live-provider/model repair/authenticated coding, other v2.1 GUI/app/connector and
profile work, physical input/8GB tests, signed bootable OS/install/update/recovery
release gates remain incomplete. Continue the original scope; do not replace
completion with a narrow synthetic, local-green, CI-green or prototype claim.
