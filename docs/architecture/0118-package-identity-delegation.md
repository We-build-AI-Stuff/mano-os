# ADR 0118: package task capability ceiling and complete UID delegation

Status: local integrated candidate, not yet native validated. Accepted native 38
used production 43; the pending guard 11 change requires fresh exact-head
native CI. This does not complete the privileged runtime, mutation-policy, activation or release gates.

The package task is authorized the six fixed dpkg capabilities, mask 0xdb:
CHOWN, DAC_OVERRIDE, FOWNER, FSETID, SETUID and SETGID. The namespace, AppArmor,
read-only runtime, syscall, IPC and native Stop boundaries restrict those powers.
Untrusted members of the same package transaction are not mutually isolated by
changing only an effective UID. A separate operation needs its own authority.

Accepted head 0e34f31 / run 41571884425 / artifact 13203340350 exercises all five fixed
pre-exec transition cases in both experimental profiles. Complete UID 6/6/6 drops
have E/P/Amb 0 and cannot re-enable capabilities or restore Root. Saved UID 0 retains
permitted/ambient 0xdb and passes those ambient capabilities through exec in both
43 and 11. Profile 11 also permits deliberate permitted-capability retention during
a complete UID change; re-enabling uses only existing bits, and exec clears E/P/Amb
when ambient was cleared. Attempts to acquire SYS_ADMIN or reset securebits fail.
The failed108986d run and the exact saved-Root regression remain preserved.

Candidate decision: use fixed securebits 11, NOROOT|NOROOT_LOCKED|
NO_SETUID_FIXUP_LOCKED. UID 0 exec restoration remains disabled and locked; normal
UID fixups remain enabled and locked. KEEP_CAPS remains mutable so baseline
setpriv can request its normal temporary retention. SETPCAP, SYS_ADMIN and
NET_ADMIN remain absent from all five post-guard sets and the bounding set.
No new capability, namespace, socket, filesystem, device or command grant is added.
This changes retention semantics; it is not bit-for-bit equivalence with 43.

The invariant is a task-wide ceiling. Initially P/E/I/B/A all equal 0xdb. capset,
ambient operations and exec cannot introduce a bit outside that ceiling; NNP,
NOROOT and the missing SETPCAP prevent setup-privilege recovery. A task already
holding SETUID/SETGID can deliberately preserve saved identities or an authorized
Root parent, so the old KEEP lock alone was not a hostile-child isolation boundary.
Filesystem/runtime integrity and effect policy remain separate mandatory gates.

Every candidate production boundary must additionally execute a fixed, bounded
setpriv delegation before APT effects. The immutable helper verifies the actual
non-Root man account, all real/effective/saved IDs, expected non-Root groups,
E/P/Amb 0, bounded I/B, securebits 11, NNP, seccomp, inherited AppArmor and identical
private namespaces. It must reject Root restoration, an outside capability and
securebits reset, then observe unchanged child state. The Root parent must retain
its own state. The Root controller independently validates the nested witness;
worker success text alone is insufficient. No model-selected argv or environment.

Acceptance requires fresh native compiled-guard/Python-boundary/PAM/Stop/packaged
workflows and independent receipts, preserving all previous gates. Existing 43
and 11 experimental controls stay; the negative 43 helper conflict must not be
skipped. Current CI 38 remains tied to its original guard 43 commit. Local Python
fixtures are not native acceptance. Resource ceilings and approved deadlines stay
unchanged; preflight overhead must be recorded, and peak memory remains unmeasured
until an actual measurement exists.

Rollback restores guard 43 and matching Python/receipt contracts through a tested
PR; the delegation check must fail closed if the expected profile is unavailable.
No fallback, automatic retry, protected-path relaxation or replay is introduced.
