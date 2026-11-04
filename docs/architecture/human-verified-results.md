# Human preview of verified result snapshots

The prompt can read a bounded snapshot through the existing native human socket.
Wire version 1 operation 10 contains exactly one 32-byte prompt ID. The adapter
derives the human UID from its fixed configured account and checks actual peer
credentials. It forwards only `human_task_result {human_uid,prompt_id}` to the
Root-only broker control channel. Neither a path nor an artifact/task ID is accepted
from the client. The public task channel cannot invoke this operation.

The broker resolves the current-boot prompt/task and owner, selects the latest
done/verified action and follows its first original artifact verification reference.
It requires that artifact's persisted identity, task, action, boot, size and actual
SHA-256 to match the protected journal. It returns at most 4096 bytes, with full
snapshot metadata, a preview digest and an explicit truncation flag. Capture
metadata's original `effect_verified:false` is not rewritten: the action's checked
artifact references establish why this historical snapshot is eligible for viewing.

The GUI pins the acknowledged prompt and task. Reads run off the GTK thread;
closed windows, uncertain/new submissions and changed task identity cannot accept
a late result. Content enters a noneditable TextView as literal text, with no
markup, link following, file opening or command execution. Binary content has no
text preview. Stop does not remove access to an already verified same-boot receipt,
and reading that receipt does not rearm work or revalidate later workspace bytes.

SQLite tests cover unverified/corrupt/cross-owner/cross-boot evidence, packet and
digest checks, prefix/binary handling and no state changes or retries. Disposable
Debian CI checks the native bridge and scope denials using a genuine verified
golden-project artifact. The default prompt GUI then displays a newly created
and verified artifact after separate native PAM approvals of a Supervised profile
and exact terminal effect. It retains a screenshot and original artifact identity.
Those native results are pending until the exact changed revision passes its VM
run and its artifacts are inspected. No provider call or physical-input claim is
part of this feature's evidence.
