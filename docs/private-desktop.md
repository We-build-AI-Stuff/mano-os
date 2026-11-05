# Private agent desktop

The `desktop.open` capability starts a task-owned Sway desktop using a private
headless Wayland output. A human approves the exact geometry, lifetime, input
budget and kernel resource budget. Workspace permission profiles do not grant
this capability. Opening does not accept an executable, environment, host display
socket, bus address or arbitrary compositor command.

The Core SDK in `mano_core.desktop` supports readiness, window inspection, opening
a terminal, focusing a session window, text input, named keys, pointer input,
workspace PNG screenshots and closing. Input uses the existing approved PTY
transport and its durable input journal. A lost or partial acknowledgement makes
the SDK refuse further desktop input; it never automatically repeats a command.
Native Stop remains independent of this SDK and kills the owned task cgroup.

Each desktop is limited to 512 MiB, 96 processes and 50 percent of one CPU, with
a maximum lifetime of 120 seconds. The approved request may lower these limits.
Only one desktop may occupy the launcher, and the existing total of two task
groups remains. Ordinary terminal ceilings remain 128 MiB, 24 processes and
20 percent CPU. The launcher parent now allows 768 MiB, 160 processes and one CPU
to accommodate one desktop, one ordinary task and its control process.

The runtime package installs the fixed worker and protocol read-only under
`/usr/lib/mano-desktop` and depends on Sway, Foot, grim and wtype. Worker startup
requires an unprivileged Linux user namespace, no capabilities, NoNewPrivileges,
seccomp and the externally owned task guard. It uses the existing task sandbox;
it adds no network, host bus, host display, device or nested namespace exception.
Every control response remains untrusted and reports `effect_verified: false`.
A screenshot checksum establishes its bytes, not whether a user goal succeeded.

## Current verification boundary

Portable tests cover request bounds, budget separation, fixed worker translation,
response identity, geometry, partial/lost input acknowledgements and refusal to
run the worker or Root coordinator on macOS. They do not prove a working GUI.

The disposable Linux CI exercise requests native PAM approval, rejects changed
arguments and wrong callers, opens a mapped Foot terminal through the production
SDK, types a workspace marker through the virtual keyboard, checks the marker
independently and exports `private-desktop.png`. It also checks the kernel limits,
the screenshot checksum, replay behavior and descendant drainage after close.
This revision is awaiting that native result. It has no accepted browser or Writer
integration, frozen-desktop Stop witness, physical input test or complete MVP
claim. Those remain part of the original version's delivery scope.


## Frozen desktop Stop exercise under development

The follow-up fixture places the private GUI in the existing public interactive
Stop slot beside the long-running ordinary task. It keeps the two-job launcher
limit intact. Through the mapped Foot terminal, virtual keyboard input starts a
forked child that becomes a new session leader. Root independently checks the
workspace PID marker, process ownership/cgroup membership and session ID.

The coordinator records the Sway, Foot and other task process IDs and freezes all
of them before freezing the broker and launcher. The real native human Stop client
must drain the task cgroups despite those freezes. New input must be denied, the
desktop action must remain unknown/unverified, and restart plus human rearm must
not resurrect its input authority. The existing standalone frozen task-PTY worker
exercise also remains. This is CI preparation, not an accepted frozen-GUI result;
physical input and concurrent human-desktop focus checks remain unproven.
