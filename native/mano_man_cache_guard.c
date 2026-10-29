/* Fixed unprivileged disposable-CI cache reader. Never a Root executor. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/landlock.h>
#include <sched.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#define CONTROL "/run/man-cache-control"
#define SELF "/run/man-cache-guard"
#define EXEC_PROBE "/tmp/.mano-man-exec-probe"
#define WRITE_PROBE "/var/cache/man/.mano-man-write-probe"

static void fail(const char *operation) {
    perror(operation);
    exit(125);
}

static void identity(void) {
    uid_t r, e, s;
    gid_t gr, ge, gs;
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0 };
    struct __user_cap_data_struct data[2] = {{0}};
    if (getresuid(&r, &e, &s) || getresgid(&gr, &ge, &gs) ||
        r != 6 || e != 6 || s != 6 || gr != 12 || ge != 12 || gs != 12 ||
        getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
        syscall(SYS_capget, &header, data)) {
        errno = EPERM; fail("man guard identity");
    }
    for (int n = 0; n < 2; ++n)
        if (data[n].effective || data[n].permitted || data[n].inheritable) {
            errno = EPERM; fail("man guard capability sets");
        }
    for (int cap = 0; cap < 64; ++cap) {
        errno = 0;
        int bounded = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (bounded != 0 && !(bounded == -1 && errno == EINVAL))
            { errno = EPERM; fail("man guard bounding set"); }
        errno = 0;
        int ambient = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
        if (ambient != 0 && !(ambient == -1 && errno == EINVAL))
            { errno = EPERM; fail("man guard ambient set"); }
    }
}

static void rule(int ruleset, const char *path, uint64_t access, int directory) {
    int fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC | (directory ? O_DIRECTORY : 0));
    struct stat info;
    if (fd < 0 || fstat(fd, &info) || (directory ? !S_ISDIR(info.st_mode) :
            (strncmp(path, "/dev/", 5) ? !S_ISREG(info.st_mode) : !S_ISCHR(info.st_mode))))
        fail("man guard fixed rule path");
    struct landlock_path_beneath_attr value = { .allowed_access = access, .parent_fd = fd };
    if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &value, 0))
        fail("man guard Landlock path rule");
    close(fd);
}

static int restrict_files(int role) {
    int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 5) { errno = ENOTSUP; fail("man guard requires Landlock ABI 5"); }
    uint64_t read = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    uint64_t execute = read | LANDLOCK_ACCESS_FS_EXECUTE;
    uint64_t writable = read | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_DIR | LANDLOCK_ACCESS_FS_MAKE_REG |
        LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE;
    struct landlock_ruleset_attr attr = {
        .handled_access_fs = writable | LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_MAKE_SOCK |
            LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
            LANDLOCK_ACCESS_FS_IOCTL_DEV,
        .handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    };
    int fd = syscall(SYS_landlock_create_ruleset, &attr, sizeof(attr), 0);
    if (fd < 0) fail("man guard Landlock ruleset");
    rule(fd, "/usr/bin", execute, 1);
    rule(fd, "/usr/lib", execute, 1);
    rule(fd, "/usr/share/locale", read, 1);
    rule(fd, "/usr/share/man", read, 1);
    rule(fd, "/var/cache/man", writable, 1);
    rule(fd, "/tmp", writable, 1); /* Deliberately excludes execute. */
    const char *files[] = { "/etc/manpath.config", "/etc/ld.so.cache", "/etc/nsswitch.conf",
        "/etc/passwd", "/etc/group", "/etc/locale.alias", "/dev/random", "/dev/urandom" };
    for (size_t n = 0; n < sizeof(files)/sizeof(files[0]); ++n)
        rule(fd, files[n], LANDLOCK_ACCESS_FS_READ_FILE, 0);
    rule(fd, "/dev/null", LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE, 0);
    rule(fd, SELF, LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_EXECUTE, 0);
    if (role == 1) {
        rule(fd, "/run/man-source-reader.py", LANDLOCK_ACCESS_FS_READ_FILE, 0);
        rule(fd, "/run/man-source-paths.json", LANDLOCK_ACCESS_FS_READ_FILE, 0);
    }
    if (role == 2) {
        rule(fd, "/run/man-source-content.py", LANDLOCK_ACCESS_FS_READ_FILE, 0);
        rule(fd, "/run/man-source-paths.json", LANDLOCK_ACCESS_FS_READ_FILE, 0);
        rule(fd, "/run/man-source-capture.txt", LANDLOCK_ACCESS_FS_READ_FILE, 0);
        rule(fd, "/run/man-source-support", LANDLOCK_ACCESS_FS_READ_DIR, 1);
        rule(fd, "/run/man-source-support/source_bytes.py", LANDLOCK_ACCESS_FS_READ_FILE, 0);
        rule(fd, "/run/man-source-support/gzip_frame.py", LANDLOCK_ACCESS_FS_READ_FILE, 0);
    }
    if (syscall(SYS_landlock_restrict_self, fd, 0)) fail("man guard Landlock enforcement");
    close(fd);
    return abi;
}

static void restrict_syscalls(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx || seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) < 0 ||
        seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1) < 0) fail("man guard seccomp context");
    const char *denied[] = { "ptrace", "process_vm_readv", "process_vm_writev", "bpf",
        "perf_event_open", "keyctl", "add_key", "request_key", "io_uring_setup", "io_uring_enter",
        "io_uring_register", "mount", "umount2", "pivot_root", "open_tree", "move_mount",
        "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr", "setns", "unshare",
        "open_by_handle_at", "name_to_handle_at", "init_module", "finit_module", "delete_module",
        "kexec_load", "kexec_file_load", "reboot", "swapon", "swapoff", "acct", "mknod", "mknodat",
        "setuid", "setgid", "setreuid", "setregid", "setresuid", "setresgid", "setgroups",
        "setfsuid", "setfsgid", "capset" };
    for (size_t n = 0; n < sizeof(denied)/sizeof(denied[0]); ++n) {
        int number = seccomp_syscall_resolve_name(denied[n]);
        if (number != __NR_SCMP_ERROR &&
            seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), number, 0) < 0)
            fail("man guard seccomp rule");
    }
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) < 0)
        fail("man guard clone3 rule");
    unsigned long namespaces[] = { CLONE_NEWUSER, CLONE_NEWNS, CLONE_NEWPID, CLONE_NEWNET,
        CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWCGROUP };
    for (size_t n = 0; n < sizeof(namespaces)/sizeof(namespaces[0]); ++n)
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
            SCMP_A0(SCMP_CMP_MASKED_EQ, namespaces[n], namespaces[n])) < 0)
            fail("man guard clone namespace rule");
    int families[] = { AF_INET, AF_INET6, AF_NETLINK, AF_PACKET };
    for (size_t n = 0; n < sizeof(families)/sizeof(families[0]); ++n)
        if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 1,
            SCMP_A0(SCMP_CMP_EQ, families[n])) < 0) fail("man guard socket rule");
    if (seccomp_load(ctx) < 0) fail("man guard seccomp load");
    seccomp_release(ctx);
}

static void allowed_open(int flags) {
    int fd = open(CONTROL, flags | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) fail("man guard control accessible before restriction");
    close(fd); /* Do not read or modify the public, test-owned control fixture. */
}

static void denied_open(int flags) {
    errno = 0;
    int fd = open(CONTROL, flags | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0) { close(fd); errno = EPERM; fail("man guard control escaped policy"); }
    if (errno != EACCES) fail("man guard control denial must be EACCES");
}

static void syscall_checks(void) {
    errno = 0;
    if (unshare(0) != -1 || errno != EPERM) fail("man guard namespace denial");
    errno = 0;
    if (setresuid(-1, -1, -1) != -1 || errno != EPERM) fail("man guard identity denial");
}

static void cache_write(void) {
    int fd = open(WRITE_PROBE, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0 || write(fd, "x", 1) != 1 || close(fd) || unlink(WRITE_PROBE))
        fail("man guard cache write positive control");
}

static void create_exec_probe(void) {
    int source = open("/usr/bin/true", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    int dest = open(EXEC_PROBE, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
    if (source < 0 || dest < 0) fail("man guard temporary exec probe creation");
    char buffer[8192];
    size_t total = 0;
    ssize_t count;
    while ((count = read(source, buffer, sizeof(buffer))) > 0) {
        total += (size_t)count;
        if (total > 2 * 1024 * 1024) { errno = EFBIG; fail("man guard exec probe size"); }
        ssize_t at = 0;
        while (at < count) {
            ssize_t written = write(dest, buffer + at, (size_t)(count - at));
            if (written <= 0) fail("man guard exec probe write");
            at += written;
        }
    }
    if (count < 0 || close(source) || close(dest)) fail("man guard exec probe copy");
}

static void wait_ok(pid_t pid) {
    int status;
    if (pid < 0 || waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status))
        { errno = EPERM; fail("man guard child failed"); }
}

int main(int argc, char **argv) {
    int source_bytes = argc == 2 && !strcmp(argv[1], "--source-bytes");
    int source_content = argc == 2 && !strcmp(argv[1], "--source-content");
    int probe_child = argc == 2 && !strcmp(argv[1], "--probe-child");
    if (argc != 1 && !source_bytes && !source_content && !probe_child)
        { errno = EINVAL; fail("man guard fixed entrypoint"); }
    identity();
    if (syscall(SYS_close_range, 3U, ~0U, 0)) fail("man guard FD closure");
    if (probe_child) {
        denied_open(O_RDONLY);
        denied_open(O_WRONLY);
        syscall_checks();
        cache_write();
        return 0;
    }
    allowed_open(O_RDONLY);
    allowed_open(O_WRONLY);
    create_exec_probe();
    pid_t before = fork();
    if (before == 0) { execl(EXEC_PROBE, EXEC_PROBE, (char *)NULL); _exit(125); }
    wait_ok(before); /* Demonstrates that mount/DAC alone previously allowed this exec. */
    int abi = restrict_files(source_content ? 2 : source_bytes ? 1 : 0);
    restrict_syscalls();
    identity();
    denied_open(O_RDONLY);
    denied_open(O_WRONLY);
    syscall_checks();
    cache_write();
    pid_t after = fork();
    if (after == 0) {
        execl(EXEC_PROBE, EXEC_PROBE, (char *)NULL);
        _exit(errno == EACCES ? 0 : 125);
    }
    wait_ok(after);
    if (unlink(EXEC_PROBE)) fail("man guard own exec probe cleanup");
    pid_t child = fork();
    if (child == 0) { execl(SELF, SELF, "--probe-child", (char *)NULL); _exit(125); }
    wait_ok(child);
    printf("{\"profile\":\"man-cache-landlock-seccomp-v3\",\"role\":\"%s\",\"landlock_abi\":%d,"
           "\"uid\":6,\"gid\":12,\"groups_empty\":true,\"nnp\":true,"
           "\"all_capability_sets_zero\":true,\"control_read_before_allowed\":true,"
           "\"control_write_before_allowed\":true,\"control_read_denied\":true,"
           "\"control_write_denied\":true,\"tmp_exec_before_allowed\":true,"
           "\"tmp_exec_denied\":true,\"cache_write_allowed\":true,"
           "\"namespace_change_denied\":true,\"identity_change_denied\":true,"
           "\"child_exec_inheritance_verified\":true,\"seccomp_enforced\":true}\n",
           source_content ? "source-content" : source_bytes ? "source-bytes" : "mandb", abi);
    if (fflush(stdout)) fail("man guard report flush");
    if (source_content) {
        execl("/usr/bin/python3", "/usr/bin/python3", "-I", "-B",
              "/run/man-source-content.py", (char *)NULL);
        fail("man guard fixed source content exec");
    }
    if (source_bytes) {
        execl("/usr/bin/python3", "/usr/bin/python3", "-I", "-B",
              "/run/man-source-reader.py", (char *)NULL);
        fail("man guard fixed source reader exec");
    }
    execl("/usr/bin/mandb", "/usr/bin/mandb", "--create", "--quiet", "/usr/share/man", (char *)NULL);
    fail("man guard fixed mandb exec");
}
