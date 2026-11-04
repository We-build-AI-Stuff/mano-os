/* Fixed unprivileged disposable-CI cache reader. Never a Root executor. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <linux/landlock.h>
#include <sched.h>
#include <seccomp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/personality.h>
#include <sys/shm.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/sysmacros.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_IOCTL_DEV
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

#define MANDB "/usr/bin/mandb"
#define MANDB_MAX_BYTES (512 * 1024)

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

static void restrict_execmem_syscalls(void) {
    int initial = personality(0xffffffffUL);
    if (initial < 0 || (initial & READ_IMPLIES_EXEC)) {
        errno = EPERM; fail("manual memory initial personality");
    }
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx || seccomp_attr_set(ctx, SCMP_FLTATR_ACT_BADARCH, SCMP_ACT_KILL_PROCESS) < 0 ||
        seccomp_attr_set(ctx, SCMP_FLTATR_CTL_TSYNC, 1) < 0)
        fail("manual memory seccomp context");
    if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mmap), 1,
            SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_WRITE | PROT_EXEC, PROT_WRITE | PROT_EXEC)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mmap), 2,
            SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC),
            SCMP_A3(SCMP_CMP_MASKED_EQ, MAP_ANONYMOUS, MAP_ANONYMOUS)) < 0 ||
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(mprotect), 1,
            SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)) < 0)
        fail("manual memory executable map transition rules");
    int pkey = seccomp_syscall_resolve_name("pkey_mprotect");
    if (pkey == __NR_SCMP_ERROR ||
        seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), pkey, 1,
            SCMP_A2(SCMP_CMP_MASKED_EQ, PROT_EXEC, PROT_EXEC)) < 0)
        fail("manual memory pkey transition rule");
    const char *denied[] = { "memfd_create", "shmget", "shmat", "userfaultfd",
        "personality", "uselib" };
    for (size_t n = 0; n < sizeof(denied)/sizeof(denied[0]); ++n) {
        int number = seccomp_syscall_resolve_name(denied[n]);
        if (number == __NR_SCMP_ERROR ||
            seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), number, 0) < 0)
            fail("manual memory alternate code route rule");
    }
    if (seccomp_load(ctx) < 0) fail("manual memory seccomp load");
    seccomp_release(ctx);
}

/* The profile transition happens at the fixed worker exec boundary, after the
 * identity/capability drop. Never attempt a privileged transition here. */
static void require_execmem_profile(void) {
    static const char expected[] = "mano-man-cache-execmem (enforce)\n";
    char buffer[128];
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) fail("manual memory profile open");
    ssize_t count = read(fd, buffer, sizeof(buffer));
    char extra;
    ssize_t tail = count < 0 ? -1 : read(fd, &extra, 1);
    if (close(fd) || count != (ssize_t)(sizeof(expected)-1) || tail != 0 ||
            memcmp(buffer, expected, sizeof(expected)-1)) {
        errno = EPERM; fail("manual memory exact enforcing profile");
    }
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

/* Measurement only: request mappings, retain kernel results, never execute them. */
struct mapping_result { int allowed; int error; };
struct mapping_controls {
    struct mapping_result baseline_read, baseline_exec, temporary_read, temporary_exec;
    struct mapping_result temporary_write_exec, anonymous_write_exec, anonymous_to_exec;
};

static struct mapping_result map_file(const char *path, int protection) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_size < 4096)
        fail("man guard mapping fixed source");
    errno = 0;
    void *address = mmap(NULL, 4096, protection, MAP_PRIVATE, fd, 0);
    struct mapping_result result = { address != MAP_FAILED,
                                    address == MAP_FAILED ? errno : 0 };
    if (close(fd) || (address != MAP_FAILED && munmap(address, 4096)))
        fail("man guard mapping source cleanup");
    return result;
}

static struct mapping_result map_anonymous(int change_protection) {
    int protection = PROT_READ | PROT_WRITE | (change_protection ? 0 : PROT_EXEC);
    errno = 0;
    void *address = mmap(NULL, 4096, protection, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct mapping_result result = { address != MAP_FAILED,
                                    address == MAP_FAILED ? errno : 0 };
    if (change_protection) {
        if (address == MAP_FAILED) fail("man guard anonymous RW positive control");
        errno = 0;
        int status = mprotect(address, 4096, PROT_READ | PROT_EXEC);
        result.allowed = status == 0;
        result.error = status == 0 ? 0 : errno;
    }
    if (address != MAP_FAILED && munmap(address, 4096))
        fail("man guard anonymous mapping cleanup");
    return result;
}

static struct mapping_controls observe_mappings(void) {
    struct mapping_controls result = {
        .baseline_read = map_file("/usr/bin/true", PROT_READ),
        .baseline_exec = map_file("/usr/bin/true", PROT_READ | PROT_EXEC),
        .temporary_read = map_file(EXEC_PROBE, PROT_READ),
        .temporary_exec = map_file(EXEC_PROBE, PROT_READ | PROT_EXEC),
        .temporary_write_exec = map_file(EXEC_PROBE, PROT_READ | PROT_WRITE | PROT_EXEC),
        .anonymous_write_exec = map_anonymous(0),
        .anonymous_to_exec = map_anonymous(1)
    };
    return result;
}

static int mapping_positives(struct mapping_controls result) {
    return result.baseline_read.allowed && result.baseline_exec.allowed &&
        result.temporary_read.allowed;
}

static void mapping_field(const char *name, struct mapping_result result, int comma) {
    printf("%s\"%s\":{\"allowed\":%s,\"errno\":%d}", comma ? "," : "", name,
           result.allowed ? "true" : "false", result.error);
}

static void mapping_packet(const char *name, struct mapping_controls result, int comma) {
    printf("%s\"%s\":{", comma ? "," : "", name);
    mapping_field("baseline_read", result.baseline_read, 0);
    mapping_field("baseline_exec", result.baseline_exec, 1);
    mapping_field("temporary_read", result.temporary_read, 1);
    mapping_field("temporary_exec", result.temporary_exec, 1);
    mapping_field("temporary_write_exec", result.temporary_write_exec, 1);
    mapping_field("anonymous_write_exec", result.anonymous_write_exec, 1);
    mapping_field("anonymous_to_exec", result.anonymous_to_exec, 1);
    printf("}");
}

/* These are syscall results, never function pointers or executable payloads.
 * Keep failed outcomes bounded; only explicit permission errors prove denial. */
struct execmem_controls {
    struct mapping_controls mappings;
    struct mapping_result baseline_write_exec, anonymous_exec, pkey_to_exec;
    struct mapping_result personality, memfd_create, shmget, shmat, userfaultfd, uselib;
};

static struct mapping_result syscall_result(long result, int error) {
    return (struct mapping_result){ result != -1, result == -1 ? error : 0 };
}

static struct mapping_result anonymous_exec(void) {
    errno = 0;
    void *address = mmap(NULL, 4096, PROT_READ | PROT_EXEC,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    struct mapping_result result = { address != MAP_FAILED,
                                    address == MAP_FAILED ? errno : 0 };
    if (address != MAP_FAILED && munmap(address, 4096))
        fail("manual memory anonymous RX cleanup");
    return result;
}

static struct mapping_result pkey_to_exec(void) {
    void *address = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (address == MAP_FAILED) fail("manual memory pkey RW positive control");
    errno = 0;
    long status = syscall(SYS_pkey_mprotect, address, 4096, PROT_READ | PROT_EXEC, -1);
    struct mapping_result result = syscall_result(status, errno);
    if (munmap(address, 4096)) fail("manual memory pkey cleanup");
    return result;
}

static struct execmem_controls observe_execmem(void) {
    struct execmem_controls result = {
        .mappings = observe_mappings(),
        .baseline_write_exec = map_file("/usr/bin/true", PROT_READ | PROT_WRITE | PROT_EXEC),
        .anonymous_exec = anonymous_exec(),
        .pkey_to_exec = pkey_to_exec()
    };
    errno = 0;
    long status = personality(0xffffffffUL);
    result.personality = syscall_result(status, errno);
    errno = 0;
    status = syscall(SYS_memfd_create, "mano-fixed-memory-control", 0);
    result.memfd_create = syscall_result(status, errno);
    if (status >= 0 && close((int)status)) fail("manual memory memfd cleanup");
    errno = 0;
    status = shmget(IPC_PRIVATE, 4096, IPC_CREAT | 0600);
    result.shmget = syscall_result(status, errno);
    if (status >= 0 && shmctl((int)status, IPC_RMID, NULL))
        fail("manual memory shared segment cleanup");
    errno = 0;
    void *attached = shmat(-1, NULL, SHM_RDONLY);
    result.shmat = (struct mapping_result){ attached != (void *)-1,
                                           attached == (void *)-1 ? errno : 0 };
    if (attached != (void *)-1 && shmdt(attached)) fail("manual memory shmat cleanup");
    errno = 0;
    status = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
    result.userfaultfd = syscall_result(status, errno);
    if (status >= 0 && close((int)status)) fail("manual memory userfaultfd cleanup");
    errno = 0;
    status = syscall(SYS_uselib, "/usr/bin/true");
    result.uselib = syscall_result(status, errno);
    return result;
}

static int permission_denied(struct mapping_result result, int seccomp_only) {
    return !result.allowed && (result.error == EPERM ||
                               (!seccomp_only && result.error == EACCES));
}

static void require_execmem_controls(struct execmem_controls result) {
    if (!mapping_positives(result.mappings) ||
            !permission_denied(result.mappings.temporary_exec, 0) ||
            !permission_denied(result.mappings.temporary_write_exec, 1) ||
            !permission_denied(result.mappings.anonymous_write_exec, 1) ||
            !permission_denied(result.mappings.anonymous_to_exec, 1)) {
        errno = EPERM; fail("manual memory mapping controls");
    }
    struct mapping_result denied[] = { result.baseline_write_exec, result.anonymous_exec,
        result.pkey_to_exec, result.personality, result.memfd_create, result.shmget,
        result.shmat, result.userfaultfd, result.uselib };
    for (size_t n = 0; n < sizeof(denied)/sizeof(denied[0]); ++n)
        if (!permission_denied(denied[n], 1)) {
            errno = EPERM; fail("manual memory explicit syscall denials");
        }
}

static void execmem_packet(struct mapping_controls before, struct execmem_controls after) {
    printf("\"execmem\":{\"profile\":\"man-execmem-enforcement-v1\","
           "\"apparmor_context\":\"mano-man-cache-execmem (enforce)\","
           "\"diagnostic_mapping_bytes_executed\":false,");
    mapping_packet("before", before, 0);
    mapping_packet("after", after.mappings, 1);
    printf(",\"syscalls\":{");
    mapping_field("baseline_write_exec", after.baseline_write_exec, 0);
    mapping_field("anonymous_exec", after.anonymous_exec, 1);
    mapping_field("pkey_to_exec", after.pkey_to_exec, 1);
    mapping_field("personality", after.personality, 1);
    mapping_field("memfd_create", after.memfd_create, 1);
    mapping_field("shmget", after.shmget, 1);
    mapping_field("shmat", after.shmat, 1);
    mapping_field("userfaultfd", after.userfaultfd, 1);
    mapping_field("uselib", after.uselib, 1);
    printf("},\"child_exec_inheritance_verified\":true,"
           "\"complete_runtime_closure_verified\":false,\"publication_authorized\":false}");
}

/* Source identity is reported from the same descriptor used by execveat.
 * Root independently holds and hashes the baseline object across this worker. */
static int open_mandb_source(struct stat *info) {
    int fd = open(MANDB, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct statvfs view;
    unsigned char magic[4];
    if (fd < 0 || fstat(fd, info) || !S_ISREG(info->st_mode) || info->st_uid != 0 ||
            (info->st_mode & 0022) || info->st_size < 64 || info->st_size > MANDB_MAX_BYTES ||
            !(info->st_mode & (info->st_gid == 12 ? S_IXGRP : S_IXOTH)) ||
            fstatvfs(fd, &view) || !(view.f_flag & ST_RDONLY) ||
            fcntl(fd, F_GETFD) != FD_CLOEXEC || pread(fd, magic, sizeof(magic), 0) != 4 ||
            memcmp(magic, "\177ELF", sizeof(magic))) {
        errno = EPERM; fail("man guard fixed readonly executable descriptor");
    }
    return fd;
}

static int64_t stat_nanoseconds(struct timespec value) {
    if (value.tv_nsec < 0 || value.tv_nsec >= 1000000000 ||
            value.tv_sec < INT64_MIN / INT64_C(1000000000) ||
            value.tv_sec > INT64_MAX / INT64_C(1000000000)) {
        errno = EOVERFLOW; fail("man guard executable identity time range");
    }
    int64_t base = (int64_t)value.tv_sec * INT64_C(1000000000);
    if (base > INT64_MAX - value.tv_nsec) {
        errno = EOVERFLOW; fail("man guard executable identity nanoseconds");
    }
    return base + value.tv_nsec;
}

static void executable_source_packet(const struct stat *info) {
    printf("\"executable_source\":{\"profile\":\"man-fixed-mandb-execfd-v1\","
           "\"path\":\"/usr/bin/mandb\",\"execution_method\":\"execveat-empty-path\","
           "\"descriptor_cloexec\":true,\"readonly_mount\":true,\"identity\":{"
           "\"device\":[%ju,%ju],\"inode\":%ju,\"uid\":%ju,\"gid\":%ju,"
           "\"mode\":%ju,\"kind\":\"file\",\"bytes\":%jd,\"nlink\":%ju,"
           "\"mtime_ns\":%" PRId64 ",\"ctime_ns\":%" PRId64 "}}",
           (uintmax_t)major(info->st_dev), (uintmax_t)minor(info->st_dev),
           (uintmax_t)info->st_ino, (uintmax_t)info->st_uid, (uintmax_t)info->st_gid,
           (uintmax_t)(info->st_mode & 07777), (intmax_t)info->st_size,
           (uintmax_t)info->st_nlink, stat_nanoseconds(info->st_mtim),
           stat_nanoseconds(info->st_ctim));
}

int main(int argc, char **argv) {
    int source_bytes = argc == 2 && !strcmp(argv[1], "--source-bytes");
    int source_content = argc == 2 && !strcmp(argv[1], "--source-content");
    int probe_child = argc == 2 && !strcmp(argv[1], "--probe-child");
    int mapping_controls = argc == 2 && !strcmp(argv[1], "--mapping-controls");
    int source_enforced = argc == 2 && !strcmp(argv[1], "--mandb-enforced-source");
    int mandb_enforced = source_enforced || (argc == 2 && !strcmp(argv[1], "--mandb-enforced"));
    int enforced_child = argc == 2 && !strcmp(argv[1], "--probe-child-enforced");
    if (argc != 1 && !mandb_enforced && !enforced_child && !source_bytes && !source_content && !probe_child && !mapping_controls)
        { errno = EINVAL; fail("man guard fixed entrypoint"); }
    identity();
    if (syscall(SYS_close_range, 3U, ~0U, 0)) fail("man guard FD closure");
    if (mandb_enforced) require_execmem_profile();
    if (probe_child || enforced_child) {
        denied_open(O_RDONLY);
        denied_open(O_WRONLY);
        syscall_checks();
        cache_write();
        if (enforced_child) require_execmem_controls(observe_execmem());
        return 0;
    }
    allowed_open(O_RDONLY);
    allowed_open(O_WRONLY);
    create_exec_probe();
    pid_t before = fork();
    if (before == 0) { execl(EXEC_PROBE, EXEC_PROBE, (char *)NULL); _exit(125); }
    wait_ok(before); /* Demonstrates that mount/DAC alone previously allowed this exec. */
    struct mapping_controls mapping_before = {0}, mapping_after = {0};
    if (mapping_controls || mandb_enforced) mapping_before = observe_mappings();
    if (mandb_enforced && (!mapping_positives(mapping_before) ||
            !mapping_before.anonymous_write_exec.allowed ||
            !mapping_before.anonymous_to_exec.allowed ||
            !permission_denied(mapping_before.temporary_exec, 0) ||
            !permission_denied(mapping_before.temporary_write_exec, 0))) {
        printf("{\"profile\":\"man-execmem-enforcement-failure-v1\","
               "\"stage\":\"prefilter\",");
        mapping_packet("before", mapping_before, 0);
        printf("}\n");
        if (fflush(stdout)) fail("manual memory pre-filter failure report flush");
        errno = EPERM; fail("manual memory pre-filter positive/profile controls");
    }
    int abi = restrict_files(source_content ? 2 : source_bytes ? 1 : 0);
    restrict_syscalls();
    if (mandb_enforced) restrict_execmem_syscalls();
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
    if (mapping_controls) mapping_after = observe_mappings();
    struct execmem_controls execmem_after = {0};
    if (mandb_enforced) {
        execmem_after = observe_execmem();
        require_execmem_controls(execmem_after);
    }
    if (!mandb_enforced && unlink(EXEC_PROBE)) fail("man guard own exec probe cleanup");
    pid_t child = fork();
    if (child == 0) { execl(SELF, SELF, mandb_enforced ? "--probe-child-enforced" : "--probe-child", (char *)NULL); _exit(125); }
    wait_ok(child);
    if (mandb_enforced && unlink(EXEC_PROBE)) fail("manual memory probe cleanup");
    if (mapping_controls) {
        struct utsname kernel;
        if (uname(&kernel)) fail("man guard mapping kernel release");
        if (!strlen(kernel.release) || strlen(kernel.release) > 128 ||
            strspn(kernel.release, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._+-")
                != strlen(kernel.release)) {
            errno = EINVAL; fail("man guard mapping kernel release characters");
        }
        printf("{\"profile\":\"man-cache-mapping-controls-v1\",\"landlock_abi\":%d,"
               "\"kernel_release\":\"%s\","
               "\"uid\":6,\"gid\":12,\"temporary_exec_before_allowed\":true,"
               "\"temporary_exec_after_denied\":true,\"diagnostic_mapping_bytes_executed\":false,",
               abi, kernel.release);
        mapping_packet("before", mapping_before, 0);
        mapping_packet("after", mapping_after, 1);
        printf(",\"complete_runtime_closure_verified\":false,"
               "\"publication_authorized\":false}\n");
        if (fflush(stdout)) fail("man guard mapping report flush");
        if (!mapping_positives(mapping_before) || !mapping_positives(mapping_after)) {
            errno = EPERM; fail("man guard mapping read/baseline-code positive controls");
        }
        return 0;
    }
    struct stat executable_info;
    int executable_fd = source_enforced ? open_mandb_source(&executable_info) : -1;
    printf("{\"profile\":\"%s\",\"role\":\"%s\",\"landlock_abi\":%d,"
           "\"uid\":6,\"gid\":12,\"groups_empty\":true,\"nnp\":true,"
           "\"all_capability_sets_zero\":true,\"control_read_before_allowed\":true,"
           "\"control_write_before_allowed\":true,\"control_read_denied\":true,"
           "\"control_write_denied\":true,\"tmp_exec_before_allowed\":true,"
           "\"tmp_exec_denied\":true,\"cache_write_allowed\":true,"
           "\"namespace_change_denied\":true,\"identity_change_denied\":true,"
           "\"child_exec_inheritance_verified\":true,\"seccomp_enforced\":true",
           source_enforced ? "man-cache-landlock-seccomp-v5" :
               mandb_enforced ? "man-cache-landlock-seccomp-v4" : "man-cache-landlock-seccomp-v3",
           source_content ? "source-content" : source_bytes ? "source-bytes" : "mandb", abi);
    if (mandb_enforced) {
        printf(",");
        execmem_packet(mapping_before, execmem_after);
    }
    if (source_enforced) {
        printf(",");
        executable_source_packet(&executable_info);
    }
    printf("}\n");
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
    if (source_enforced) {
        char *const arguments[] = { MANDB, "--create", "--quiet", "/usr/share/man", NULL };
        extern char **environ;
        syscall(SYS_execveat, executable_fd, "", arguments, environ, AT_EMPTY_PATH);
        fail("man guard fixed mandb descriptor exec");
    }
    execl("/usr/bin/mandb", "/usr/bin/mandb", "--create", "--quiet", "/usr/share/man", (char *)NULL);
    fail("man guard fixed mandb exec");
}
