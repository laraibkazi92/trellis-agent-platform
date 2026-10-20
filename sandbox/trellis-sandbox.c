/* trellis-sandbox: privilege drop + Landlock confinement + exec.
 *
 * Opens every granted path before changing identity, drops to the target
 * uid/gid, zeroes capabilities, lowers resource limits, installs a Landlock
 * filesystem domain, installs a seccomp deny-list, then execs the command in
 * place (no fork, so exit codes and signals pass through). --no-seccomp skips
 * the deny-list.
 *
 * The helper does not assume it starts as root. When the caller already runs as
 * the target identity (a hub that runs as the sandbox uid, unprivileged test
 * runs) the chown and the identity syscalls are skipped; supplementary groups
 * may survive the attempt when the caller lacks CAP_SETGID, which is reported on
 * stderr. A non-root caller that asks for a different identity cannot switch
 * and exits 68. Capabilities, limits, Landlock and seccomp are applied either
 * way.
 *
 * Exit: 64 usage, 65 Landlock unavailable/failure, 66 seccomp install failure,
 * 67 path grant failure, 68 privilege drop failure, 69 rlimit failure,
 * 126/127 exec failure.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/types.h>
#include <limits.h>
#include <sched.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#define VERSION "0.3.0"

#define MB (1024ULL * 1024ULL)

/* asm-generic syscall numbers, valid on x86_64 and arm64 */
#define SYS_LL_CREATE 444
#define SYS_LL_ADD_RULE 445
#define SYS_LL_RESTRICT_SELF 446

#define LL_CREATE_VERSION (1U << 0)
#define LL_RULE_PATH_BENEATH 1

#define LL_EXECUTE (1ULL << 0)
#define LL_WRITE_FILE (1ULL << 1)
#define LL_READ_FILE (1ULL << 2)
#define LL_READ_DIR (1ULL << 3)
#define LL_REMOVE_DIR (1ULL << 4)
#define LL_REMOVE_FILE (1ULL << 5)
#define LL_MAKE_CHAR (1ULL << 6)
#define LL_MAKE_DIR (1ULL << 7)
#define LL_MAKE_REG (1ULL << 8)
#define LL_MAKE_SOCK (1ULL << 9)
#define LL_MAKE_FIFO (1ULL << 10)
#define LL_MAKE_BLOCK (1ULL << 11)
#define LL_MAKE_SYM (1ULL << 12)
#define LL_REFER (1ULL << 13)      /* ABI 2 */
#define LL_TRUNCATE (1ULL << 14)   /* ABI 3 */
#define LL_IOCTL_DEV (1ULL << 15)  /* ABI 5 */
#define LL_SCOPE_ABSTRACT_UNIX_SOCKET (1U << 0) /* ABI 6 */
#define LL_SCOPE_SIGNAL (1U << 1)               /* ABI 6 */

#if defined(__x86_64__)
#define TRELLIS_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define TRELLIS_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "trellis-sandbox has no seccomp arch guard for this architecture"
#endif

#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS SECCOMP_RET_KILL
#endif
#ifndef __NR_clone3
#define __NR_clone3 435
#endif
#ifndef __NR_io_uring_setup
#define __NR_io_uring_setup 425
#define __NR_io_uring_enter 426
#define __NR_io_uring_register 427
#endif

#define LL_ABI1_MASK                                                          \
    (LL_EXECUTE | LL_WRITE_FILE | LL_READ_FILE | LL_READ_DIR | LL_REMOVE_DIR | \
     LL_REMOVE_FILE | LL_MAKE_CHAR | LL_MAKE_DIR | LL_MAKE_REG | LL_MAKE_SOCK |\
     LL_MAKE_FIFO | LL_MAKE_BLOCK | LL_MAKE_SYM)
#define LL_RO_RIGHTS (LL_EXECUTE | LL_READ_FILE | LL_READ_DIR)

/* Structs are copied from <linux/landlock.h> so the header version is irrelevant. */
struct ruleset_attr {
    __u64 handled_access_fs;
    __u64 handled_access_net;
    __u64 scoped;
};
struct path_beneath_attr {
    __u64 allowed_access;
    __s32 parent_fd;
} __attribute__((packed));

/* /dev/null and friends must stay writable under a read-only root, or every
 * shell redirect fails. Only these nodes are granted, never all of /dev. */
static const char *const dev_nodes[] = {
    "/dev/null", "/dev/zero", "/dev/full",
    "/dev/random", "/dev/urandom", "/dev/tty",
};

enum {
    EXIT_USAGE = 64, EXIT_LANDLOCK = 65, EXIT_SECCOMP = 66,
    EXIT_GRANT = 67, EXIT_PRIVDROP = 68, EXIT_RLIMIT = 69,
};

struct list {
    char **v;
    size_t n, cap;
};

struct opts {
    struct list ro, rw;
    const char *tmpdir;
    uid_t uid;
    gid_t gid;
    int have_uid, have_gid, no_seccomp, dry_run, print_plan;
    char **cmd;
};

__attribute__((noreturn))
static void die(int code, const char *fmt, ...)
{
    va_list ap;

    fputs("trellis-sandbox: ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(code);
}

__attribute__((noreturn))
static void die_errno(int code, const char *what)
{
    fputs("trellis-sandbox: ", stderr);
    perror(what);
    exit(code);
}

static void usage(void)
{
    fputs("Usage: trellis-sandbox --ro DIR [--ro DIR]... --rw DIR [--rw DIR]...\n"
          "                      --tmpdir DIR [--uid UID --gid GID] [--no-seccomp]\n"
          "                      [--dry-run] [--print-plan] -- CMD [ARG...]\n"
          "       trellis-sandbox --version\n", stderr);
}

static void push(struct list *l, char *s)
{
    if (l->n == l->cap) {
        size_t cap = l->cap ? l->cap * 2 : 8;
        char **v = realloc(l->v, cap * sizeof(*v));
        if (!v)
            die_errno(EXIT_LANDLOCK, "realloc");
        l->v = v;
        l->cap = cap;
    }
    l->v[l->n++] = s;
}

static int parse_id(const char *s, unsigned long *out)
{
    char *end = NULL;
    unsigned long v;

    if (!s || !*s)
        return -1;
    errno = 0;
    v = strtoul(s, &end, 10);
    if (errno || !end || *end || v > 0xffffffffUL)
        return -1;
    *out = v;
    return 0;
}

static void parse_args(int argc, char **argv, struct opts *o)
{
    int i, sep = 0;

    memset(o, 0, sizeof(*o));
    for (i = 1; i < argc; i++) {
        char *a = argv[i], *val;
        unsigned long v;

        if (!strcmp(a, "--")) {
            sep = 1;
            i++;
            break;
        }
        if (!strcmp(a, "--version")) {
            printf("trellis-sandbox %s\n", VERSION);
            exit(0);
        }
        if (!strcmp(a, "--no-seccomp")) {
            o->no_seccomp = 1;
            continue;
        }
        if (!strcmp(a, "--dry-run")) {
            o->dry_run = 1;
            continue;
        }
        if (!strcmp(a, "--print-plan")) {
            o->print_plan = 1;
            continue;
        }
        if (strcmp(a, "--ro") && strcmp(a, "--rw") && strcmp(a, "--tmpdir") &&
            strcmp(a, "--uid") && strcmp(a, "--gid"))
            die(EXIT_USAGE, "unknown option '%s'", a);
        if (i + 1 >= argc)
            die(EXIT_USAGE, "%s requires an argument", a);
        val = argv[++i];
        if (!strcmp(a, "--ro")) {
            push(&o->ro, val);
        } else if (!strcmp(a, "--rw")) {
            push(&o->rw, val);
        } else if (!strcmp(a, "--tmpdir")) {
            o->tmpdir = val;
        } else {
            if (parse_id(val, &v))
                die(EXIT_USAGE, "invalid %s value '%s'", a, val);
            if (!strcmp(a, "--uid")) {
                o->have_uid = 1;
                o->uid = (uid_t)v;
            } else {
                o->have_gid = 1;
                o->gid = (gid_t)v;
            }
        }
    }
    if (!sep)
        die(EXIT_USAGE, "missing '--' before command");
    if (o->have_uid != o->have_gid)
        die(EXIT_USAGE, "--uid and --gid must be given together");
    if (o->have_uid && o->uid == 0)
        die(EXIT_USAGE, "--uid 0 would run the tool as root");
    if (!o->tmpdir)
        die(EXIT_USAGE, "--tmpdir is required");
    o->cmd = &argv[i];
    if (!o->dry_run && !o->print_plan && !o->cmd[0])
        die(EXIT_USAGE, "missing command after '--'");
}

static char *resolve_dir(const char *flag, const char *path)
{
    char *resolved = realpath(path, NULL);
    struct stat st;

    if (!resolved)
        die(EXIT_GRANT, "%s '%s': %s", flag, path, strerror(errno));
    if (stat(resolved, &st))
        die(EXIT_GRANT, "%s '%s': %s", flag, resolved, strerror(errno));
    if (!S_ISDIR(st.st_mode))
        die(EXIT_GRANT, "%s '%s': not a directory", flag, resolved);
    return resolved;
}

static int open_grant(const char *flag, const char *path)
{
    int fd = open(path, O_PATH | O_CLOEXEC);
    if (fd < 0)
        die(EXIT_GRANT, "%s '%s': %s", flag, path, strerror(errno));
    return fd;
}

static int landlock_abi(void)
{
    long ret = syscall(SYS_LL_CREATE, NULL, (size_t)0, LL_CREATE_VERSION);
    return ret > 0 ? (int)ret : 0;
}

static uint64_t handled_mask(int abi)
{
    uint64_t m = LL_ABI1_MASK;
    if (abi >= 2)
        m |= LL_REFER;
    if (abi >= 3)
        m |= LL_TRUNCATE;
    if (abi >= 5)
        m |= LL_IOCTL_DEV;
    return m;
}

/* Older kernels EINVAL on struct sizes they do not know. */
static size_t attr_size(int abi)
{
    return abi < 4 ? 8 : abi < 6 ? 16 : 24;
}

static void json_str(const char *s)
{
    const unsigned char *p = (const unsigned char *)s;

    putchar('"');
    for (; *p; p++) {
        if (*p == '"' || *p == '\\')
            printf("\\%c", *p);
        else if (*p == '\n')
            fputs("\\n", stdout);
        else if (*p < 0x20)
            printf("\\u%04x", *p);
        else
            putchar(*p);
    }
    putchar('"');
}

static void json_list(const char *key, const struct list *l)
{
    size_t i;

    printf("\"%s\":[", key);
    for (i = 0; i < l->n; i++) {
        if (i)
            putchar(',');
        json_str(l->v[i]);
    }
    putchar(']');
}

static void print_plan(const struct opts *o, const struct list *ro,
                       const struct list *rw, const char *tmpdir, int abi)
{
    printf("{\"helper_version\":\"%s\",\"abi\":%d,\"uid\":", VERSION, abi);
    if (o->have_uid)
        printf("%lu", (unsigned long)o->uid);
    else
        fputs("null", stdout);
    fputs(",\"gid\":", stdout);
    if (o->have_gid)
        printf("%lu", (unsigned long)o->gid);
    else
        fputs("null", stdout);
    fputs(",\"tmpdir\":", stdout);
    json_str(tmpdir);
    putchar(',');
    json_list("ro", ro);
    putchar(',');
    json_list("rw", rw);
    printf(",\"handled_access_fs\":\"0x%llx\",\"scoped\":%d,\"seccomp\":%s}\n",
           (unsigned long long)handled_mask(abi),
           abi >= 6 ? (LL_SCOPE_ABSTRACT_UNIX_SOCKET | LL_SCOPE_SIGNAL) : 0,
           o->no_seccomp ? "false" : "true");
}

static void zero_capabilities(void)
{
    struct __user_cap_header_struct hdr = {
        .version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2] = {{0}};
    int was_root = geteuid() == 0;

    /* After a successful setuid the sets are already empty; this is what makes
     * CapEff==0 verifiable when we keep the current identity. */
    if (syscall(SYS_capset, &hdr, data) && was_root)
        die_errno(EXIT_PRIVDROP, "capset");
}

/* True only when a group other than the sandbox's primary gid survives. */
static int has_extra_groups(gid_t primary)
{
    int i, n = getgroups(0, NULL);
    gid_t *groups;

    if (n <= 0)
        return 0;
    groups = malloc((size_t)n * sizeof(*groups));
    if (!groups)
        return 0; /* a diagnostic must not fail the run */
    n = getgroups(n, groups);
    for (i = 0; i < n; i++) {
        if (groups[i] != primary) {
            free(groups);
            return 1;
        }
    }
    free(groups);
    return 0;
}

static void drop_privileges(const struct opts *o, const char *tmpdir)
{
    /* Re-owning the run dir is part of the identity change, not something a
     * same-identity caller needs: a non-root hub at the target uid would only
     * perform a same-owner no-op, and one at any other uid fails here with
     * EPERM -- which is correct, it cannot switch. */
    if (geteuid() != o->uid || getegid() != o->gid) {
        if (chown(tmpdir, o->uid, o->gid))
            die_errno(EXIT_PRIVDROP, "chown(tmpdir)");
    }
    /* An unprivileged caller cannot clear groups, so EPERM here is expected
     * when it already runs as the target identity. Warn only when a group
     * other than the primary one survives: Docker always lists the primary gid
     * in the supplementary set, which is harmless. */
    if (setgroups(0, NULL) && errno != EPERM)
        die_errno(EXIT_PRIVDROP, "setgroups");
    if (has_extra_groups(o->gid))
        fputs("trellis-sandbox: warning: supplementary groups retained "
              "(needs CAP_SETGID)\n", stderr);
    /* Already at the target identity (unprivileged test runs): the remaining
     * identity syscalls would only fail with EPERM. */
    if (geteuid() == o->uid && getegid() == o->gid)
        return;
    if (setgid(o->gid))
        die_errno(EXIT_PRIVDROP, "setgid");
    if (setuid(o->uid))
        die_errno(EXIT_PRIVDROP, "setuid");
}

/* Unset falls back to the default; an explicit 0 leaves the inherited limit
 * alone (usually "unlimited"). */
static unsigned long long env_limit(const char *var, unsigned long long def)
{
    const char *s = getenv(var);
    char *end = NULL;
    unsigned long long v;

    if (!s || !*s)
        return def;
    errno = 0;
    v = strtoull(s, &end, 10);
    if (*s == '-' || errno || end == s || *end)
        die(EXIT_USAGE, "invalid %s value '%s'", var, s);
    return v;
}

static unsigned long long env_limit_mb(const char *var, unsigned long long def)
{
    unsigned long long mb = env_limit(var, def);

    if (mb > ULLONG_MAX / MB)
        die(EXIT_USAGE, "%s value is too large", var);
    return mb * MB;
}

static void set_rlimit(int resource, const char *what, unsigned long long value)
{
    struct rlimit rl = {(rlim_t)value, (rlim_t)value};

    if (setrlimit(resource, &rl))
        die_errno(EXIT_RLIMIT, what);
}

/* Lowering a limit is allowed unprivileged, so this works before and after the
 * identity drop; the earlier it runs, the less the remaining setup can consume
 * and the harder it is for the exec'd command to raise the limit again. */
static void apply_rlimits(void)
{
    unsigned long long v;

    v = env_limit_mb("SANDBOX_RLIMIT_AS_MB", 4096);
    if (v)
        set_rlimit(RLIMIT_AS, "setrlimit(RLIMIT_AS)", v);
    v = env_limit("SANDBOX_RLIMIT_CPU_S", 600);
    if (v)
        set_rlimit(RLIMIT_CPU, "setrlimit(RLIMIT_CPU)", v);
    /* Off by default: RLIMIT_NPROC counts every process of the real uid on the
     * host (containers share the kernel uid table), so a shared operator uid is
     * already near the limit. Use the container's pids_limit, which is per
     * container, unless the sandbox uid is dedicated. */
    v = env_limit("SANDBOX_RLIMIT_NPROC", 0);
    if (v)
        set_rlimit(RLIMIT_NPROC, "setrlimit(RLIMIT_NPROC)", v);
    v = env_limit_mb("SANDBOX_RLIMIT_FSIZE_MB", 64);
    if (v)
        set_rlimit(RLIMIT_FSIZE, "setrlimit(RLIMIT_FSIZE)", v);
    /* Core dumps would write megabytes into the tmpdir on every crash. */
    set_rlimit(RLIMIT_CORE, "setrlimit(RLIMIT_CORE)", 0);
}

static void add_rule(int ruleset, int parent, uint64_t rights, const char *path)
{
    struct path_beneath_attr attr = {.allowed_access = rights, .parent_fd = parent};

    if (syscall(SYS_LL_ADD_RULE, ruleset, LL_RULE_PATH_BENEATH, &attr, 0))
        die(EXIT_GRANT, "landlock_add_rule '%s': %s", path, strerror(errno));
}

#define MAX_FILTER_INSNS 256

static void emit(struct sock_filter *insns, size_t *n, struct sock_filter insn)
{
    if (*n >= MAX_FILTER_INSNS)
        die(EXIT_SECCOMP, "seccomp filter too large");
    insns[(*n)++] = insn;
}

static void emit_ret(struct sock_filter *insns, size_t *n, uint32_t ret)
{
    emit(insns, n, (struct sock_filter)BPF_STMT(BPF_RET | BPF_K, ret));
}

static uint32_t errno_ret(int err)
{
    return SECCOMP_RET_ERRNO | ((uint32_t)err & SECCOMP_RET_DATA);
}

static void install_seccomp(void)
{
    /* Errno choice matters: probing runtimes degrade cleanly on ENOSYS, while
     * EPERM is reserved for operations nothing legitimate probes. */
    static const int eperm_nrs[] = {
#ifdef __NR_unshare
        __NR_unshare,
#endif
#ifdef __NR_setns
        __NR_setns,
#endif
#ifdef __NR_mount
        __NR_mount,
#endif
#ifdef __NR_umount2
        __NR_umount2,
#endif
#ifdef __NR_pivot_root
        __NR_pivot_root,
#endif
#ifdef __NR_chroot
        __NR_chroot,
#endif
#ifdef __NR_mount_setattr
        __NR_mount_setattr,
#endif
#ifdef __NR_open_tree
        __NR_open_tree,
#endif
#ifdef __NR_move_mount
        __NR_move_mount,
#endif
#ifdef __NR_fsopen
        __NR_fsopen,
#endif
#ifdef __NR_fsmount
        __NR_fsmount,
#endif
#ifdef __NR_fspick
        __NR_fspick,
#endif
#ifdef __NR_ptrace
        __NR_ptrace,
#endif
#ifdef __NR_process_vm_readv
        __NR_process_vm_readv,
#endif
#ifdef __NR_process_vm_writev
        __NR_process_vm_writev,
#endif
#ifdef __NR_bpf
        __NR_bpf,
#endif
#ifdef __NR_perf_event_open
        __NR_perf_event_open,
#endif
#ifdef __NR_keyctl
        __NR_keyctl,
#endif
#ifdef __NR_add_key
        __NR_add_key,
#endif
#ifdef __NR_request_key
        __NR_request_key,
#endif
#ifdef __NR_userfaultfd
        __NR_userfaultfd,
#endif
#ifdef __NR_init_module
        __NR_init_module,
#endif
#ifdef __NR_finit_module
        __NR_finit_module,
#endif
#ifdef __NR_delete_module
        __NR_delete_module,
#endif
#ifdef __NR_kexec_load
        __NR_kexec_load,
#endif
#ifdef __NR_kexec_file_load
        __NR_kexec_file_load,
#endif
#ifdef __NR_reboot
        __NR_reboot,
#endif
#ifdef __NR_seccomp
        __NR_seccomp,
#endif
    };
    static const int enosys_nrs[] = {
#ifdef __NR_io_uring_setup
        __NR_io_uring_setup,
#endif
#ifdef __NR_io_uring_enter
        __NR_io_uring_enter,
#endif
#ifdef __NR_io_uring_register
        __NR_io_uring_register,
#endif
        __NR_clone3,
    };
    struct sock_filter insns[MAX_FILTER_INSNS];
    struct sock_fprog prog;
    size_t n = 0, i;

    emit(&insns[0], &n, (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)));
    emit(&insns[0], &n, (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, TRELLIS_AUDIT_ARCH, 1, 0));
    emit_ret(&insns[0], &n, SECCOMP_RET_KILL_PROCESS);
    emit(&insns[0], &n, (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)));

#if defined(__x86_64__)
    /* x32 syscalls set __X32_SYSCALL_BIT in the number while still reporting
     * AUDIT_ARCH_X86_64; without this they bypass every deny entry below. */
    emit(&insns[0], &n, (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JGE | BPF_K, 0x40000000U, 0, 1));
    emit_ret(&insns[0], &n, errno_ret(ENOSYS));
#endif

    for (i = 0; i < sizeof(eperm_nrs) / sizeof(eperm_nrs[0]); i++) {
        emit(&insns[0], &n, (struct sock_filter)BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)eperm_nrs[i], 0, 1));
        emit_ret(&insns[0], &n, errno_ret(EPERM));
    }
    for (i = 0; i < sizeof(enosys_nrs) / sizeof(enosys_nrs[0]); i++) {
        emit(&insns[0], &n, (struct sock_filter)BPF_JUMP(
            BPF_JMP | BPF_JEQ | BPF_K, (uint32_t)enosys_nrs[i], 0, 1));
        emit_ret(&insns[0], &n, errno_ret(ENOSYS));
    }

#ifdef __NR_clone
    /* clone(CLONE_NEWUSER) is EPERM; plain clone stays allowed so libc and
     * pthread_create keep working. */
    emit(&insns[0], &n, (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JEQ | BPF_K, __NR_clone, 0, 3));
    emit(&insns[0], &n, (struct sock_filter)BPF_STMT(
        BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0])));
    emit(&insns[0], &n, (struct sock_filter)BPF_JUMP(
        BPF_JMP | BPF_JSET | BPF_K, CLONE_NEWUSER, 0, 1));
    emit_ret(&insns[0], &n, errno_ret(EPERM));
#endif

    emit_ret(&insns[0], &n, SECCOMP_RET_ALLOW);

    prog.len = (unsigned short)n;
    prog.filter = insns;
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog))
        die_errno(EXIT_SECCOMP, "seccomp filter");
}

int main(int argc, char **argv)
{
    struct opts o;
    struct list ro = {0}, rw = {0};
    int *ro_fds = NULL, *rw_fds = NULL, tmp_fd, ruleset_fd;
    int dev_fds[sizeof(dev_nodes) / sizeof(dev_nodes[0])];
    size_t i, ndev = sizeof(dev_nodes) / sizeof(dev_nodes[0]);
    struct ruleset_attr attr;
    const char *tmpdir;
    uint64_t mask;
    int abi;

    if (argc == 1) {
        usage();
        return EXIT_USAGE;
    }
    parse_args(argc, argv, &o);

    /* 1. Resolve and validate all grants before touching identity. */
    for (i = 0; i < o.ro.n; i++)
        push(&ro, resolve_dir("--ro", o.ro.v[i]));
    for (i = 0; i < o.rw.n; i++)
        push(&rw, resolve_dir("--rw", o.rw.v[i]));
    tmpdir = resolve_dir("--tmpdir", o.tmpdir);

    abi = landlock_abi();
    if (o.dry_run || o.print_plan) {
        print_plan(&o, &ro, &rw, tmpdir, abi);
        return 0;
    }
    if (abi <= 0)
        die(EXIT_LANDLOCK, "landlock unavailable (ABI 0)");

    /* 2. Open every grant before the identity change, so the target uid need
     * not be able to traverse the path. */
    if (ro.n) {
        ro_fds = calloc(ro.n, sizeof(*ro_fds));
        if (!ro_fds)
            die_errno(EXIT_LANDLOCK, "calloc");
    }
    for (i = 0; i < ro.n; i++)
        ro_fds[i] = open_grant("--ro", ro.v[i]);
    if (rw.n) {
        rw_fds = calloc(rw.n, sizeof(*rw_fds));
        if (!rw_fds)
            die_errno(EXIT_LANDLOCK, "calloc");
    }
    for (i = 0; i < rw.n; i++)
        rw_fds[i] = open_grant("--rw", rw.v[i]);
    tmp_fd = open_grant("--tmpdir", tmpdir);
    for (i = 0; i < ndev; i++)
        dev_fds[i] = open(dev_nodes[i], O_PATH | O_CLOEXEC);

    /* 3-5. Drop identity (or keep it) and zero capabilities. */
    if (o.have_uid)
        drop_privileges(&o, tmpdir);
    zero_capabilities();

    /* Limits go in now: lowering works unprivileged, and once the target
     * identity is active they can never be raised again. */
    apply_rlimits();

    /* 6. Required for unprivileged Landlock. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
        die_errno(EXIT_LANDLOCK, "prctl(PR_SET_NO_NEW_PRIVS)");

    /* 8. Handled rights and struct size follow the probed ABI. */
    mask = handled_mask(abi);
    memset(&attr, 0, sizeof(attr));
    attr.handled_access_fs = mask;
    if (abi >= 6)
        attr.scoped = LL_SCOPE_ABSTRACT_UNIX_SOCKET | LL_SCOPE_SIGNAL;
    ruleset_fd = (int)syscall(SYS_LL_CREATE, &attr, attr_size(abi), 0);
    if (ruleset_fd < 0)
        die_errno(EXIT_LANDLOCK, "landlock_create_ruleset");

    /* 9. read-only: execute+read; rw/tmpdir: every handled right. */
    for (i = 0; i < ro.n; i++)
        add_rule(ruleset_fd, ro_fds[i], LL_RO_RIGHTS, ro.v[i]);
    for (i = 0; i < rw.n; i++)
        add_rule(ruleset_fd, rw_fds[i], mask, rw.v[i]);
    add_rule(ruleset_fd, tmp_fd, mask, tmpdir);
    for (i = 0; i < ndev; i++) {
        uint64_t rights = LL_READ_FILE | LL_WRITE_FILE;
        if (abi >= 5)
            rights |= LL_IOCTL_DEV;
        if (dev_fds[i] >= 0)
            add_rule(ruleset_fd, dev_fds[i], rights, dev_nodes[i]);
    }

    /* 10. */
    if (syscall(SYS_LL_RESTRICT_SELF, ruleset_fd, 0))
        die_errno(EXIT_LANDLOCK, "landlock_restrict_self");

    /* 11. Seccomp last, after the uid drop and Landlock, so the filter never has
     * to allow setuid/setgid/chown. */
    if (!o.no_seccomp)
        install_seccomp();

    for (i = 0; i < ro.n; i++)
        close(ro_fds[i]);
    for (i = 0; i < rw.n; i++)
        close(rw_fds[i]);
    for (i = 0; i < ndev; i++)
        close(dev_fds[i]);
    close(tmp_fd);
    close(ruleset_fd);

    /* 12. */
    if (setenv("TMPDIR", tmpdir, 1) || setenv("HOME", tmpdir, 1))
        die_errno(EXIT_PRIVDROP, "setenv");

    /* 13. */
    execvp(o.cmd[0], o.cmd);
    {
        int err = errno;

        errno = err; /* die_errno's fputs may clobber it before perror */
        die_errno(err == ENOENT ? 127 : 126, "exec");
    }
}
