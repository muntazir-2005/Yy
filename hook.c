#include "hook.h"
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <os/lock.h>
#include <sys/sysctl.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <stdlib.h>

// تضمين fishhook من داخل المشروع (تأكد من وجود fishhook.h و fishhook.c)
#include "fishhook.h"

// ============================================================
//                قسم Function Table Hooking
// ============================================================
#define MAX_HOOKS 64

typedef struct {
    _Atomic(void*) *slot;
    void *orig;
    void *repl;
    bool active;
} hook_entry_t;

static hook_entry_t g_hooks[MAX_HOOKS];
static int g_count = 0;
static bool g_paused = false;
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;

static int find_index(_Atomic(void*) *slot) {
    for (int i = 0; i < g_count; i++) {
        if (g_hooks[i].slot == slot) return i;
    }
    return -1;
}

static bool is_replacement_of_another_hook(void *candidate) {
    for (int i = 0; i < g_count; i++) {
        if (g_hooks[i].active && g_hooks[i].repl == candidate) return true;
    }
    return false;
}

bool hook_init(void) {
    os_unfair_lock_lock(&g_lock);
    g_count = 0;
    g_paused = false;
    os_unfair_lock_unlock(&g_lock);
    return true;
}

bool hook_install(void *slot, void *replacement, void **original_out) {
    if (!slot || !replacement || !original_out) return false;
    _Atomic(void*) *atomic_slot = (_Atomic(void*)*)slot;

    os_unfair_lock_lock(&g_lock);
    int idx = find_index(atomic_slot);
    if (idx >= 0) {
        *original_out = g_hooks[idx].orig;
        g_hooks[idx].repl = replacement;
        if (!g_paused) {
            atomic_store_explicit(atomic_slot, replacement, memory_order_release);
            g_hooks[idx].active = true;
        }
        os_unfair_lock_unlock(&g_lock);
        return true;
    }

    if (g_count >= MAX_HOOKS) {
        os_unfair_lock_unlock(&g_lock);
        return false;
    }

    void *current = atomic_load_explicit(atomic_slot, memory_order_acquire);
    if (is_replacement_of_another_hook(current)) {
        os_unfair_lock_unlock(&g_lock);
        return false;
    }

    *original_out = current;
    g_hooks[g_count++] = (hook_entry_t){
        .slot = atomic_slot,
        .orig = current,
        .repl = replacement,
        .active = !g_paused
    };
    if (!g_paused) {
        atomic_store_explicit(atomic_slot, replacement, memory_order_release);
    }
    os_unfair_lock_unlock(&g_lock);
    return true;
}

bool hook_uninstall(void *slot) {
    if (!slot) return false;
    _Atomic(void*) *atomic_slot = (_Atomic(void*)*)slot;

    os_unfair_lock_lock(&g_lock);
    int idx = find_index(atomic_slot);
    if (idx < 0) {
        os_unfair_lock_unlock(&g_lock);
        return false;
    }

    void *current = atomic_load_explicit(atomic_slot, memory_order_acquire);
    if (current == g_hooks[idx].repl) {
        atomic_store_explicit(atomic_slot, g_hooks[idx].orig, memory_order_release);
    }
    g_hooks[idx] = g_hooks[--g_count];
    os_unfair_lock_unlock(&g_lock);
    return true;
}

bool hook_is_installed(void *slot) {
    if (!slot) return false;
    _Atomic(void*) *atomic_slot = (_Atomic(void*)*)slot;
    os_unfair_lock_lock(&g_lock);
    int idx = find_index(atomic_slot);
    bool result = (idx >= 0);
    os_unfair_lock_unlock(&g_lock);
    return result;
}

bool hook_is_active(void *slot) {
    if (!slot) return false;
    _Atomic(void*) *atomic_slot = (_Atomic(void*)*)slot;
    os_unfair_lock_lock(&g_lock);
    int idx = find_index(atomic_slot);
    bool result = (idx >= 0) && g_hooks[idx].active && !g_paused;
    os_unfair_lock_unlock(&g_lock);
    return result;
}

int hook_count(void) {
    os_unfair_lock_lock(&g_lock);
    int c = g_count;
    os_unfair_lock_unlock(&g_lock);
    return c;
}

bool hook_pause_all(void) {
    os_unfair_lock_lock(&g_lock);
    g_paused = true;
    for (int i = 0; i < g_count; i++) {
        atomic_store_explicit(g_hooks[i].slot, g_hooks[i].orig, memory_order_release);
        g_hooks[i].active = false;
    }
    os_unfair_lock_unlock(&g_lock);
    return true;
}

bool hook_resume_all(void) {
    os_unfair_lock_lock(&g_lock);
    g_paused = false;
    for (int i = 0; i < g_count; i++) {
        atomic_store_explicit(g_hooks[i].slot, g_hooks[i].repl, memory_order_release);
        g_hooks[i].active = true;
    }
    os_unfair_lock_unlock(&g_lock);
    return true;
}

void hook_deinit(void) {
    os_unfair_lock_lock(&g_lock);
    for (int i = 0; i < g_count; i++) {
        void *current = atomic_load_explicit(g_hooks[i].slot, memory_order_acquire);
        if (current == g_hooks[i].repl) {
            atomic_store_explicit(g_hooks[i].slot, g_hooks[i].orig, memory_order_release);
        }
    }
    g_count = 0;
    g_paused = false;
    os_unfair_lock_unlock(&g_lock);
}

// ============================================================
//                قسم AntiBan (باستخدام fishhook)
// ============================================================

// --- قيم مزيفة ---
static const char *fake_model = "iPhone14,2";
static const char *fake_osversion = "17.4.1";
static const char *fake_machine = "arm64";

// --- اعتراضات sysctl / uname / statfs ---
static int (*orig_sysctlbyname)(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int fake_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if (name && oldp && oldlenp) {
        if (strcmp(name, "hw.model") == 0) {
            size_t len = strlen(fake_model) + 1;
            if (*oldlenp >= len) {
                memcpy(oldp, fake_model, len);
                *oldlenp = len;
                return 0;
            }
        }
        if (strcmp(name, "kern.osversion") == 0) {
            size_t len = strlen(fake_osversion) + 1;
            if (*oldlenp >= len) {
                memcpy(oldp, fake_osversion, len);
                *oldlenp = len;
                return 0;
            }
        }
        if (strcmp(name, "hw.machine") == 0) {
            size_t len = strlen(fake_machine) + 1;
            if (*oldlenp >= len) {
                memcpy(oldp, fake_machine, len);
                *oldlenp = len;
                return 0;
            }
        }
    }
    return orig_sysctlbyname(name, oldp, oldlenp, newp, newlen);
}

static int (*orig_sysctl)(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen);
static int fake_sysctl(int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    return orig_sysctl(name, namelen, oldp, oldlenp, newp, newlen);
}

static int (*orig_uname)(struct utsname *);
static int fake_uname(struct utsname *u) {
    int ret = orig_uname(u);
    if (ret == 0 && u) {
        strlcpy(u->machine, fake_machine, sizeof(u->machine));
        strlcpy(u->sysname, "Darwin", sizeof(u->sysname));
        strlcpy(u->release, "22.5.0", sizeof(u->release));
        strlcpy(u->version, "Darwin Kernel Version 22.5.0: ...", sizeof(u->version));
    }
    return ret;
}

static int (*orig_statfs)(const char *, struct statfs *);
static int fake_statfs(const char *path, struct statfs *buf) {
    int ret = orig_statfs(path, buf);
    if (ret == 0 && buf) {
        if (strcmp(path, "/private/var") == 0 ||
            strcmp(path, "/jb") == 0 ||
            strcmp(path, "/.mount_rw") == 0) {
            return -1;
        }
    }
    return ret;
}

// --- اعتراضات فئات ABase الأمنية (يجب التحقق من الأسماء الصحيحة باستخدام nm) ---
static void dummy_security_imp() {}
static void dummy_security_store() {}
static void dummy_encrypted_json() {}
static void dummy_encrypted_ini() {}
static void dummy_log_crypt() {}

bool hook_antiban_install_syscalls(void) {
    struct rebinding rebindings[] = {
        {"sysctlbyname", (void *)fake_sysctlbyname, (void **)&orig_sysctlbyname},
        {"sysctl",       (void *)fake_sysctl,       (void **)&orig_sysctl},
        {"uname",        (void *)fake_uname,        (void **)&orig_uname},
        {"statfs",       (void *)fake_statfs,       (void **)&orig_statfs},
    };
    if (rebind_symbols(rebindings, sizeof(rebindings)/sizeof(rebindings[0])) < 0) {
        return false;
    }
    return true;
}

bool hook_antiban_install_security(void) {
    // الأسماء المُشوَّهة (Mangled names) لفئات ABase – تأكد من صحتها مع لعبتك
    struct rebinding rebindings[] = {
        {"_ZN5ABase16SecurityStoreImpE",      (void *)dummy_security_imp,    NULL},
        {"_ZN5ABase13SecurityStoreE",         (void *)dummy_security_store,  NULL},
        {"_ZN5ABase21EncryptedJsonFileImplE", (void *)dummy_encrypted_json, NULL},
        {"_ZN5ABase20EncryptedIniFileImplE",  (void *)dummy_encrypted_ini,  NULL},
        {"_ZN5ABase8LogCryptE",               (void *)dummy_log_crypt,      NULL},
    };
    if (rebind_symbols(rebindings, sizeof(rebindings)/sizeof(rebindings[0])) < 0) {
        return false;
    }
    return true;
}

bool hook_antiban_install_all(void) {
    bool ok1 = hook_antiban_install_syscalls();
    bool ok2 = hook_antiban_install_security();
    return ok1 && ok2;
}
