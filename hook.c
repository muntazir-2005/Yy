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
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>

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
//        قسم Symbol Hooking الآمن (بديل fishhook)
// ============================================================

static inline void *strip_pac_ptr(void *ptr) {
#if defined(__arm64e__)
    return ptrauth_strip(ptr, ptrauth_key_asia);
#else
    return ptr;
#endif
}

static bool hook_c_symbol(const char *symbol, void *replacement, void **original) {
    if (!symbol || !replacement || !original) return false;

    void *addr = dlsym(RTLD_DEFAULT, symbol);
    if (!addr) return false;

    addr = strip_pac_ptr(addr);

    Dl_info info;
    if (dladdr(addr, &info) == 0) return false;

    // نفحص فقط الصورة التي تحوي الدالة
    uint32_t image_idx = UINT32_MAX;
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        if (_dyld_get_image_header(i) == info.dli_fbase) {
            image_idx = i;
            break;
        }
    }
    if (image_idx == UINT32_MAX) return false;

    const struct mach_header_64 *header = (const struct mach_header_64 *)info.dli_fbase;
    struct load_command *lc = (struct load_command *)(header + 1);
    intptr_t slide = _dyld_get_image_vmaddr_slide(image_idx);

    for (uint32_t i = 0; i < header->ncmds; i++) {
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *seg = (struct segment_command_64 *)lc;
            if (strcmp(seg->segname, "__DATA") == 0) {
                struct section_64 *sect = (struct section_64 *)(seg + 1);
                for (uint32_t j = 0; j < seg->nsects; j++) {
                    if (strcmp(sect->sectname, "__la_symbol_ptr") == 0) {
                        uintptr_t base = slide + sect->addr;
                        size_t num = sect->size / sizeof(void*);
                        void **pointers = (void **)base;
                        for (size_t k = 0; k < num; k++) {
                            void *candidate = pointers[k];
                            if (strip_pac_ptr(candidate) == addr) {
                                // وجدنا المؤشر: استبدله
                                void *old = atomic_exchange_explicit(
                                    (_Atomic(void*)*)&pointers[k], replacement,
                                    memory_order_acq_rel);
                                *original = old;
                                return true;
                            }
                        }
                    }
                    sect++;
                }
            }
        }
        lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
    }

    return false;
}

// ============================================================
//                دوال AntiBan (باستخدام hook_c_symbol)
// ============================================================

static const char *fake_model = "iPhone14,2";
static const char *fake_osversion = "17.4.1";
static const char *fake_machine = "arm64";

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
        } else if (strcmp(name, "kern.osversion") == 0) {
            size_t len = strlen(fake_osversion) + 1;
            if (*oldlenp >= len) {
                memcpy(oldp, fake_osversion, len);
                *oldlenp = len;
                return 0;
            }
        } else if (strcmp(name, "hw.machine") == 0) {
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

bool hook_antiban_install_syscalls(void) {
    bool ok = true;
    ok = ok && hook_c_symbol("sysctlbyname", (void *)fake_sysctlbyname, (void **)&orig_sysctlbyname);
    ok = ok && hook_c_symbol("sysctl",       (void *)fake_sysctl,       (void **)&orig_sysctl);
    ok = ok && hook_c_symbol("uname",        (void *)fake_uname,        (void **)&orig_uname);
    ok = ok && hook_c_symbol("statfs",       (void *)fake_statfs,       (void **)&orig_statfs);
    return ok;
}

bool hook_antiban_install_security(void) {
    // معطلة مؤقتاً لحين استخراج التوقيعات الصحيحة
    return true;
}

bool hook_antiban_install_all(void) {
    return hook_antiban_install_syscalls() && hook_antiban_install_security();
}
