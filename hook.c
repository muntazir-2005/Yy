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
    for (int i = 0; i < g_count; i++)
        if (g_hooks[i].slot == slot) return i;
    return -1;
}

static bool is_replacement_of_another_hook(void *candidate) {
    for (int i = 0; i < g_count; i++)
        if (g_hooks[i].active && g_hooks[i].repl == candidate) return true;
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

// (باقي دوال Function Table كما هي: hook_uninstall, hook_is_installed, ...)
// ... أختصرها هنا للاختصار، لكنها موجودة في النسخة الكاملة ...

bool hook_uninstall(void *slot) { /* ... */ }
bool hook_is_installed(void *slot) { /* ... */ }
bool hook_is_active(void *slot) { /* ... */ }
int hook_count(void) { return g_count; }
bool hook_pause_all(void) { /* ... */ }
bool hook_resume_all(void) { /* ... */ }
void hook_deinit(void) { /* ... */ }

// ============================================================
//        قسم Symbol Hooking الآمن (بديل fishhook)
// ============================================================

// إزالة بتات PAC من مؤشر
static inline void *strip_pac_ptr(void *ptr) {
#if defined(__arm64e__)
    return ptrauth_strip(ptr, ptrauth_key_asia);
#else
    return ptr;
#endif
}

// دالة لاعتراض دالة C معينة عن طريق رمزها
// تعمل مثل rebind_symbols لكن آمنة وتفحص الوجود
static bool hook_c_symbol(const char *symbol, void *replacement, void **original) {
    if (!symbol || !replacement || !original) return false;

    // البحث عن الرمز في المكتبات المحملة
    void *addr = dlsym(RTLD_DEFAULT, symbol);
    if (!addr) return false; // الرمز غير موجود، لا نحاول

    // إزالة PAC إذا كان ARM64e
    addr = strip_pac_ptr(addr);

    // نحتاج للوصول إلى مؤشر الرمز في __DATA,__la_symbol_ptr
    // نستخدم _dyld API للعثور على مؤشر الرمز غير المباشر
    uint32_t count = _dyld_image_count();
    for (uint32_t i = 0; i < count; i++) {
        const struct mach_header *header = _dyld_get_image_header(i);
        if (!header) continue;

        // نبحث في هذا الملف عن العنوان الذي يطابق addr
        const char *image_name = _dyld_get_image_name(i);
        void *symbol_ptr = NULL;

        // نحتاج إلى استخدام dlsym مرة أخرى للحصول على المؤشر الحقيقي القابل للتخزين (indirect pointer)
        // لكن هذا معقد. سنستخدم طريقة أبسط: نعثر على القيمة المخزنة حالياً في __la_symbol_ptr
        // عبر استخدام symbol_ptr = dlsym(RTLD_SELF, symbol) لكن هذا يعيد نفس العنوان.
        // لذلك نستخدم آلية "Atomic exchange" على المؤشر الذي نعرفه من عنوان المقطع.
        // هنا سنبسط ونفترض أن التطبيق مرتبط بالرمز المطلوب، ونبحث يدويًا.

        // الحل المبسط: نفحص جميع مقاطع البيانات في الصورة بحثًا عن عنوان مطابق.
        if (header->magic == MH_MAGIC_64 || header->magic == MH_CIGAM_64) {
            struct mach_header_64 *mh = (struct mach_header_64 *)header;
            struct load_command *lc = (struct load_command *)(mh + 1);
            for (uint32_t j = 0; j < mh->ncmds; j++) {
                if (lc->cmd == LC_SEGMENT_64) {
                    struct segment_command_64 *seg = (struct segment_command_64 *)lc;
                    if (strcmp(seg->segname, "__DATA") == 0) {
                        // نبحث في sections
                        struct section_64 *sect = (struct section_64 *)(seg + 1);
                        for (uint32_t k = 0; k < seg->nsects; k++) {
                            if (strcmp(sect->sectname, "__la_symbol_ptr") == 0) {
                                uintptr_t base = (uintptr_t)_dyld_get_image_vmaddr_slide(i) + sect->addr;
                                size_t size = sect->size;
                                void **pointers = (void **)base;
                                size_t num = size / sizeof(void*);
                                for (size_t p = 0; p < num; p++) {
                                    if (strip_pac_ptr(pointers[p]) == addr) {
                                        // وجدنا المؤشر غير المباشر!
                                        symbol_ptr = &pointers[p];
                                        break;
                                    }
                                }
                                if (symbol_ptr) break;
                            }
                            sect++;
                        }
                    }
                }
                lc = (struct load_command *)((uint8_t *)lc + lc->cmdsize);
            }
        }
        if (symbol_ptr) {
            // استبدال المؤشر بقفل ذري
            void *old_val = atomic_exchange_explicit((_Atomic(void*)*)symbol_ptr, replacement, memory_order_acq_rel);
            *original = old_val;
            return true;
        }
    }

    return false; // لم نجد المؤشر
}

// ============================================================
//                دوال AntiBan (باستخدام Symbol Hooking الجديد)
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
    return true; // لم تُفعّل حتى نحصل على التواقيع
}

bool hook_antiban_install_all(void) {
    return hook_antiban_install_syscalls() && hook_antiban_install_security();
}
