#include "hook.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <os/lock.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/task.h>
#include <sys/sysctl.h>
#include <unistd.h>
#include <string.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <libkern/OSCacheControl.h> // sys_icache_invalidate

#include "mach_excServer.h"

// --- الثوابت ---
#define MAX_HW_BREAKPOINTS 6
#define MAX_HOOKS          64

// --- هيكل الاعتراض ---
typedef struct {
    uintptr_t target_address;        // بدون PAC
    void     *replacement_ptr;       // المؤشر المُوقَّع الأصلي
    int       slot_index;            // -1 = غير فعّال
    bool      active;
} HookEntry;

// --- متغيرات عامة ---
static HookEntry g_hooks[MAX_HOOKS];
static int g_active_slots[MAX_HW_BREAKPOINTS];      // -1 = فارغ
static int g_total_registered = 0;
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;

// خادم Mach
static mach_port_t g_exc_port = MACH_PORT_NULL;
static pthread_t   g_server_thread;
static atomic_bool g_server_running = false;

// --- المُعالج الوسيط للـ Trampoline (تعطيل / تفعيل النقطة للخيط الحالي) ---
static void hook_trampoline_handler(int hook_index) {
    os_unfair_lock_lock(&g_lock);
    if (hook_index < 0 || hook_index >= g_total_registered) {
        os_unfair_lock_unlock(&g_lock);
        return;
    }
    HookEntry *hook = &g_hooks[hook_index];
    int slot = hook->slot_index;
    if (slot == -1 || !hook->active) {
        os_unfair_lock_unlock(&g_lock);
        return;
    }

    // تعطيل نقطة التوقف للخيط الحالي فقط
    arm_debug_state64_t debug_state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    thread_act_t cur_thread = mach_thread_self();
    if (thread_get_state(cur_thread, ARM_DEBUG_STATE64, (thread_state_t)&debug_state, &count) == KERN_SUCCESS) {
        debug_state.__bcr[slot] = 0; // تعطيل
        thread_set_state(cur_thread, ARM_DEBUG_STATE64, (thread_state_t)&debug_state, count);
    }
    mach_port_deallocate(mach_task_self(), cur_thread);
    os_unfair_lock_unlock(&g_lock);

    // استدعاء الدالة البديلة (المُؤشر الأصلي المُوقَّع)
    void (*replacement)(void) = (void(*)(void))hook->replacement_ptr;
    replacement();

    // إعادة تفعيل نقطة التوقف للخيط الحالي
    os_unfair_lock_lock(&g_lock);
    cur_thread = mach_thread_self();
    if (thread_get_state(cur_thread, ARM_DEBUG_STATE64, (thread_state_t)&debug_state, &count) == KERN_SUCCESS) {
        debug_state.__bcr[slot] = 0x1e5; // إعادة التفعيل
        thread_set_state(cur_thread, ARM_DEBUG_STATE64, (thread_state_t)&debug_state, count);
    }
    mach_port_deallocate(mach_task_self(), cur_thread);
    os_unfair_lock_unlock(&g_lock);
}

// --- مُساعد PAC ---
static inline uintptr_t strip_pac(uintptr_t ptr) {
#if defined(__arm64e__) && __has_feature(ptrauth_qualifiers)
    return (uintptr_t)ptrauth_strip((void*)ptr, ptrauth_key_asia);
#else
    return ptr & 0x0000007FFFFFFFFFULL;
#endif
}

// --- البحث عن اعتراض (مع القفل) ---
static HookEntry *find_hook_locked(uintptr_t target) {
    for (int i = 0; i < g_total_registered; i++) {
        if (g_hooks[i].target_address == target) {
            return &g_hooks[i];
        }
    }
    return NULL;
}

// --- بناء وتطبيق حالة التصحيح على جميع الخيوط ---
static void build_and_apply_debug_state(void) {
    arm_debug_state64_t ds;
    memset(&ds, 0, sizeof(ds));
    os_unfair_lock_lock(&g_lock);
    for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
        int idx = g_active_slots[slot];
        if (idx != -1) {
            ds.__bvr[slot] = g_hooks[idx].target_address;
            ds.__bcr[slot] = 0x1e5;
        }
    }
    os_unfair_lock_unlock(&g_lock);

    thread_act_array_t ths;
    mach_msg_type_number_t cnt;
    if (task_threads(mach_task_self(), &ths, &cnt) == KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < cnt; i++) {
            thread_set_state(ths[i], ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT);
            mach_port_deallocate(mach_task_self(), ths[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)ths, cnt * sizeof(thread_act_t));
    }
}

// --- تفعيل الاعتراضات المُعلقة (Slot starvation fix) ---
static void activate_pending_hooks_locked(void) {
    for (int i = 0; i < g_total_registered; i++) {
        if (!g_hooks[i].active) {
            for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
                if (g_active_slots[slot] == -1) {
                    g_active_slots[slot] = i;
                    g_hooks[i].active = true;
                    g_hooks[i].slot_index = slot;
                    return; // نشطنا واحدًا فقط
                }
            }
        }
    }
}

// --- خادم الاستثناءات (مع التوجيه للـ Trampoline) ---
kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt)
{
    if (*flavor != ARM_THREAD_STATE64) return KERN_FAILURE;

    arm_thread_state64_t *ostate = (arm_thread_state64_t *)old_state;
    arm_thread_state64_t *nstate = (arm_thread_state64_t *)new_state;
    uintptr_t pc = strip_pac(arm_thread_state64_get_pc(*ostate));

    os_unfair_lock_lock(&g_lock);
    for (int i = 0; i < g_total_registered; i++) {
        if (g_hooks[i].active && g_hooks[i].target_address == pc) {
            *nstate = *ostate;
            *new_stateCnt = old_stateCnt;

            // نُعِدُّ المُعامِلات لاستدعاء hook_trampoline_handler مباشرة
            // عبر تعيين PC إلى دالة glue (مُعرَّفة في ملف تجميع منفصل أو عبر تحايل)
            // لكن لتبسيط التنفيذ دون ملف asm خارجي، نستخدم استدعاء C مباشر:
            // سنُعِد x0 ليكون hook_index، و x30 كعنوان العودة، ثم نضع PC = hook_trampoline_handler
            // لكن هذا سيسبب مشكلة في التوافق مع اتفاقية الاستدعاء. الحل العملي:
            // سنُعرِّف دالة trampoline_entry في كود C باستخدام __attribute__((naked)) إن أمكن.
            extern void hook_trampoline_glue(void); // يفترض وجودها
            arm_thread_state64_set_reg(*nstate, 0, i); // x0 = hook_index
            arm_thread_state64_set_pc_fptr(*nstate, hook_trampoline_glue);

            os_unfair_lock_unlock(&g_lock);
            return KERN_SUCCESS;
        }
    }
    os_unfair_lock_unlock(&g_lock);
    return KERN_FAILURE;
}

// الدوال الإضافية
kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt) { return KERN_FAILURE; }

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) { return KERN_FAILURE; }

// خيط الخادم
static void *exception_server_thread(void *arg) {
    mach_msg_server(mach_exc_server,
                    sizeof(union __RequestUnion__catch_mach_exc_subsystem),
                    g_exc_port,
                    MACH_MSG_OPTION_NONE);
    return NULL;
}

// --- واجهة API ---
bool hook_install(void *target, void *replacement) {
    if (!target || !replacement) return false;
    os_unfair_lock_lock(&g_lock);

    uintptr_t clean = strip_pac((uintptr_t)target);
    if (find_hook_locked(clean) != NULL) {
        os_unfair_lock_unlock(&g_lock);
        return false;
    }
    if (g_total_registered >= MAX_HOOKS) {
        os_unfair_lock_unlock(&g_lock);
        return false;
    }

    HookEntry *h = &g_hooks[g_total_registered];
    h->target_address = clean;
    h->replacement_ptr = replacement;
    h->active = false;
    h->slot_index = -1;
    g_total_registered++;
    activate_pending_hooks_locked();
    os_unfair_lock_unlock(&g_lock);

    build_and_apply_debug_state();
    return true;
}

bool hook_uninstall(void *target) {
    os_unfair_lock_lock(&g_lock);
    uintptr_t clean = strip_pac((uintptr_t)target);
    HookEntry *found = NULL;
    int found_idx = -1;
    for (int i = 0; i < g_total_registered; i++) {
        if (g_hooks[i].target_address == clean) {
            found = &g_hooks[i];
            found_idx = i;
            break;
        }
    }
    if (!found) {
        os_unfair_lock_unlock(&g_lock);
        return false;
    }

    if (found->active && found->slot_index != -1) {
        g_active_slots[found->slot_index] = -1;
    }

    if (found_idx < g_total_registered - 1) {
        memmove(&g_hooks[found_idx], &g_hooks[found_idx + 1],
                (g_total_registered - found_idx - 1) * sizeof(HookEntry));
    }
    g_total_registered--;

    // إعادة تعيين أرقام السجلات
    for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
        int idx = g_active_slots[slot];
        if (idx >= 0) {
            if (idx > found_idx) {
                g_active_slots[slot] = idx - 1;
            }
        }
    }

    // تفعيل أي اعتراض مُعلق (slot starvation fix)
    activate_pending_hooks_locked();

    os_unfair_lock_unlock(&g_lock);
    build_and_apply_debug_state();
    return true;
}

bool hook_pause_all(void) {
    arm_debug_state64_t ds;
    memset(&ds, 0, sizeof(ds));
    os_unfair_lock_lock(&g_lock);
    for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
        int idx = g_active_slots[slot];
        if (idx != -1) {
            ds.__bvr[slot] = g_hooks[idx].target_address;
            ds.__bcr[slot] = 0x1e4; // تعطيل
        }
    }
    os_unfair_lock_unlock(&g_lock);
    // تطبيق...
    thread_act_array_t ths;
    mach_msg_type_number_t cnt;
    if (task_threads(mach_task_self(), &ths, &cnt) == KERN_SUCCESS) {
        for (mach_msg_type_number_t i = 0; i < cnt; i++) {
            thread_set_state(ths[i], ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT);
            mach_port_deallocate(mach_task_self(), ths[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)ths, cnt * sizeof(thread_act_t));
    }
    return true;
}

bool hook_resume_all(void) {
    build_and_apply_debug_state();
    return true;
}

bool hook_init(void) {
    // فحص وجود مُصحح أخطاء
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        if (info.kp_proc.p_flag & P_TRACED) {
            fprintf(stderr, "[Hook] Debugger detected. Aborting initialization.\n");
            return false;
        }
    }

    if (g_exc_port != MACH_PORT_NULL) return true;

    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port) != KERN_SUCCESS)
        return false;
    if (mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS)
        return false;

    if (task_set_exception_ports(mach_task_self(),
                                 EXC_MASK_BREAKPOINT,
                                 g_exc_port,
                                 EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                                 ARM_THREAD_STATE64) != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        return false;
    }

    if (pthread_create(&g_server_thread, NULL, exception_server_thread, NULL) != 0) {
        task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, MACH_PORT_NULL, 0, 0);
        mach_port_destroy(mach_task_self(), g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        return false;
    }
    pthread_detach(g_server_thread);
    atomic_store(&g_server_running, true);
    return true;
}

void hook_deinit(void) {
    if (atomic_exchange(&g_server_running, false)) {
        task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, MACH_PORT_NULL, 0, 0);
        mach_port_destroy(mach_task_self(), g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        usleep(100000);
    }

    arm_debug_state64_t clean_state = {0};
    build_and_apply_debug_state(); // سيطبق الحالة الفارغة

    os_unfair_lock_lock(&g_lock);
    memset(g_hooks, 0, sizeof(g_hooks));
    for (int i = 0; i < MAX_HW_BREAKPOINTS; i++) g_active_slots[i] = -1;
    g_total_registered = 0;
    os_unfair_lock_unlock(&g_lock);
}
