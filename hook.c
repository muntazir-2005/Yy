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

#include "mach_excServer.h"

// --- الثوابت ---
#define MAX_HW_BREAKPOINTS 6
#define MAX_HOOKS          64

// --- هيكل الاعتراض ---
typedef struct {
    uintptr_t target_address;
    void     *replacement_ptr;
    int       slot_index;
    bool      active;
} HookEntry;

// --- متغيرات عامة ---
static HookEntry g_hooks[MAX_HOOKS];
static int g_active_slots[MAX_HW_BREAKPOINTS] = {-1,-1,-1,-1,-1,-1};
static int g_total_registered = 0;
static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;

static mach_port_t g_exc_port = MACH_PORT_NULL;
static pthread_t   g_server_thread;
static atomic_bool g_server_running = false;

// --- إعلان الدوال المساعدة ---
__attribute__((used)) static void hook_trampoline_handler(int hook_index);

// --- دالة الـ Trampoline glue (تحفظ السياق وتستدعي handler) ---
__attribute__((naked, used)) static void hook_trampoline_glue(void) {
    __asm volatile(
        "stp x29, x30, [sp, #-16]!\n\t"
        "bl  _hook_trampoline_handler\n\t"
        "ldp x29, x30, [sp], #16\n\t"
        "ret\n"
    );
}

// --- المُعالج الوسيط (تعطيل نقطة التوقف، استدعاء البديل، إعادة التفعيل) ---
__attribute__((used)) static void hook_trampoline_handler(int hook_index) {
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

    arm_debug_state64_t debug_state;
    mach_msg_type_number_t count = ARM_DEBUG_STATE64_COUNT;
    thread_act_t cur_thread = mach_thread_self();
    if (thread_get_state(cur_thread, ARM_DEBUG_STATE64, (thread_state_t)&debug_state, &count) == KERN_SUCCESS) {
        debug_state.__bcr[slot] = 0;
        thread_set_state(cur_thread, ARM_DEBUG_STATE64, (thread_state_t)&debug_state, count);
    }
    mach_port_deallocate(mach_task_self(), cur_thread);
    os_unfair_lock_unlock(&g_lock);

    void (*replacement)(void) = (void(*)(void))hook->replacement_ptr;
    replacement();

    os_unfair_lock_lock(&g_lock);
    cur_thread = mach_thread_self();
    if (thread_get_state(cur_thread, ARM_DEBUG_STATE64, (thread_state_t)&debug_state, &count) == KERN_SUCCESS) {
        debug_state.__bcr[slot] = 0x1e5;
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

static HookEntry *find_hook_locked(uintptr_t target) {
    for (int i = 0; i < g_total_registered; i++)
        if (g_hooks[i].target_address == target) return &g_hooks[i];
    return NULL;
}

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

static void activate_pending_hooks_locked(void) {
    for (int i = 0; i < g_total_registered; i++) {
        if (!g_hooks[i].active) {
            for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
                if (g_active_slots[slot] == -1) {
                    g_active_slots[slot] = i;
                    g_hooks[i].active = true;
                    g_hooks[i].slot_index = slot;
                    return;
                }
            }
        }
    }
}

// --- خادم الاستثناءات ---
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
            nstate->__x[0] = i;
            arm_thread_state64_set_pc_fptr(*nstate, &hook_trampoline_glue);
            os_unfair_lock_unlock(&g_lock);
            return KERN_SUCCESS;
        }
    }
    os_unfair_lock_unlock(&g_lock);
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise(
    mach_port_t ep, mach_port_t th, mach_port_t t,
    exception_type_t e, mach_exception_data_t c, mach_msg_type_number_t cc) {
    (void)ep;(void)th;(void)t;(void)e;(void)c;(void)cc;
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t ep, mach_port_t th, mach_port_t t,
    exception_type_t e, mach_exception_data_t c, mach_msg_type_number_t cc,
    int *fl, thread_state_t os, mach_msg_type_number_t osc,
    thread_state_t ns, mach_msg_type_number_t *nsc) {
    (void)ep;(void)th;(void)t;(void)e;(void)c;(void)cc;
    (void)fl;(void)os;(void)osc;(void)ns;(void)nsc;
    return KERN_FAILURE;
}

static void *exception_server_thread(void *arg) {
    (void)arg;
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
    if (find_hook_locked(clean) || g_total_registered >= MAX_HOOKS) {
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
    int found_idx = -1;
    for (int i = 0; i < g_total_registered; i++) {
        if (g_hooks[i].target_address == clean) { found_idx = i; break; }
    }
    if (found_idx == -1) { os_unfair_lock_unlock(&g_lock); return false; }

    HookEntry *found = &g_hooks[found_idx];
    if (found->active && found->slot_index != -1)
        g_active_slots[found->slot_index] = -1;

    if (found_idx < g_total_registered - 1)
        memmove(&g_hooks[found_idx], &g_hooks[found_idx+1],
                (g_total_registered - found_idx - 1)*sizeof(HookEntry));
    g_total_registered--;

    for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
        int idx = g_active_slots[slot];
        if (idx > found_idx) g_active_slots[slot] = idx - 1;
    }

    activate_pending_hooks_locked();
    os_unfair_lock_unlock(&g_lock);
    build_and_apply_debug_state();
    return true;
}

bool hook_pause_all(void) {
    arm_debug_state64_t ds;
    memset(&ds, 0, sizeof(ds));
    os_unfair_lock_lock(&g_lock);
    for (int s=0; s<MAX_HW_BREAKPOINTS; s++) {
        int idx = g_active_slots[s];
        if (idx != -1) {
            ds.__bvr[s] = g_hooks[idx].target_address;
            ds.__bcr[s] = 0x1e4;
        }
    }
    os_unfair_lock_unlock(&g_lock);

    thread_act_array_t ths; mach_msg_type_number_t cnt;
    if (task_threads(mach_task_self(), &ths, &cnt) == KERN_SUCCESS) {
        for (mach_msg_type_number_t i=0; i<cnt; i++) {
            thread_set_state(ths[i], ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT);
            mach_port_deallocate(mach_task_self(), ths[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)ths, cnt*sizeof(thread_act_t));
    }
    return true;
}

bool hook_resume_all(void) {
    build_and_apply_debug_state();
    return true;
}

bool hook_init(void) {
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        if (info.kp_proc.p_flag & P_TRACED) {
            fprintf(stderr, "[Hook] Debugger detected.\n");
            return false;
        }
    }

    if (g_exc_port != MACH_PORT_NULL) return true;

    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port) != KERN_SUCCESS) return false;
    if (mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) return false;

    if (task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, g_exc_port,
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

    arm_debug_state64_t ds;
    memset(&ds, 0, sizeof(ds));
    thread_act_array_t ths; mach_msg_type_number_t cnt;
    if (task_threads(mach_task_self(), &ths, &cnt) == KERN_SUCCESS) {
        for (mach_msg_type_number_t i=0; i<cnt; i++) {
            thread_set_state(ths[i], ARM_DEBUG_STATE64, (thread_state_t)&ds, ARM_DEBUG_STATE64_COUNT);
            mach_port_deallocate(mach_task_self(), ths[i]);
        }
        vm_deallocate(mach_task_self(), (vm_address_t)ths, cnt*sizeof(thread_act_t));
    }

    os_unfair_lock_lock(&g_lock);
    memset(g_hooks, 0, sizeof(g_hooks));
    for (int i=0; i<MAX_HW_BREAKPOINTS; i++) g_active_slots[i] = -1;
    g_total_registered = 0;
    os_unfair_lock_unlock(&g_lock);
}
