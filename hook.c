#include "hook.h"
#include "mach_excServer.h"

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/sysctl.h>

#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

// متغيرات النظام العامة
static struct hook_info g_hooks[MAX_HW_HOOKS];
static int g_active_count = 0;
static mach_port_t g_server_port = MACH_PORT_NULL;

// دالة تنظيف بتات PAC لمعالجات ARM64e
static inline uintptr_t strip_pac_bits(uintptr_t ptr) {
#if defined(__arm64e__) && __has_feature(ptrauth_qualifiers)
    return (uintptr_t)ptrauth_strip((void *)ptr, ptrauth_key_asia);
#else
    return ptr & 0x0000007FFFFFFFFFULL;
#endif
}

// implementation لدالة catch_mach_exception_raise_state المطلوبة من mach_excServer.h
kern_return_t catch_mach_exception_raise_state(
    mach_port_t exception_port,
    exception_type_t exception,
    const mach_exception_data_t code,
    mach_msg_type_number_t codeCnt,
    int *flavor,
    const thread_state_t old_state,
    mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state,
    mach_msg_type_number_t *new_stateCnt) {

    if (*flavor != ARM_THREAD_STATE64) {
        return KERN_FAILURE;
    }

    arm_thread_state64_t *state_old = (arm_thread_state64_t *)old_state;
    arm_thread_state64_t *state_new = (arm_thread_state64_t *)new_state;

    // استخراج PC بدون توقيع PAC
    uintptr_t current_pc = strip_pac_bits((uintptr_t)arm_thread_state64_get_pc(*state_old));

    for (int i = 0; i < g_active_count; ++i) {
        if (g_hooks[i].target_address == current_pc) {
            *state_new = *state_old;
            *new_stateCnt = old_stateCnt;

            // توجيه المسجل PC إلى الدالة البديلة
            arm_thread_state64_set_pc_fptr(*state_new, (void *)g_hooks[i].replacement_address);
            return KERN_SUCCESS;
        }
    }

    return KERN_FAILURE;
}

// خوادم الاستثناءات المكملة لـ mach_excServer
kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port,
    mach_port_t thread,
    mach_port_t task,
    exception_type_t exception,
    mach_exception_data_t code,
    mach_msg_type_number_t codeCnt) {
    return KERN_FAILURE;
}

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
    mach_msg_type_number_t *new_stateCnt) {
    return KERN_FAILURE;
}

// دالة الاستماع للاستثناءات في خلفية التطبيق
static void *server_thread_func(void *param) {
    mach_msg_server(
        mach_exc_server,
        sizeof(union __RequestUnion__catch_mach_exc_subsystem),
        g_server_port,
        MACH_MSG_OPTION_NONE
    );
    return NULL;
}

// دالة تفعيل الـ Hook
bool hook_install(void *targets[], void *replacements[], int count) {
    if (count <= 0 || count > MAX_HW_HOOKS) return false;

    static bool is_init = false;
    if (!is_init) {
        // إنشاء وإعداد منفذ Mach الخاص بالتطبيق
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_server_port) != KERN_SUCCESS) {
            return false;
        }
        if (mach_port_insert_right(mach_task_self(), g_server_port, g_server_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
            return false;
        }

        // توجيه استثناءات Breakpoint إلى منفذنا
        if (task_set_exception_ports(
                mach_task_self(),
                EXC_MASK_BREAKPOINT,
                g_server_port,
                EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                ARM_THREAD_STATE64) != KERN_SUCCESS) {
            return false;
        }

        // تشغيل خيط الاستماع
        pthread_t tid;
        if (pthread_create(&tid, NULL, server_thread_func, NULL) != 0) {
            return false;
        }
        pthread_detach(tid);

        is_init = true;
    }

    // إعداد مسجلات العتاد (ARM Debug Registers)
    arm_debug_state64_t debug_state = {0};
    for (int i = 0; i < count; i++) {
        uintptr_t target_clean = strip_pac_bits((uintptr_t)targets[i]);
        g_hooks[i].target_address = target_clean;
        g_hooks[i].replacement_address = (uintptr_t)replacements[i];

        debug_state.__bvr[i] = target_clean;
        debug_state.__bcr[i] = 0x1e5; // تفعيل الـ Breakpoint لمستوى تنفيذ المستخدم (EL0)
    }
    g_active_count = count;

    // تطبيق المسجلات على كافة خيوط المعالجة الحالية
    thread_act_array_t thread_list;
    mach_msg_type_number_t thread_count = 0;

    if (task_threads(mach_task_self(), &thread_list, &thread_count) != KERN_SUCCESS) {
        return false;
    }

    bool all_ok = true;
    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        if (thread_set_state(thread_list[i], ARM_DEBUG_STATE64, (thread_state_t)&debug_state, ARM_DEBUG_STATE64_COUNT) != KERN_SUCCESS) {
            all_ok = false;
        }
        mach_port_deallocate(mach_task_self(), thread_list[i]);
    }

    vm_deallocate(mach_task_self(), (vm_address_t)thread_list, thread_count * sizeof(thread_act_t));

    return all_ok;
}
