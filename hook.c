#include "hook.h"
#include "mach_excServer.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <pthread.h>
#include <mach/mach.h>
#include <sys/sysctl.h>

#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

// هيكل تسجيل الـ Hooks
struct hook_entry {
    uintptr_t target_addr;
    uintptr_t replacement_addr;
};

#define MAX_HOOKS 6
static struct hook_entry g_hooks[MAX_HOOKS];
static int g_active_hooks = 0;
static mach_port_t g_exception_server = MACH_PORT_NULL;

// دالة تنظيف بتات PAC من العناوين على معالجات ARM64e
static inline uintptr_t strip_pac(uintptr_t addr) {
#if defined(__arm64e__) && __has_feature(ptrauth_qualifiers)
    return (uintptr_t)ptrauth_strip((void *)addr, ptrauth_key_asia);
#else
    // إزالة بتات PAC عبر Address Mask لـ ARM64 (64-bit iOS)
    return addr & 0x0000007FFFFFFFFFPR;
#endif
}

// معالج استثناءات Mach
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

    arm_thread_state64_t *old_thread_state = (arm_thread_state64_t *)old_state;
    arm_thread_state64_t *new_thread_state = (arm_thread_state64_t *)new_state;

    // استخراج الـ PC المجرد بدون PAC
    uintptr_t current_pc = strip_pac((uintptr_t)arm_thread_state64_get_pc(*old_thread_state));

    for (int i = 0; i < g_active_hooks; ++i) {
        if (g_hooks[i].target_addr == current_pc) {
            *new_thread_state = *old_thread_state;
            *new_stateCnt = old_stateCnt;

            // توجيه الـ PC إلى الدالة الجديدة
            arm_thread_state64_set_pc_fptr(*new_thread_state, (void *)g_hooks[i].replacement_addr);
            return KERN_SUCCESS;
        }
    }

    return KERN_FAILURE;
}

// دوال معالجة إضافية مطلوبة بواسطة mach_excServer
kern_return_t catch_mach_exception_raise(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code, mach_msg_type_number_t codeCnt) {
    return KERN_FAILURE;
}

kern_return_t catch_mach_exception_raise_state_identity(
    mach_port_t exception_port, mach_port_t thread, mach_port_t task,
    exception_type_t exception, mach_exception_data_t code, mach_msg_type_number_t codeCnt,
    int *flavor, thread_state_t old_state, mach_msg_type_number_t old_stateCnt,
    thread_state_t new_state, mach_msg_type_number_t *new_stateCnt) {
    return KERN_FAILURE;
}

extern boolean_t mach_exc_server(mach_msg_header_t *InHeadP, mach_msg_header_t *OutHeadP);

// خيل الاستماع للاستثناءات
static void *exception_listener_thread(void *arg) {
    mach_msg_server(mach_exc_server, 2048, g_exception_server, MACH_MSG_OPTION_NONE);
    return NULL;
}

// الدالة الرئيسية لتطبيق الـ Hook
bool install_hardware_hooks(void *targets[], void *replacements[], int count) {
    if (count <= 0 || count > MAX_HOOKS) return false;

    static bool initialized = false;
    if (!initialized) {
        // 1. إنشاء منفذ Mach الاستثنائي
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exception_server) != KERN_SUCCESS) {
            return false;
        }
        if (mach_port_insert_right(mach_task_self(), g_exception_server, g_exception_server, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
            return false;
        }

        // 2. تسجيل الاستثناءات الخاصة بـ EXC_BREAKPOINT
        if (task_set_exception_ports(
                mach_task_self(),
                EXC_MASK_BREAKPOINT,
                g_exception_server,
                EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                ARM_THREAD_STATE64) != KERN_SUCCESS) {
            return false;
        }

        // 3. تشغيل Thread للاستماع للاستثناءات
        pthread_t thread;
        if (pthread_create(&thread, NULL, exception_listener_thread, NULL) != 0) {
            return false;
        }
        pthread_detach(thread);

        initialized = true;
    }

    // إعداد حالة الـ Debug Registers
    arm_debug_state64_t debug_state = {0};
    for (int i = 0; i < count; i++) {
        uintptr_t stripped_target = strip_pac((uintptr_t)targets[i]);
        g_hooks[i].target_addr = stripped_target;
        g_hooks[i].replacement_addr = (uintptr_t)replacements[i];

        debug_state.__bvr[i] = stripped_target;
        debug_state.__bcr[i] = 0x1e5; // تمكين Breakpoint للتنفيذ على مستوى EL0
    }
    g_active_hooks = count;

    // تطبيق الحالة على جميع الـ Threads الحالية
    thread_act_array_t threads;
    mach_msg_type_number_t thread_count = 0;

    if (task_threads(mach_task_self(), &threads, &thread_count) != KERN_SUCCESS) {
        return false;
    }

    bool success = true;
    for (mach_msg_type_number_t i = 0; i < thread_count; ++i) {
        if (thread_set_state(threads[i], ARM_DEBUG_STATE64, (thread_state_t)&debug_state, ARM_DEBUG_STATE64_COUNT) != KERN_SUCCESS) {
            success = false;
        }
        mach_port_deallocate(mach_task_self(), threads[i]);
    }

    // تنظيف ذاكرة قائمة الـ Threads بشكل صحيح
    vm_deallocate(mach_task_self(), (vm_address_t)threads, thread_count * sizeof(thread_act_t));

    return success;
}
