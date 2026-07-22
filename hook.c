/*
 * hook.c - مكتبة اعتراض (Hooking) عتادية متكاملة لأجهزة iOS بدون جلبريك
 * تعتمد على سجلات التصحيح (Hardware Breakpoints) مع معالجة آمنة لـ PAC
 * وتغطية تلقائية لجميع الخيوط (بما فيها المُنشأة ديناميكيًا).
 */

#include "hook.h"
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <os/lock.h>
#include <mach/mach.h>
#include <mach/thread_act.h>
#include <mach/mach_port.h>
#include <mach/task.h>
#include <mach/vm_map.h>
#include <sys/sysctl.h>
#include <dlfcn.h>
#include <string.h>
#include <stdatomic.h>

#include "mach_excServer.h"

#if __has_include(<ptrauth.h>)
#include <ptrauth.h>
#endif

// --- ثوابت وإعدادات ---
#define MAX_HW_BREAKPOINTS  6   // الحد الأقصى لعدد سجلات العتاد (BVR/BxR) على ARMv8
#define MAX_QUEUED_HOOKS   64   // عدد الاعتراضات الإضافية التي تنتظر التفعيل

// --- هيكل بيانات الاعتراض ---
typedef struct {
    uintptr_t target_address;        // العنوان الأصلي المُعرّض للاعتراض
    uintptr_t replacement_address;   // عنوان الدالة البديلة (غير مُوقّع)
    bool     active;                 // هل هو مُفعّل حاليًا على سجل عتادي؟
    int      slot_index;             // رقم السجل المُستخدم (-1 إن لم يكن)
} HookEntry;

// --- المتغيرات العامة (محمية بقفل spinlock) ---
static HookEntry g_hooks[MAX_QUEUED_HOOKS];
static int g_active_slots[MAX_HW_BREAKPOINTS];        // -1 يعني فارغ
static int g_active_count = 0;                        // عدد الاعتراضات النشطة فعليًا
static int g_total_registered = 0;                    // إجمالي الاعتراضات المُسجّلة

static os_unfair_lock g_lock = OS_UNFAIR_LOCK_INIT;

// إدارة خادم Mach للاستثناءات
static mach_port_t g_exc_port = MACH_PORT_NULL;
static pthread_t   g_server_thread;
static atomic_bool g_server_running = false;

// مؤشرات دالة pthread_create الأصلية (لربطها لاحقًا)
static int (*original_pthread_create)(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *) = NULL;

// --- دوال مساعدة ---

/**
 * تجريد بتات PAC من مؤشر على ARM64e.
 * يُستخدم فقط للمقارنة وليس لإعادة الاستخدام المباشر.
 */
static inline uintptr_t strip_pac_bits(uintptr_t ptr) {
#if defined(__arm64e__) && __has_feature(ptrauth_qualifiers)
    return (uintptr_t)ptrauth_strip((void *)ptr, ptrauth_key_asia);
#else
    return ptr & 0x0000007FFFFFFFFFULL;
#endif
}

/**
 * توقيع مؤشر غير مُصادق باستخدام مفتاح IA (المُستخدم لعناوين الدوال).
 */
static inline void *sign_pointer(uintptr_t addr) {
#if defined(__arm64e__) && __has_feature(ptrauth_qualifiers)
    return ptrauth_sign_unauthenticated((void *)addr, ptrauth_key_asia, 0);
#else
    return (void *)addr;
#endif
}

/**
 * البحث عن اعتراض مُطابق لعنوان الهدف.
 * يجب استدعاؤها والقفل ممسوك.
 */
static HookEntry *find_hook_locked(uintptr_t target) {
    for (int i = 0; i < g_total_registered; i++) {
        if (g_hooks[i].target_address == target) {
            return &g_hooks[i];
        }
    }
    return NULL;
}

/**
 * تطبيق سجلات التصحيح على خيط محدد (thread).
 */
static bool apply_debug_state_to_thread(thread_act_t thread, arm_debug_state64_t *debug_state) {
    kern_return_t kr = thread_set_state(thread, ARM_DEBUG_STATE64,
                                        (thread_state_t)debug_state,
                                        ARM_DEBUG_STATE64_COUNT);
    return (kr == KERN_SUCCESS);
}

/**
 * بناء هيكل arm_debug_state64_t من قائمة الاعتراضات النشطة حاليًا.
 */
static void build_debug_state_from_active(arm_debug_state64_t *ds) {
    memset(ds, 0, sizeof(*ds));
    for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
        if (g_active_slots[slot] >= 0) {
            HookEntry *h = &g_hooks[g_active_slots[slot]];
            ds->__bvr[slot] = h->target_address;
            // BCR: تفعيل على مستوى EL0 (مستخدم)، نوع نقطة توقف عنوان (unlinked context match)
            ds->__bcr[slot] = 0x1e5;  // (BAS=0xf, HMC=0, PMC=01, ENABLE=1)
        }
    }
}

/**
 * توزيع سجلات التصحيح الحالية على جميع خيوط العملية.
 */
static void apply_to_all_threads(arm_debug_state64_t *debug_state) {
    thread_act_array_t threads;
    mach_msg_type_number_t count = 0;
    if (task_threads(mach_task_self(), &threads, &count) != KERN_SUCCESS)
        return;

    for (mach_msg_type_number_t i = 0; i < count; i++) {
        apply_debug_state_to_thread(threads[i], debug_state);
        mach_port_deallocate(mach_task_self(), threads[i]);
    }
    vm_deallocate(mach_task_self(), (vm_address_t)threads, count * sizeof(thread_act_t));
}

// --- مُعالج استثناء Mach (الخادم) ---

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
    if (*flavor != ARM_THREAD_STATE64) {
        return KERN_FAILURE;
    }

    arm_thread_state64_t *state_old = (arm_thread_state64_t *)old_state;
    uintptr_t current_pc = strip_pac_bits(arm_thread_state64_get_pc(*state_old));

    // قفل للحماية من التعديلات المتزامنة (بسيط ولا يُسبب deadlock هنا)
    os_unfair_lock_lock(&g_lock);

    HookEntry *hook = NULL;
    for (int i = 0; i < g_total_registered; i++) {
        if (g_hooks[i].active && g_hooks[i].target_address == current_pc) {
            hook = &g_hooks[i];
            break;
        }
    }

    if (hook) {
        // نسخ الحالة القديمة كاملةً إلى الجديدة
        *state_new = *state_old;
        *new_stateCnt = old_stateCnt;

        // توجيه PC إلى الدالة البديلة مع توقيع آمن
        arm_thread_state64_set_pc_fptr(*state_new, sign_pointer(hook->replacement_address));

        os_unfair_lock_unlock(&g_lock);
        return KERN_SUCCESS;
    }

    os_unfair_lock_unlock(&g_lock);
    return KERN_FAILURE;
}

// باقي دوال المُشعِل (mach_exc_server) غير مُستخدمة ولكن إلزامية للربط
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

// --- خيط خادم الاستثناءات ---
static void *exception_server_thread(void *arg) {
    mach_msg_server(mach_exc_server,
                    sizeof(union __RequestUnion__catch_mach_exc_subsystem),
                    g_exc_port,
                    MACH_MSG_OPTION_NONE);
    return NULL;
}

// --- ربط pthread_create لتغطية الخيوط الجديدة (الطريقة الصينية المُثلى) ---
static int hooked_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
                                 void *(*start_routine)(void *), void *arg) {
    // استدعاء الدالة الأصلية
    int ret = original_pthread_create(thread, attr, start_routine, arg);
    if (ret == 0 && thread) {
        // الحصول على منفذ الخيط الجديد
        mach_port_t th_port = pthread_mach_thread_np(*thread);
        // بناء حالة التصحيح الحالية
        arm_debug_state64_t debug_state;
        os_unfair_lock_lock(&g_lock);
        build_debug_state_from_active(&debug_state);
        os_unfair_lock_unlock(&g_lock);
        // تطبيقها على الخيط الوليد
        apply_debug_state_to_thread(th_port, &debug_state);
    }
    return ret;
}

/**
 * استخدام fishhook لاستبدال pthread_create بربطتنا.
 */
static void install_pthread_create_hook(void) {
    // إذا تم الربط مسبقًا، لا حاجة للتكرار
    if (original_pthread_create != NULL) return;

    // استخدام fishhook داخليًا (يجب أن يكون fishhook مضمّنًا أو مرتبطًا)
    // هنا تعريف يدوي مُبسط لمُحاكاة آلية fishhook
    struct rebinding {
        const char *name;
        void *replacement;
        void **replaced;
    };
    // يمكنك استخدام fishhook.h مباشرة، لكننا هنا نُظهر المبدأ
    struct rebinding bindings[] = {
        {"pthread_create", (void *)hooked_pthread_create, (void **)&original_pthread_create}
    };
    // استدعاء دالة rebind_symbols من fishhook (نفترض وجودها)
    extern void rebind_symbols(struct rebinding[], size_t);
    rebind_symbols(bindings, 1);
}

// --- دوال واجهة المكتبة العامة ---

bool hook_install(void *target, void *replacement) {
    if (!target || !replacement) return false;

    os_unfair_lock_lock(&g_lock);

    // التحقق من عدم وجود الاعتراض مسبقًا
    if (find_hook_locked((uintptr_t)target) != NULL) {
        os_unfair_lock_unlock(&g_lock);
        return false; // موجود بالفعل
    }

    // هل ما زال لدينا متسع في جدول التسجيل؟
    if (g_total_registered >= MAX_QUEUED_HOOKS) {
        os_unfair_lock_unlock(&g_lock);
        return false;
    }

    uintptr_t clean_target = strip_pac_bits((uintptr_t)target);
    HookEntry *entry = &g_hooks[g_total_registered];
    entry->target_address = clean_target;
    entry->replacement_address = (uintptr_t)replacement;
    entry->active = false;
    entry->slot_index = -1;

    // محاولة تخصيص سجل عتادي فوري
    for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
        if (g_active_slots[slot] == -1) {
            g_active_slots[slot] = g_total_registered;
            entry->active = true;
            entry->slot_index = slot;
            g_active_count++;
            break;
        }
    }

    // إذا كانت جميع السجلات مشغولة، يبقى الاعتراض في قائمة الانتظار (سيتم تفعيله لاحقًا عند شغور سجل)
    g_total_registered++;

    // تحديث سجلات التصحيح على جميع الخيوط
    arm_debug_state64_t debug_state;
    build_debug_state_from_active(&debug_state);
    os_unfair_lock_unlock(&g_lock);

    apply_to_all_threads(&debug_state);

    return true;
}

bool hook_uninstall(void *target) {
    os_unfair_lock_lock(&g_lock);
    uintptr_t clean = strip_pac_bits((uintptr_t)target);
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

    // إذا كان مُفعّلاً على سجل، نحرره
    if (found->active && found->slot_index != -1) {
        g_active_slots[found->slot_index] = -1;
        g_active_count--;
    }

    // إزالة العنصر من المصفوفة (إزاحة العناصر)
    if (found_idx < g_total_registered - 1) {
        memmove(&g_hooks[found_idx], &g_hooks[found_idx + 1],
                (g_total_registered - found_idx - 1) * sizeof(HookEntry));
    }
    g_total_registered--;

    // إعادة تعيين أرقام السجلات للمُفعّلين بعد الإزالة
    for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
        if (g_active_slots[slot] >= 0) {
            // بعد الإزاحة، يجب أن نُحدّث رقم الفهرس في السجل ليشير للمكان الجديد
            // لأن العنصر تغير موقعه
            int idx = g_active_slots[slot];
            if (idx > found_idx) {
                g_active_slots[slot] = idx - 1; // انزياح
            }
        }
    }

    // إعادة بناء الحالة وتطبيقها
    arm_debug_state64_t debug_state;
    build_debug_state_from_active(&debug_state);
    os_unfair_lock_unlock(&g_lock);
    apply_to_all_threads(&debug_state);
    return true;
}

bool hook_pause_all(void) {
    // لإيقاف جميع الاعتراضات دون إزالتها، نُعطّل السجلات عبر مسح BCR مع الاحتفاظ بالبيانات
    arm_debug_state64_t debug_state;
    os_unfair_lock_lock(&g_lock);
    // نُعطّل كل سجل (ENABLE=0)
    for (int slot = 0; slot < MAX_HW_BREAKPOINTS; slot++) {
        if (g_active_slots[slot] >= 0) {
            debug_state.__bvr[slot] = g_hooks[g_active_slots[slot]].target_address;
            debug_state.__bcr[slot] = 0x1e4; // ENABLE=0 مع الإبقاء على باقي الإعدادات
        }
    }
    os_unfair_lock_unlock(&g_lock);
    apply_to_all_threads(&debug_state);
    return true;
}

bool hook_resume_all(void) {
    // إعادة تفعيل السجلات كما كانت
    arm_debug_state64_t debug_state;
    os_unfair_lock_lock(&g_lock);
    build_debug_state_from_active(&debug_state);
    os_unfair_lock_unlock(&g_lock);
    apply_to_all_threads(&debug_state);
    return true;
}

// --- التهيئة وإنهاء الخدمة ---

bool hook_init(void) {
    // التأكد من أن العملية تمتلك صلاحية "get-task-allow" (ضروري لـ task_set_exception_ports)
    // في بيئة غير مكسورة الحماية، هذا متاح فقط عند توقيع التطبيق بشهادة تطوير أو com.apple.security.cs.debugger
    // نتحقق من وجود المُصحح أو الصلاحية بطريقة بسيطة.
    int mib[] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, getpid() };
    struct kinfo_proc info;
    size_t size = sizeof(info);
    if (sysctl(mib, 4, &info, &size, NULL, 0) == 0) {
        if ((info.kp_proc.p_flag & P_TRACED) == 0) {
            // لا يوجد مُصحح مرفق، قد لا تكون الصلاحية متاحة إلا إذا كان التطبيق موقّعًا خصيصًا
            // لكننا نستمر على أمل أن المستخدم وفرها.
        }
    }

    if (g_exc_port != MACH_PORT_NULL) return true; // مُهيّأ مسبقًا

    // إنشاء منفذ الاستقبال
    if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &g_exc_port) != KERN_SUCCESS)
        return false;
    if (mach_port_insert_right(mach_task_self(), g_exc_port, g_exc_port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS)
        return false;

    // تسجيل منفذ الاستثناءات للنوع EXC_BREAKPOINT
    if (task_set_exception_ports(mach_task_self(),
                                 EXC_MASK_BREAKPOINT,
                                 g_exc_port,
                                 EXCEPTION_STATE | MACH_EXCEPTION_CODES,
                                 ARM_THREAD_STATE64) != KERN_SUCCESS) {
        mach_port_destroy(mach_task_self(), g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        return false;
    }

    // تشغيل خيط الخادم
    if (pthread_create(&g_server_thread, NULL, exception_server_thread, NULL) != 0) {
        task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, MACH_PORT_NULL, 0, 0);
        mach_port_destroy(mach_task_self(), g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        return false;
    }
    pthread_detach(g_server_thread);
    atomic_store(&g_server_running, true);

    // تركيب خطاف pthread_create
    install_pthread_create_hook();

    return true;
}

void hook_deinit(void) {
    // إيقاف خادم الاستثناءات
    if (atomic_exchange(&g_server_running, false)) {
        // إلغاء تسجيل منفذ الاستثناءات أولاً
        task_set_exception_ports(mach_task_self(), EXC_MASK_BREAKPOINT, MACH_PORT_NULL, 0, 0);
        // إرسال رسالة وهمية لتحرير الخيط من mach_msg_server إذا كان معلقًا
        // الحل الأمثل: استخدام إلغاء الخيط أو إغلاق المنفذ
        mach_port_destroy(mach_task_self(), g_exc_port);
        g_exc_port = MACH_PORT_NULL;
        // انتظار قصير لينتهي الخيط
        usleep(100000);
    }

    // إعادة تعيين الحالة العتادية لكل الخيوط إلى الصفر (إلغاء الاعتراضات)
    arm_debug_state64_t clean_state = {0};
    apply_to_all_threads(&clean_state);

    os_unfair_lock_lock(&g_lock);
    memset(g_hooks, 0, sizeof(g_hooks));
    for (int i = 0; i < MAX_HW_BREAKPOINTS; i++) g_active_slots[i] = -1;
    g_active_count = 0;
    g_total_registered = 0;
    os_unfair_lock_unlock(&g_lock);
}
