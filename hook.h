#ifndef HOOK_H
#define HOOK_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// -----------------------------------------------
//  وحدات الماكرو المساعدة
// -----------------------------------------------

/**
 * يستخدم لتمرير slot من النوع _Atomic(void*) بأمان.
 * مثال: hook_install(HOOK_SLOT(my_slot), ...);
 */
#define HOOK_SLOT(ptr) ((void*)&(ptr))

// -----------------------------------------------
//  Function Table Hooking API
//  (للدوال التي تملك متغيرات _Atomic(void*) خاصة بك)
// -----------------------------------------------

/**
 * تهيئة نظام التوجيه. يجب استدعاؤها مرة واحدة عند بدء التطبيق.
 * @return true دائمًا.
 */
bool hook_init(void);

/**
 * تثبيت اعتراض على دالة عبر slot ذري.
 * @param slot         مؤشر إلى _Atomic(void*) يحمل مؤشر الدالة.
 * @param replacement  الدالة البديلة.
 * @param original_out يستقبل مؤشر الدالة الأصلية (لاستدعائها لاحقًا).
 * @return true إذا نجح التثبيت.
 */
bool hook_install(void *slot, void *replacement, void **original_out);

/**
 * إزالة اعتراض من slot وإعادة المؤشر الأصلي.
 * @param slot مؤشر إلى slot المُعترَض.
 * @return true إذا تمت الإزالة.
 */
bool hook_uninstall(void *slot);

/**
 * فحص ما إذا كان slot مسجلاً في جدول الاعتراضات (حتى لو كان مُعلَّقًا).
 * @param slot مؤشر إلى slot المُراد فحصه.
 * @return true إذا كان الاعتراض مثبتًا.
 */
bool hook_is_installed(void *slot);

/**
 * فحص ما إذا كان الاعتراض نشطًا فعليًا على slot في هذه اللحظة.
 * @param slot مؤشر إلى slot المُراد فحصه.
 * @return true إذا كان الاعتراض نشطًا.
 */
bool hook_is_active(void *slot);

/**
 * إرجاع عدد الاعتراضات المسجلة حاليًا.
 * @return عدد الاعتراضات.
 */
int  hook_count(void);

/**
 * إيقاف جميع الاعتراضات مؤقتًا (استعادة المؤشرات الأصلية دون حذفها من الجدول).
 * @return true دائمًا.
 */
bool hook_pause_all(void);

/**
 * إعادة تفعيل جميع الاعتراضات المُعلَّقة.
 * @return true دائمًا.
 */
bool hook_resume_all(void);

/**
 * إنهاء نظام التوجيه واستعادة جميع المؤشرات الأصلية.
 */
void hook_deinit(void);

// -----------------------------------------------
//  AntiBan API (Symbol Hooking الآمن)
//  (اعتراض دوال النظام C مثل sysctl/uname/statfs)
// -----------------------------------------------

/**
 * تثبيت اعتراضات دوال النظام لمنع كشف بيئة الجهاز.
 * تشمل: sysctlbyname, sysctl, uname, statfs.
 * @return true إذا تم تثبيت الاعتراضات بنجاح (حتى لو جزئيًا).
 */
bool hook_antiban_install_syscalls(void);

/**
 * تثبيت اعتراضات الفئات الأمنية (ABase Security Store...).
 * حاليًا معطلة حتى يتم استخراج التوقيعات الصحيحة.
 * @return true دائمًا (لا تفعل شيئًا في هذه النسخة).
 */
bool hook_antiban_install_security(void);

/**
 * تثبيت جميع طبقات AntiBan مرة واحدة.
 * @return true إذا تم تثبيت اعتراضات النظام على الأقل.
 */
bool hook_antiban_install_all(void);

#ifdef __cplusplus
}
#endif

#endif // HOOK_H
