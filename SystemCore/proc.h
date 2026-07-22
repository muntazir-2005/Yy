// ============================================================================
// proc.h - تعريفات بديلة لهيكل kinfo_proc والثوابت المرتبطة
// ============================================================================
// ملاحظة: هذا الملف يُستخدم فقط في حالة عدم توفر <sys/proc.h> الأصلي أو
// لتفادي التعارض مع رأس النظام. يُنصح بحذف أي ملف proc.h محلي والاكتفاء
// بـ #include <sys/proc.h> بعد التأكد من وجوده في مسار البحث.
// إذا كنت تواجه مشاكل مع رأس النظام، استخدم هذا الملف كبديل.
// ============================================================================

#ifndef _SYS_PROC_H_
#define _SYS_PROC_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/signal.h>

// ============================================================================
// [1] الثوابت الأساسية
// ============================================================================
#define P_TRACED        0x00000800      // عملية تحت التتبع (debugger)

// ============================================================================
// [2] تعريفات هيكل kinfo_proc (نسخة مبسطة – قد تحتاج للتعديل حسب SDK)
// ============================================================================
struct extern_proc {
    // تعريف مختصر – في الواقع هذا الهيكل أكبر، لكننا نحتاج فقط
    // إلى الحقل p_flag الموجود داخل kp_proc
    int p_flag;                         // العمليات (يحتوي على P_TRACED)
    // أعضاء آخرون ...
};

struct eproc {
    struct  proc *e_paddr;               // عنوان proc
    struct  session *e_sess;              // الجلسة
    struct  pcred e_pcred;                 // صلاحيات العمليات
    struct  ucred e_ucred;                 // صلاحيات المستخدم
    struct  vmspace e_vm;                  // مساحة الذاكرة
    pid_t   e_ppid;                         // parent pid
    pid_t   e_pgid;                         // process group id
    short   e_jobc;                          // job control counter
    dev_t   e_tdev;                          // controlling terminal
    pid_t   e_tpgid;                         // terminal process group id
    struct  session *e_tsess;                 // terminal session
    char    e_login[12];                      // setlogin() name
    long    e_spare[4];                       // spare
    char    e_sessid;                          // session id
    char    e_sid;                             // session id (again)
    char    e_pad[2];                          // padding
    dev_t   e_tdev_freebsd;                    // freebsd compat
    struct  sigiolst e_sigiolst;                // signal i/o list
    struct  xucred e_xucred;                    // exported ucred
};

struct kinfo_proc {
    struct  extern_proc kp_proc;           // معلومات العملية
    struct  eproc kp_eproc;                 // معلومات إضافية
};

#endif /* _SYS_PROC_H_ */