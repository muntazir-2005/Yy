#ifndef HOOK_H
#define HOOK_H
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

// ماكرو أمان النوع لـ Function Table Hooking
#define HOOK_SLOT(ptr) ((void*)&(ptr))

// --- Function Table API (للدوال التي تملك slots) ---
bool hook_init(void);
bool hook_install(void *slot, void *replacement, void **original_out);
bool hook_uninstall(void *slot);
bool hook_is_installed(void *slot);
bool hook_is_active(void *slot);
int  hook_count(void);
bool hook_pause_all(void);
bool hook_resume_all(void);
void hook_deinit(void);

// --- AntiBan API (اعتراض دوال النظام والحماية) ---
// يستخدم fishhook داخلياً
bool hook_antiban_install_syscalls(void);   // sysctl, uname, statfs
bool hook_antiban_install_security(void);   // فئات ABase الأمنية
bool hook_antiban_install_all(void);        // كليهما

#ifdef __cplusplus
}
#endif
#endif
