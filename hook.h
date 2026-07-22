#ifndef HOOK_H
#define HOOK_H
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
bool hook_init(void);
bool hook_install(void *target, void *replacement);
bool hook_uninstall(void *target);
bool hook_pause_all(void);
bool hook_resume_all(void);
void hook_deinit(void);
#ifdef __cplusplus
}
#endif
#endif
