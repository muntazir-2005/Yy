#ifndef HOOK_H
#define HOOK_H

#include <stdbool.h>
#include <stdint.h>
#include <mach/mach.h>

#ifdef __cplusplus
extern "C" {
#endif

// تعريف عدد الـ Hooks
#ifndef MAX_HW_HOOKS
#define MAX_HW_HOOKS 6
#endif

struct hook_info {
    uintptr_t target_address;
    uintptr_t replacement_address;
};

bool hook_install(void *targets[], void *replacements[], int count);

#ifdef __cplusplus
}
#endif

#endif // HOOK_H
