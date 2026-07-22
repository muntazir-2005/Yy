#import "hook.h"

__attribute__((constructor))
static void tweak_initialize(void) {
    hook_init();
    hook_antiban_install_all();
}
