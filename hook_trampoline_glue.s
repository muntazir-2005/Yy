.globl _hook_trampoline_glue
.p2align 2
_hook_trampoline_glue:
    // x0 يحتوي على hook_index الذي مررناه من مُعالج الاستثناء
    stp x29, x30, [sp, #-16]!
    bl _hook_trampoline_handler
    ldp x29, x30, [sp], #16
    ret
