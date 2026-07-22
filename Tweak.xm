#import "hook.h"

%ctor {
    hook_init();

    // تفعيل كل اعتراضات AntiBan (دوال النظام + فئات ABase)
    hook_antiban_install_all();

    // بالإضافة إلى توجيه أي دوال داخلية خاصة بك عبر HOOK_SLOT إذا أردت
}
