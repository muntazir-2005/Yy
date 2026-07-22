#import "hook.h"

%ctor {
    // تهيئة نظام التوجيه الداخلي (Function Table)
    hook_init();

    // تفعيل كل طبقات AntiBan مرة واحدة:
    // - اعتراض sysctl / uname / statfs
    // - تعطيل فئات الأمان ABase (SecurityStore, EncryptedJson, LogCrypt)
    hook_antiban_install_all();
}
