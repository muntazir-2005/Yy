export THEOS = /var/mobile/theos

# اسم التweak
TWEAK_NAME = AmmarVIP

# الملفات المصدرية (بلغة C، C++، Objective-C، Objective-C++)
AmmarVIP_FILES = Tweak.xm
# أعلام المترجم: تضمين المجلد الحالي، إخفاء الرموز، مستوى التحسين O1
AmmarVIP_CFLAGS = -I. -fvisibility=hidden -O1

# الأطر المطلوبة
AmmarVIP_FRAMEWORKS = Foundation UIKit

# البنية المدعومة وإصدار iOS المستهدف
ARCHS = arm64
TARGET = iphone:clang:latest:13.0

include $(THEOS)/makefiles/common.mk
include $(THEOS_MAKE_PATH)/tweak.mk

# تنفيذ script تشويش المفاتيح قبل البناء النهائي
before-package::
	@echo "[Ammar 2026] تشغيل script تشويش المفاتيح..."
	@chmod +x ./auto_obfuscate_key.sh
	@./auto_obfuscate_key.sh

# عرض مسار الـ dylib بعد البناء
after-package::
	@echo "[Ammar 2026] تم البناء. الـ dylib جاهز في:"
	@echo "    $(THEOS_OBJ_DIR)/debug/$(TWEAK_NAME).dylib"