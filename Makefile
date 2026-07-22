ARCHS = arm64
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MyLibyanaPatch

# جلب ملفات السورس من المسار الرئيسي
MyLibyanaPatch_FILES = Tweak.xm fishhook.c hook.c mach_excServer.c 

# جلب أي ملفات سورس إضافية من مجلدي SystemCore و ESP
MyLibyanaPatch_FILES += $(wildcard SystemCore/*.c) $(wildcard SystemCore/*.cpp) $(wildcard SystemCore/*.m) $(wildcard SystemCore/*.mm)
MyLibyanaPatch_FILES += $(wildcard ESP/*.c) $(wildcard ESP/*.cpp) $(wildcard ESP/*.m) $(wildcard ESP/*.mm)

# إعدادات المترجم: تضمين مجلدي SystemCore و ESP للبحث عن ملفات الترويسة (Headers)
MyLibyanaPatch_CFLAGS = -fobjc-arc -ISystemCore -IESP
MyLibyanaPatch_CCFLAGS = -std=c++14 -O2 -ISystemCore -IESP

include $(THEOS_MAKE_PATH)/tweak.mk
