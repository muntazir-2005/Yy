# تم إزالة SpringBoard لأننا نستهدف تطبيقاً بدون جيلبريك
ARCHS = arm64
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MyLibyanaPatch

# جلب جميع ملفات السورس
MyLibyanaPatch_FILES = Tweak.xm $(wildcard SystemCore/*.m) $(wildcard SystemCore/*.mm) $(wildcard SystemCore/*.cpp) $(wildcard SystemCore/*.c)

# إعدادات المترجم
MyLibyanaPatch_CFLAGS = -fobjc-arc -ISystemCore
MyLibyanaPatch_CCFLAGS = -std=c++14 -O2 -ISystemCore

include $(THEOS_MAKE_PATH)/tweak.mk
