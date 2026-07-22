TARGET := iphone:clang:latest:14.0
ARCHS := arm64 arm64e

# تضمين المسار الصحيح لملفات Theos في GitHub Actions
include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MyLibyanaPatch

# ربط كافة الملفات والمجلدات وتغيير SYS إلى SystemCore لتجنب تعارض النظام
MyLibyanaPatch_FILES = Tweak.xm \
                        fishhook.c \
                        hook.c \
                        mach_excServer.c \
                        $(wildcard ESP/*.c ESP/*.cpp ESP/*.m ESP/*.mm) \
                        $(wildcard SystemCore/*.c SystemCore/*.cpp SystemCore/*.m SystemCore/*.mm)

# تضمين مسارات المجلدات الفرعية والمكتبات (تأكد من تغيير اسم المجلد هنا أيضاً)
MyLibyanaPatch_CFLAGS = -fobjc-arc -I. -IESP -ISystemCore
MyLibyanaPatch_LDFLAGS = -undefined dynamic_lookup

# تضمين مسار البناء النهائي الخاص بـ Theos
include $(THEOS_MAKE_PATH)/tweak.mk
