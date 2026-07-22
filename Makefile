ARCHS = arm64
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MyLibyanaPatch

# كل الملفات المصدرية التي سيتم ترجمتها
MyLibyanaPatch_FILES = Tweak.xm hook.c fishhook.c

MyLibyanaPatch_CFLAGS = -fobjc-arc
MyLibyanaPatch_CCFLAGS = -std=c++14 -O2

include $(THEOS_MAKE_PATH)/tweak.mk
