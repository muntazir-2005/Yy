ARCHS = arm64
TARGET = iphone:clang:latest:14.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = MyLibyanaPatch
MyLibyanaPatch_FILES = Tweak.xm hook.c
MyLibyanaPatch_CFLAGS = -fobjc-arc
MyLibyanaPatch_CCFLAGS = -std=c++14 -O2

include $(THEOS_MAKE_PATH)/tweak.mk
