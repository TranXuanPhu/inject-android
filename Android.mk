LOCAL_PATH := $(call my-dir)
MY_INC := $(LOCAL_PATH)/../../../__Global/Android/inc
MY_LIB := $(LOCAL_PATH)/../../../__Global/Android/lib
MY_SRC := $(LOCAL_PATH)/../../../__Global/Android/src
include $(CLEAR_VARS)

########################
# prepare crypto_aigo
include $(CLEAR_VARS)
LOCAL_MODULE    := crypto_aigo
LOCAL_SRC_FILES := $(MY_LIB)/$(TARGET_ARCH_ABI)/libcrypto_aigo.a
include $(PREBUILT_STATIC_LIBRARY)
########################
########################
# prepare main
include $(CLEAR_VARS)
LOCAL_MODULE    := main
LOCAL_SRC_FILES := $(MY_LIB)/$(TARGET_ARCH_ABI)/libmain.a
include $(PREBUILT_STATIC_LIBRARY)
########################

include $(CLEAR_VARS)
LOCAL_MODULE := injector
LOCAL_SRC_FILES :=$(wildcard $(LOCAL_PATH)/*.cpp)
LOCAL_C_INCLUDES += $(LOCAL_PATH)
LOCAL_C_INCLUDES += $(MY_INC)/Crypto
LOCAL_C_INCLUDES += $(MY_INC)/Main	
#LOCAL_LDFLAGS += -pie

LOCAL_CFLAGS     := -Wall -Wextra -Wno-sentinel -Wno-unused-parameter -fvisibility=hidden -Wno-implicit-function-declaration \
					-Wno-int-conversion -Wno-unused-variable -Wno-format -Wno-format-extra-args -Wno-integer-overflow

LOCAL_STATIC_LIBRARIES	+= main crypto_aigo 

LOCAL_CONLYFLAGS := -std=c++11
LOCAL_LDLIBS     := -llog -ldl


include $(BUILD_EXECUTABLE)
