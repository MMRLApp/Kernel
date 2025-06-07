#ifndef __KSU_H_APK_V2_SIGN
#define __KSU_H_APK_V2_SIGN

#include <linux/types.h>

#ifndef CERT_MAX_LENGTH
#define CERT_MAX_LENGTH 1024
#endif

bool is_manager_apk(char *path);

#endif
