/*
 * @LastEditors: auto
 */
#ifndef __OS_ADAPTER_H__
#define __OS_ADAPTER_H__

#ifdef __cplusplus
extern "C" {
#endif

#define OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32

void apt_pre_init(void);

#ifdef __cplusplus
}
#endif

#endif