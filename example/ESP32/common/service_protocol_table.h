#ifndef SERVICE_PROTOCOL_TABLE_H
#define SERVICE_PROTOCOL_TABLE_H

// #include "pb.h"
// #include "service_protocol_port.h"
// #include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

// typedef struct {
//     uint16_t sid; 
//     uint16_t rid;
// } app_protocol_uri_t;

// typedef struct {
//     const pb_msgdesc_t *field; 
//     void (*handler)(protocol_code_t code, uint32_t mid, void *data, uint32_t len);
// } app_protocol_handler_t;

// typedef struct {
//     app_protocol_handler_t **sid_table;
//     uint8_t *max_cid_table;
//     uint8_t max_sid;
//     uint8_t base_sid;

// } app_protocol_table_t;


typedef enum 
{
	FORMAL_BASE_SID = 0x00,
    DEV_MANAGE = 1,
    USER_SETTING,           // 2
    EXERCISE_DATA_MANAGE,   // 3
    RAW_DATA_MANAGE,        // 4
    OTA_MANAGE,             // 5
    FILE_MANAGE,            // 6
    LOG_MANAGE,             // 7
    AUXILIARY_MANAGE,       // 8
    REVERSE_CTRL_MANAGE,    // 9

    MAX_FORMAT_SID,

	FACTORY_BASE_SID = 0x7E,
    TEST_MANAGE ,
    FACTORY_MANAHE,
    BLE_TEST_MANAGE,

    MAX_FACTORY_SID,
    MAX_SID,
} sid_t;


//---------------------------------------------------------------------
// formal protocol                 
//---------------------------------------------------------------------
typedef enum 
{
    CONN_PARM_SET = 1,
    DEV_INFO_GET ,
    BAT_INFO_GET,
    TIME_SET ,
    BIND,
    UNBIND,

    DEV_MANAGE_MAX_CID,
} dev_manage_cid_t;


typedef enum 
{
    OTA_CHECK = 1,
    OTA_FILE_DATA,
    OTA_VERIFY,

    OTA_MANAGE_MAX_CID,
} ota_manage_cid_t;


typedef enum 
{
    GET_FILE_INDEX       = 1,    // 获取文件列表
    GET_FILE_DATA        = 2,    // 获取文件
    DEL_FILE_DATA        = 3,    // 删除文件
    DOWNLOAD_FILE_HEAD   = 4,    // 下发文件头
    DOWNLOAD_FILE_DATA   = 5,    // 下发文件数据
    DOWNLOAD_FILE_VERIFY = 6,    // 下发文件检验

    DEL_ONE_FILE_DATA     = 7,    // 删除指定的一个文件

    FILE_TRANS_MAX_CID,
} file_manage_cid_t;



typedef enum 
{
    FM_SWITCH_TEMP_1 = 1,
    FM_SWITCH_CMD,
    FM_LATENCY_TEST_CONFIG,
    FM_LATENCY_TEST_PUSH,

    FM_SWITCH_MAX_CID,
} fw_switch_manage_cid_t;



#ifdef __cplusplus
}
#endif

#endif /* SERVICE_PROTOCOL_PORT_H */
