
#include "service_protocol_table.h"
#include "service_protocol_port.h"

//---------------------------------------------------------------------
// formal protocol                 
//---------------------------------------------------------------------
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "dev_manage_service.pb.h"
#include "sys_bat.pb.h"

static void dev_info_get_req_handler(protocol_code_t code, uint32_t mid, void *data, uint32_t len)
{
#if 0
    battery_info_t battery_info = battery_info_t_init_zero;

    static uint8_t voltage = 1;
    battery_info.voltage = voltage%101;
    voltage++;

    protocol_head_t protocol_head;
    protocol_head.sid = 1;
    protocol_head.rid = 1;
    protocol_head.mid = mid;

    printf("=======================>>> dev_info_get_req_handler, start tx\n");

    app_protocol_tx(protocol_head, PROTO_RSP_SUCCESS_CONTENT_2_05, battery_info_t_fields, &battery_info, sizeof(battery_info));

#else
    bat_info_t bat_info = bat_info_t_init_zero;

    static uint8_t voltage = 1;
    bat_info.bat_level = voltage%101;
    voltage++;

    bat_info.voltage = (3000 + voltage) % 4200;
    bat_info.bat_temp = 25;

    protocol_head_t protocol_head;
    protocol_head.sid = 1;
    protocol_head.rid = 3;
    protocol_head.mid = mid;

    printf("=======================>>> dev_info_get_req_handler, start tx\n");

    app_protocol_tx(protocol_head, PROTO_RSP_SUCCESS_CONTENT_2_05, bat_info_t_fields, &bat_info, sizeof(bat_info));

#endif
}

static void dev_info_get_rsp_handler(protocol_code_t code, uint32_t mid, void *data, uint32_t len)
{
    battery_info_t *battery_info = (battery_info_t *)data;

    printf("=======================>>> dev_info_get_rsp_handler <<<===================== \n");

    printf("battery_info.voltage : %d\n", battery_info->voltage);

    printf("============================================================================\n");
}

static void dev_info_rsp_err_handler(protocol_code_t code, uint32_t mid, void *data, uint32_t len)
{
    printf("=======================>>> dev_info_rsp_err_handler <<<===================== \n");

    printf("code : %d\n", code);

    printf("============================================================================\n");
}


//--------------------------------------- req --------------------------------------//


// dev_manage service
static app_protocol_handler_t dev_service_table[] = 
{
    {NULL, NULL},
    [CONN_PARM_SET]     = {NULL,                    dev_info_get_req_handler},
    [DEV_INFO_GET]      = {NULL,                    dev_info_get_req_handler},
    [BAT_INFO_GET]      = {NULL,                    dev_info_get_req_handler},

};


// ota service
static app_protocol_handler_t ota_service_table[] = 
{
    [0]                     = {NULL, NULL},
};


// file service
static app_protocol_handler_t file_trans_service_table[] =
{
    [0]                    = {NULL,                     NULL                   },
};


// sid table
static app_protocol_handler_t *foraml_sid_table[] = 
{   [0] = NULL,
    [DEV_MANAGE]            = dev_service_table,
    // [OTA_MANAGE]            = ota_service_table,
    // [FILE_MANAGE]           = file_trans_service_table,
};

// max cid
static uint8_t foraml_max_cid_table[] = 
{   0,
    [DEV_MANAGE]            = DEV_MANAGE_MAX_CID,
};

//---------------------------------------------------------------------
// factory protocol                 
//---------------------------------------------------------------------

// fm manage service
static app_protocol_handler_t fm_service_table[] =
{
    [0]                                     = {NULL, NULL},
    [FM_SWITCH_TEMP_1]                      = {NULL, NULL},
};


// sid table
static app_protocol_handler_t *factory_sid_table[] = 
{   [0] = NULL,
    [TEST_MANAGE - FACTORY_BASE_SID]         = NULL,
    [FACTORY_MANAHE - FACTORY_BASE_SID]      = fm_service_table,

};



//--------------------------------------- rsp --------------------------------------//


// dev_manage service
static app_protocol_handler_t rsp_dev_service_table[] = 
{
    {NULL, NULL},
    [CONN_PARM_SET]     = {battery_info_t_fields,                    dev_info_get_rsp_handler},

};


// ota service
static app_protocol_handler_t rsp_ota_service_table[] = 
{
//     [0]                     = {NULL, NULL},
};


// file service
static app_protocol_handler_t rsp_file_trans_service_table[] =
{
    [0]                    = {NULL,                     NULL                   },
};


// sid table
static app_protocol_handler_t *rsp_foraml_sid_table[] = 
{   [0] = NULL,
    [DEV_MANAGE]            = rsp_dev_service_table,
    [OTA_MANAGE]            = rsp_ota_service_table,
    [FILE_MANAGE]           = rsp_file_trans_service_table,
};

// max cid
static uint8_t rsp_foraml_max_cid_table[] = 
{   0,
    [DEV_MANAGE]            = DEV_MANAGE_MAX_CID,
    [OTA_MANAGE]            = OTA_MANAGE_MAX_CID,
    [FILE_MANAGE]           = FILE_TRANS_MAX_CID,

};

//---------------------------------------------------------------------
// factory protocol                 
//---------------------------------------------------------------------

// fm manage service
static app_protocol_handler_t rsp_fm_service_table[] =
{
    [0]                                     = {NULL, NULL},
    [FM_SWITCH_TEMP_1]                      = {NULL, NULL},
};


// sid table
static app_protocol_handler_t *rsp_factory_sid_table[] = 
{   [0] = NULL,
    [TEST_MANAGE - FACTORY_BASE_SID]         = NULL,
    [FACTORY_MANAHE - FACTORY_BASE_SID]      = rsp_fm_service_table,

};



//--------------------------------------- rsp error --------------------------------------//


// dev_manage service
static app_protocol_handler_t rsp_err_dev_service_table[] = 
{
    {NULL, NULL},
    [CONN_PARM_SET]     = {NULL,                    dev_info_rsp_err_handler},
    // [DEV_INFO_GET]      = {NULL,                    dev_info_get},

};


// sid table
static app_protocol_handler_t *rsp_err_foraml_sid_table[] = 
{   [0] = NULL,
    [DEV_MANAGE]            = rsp_err_dev_service_table,
};

// max cid
static uint8_t rsp_err_foraml_max_cid_table[] = 
{   0,
    [DEV_MANAGE]            = DEV_MANAGE_MAX_CID,
    [OTA_MANAGE]            = OTA_MANAGE_MAX_CID,
    [FILE_MANAGE]           = FILE_TRANS_MAX_CID,
    // [DANCE_PAD_MANAGE]      = PAD_MANAGE_MAX_CID,

};

//---------------------------------------------------------------------
// factory protocol                 
//---------------------------------------------------------------------

// fm manage service
static app_protocol_handler_t rsp_err_fm_service_table[] =
{
    [0]                                     = {NULL, NULL},
    [FM_SWITCH_TEMP_1]                      = {NULL, NULL},
};


// sid table
static app_protocol_handler_t *rsp_err_factory_sid_table[] = 
{   [0] = NULL,
    [TEST_MANAGE - FACTORY_BASE_SID]         = NULL,
    [FACTORY_MANAHE - FACTORY_BASE_SID]      = rsp_err_fm_service_table,

};


// max cid
static uint8_t factory_max_cid_table[] = 
{   0,
    [TEST_MANAGE - FACTORY_BASE_SID]         = 0,
    [FACTORY_MANAHE - FACTORY_BASE_SID]      = FM_SWITCH_MAX_CID,
};



app_protocol_table_t req_pb_table = {
    .sid_table = foraml_sid_table,
    .max_cid_table = foraml_max_cid_table,
    .max_sid = MAX_FORMAT_SID,
    .base_sid = FORMAL_BASE_SID,
};

app_protocol_table_t req_nake_table = {
    .sid_table = factory_sid_table,
    .max_cid_table = factory_max_cid_table,
    .max_sid = MAX_FACTORY_SID,
    .base_sid = FACTORY_BASE_SID,
};


app_protocol_table_t rsp_pb_table = {
    .sid_table = rsp_foraml_sid_table,
    .max_cid_table = rsp_foraml_max_cid_table,
    .max_sid = MAX_FORMAT_SID,
    .base_sid = FORMAL_BASE_SID,
};

app_protocol_table_t rsp_nake_table = {
    .sid_table = rsp_factory_sid_table,
    .max_cid_table = factory_max_cid_table,
    .max_sid = MAX_FACTORY_SID,
    .base_sid = FACTORY_BASE_SID,
};


app_protocol_table_t rsp_err_pb_table = {
    .sid_table = rsp_err_foraml_sid_table,
    .max_cid_table = rsp_err_foraml_max_cid_table,
    .max_sid = MAX_FORMAT_SID,
    .base_sid = FORMAL_BASE_SID,
};

app_protocol_table_t rsp_err_nake_table = {
    .sid_table = rsp_err_factory_sid_table,
    .max_cid_table = factory_max_cid_table,
    .max_sid = MAX_FACTORY_SID,
    .base_sid = FACTORY_BASE_SID,
};
