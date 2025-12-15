#include "trans.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include "esp_timer.h"
#include "esp_log.h"
#include "esp_sleep.h"
#include "sdkconfig.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_err.h"

#include "gattc_demo.h"
#include "period_task.h"
#include "common.h"

#include "os_adapter.h"
#include "apt_protocol.h"
#include "service_protocol_table.h"
#include "service_protocol_port.h"
// #include "dev_manage_service.pb.h"


static apt_t *apt = NULL;



static uint32_t osal_get_ms(void)
{
    // return esp_timer_get_time()/1000;
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec/1000);
}

//---------------------------------------------------------------------
// log              
//---------------------------------------------------------------------
static void apt_log_output(uint32_t level, const char *message)
{
    printf("%d ", level);
    printf("%s", message);
}

//---------------------------------------------------------------------
// interface             
//---------------------------------------------------------------------


static volatile uint8_t send_flag = 0;

static uint8_t ble_con_id = 0;
static uint32_t start_time_ms = 0;


static void ble_connected_handle(uint8_t conn_id)
{
    ble_con_id = conn_id;
    send_flag = 1;
}


static void ble_disconnected_handle(uint8_t conn_id)
{
    ble_con_id = -1;
    send_flag = 0;
}

static void ble_rx(uint8_t conn_id, uint8_t *data, uint16_t len)
{
    printf("-------------------------------- ble_rx, len : %d\n", len);

    apt_input(apt, data, len);
}



//---------------------------------------------------------------------
// apt port              
//---------------------------------------------------------------------
static int32_t apt_output(const apt_t *apt, void *data, uint32_t len)
{
    ble_tx(ble_con_id, (uint8_t *)data, len);
    return 0;
}

static void apt_req_listener(const apt_t *apt, const apt_msg_t *apt_msg, uint32_t msg_id)
{
    printf("-------------------------------- apt recv req ---------------------------\n");
    printf("code : %d, msg_id : %d\n", apt_msg->code, msg_id);
    printf("-------------------------------------------------------------------------\n");

    protocol_head_t protocol_head;
    protocol_head.sid = apt_msg->uri.sid;
    protocol_head.rid = apt_msg->uri.rid;
    protocol_head.mid = (uint16_t)msg_id;

    app_protocol_input_process(protocol_head, apt_msg->code, apt_msg->payload, apt_msg->payload_size);
}

static void apt_rsp_listener(const apt_t *apt, const apt_msg_t *apt_msg, uint32_t msg_id, uint32_t alive_ms)
{
    printf("-------------------------------- apt recv rsp ---------------------------\n");
    printf("code : %d, msg_id : %d, alive_ms : %d\n", apt_msg->code, msg_id, alive_ms);
    printf("-------------------------------------------------------------------------\n");

    protocol_head_t protocol_head;
    protocol_head.sid = apt_msg->uri.sid;
    protocol_head.rid = apt_msg->uri.rid;
    protocol_head.mid = (uint16_t)msg_id;

    app_protocol_input_process(protocol_head, apt_msg->code, apt_msg->payload, apt_msg->payload_size);
}


static void apt_init(void) 
{

    apt_log_level_set(APT_LOG_TRACE);
    apt_log_output_register(apt_log_output);

    apt_parm_t apt_parm;
    apt_parm.work_thread_name = "apt_thread";
    apt_parm.work_thread_priority = 3;
    apt_parm.work_thread_stack_size = 4096*3;

    apt_interface_t apt_interface;
    apt_interface.output = apt_output;
    apt_interface.req_listener = apt_req_listener;
    apt_interface.rsp_listener = apt_rsp_listener;

    apt = apt_create(&apt_parm, &apt_interface, NULL);
    if (apt == NULL) {
        printf("apt init fail\n");
    } else {
        printf("apt init ok ~~~~~~~~~! \n");
    }
}


//---------------------------------------------------------------------
// app protocol             
//---------------------------------------------------------------------
static int32_t app_proto_tx(protocol_head_t protocol_head, uint32_t code, void *data, uint32_t len, uint32_t used_pb_flag)
{
    if (code < PROTO_RSP_SUCCESS_CREATED_2_01 || code >= PROTO_RSP_CODE_MAX) {
        printf("app_proto_tx, code error, code : %d\n", code);
        return -1;
    }

    int32_t req_id;
    if (code < PROTO_REQ_GET) {
        // rsp
        apt_msg_t apt_msg;
        apt_msg.uri.sid = protocol_head.sid;
        apt_msg.uri.rid = protocol_head.rid;
        apt_msg.code = code;
        apt_msg.content_type = used_pb_flag == 0 ? APT_OCTET_STREAM : APT_PROTOBUF;
        apt_msg.payload_size = len;
        apt_msg.payload = data;
        req_id = apt_rsp(apt, &apt_msg, protocol_head.mid, 1);

    } else {
        // req
        apt_msg_t apt_msg;
        apt_msg.uri.sid = protocol_head.sid;
        apt_msg.uri.rid = protocol_head.rid;
        apt_msg.code = code;
        apt_msg.content_type = used_pb_flag == 0 ? APT_OCTET_STREAM : APT_PROTOBUF;
        apt_msg.payload_size = len;
        apt_msg.payload = data;

        apt_ctrl_parm_t ctrl_parm;
        ctrl_parm.need_rsp = 1;
        ctrl_parm.alive_time_ms = 3800;
        ctrl_parm.timeout_ms = 4000;
        req_id = apt_req(apt, &apt_msg, &ctrl_parm, 1); 
    }

    printf("-------------------->>> app_proto_tx, req_id : %d\n", req_id);

    return req_id;
}

void app_protocol_init(void)
{
    protocol_interface_t interface;
    interface.protocol_malloc = apt_payload_mem_get;
    interface.protocol_free = apt_payload_mem_free;
    interface.protocol_tx = app_proto_tx;

    protocol_interface_register(&interface);

    extern app_protocol_table_t req_nake_table;
    extern app_protocol_table_t req_pb_table;
    extern app_protocol_table_t rsp_pb_table;
    extern app_protocol_table_t rsp_nake_table;
    extern app_protocol_table_t rsp_err_pb_table;
    extern app_protocol_table_t rsp_err_nake_table;
    protocol_table_register(REQ_NAKE_PROTOCOL_TYPE, &req_nake_table);
    protocol_table_register(REQ_PB_PROTOCOL_TYPE, &req_pb_table);
    protocol_table_register(RSP_PB_PROTOCOL_TYPE, &rsp_pb_table);
    protocol_table_register(RSP_NAKE_PROTOCOL_TYPE, &rsp_nake_table);
    protocol_table_register(RSP_PB_ERROR_TYPE, &rsp_err_pb_table);
    protocol_table_register(RSP_NAKE_ERROR_TYPE, &rsp_err_nake_table);
}

//---------------------------------------------------------------------
// test             
//---------------------------------------------------------------------
#define TEST_LEN   100

static void ptotocol_test(void)
{

    if (send_flag != 0) {
        // uint8_t *test_data = apt_payload_mem_get(TEST_LEN);
        // if (test_data == NULL) {
        //     printf("!!!!!!!!!!!!!!!! test, get mem fail\n");
        //     return;
        // }

        // for (uint32_t i = 0; i < TEST_LEN; i++)
        // {
        //     test_data[i] = i%255;
        // }

        // apt_msg_t apt_msg;
        // apt_msg.uri.sid = 1;
        // apt_msg.uri.rid = 1;
        // apt_msg.code = REQ_GET;
        // apt_msg.content_type = APT_PROTOBUF;
        // apt_msg.payload_size = TEST_LEN;
        // apt_msg.payload = test_data;

        // // printf("==================>>> test_data : %08x\n", (uint32_t)test_data);
        // // printf("==================>>> apt_msg.payload : %08x\n", (uint32_t)apt_msg.payload);

        // apt_ctrl_parm_t ctrl_parm;
        // ctrl_parm.need_rsp = 1;
        // ctrl_parm.alive_time_ms = 500;
        // ctrl_parm.timeout_ms = 2000;

        // int32_t req_id = apt_req(apt, &apt_msg, &ctrl_parm, 1);
        // printf("-------------------->>> req_id : %d\n", req_id);

        protocol_head_t protocol_head;
        protocol_head.sid = 1;
        protocol_head.rid = 1;

        int32_t req_id = app_protocol_tx(protocol_head, PROTO_REQ_GET, NULL, NULL, 0);
        printf("-------------------->>> req_id : %d\n", req_id);

        printf("------------------------------------->>>count, free mem is %d, min mem is %d\n", xPortGetFreeHeapSize(), xPortGetMinimumEverFreeHeapSize());
    }
  
}


void trans_task_init(void)
{
	ESP_LOGI("trans", "trans init start ... ");

    apt_pre_init();
    apt_init();
    app_protocol_init();

    connect_register(ble_connected_handle, ble_disconnected_handle);
    ble_rx_register(ble_rx);

    period_task_register(ptotocol_test);

    ble_init();
}


