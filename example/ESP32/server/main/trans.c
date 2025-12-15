#include "trans.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>
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

#include <time.h>
#include <sys/time.h>

#include "os_adapter.h"
#include "apt_protocol.h"
#include "service_protocol_table.h"
#include "service_protocol_port.h"



static apt_t *apt = NULL;


//---------------------------------------------------------------------
// ms get                 
//---------------------------------------------------------------------
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


//---------------------------------------------------------------------
// test start               
//---------------------------------------------------------------------

static volatile uint8_t send_flag = 0;

static int32_t ble_con_id = 0;

static void ble_connected_handle(uint8_t conn_id)
{
    ble_con_id = conn_id;
    ble_con_id = 1;
    printf("ble connected\n");
}

static void ble_disconnected_handle(uint8_t conn_id)
{
    ble_con_id = -1;
    send_flag = 0;

    printf("ble disconnected\n");

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
    printf("sid : %d, rid : %d, msg_id : %d, code : %d\n", apt_msg->uri.sid, apt_msg->uri.rid, msg_id, apt_msg->code);
    printf("-------------------------------------------------------------------------\n");

    // uint8_t *pay_buf = apt_payload_mem_get(sizeof(apt_msg_t));
    // if (pay_buf == NULL) {
    //     printf("apt_req_listener, get mem fail\n");
    //     return;
    // }

    // apt_msg_t rsp_apt_msg;
    // rsp_apt_msg.uri.sid = apt_msg->uri.sid;
    // rsp_apt_msg.uri.rid = apt_msg->uri.rid;
    // rsp_apt_msg.code = RSP_SUCCESS_CONTENT_2_05;
    // rsp_apt_msg.content_type = apt_msg->content_type;
    // rsp_apt_msg.payload_size = sizeof(apt_msg_t);
    // rsp_apt_msg.payload = pay_buf;

    // memcpy(pay_buf, &rsp_apt_msg, sizeof(apt_msg_t));

    // int32_t rsp_ret = apt_rsp(apt, &rsp_apt_msg, msg_id, 1);
    // printf("-------------------->>> rsp_ret : %d\n", rsp_ret);


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
    apt_parm.work_thread_name = "apt_thread2";
    apt_parm.work_thread_priority = 2;
    apt_parm.work_thread_stack_size = 4096*10;

    apt_interface_t apt_interface;
    apt_interface.output = apt_output;
    apt_interface.req_listener = apt_req_listener;
    apt_interface.rsp_listener = apt_rsp_listener;

    printf("apt create start\n");
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
        ctrl_parm.alive_time_ms = 500;
        ctrl_parm.timeout_ms = 2000;
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
    protocol_table_register(REQ_NAKE_PROTOCOL_TYPE, &req_nake_table);
    protocol_table_register(REQ_PB_PROTOCOL_TYPE, &req_pb_table);
    protocol_table_register(RSP_PB_PROTOCOL_TYPE, &rsp_pb_table);
    protocol_table_register(RSP_NAKE_PROTOCOL_TYPE, &rsp_nake_table);
}


static void os_check(void)
{
    printf("------------->>>count, free mem is %d, min mem is %d\n", xPortGetFreeHeapSize(), xPortGetMinimumEverFreeHeapSize());
}



void trans_task_init(void)
{

	ESP_LOGI("trans", "trans init start ... ");

    apt_pre_init();
    apt_init();
    app_protocol_init();

    connect_register(ble_connected_handle, ble_disconnected_handle);
    ble_rx_register(ble_rx);

    period_task_register(os_check);

    printf("free mem is %d, min mem is %d\n", xPortGetFreeHeapSize(), xPortGetMinimumEverFreeHeapSize());
    
    ble_init();

    ESP_LOGI("trans", "trans init over ... ");
}


