
#include "service_protocol_port.h"
#include "pb_encode.h"
#include "pb_decode.h"
#include <stdio.h>

#define PROTOCOL_APP_PRINTF                 printf
#define MAX_PROTOCOL_BUF_SIZE               (4096*2)


typedef struct {
    app_protocol_table_t *protocol_table[PROTOCOL_TYPE_MAX];
    uint8_t app_rx_buf[MAX_PROTOCOL_BUF_SIZE];
    protocol_interface_t protocol_interface;
} service_protocol_priv_data_t;


static service_protocol_priv_data_t service_protocol_priv_data;


void protocol_interface_register(const protocol_interface_t *interface)
{
    service_protocol_priv_data.protocol_interface.protocol_malloc = interface->protocol_malloc;
    service_protocol_priv_data.protocol_interface.protocol_free = interface->protocol_free;
    service_protocol_priv_data.protocol_interface.protocol_tx = interface->protocol_tx;
}


static uint32_t app_protocol_decode(const pb_msgdesc_t *fields, uint8_t *data, uint16_t len, void *msg)
{   
    if (fields == NULL || len == 0) {
        return 0;
    }
    
    pb_istream_t stream = pb_istream_from_buffer(data, len);
    if(pb_decode(&stream, fields, msg))
        return len - stream.bytes_left;
    else
        return 0;
}



int32_t app_protocol_tx(protocol_head_t protocol_head, uint32_t code, const pb_msgdesc_t *fields, void *data, uint32_t len)
{
    if (code < PROTO_RSP_SUCCESS_CREATED_2_01 || code > PROTO_REQ_PUBLISH) {
        PROTOCOL_APP_PRINTF("app_protocol_tx, code error, code : %d, sid : %d, rid : %d\n", code, protocol_head.sid, protocol_head.rid); 
        return -1;
    }

    int32_t ret = 0;
    uint32_t size = 0;

    uint8_t *buf = NULL;
    uint32_t used_pb = 0;
    uint32_t tx_size = 0;
    if (fields != NULL) {
        bool rett = pb_get_encoded_size(&size, fields, data);
        PROTOCOL_APP_PRINTF("app_protocol_tx, pb_get_encoded_size ret : %d, size is %d, len is %d\n", rett, size, len);

        buf = (uint8_t *)service_protocol_priv_data.protocol_interface.protocol_malloc(size);
        if (buf == NULL) {
            PROTOCOL_APP_PRINTF("app_protocol_tx, mem get failed, sid : %d, rid : %d, size : %d\n", protocol_head.sid, protocol_head.rid, size);
            return -11;
        }

        pb_ostream_t stream = pb_ostream_from_buffer(buf, size);
        bool status = pb_encode(&stream, fields, data);
        if (!status) {
            PROTOCOL_APP_PRINTF("app_protocol_tx error, pb_encode status : %d\n", status);
            service_protocol_priv_data.protocol_interface.protocol_free(buf);
            buf = NULL;
            ret = -10;
            return ret;
        }
        tx_size = stream.bytes_written;
        used_pb = 1;
    } else {
        tx_size = len;
        buf = (uint8_t *)service_protocol_priv_data.protocol_interface.protocol_malloc(tx_size);
        if (buf == NULL) {
            PROTOCOL_APP_PRINTF("app_protocol_tx, mem get failed, sid : %d, rid : %d, size : %d\n", protocol_head.sid, protocol_head.rid, size);
            return -11;
        }

        if (tx_size > 0) {
            memcpy(buf, data, tx_size);
        }
        used_pb = 1;
    }
    
    ret = service_protocol_priv_data.protocol_interface.protocol_tx(protocol_head, code, buf, tx_size, used_pb);
    if (ret < 0 && buf != NULL) {
        service_protocol_priv_data.protocol_interface.protocol_free(buf);
    } 
    
    PROTOCOL_APP_PRINTF("app_protocol_tx ok, size : %d\n", tx_size);
    

    return ret;
}

void app_protocol_input_process(protocol_head_t protocol_head, uint32_t code, void *payload, uint32_t payload_len)
{
    uint8_t sid = protocol_head.sid;
    uint8_t rid = protocol_head.rid;

    if (code < PROTO_RSP_SUCCESS_CREATED_2_01 || code > PROTO_REQ_PUBLISH) {
        PROTOCOL_APP_PRINTF("app_protocol_input_process, code error, code : %d, sid : %d, rid : %d\n", code, sid, rid); 
        return;
    }

    PROTOCOL_APP_PRINTF("app_protocol_input_process, code : %d, sid : %d, rid : %d\n", code, sid, rid); 
    app_protocol_table_t *protocol_table = NULL;

    if (code >= PROTO_REQ_GET) {
        // req

        if (service_protocol_priv_data.protocol_table[REQ_NAKE_PROTOCOL_TYPE] != NULL) {
            PROTOCOL_APP_PRINTF("app_protocol_input_process, recv req, base_sid : %d, sid : %d\n", 
            service_protocol_priv_data.protocol_table[REQ_NAKE_PROTOCOL_TYPE]->base_sid, sid); 
            if (sid >= service_protocol_priv_data.protocol_table[REQ_NAKE_PROTOCOL_TYPE]->base_sid) {
            // factory protocol
                protocol_table = service_protocol_priv_data.protocol_table[REQ_NAKE_PROTOCOL_TYPE];
            } else {
                // formal protocol handle
                protocol_table = service_protocol_priv_data.protocol_table[REQ_PB_PROTOCOL_TYPE];
            }
        } else {
            PROTOCOL_APP_PRINTF("app_protocol_input_process, recv req, REQ_NAKE_PROTOCOL_TYPE == NULL\n"); 
        }
    } else {
        // rsp

        // error code
        if (code >= PROTO_RSP_ERROR_BAD_REQUEST_4_00) {
            if (service_protocol_priv_data.protocol_table[RSP_NAKE_ERROR_TYPE] != NULL) {
                PROTOCOL_APP_PRINTF("app_protocol_input_process, recv rsp error, base_sid : %d, sid : %d\n", 
                service_protocol_priv_data.protocol_table[RSP_NAKE_ERROR_TYPE]->base_sid, sid); 

                if (sid >= service_protocol_priv_data.protocol_table[RSP_NAKE_ERROR_TYPE]->base_sid) {
                // factory protocol
                    protocol_table = service_protocol_priv_data.protocol_table[RSP_NAKE_ERROR_TYPE];
                } else {
                    // formal protocol handle
                    protocol_table = service_protocol_priv_data.protocol_table[RSP_PB_ERROR_TYPE];
                }
            } else {
                PROTOCOL_APP_PRINTF("app_protocol_input_process, recv rsp error, RSP_NAKE_ERROR_TYPE == NULL\n"); 
            }
        } else {
            if (service_protocol_priv_data.protocol_table[RSP_NAKE_PROTOCOL_TYPE] != NULL) {
                PROTOCOL_APP_PRINTF("app_protocol_input_process, recv rsp, base_sid : %d, sid : %d\n", 
                service_protocol_priv_data.protocol_table[RSP_NAKE_PROTOCOL_TYPE]->base_sid, sid); 

                if (sid >= service_protocol_priv_data.protocol_table[RSP_NAKE_PROTOCOL_TYPE]->base_sid) {
                // factory protocol
                    protocol_table = service_protocol_priv_data.protocol_table[RSP_NAKE_PROTOCOL_TYPE];
                } else {
                    // formal protocol handle
                    protocol_table = service_protocol_priv_data.protocol_table[RSP_PB_PROTOCOL_TYPE];
                }
            } else {
                PROTOCOL_APP_PRINTF("app_protocol_input_process, recv rsp, RSP_NAKE_PROTOCOL_TYPE == NULL\n"); 
            }
        }
    }
    
    if (protocol_table == NULL) {
        PROTOCOL_APP_PRINTF("app_protocol_input_process, error, protocol_table == NULL\n"); 
        return;
    }

    uint8_t table_sid = sid - protocol_table->base_sid;

    PROTOCOL_APP_PRINTF("app_protocol_input_process, max_sid : %d, table_sid : %d\n", protocol_table->max_sid, table_sid); 
    if (sid < protocol_table->max_sid 
    && protocol_table->sid_table[table_sid] != NULL) {  

        if (rid < protocol_table->max_cid_table[table_sid] && 
        protocol_table->sid_table[table_sid][rid].handler != NULL) {
            memset(service_protocol_priv_data.app_rx_buf, 0, sizeof(service_protocol_priv_data.app_rx_buf));

            uint32_t msg_len = 0;
            if (protocol_table->sid_table[table_sid][rid].field != NULL) {
                msg_len = app_protocol_decode(protocol_table->sid_table[table_sid][rid].field, payload, payload_len, service_protocol_priv_data.app_rx_buf);
            } else {
                memcpy(service_protocol_priv_data.app_rx_buf, payload, payload_len);
                msg_len = payload_len;
            }

            // PROTOCOL_APP_PRINTF("protocol_handle handler, sid : %d, base_sid : %d, table_sid : %d, rid : %d\n", sid, protocol_table->base_sid, table_sid, rid);
            
            if (protocol_table->sid_table[table_sid][rid].handler) {
                PROTOCOL_APP_PRINTF("protocol_handle, app_decode msg_len : %d\n", msg_len); 
                protocol_table->sid_table[table_sid][rid].handler(code, protocol_head.mid, service_protocol_priv_data.app_rx_buf, msg_len);
            } else {
                PROTOCOL_APP_PRINTF("app_protocol_input_process, error, protocol_table->sid_table[table_sid][rid].handler == NULL 2\n"); 
            }
        } else {
            PROTOCOL_APP_PRINTF("app_protocol_input_process, error, protocol_table->sid_table[table_sid][rid].handler == NULL\n"); 
        }
    } else {
        PROTOCOL_APP_PRINTF("app_protocol_input_process, error, protocol_table->sid_table[table_sid] == NULL\n"); 
    }
}


void protocol_table_register(protocol_type_t protocol_type, void *protocol_table)
{
    if (protocol_type >= PROTOCOL_TYPE_MAX) {
        return;
    } 

    service_protocol_priv_data.protocol_table[protocol_type] = (app_protocol_table_t *)protocol_table;
}





