/*
 * @LastEditors: auto
 */
#ifndef SERVICE_PROTOCOL_PORT_H
#define SERVICE_PROTOCOL_PORT_H

#include <stdint.h>
#include "pb.h"
#include "common.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    REQ_PB_PROTOCOL_TYPE = 0,
    REQ_NAKE_PROTOCOL_TYPE,
    RSP_PB_PROTOCOL_TYPE,
    RSP_NAKE_PROTOCOL_TYPE,
    RSP_PB_ERROR_TYPE,
    RSP_NAKE_ERROR_TYPE,
    PROTOCOL_TYPE_MAX,
} protocol_type_t;


typedef enum {
    PROTO_RSP_SUCCESS_CREATED_2_01                     = (2 << 2) + 1,        // only used on response to "POST" and "PUT" like HTTP 201
    PROTO_RSP_SUCCESS_DELETED_2_02                     = (2 << 2) + 2,        // only used on response to "DELETE" and "POST" like HTTP 204
    PROTO_RSP_SUCCESS_VALID_2_03                       = (2 << 2) + 3,
    PROTO_RSP_SUCCESS_CHANGED_2_04                     = (2 << 2) + 4,        // only used on response to "POST" and "PUT" like HTTP 204
    PROTO_RSP_SUCCESS_CONTENT_2_05                     = (2 << 2) + 5,        // only used on response to "GET" like HTTP 200 (OK)

    PROTO_RSP_ERROR_BAD_REQUEST_4_00                   = (2 << 4) + 0,        // like HTTP 400
    PROTO_RSP_ERROR_UNAUTHORIZED_4_01                  = (2 << 4) + 1,
    PROTO_RSP_BAD_OPTION_4_02                          = (2 << 4) + 2,
    PROTO_RSP_FORBIDDEN_4_03                           = (2 << 4) + 3,
    PROTO_RSP_NOT_FOUND_4_04                           = (2 << 4) + 4,
    PROTO_RSP_METHOD_NOT_ALLOWED_4_05                  = (2 << 4) + 5,
    PROTO_RSP_METHOD_NOT_ACCEPTABLE_4_06               = (2 << 4) + 6,
    PROTO_RSP_REQUEST_TIMEOUT_4_08                     = (2 << 4) + 8,
    PROTO_RSP_PRECONDITION_FAILED_4_12                 = (2 << 4) + 12,
    PROTO_RSP_REQUEST_ENTITY_TOO_LARGE_4_13            = (2 << 4) + 13,
    PROTO_RSP_UNSUPPORTED_CONTENT_FORMAT_4_15          = (2 << 4) + 15,
    PROTO_RSP_INTERNAL_SERVER_ERROR_5_00               = (2 << 5) + 0,
    PROTO_RSP_NOT_IMPLEMENTED_5_01                     = (2 << 5) + 1,
    PROTO_RSP_BAD_GATEWAY_5_02                         = (2 << 5) + 2,
    PROTO_RSP_SERVICE_UNAVAILABLE_5_03                 = (2 << 5) + 3,
    PROTO_RSP_GATEWAY_TIMEOUT_5_04                     = (2 << 5) + 4,
    PROTO_RSP_PROXYING_NOT_SUPPORTED_5_05              = (2 << 5) + 5,


    PROTO_REQ_GET                                      = (2 << 6) + 1,   
    PROTO_REQ_POST                                     , 
    PROTO_REQ_PUT                                      , 
    PROTO_REQ_DELETE                                   , 

    PROTO_REQ_SUBSCRIBE                                = (2 << 6) + 6,  
    PROTO_REQ_PUBLISH                                  , 

    PROTO_RSP_CODE_MAX,
} protocol_code_t;

typedef struct {
    const pb_msgdesc_t *field; 
    void (*handler)(protocol_code_t code, uint32_t mid, void *data, uint32_t len);
} app_protocol_handler_t;

typedef struct {
    app_protocol_handler_t **sid_table;
    uint8_t *max_cid_table;
    uint8_t max_sid;
    uint8_t base_sid;

} app_protocol_table_t;

typedef struct {
    uint8_t sid;
    uint8_t rid;
    uint16_t mid;
} protocol_head_t;

typedef struct {
    void *(*protocol_malloc)(size_t size);
    void (*protocol_free)(void *mem);
    int32_t (*protocol_tx)(protocol_head_t protocol_head, uint32_t code, void *data, uint32_t len, uint32_t used_pb_flag);
} protocol_interface_t;

void protocol_interface_register(const protocol_interface_t *interface);
void protocol_table_register(protocol_type_t protocol_type, void *protocol_table);

void app_protocol_input_process(protocol_head_t protocol_head, uint32_t code, void *payload, uint32_t payload_len);
int32_t app_protocol_tx(protocol_head_t protocol_head, uint32_t code, const pb_msgdesc_t *fields, void *data, uint32_t len);


#ifdef __cplusplus
}
#endif

#endif /* SERVICE_PROTOCOL_PORT_H */
