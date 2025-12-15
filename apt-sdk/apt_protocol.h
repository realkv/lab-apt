#ifndef __APT_PROTOCOL_H__
#define __APT_PROTOCOL_H__

#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    char *thread_name;
    int32_t thread_priority;
    uint32_t thread_stack_size;
    void (*thread_func)(void *arg);
    void *arg;
} apt_thread_config_t;



typedef struct {
    // --- Thread Management ---
    struct {
        /**
         * @brief Creates a new thread.
         * @param thread Pointer to a pointer that will hold the new thread handle.
         * @param thread_config Configuration for the new thread.
         * @return 0 on success, -1 on failure.
         */
        int32_t (*thread_create)(void **thread, apt_thread_config_t *thread_config);

        /**
         * @brief Destroys an existing thread.
         * @param thread Pointer to a pointer holding the thread handle to destroy.
         * @return 0 on success, -1 on failure.
         */
        int32_t (*thread_destory)(void **thread);

        /**
         * @brief Exits the current thread.
         * @param thread Pointer to a pointer holding the current thread handle.
         */
        void (*thread_exit)(void **thread);

    } apt_thread;

    // --- Queue Management ---
    struct {
        /**
         * @brief Initializes a queue.
         * @param queue Pointer to a pointer that will hold the new queue handle.
         * @param item_num The maximum number of items the queue can hold.
         * @param item_size The size of each item in the queue.
         * @return 0 on success, -1 on failure.
         */
        int32_t (*queue_create)(void **queue, uint32_t item_num, uint32_t item_size);

        /**
         * @brief Sends data to a queue with a specified timeout.
         * @param queue Pointer to a pointer holding the queue handle.
         * @param data Pointer to the data to send.
         * @param size The size of the data to send.
         * @param timeout The timeout in milliseconds to wait if the queue is full.
         * @return 0 on success, -1 on failure.
         */
        int32_t (*queue_send)(void **queue, void *data, uint32_t size, uint32_t timeout);

        /**
         * @brief Sends data with higher priority to a queue with a specified timeout.
         * @param queue Pointer to a pointer holding the queue handle.
         * @param data Pointer to the data to send.
         * @param size The size of the data to send.
         * @param timeout The timeout in milliseconds to wait if the queue is full.
         * @return 0 on success, -1 on failure.
         */
        int32_t (*queue_send_prior)(void **queue, void *data, uint32_t size, uint32_t timeout);

        /**
         * @brief Receives data from a queue with a specified timeout.
         * @param queue Pointer to a pointer holding the queue handle.
         * @param data Pointer to a buffer to store the received data.
         * @param size The maximum size of the data to receive.
         * @param timeout The timeout in milliseconds to wait if the queue is empty.
         * @return 0 on success, -1 on failure.
         */
        int32_t (*queue_recv)(void **queue, void *data, uint32_t size, uint32_t timeout);

        /**
         * @brief Releases resources associated with a queue.
         * @param queue Pointer to a pointer holding the queue handle to destroy.
         */
        void (*queue_destory)(void **queue);
    } apt_queue;

    // --- Time Management ---
    struct {
        /**
         * @brief Gets the current time in milliseconds.
         * @return The current time in milliseconds.
         */
        uint32_t (*get_ms)(void);;

        /**
         * @brief Delays the current thread for a specified number of milliseconds.
         * @param ms The number of milliseconds to delay.
         */
        void (*delay_ms)(uint32_t ms);
    } apt_time;

    // --- Critical Section Management ---
    struct {
        /**
         * @brief Creates a critical section object.
         * @param critical_section Pointer to a pointer that will hold the new critical section handle.
         * @return 0 on success, -1 on failure.
         */
        int32_t (*critical_section_create)(void **critical_section);

        /**
         * @brief Destroys a critical section object.
         * @param critical_section Pointer to a pointer holding the critical section handle to destroy.
         */
        void (*critical_section_destory)(void **critical_section);

        /**
         * @brief Enters a critical section, preventing concurrent access.
         * @param critical_section Pointer to a pointer holding the critical section handle.
         */
        void (*enter_critical_section)(void **critical_section);

        /**
         * @brief Leaves a critical section, allowing concurrent access.
         * @param critical_section Pointer to a pointer holding the critical section handle.
         */
        void (*leave_critical_section)(void **critical_section);
    } apt_critical;

    // --- Memory Management ---
    struct {

        /**
         * @brief Allocates a block of memory.
         * @param size The number of bytes to allocate.
         * @return A pointer to the allocated memory block, or NULL if allocation fails.
         */
        void *(*malloc)(size_t size);

        /**
         * @brief Frees a previously allocated block of memory.
         * @param mem Pointer to the memory block to free.
         */
        void (*free)(void *mem);
    } apt_mem;

    
} apt_adapter_port_t;


typedef struct _priv_apt_t priv_apt_t;


typedef struct {
    priv_apt_t *priv_apt;
    void *user_data;
} apt_t;


typedef struct {
    char *work_thread_name;
    int32_t work_thread_priority;
    uint32_t work_thread_stack_size;
} apt_parm_t;



typedef enum {
    APT_OCTET_STREAM                              = 0,                  /* application/octet-stream */
    APT_PROTOBUF                                  = 1,                  /* application/protobuf  */
    APT_JSON                                      = 2,                  /* application/json  */
    APT_CBOR                                         ,
    APT_MAX 
} apt_content_type_t;


typedef enum {

    RSP_SUCCESS_CREATED_2_01                     = (2 << 2) + 1,        // only used on response to "POST" and "PUT" like HTTP 201
    RSP_SUCCESS_DELETED_2_02                     = (2 << 2) + 2,        // only used on response to "DELETE" and "POST" like HTTP 204
    RSP_SUCCESS_VALID_2_03                       = (2 << 2) + 3,
    RSP_SUCCESS_CHANGED_2_04                     = (2 << 2) + 4,        // only used on response to "POST" and "PUT" like HTTP 204
    RSP_SUCCESS_CONTENT_2_05                     = (2 << 2) + 5,        // only used on response to "GET" like HTTP 200 (OK)

    RSP_ERROR_BAD_REQUEST_4_00                   = (2 << 4) + 0,        // like HTTP 400
    RSP_ERROR_UNAUTHORIZED_4_01                  = (2 << 4) + 1,
    RSP_BAD_OPTION_4_02                          = (2 << 4) + 2,
    RSP_FORBIDDEN_4_03                           = (2 << 4) + 3,
    RSP_NOT_FOUND_4_04                           = (2 << 4) + 4,
    RSP_METHOD_NOT_ALLOWED_4_05                  = (2 << 4) + 5,
    RSP_METHOD_NOT_ACCEPTABLE_4_06               = (2 << 4) + 6,
    RSP_REQUEST_TIMEOUT_4_08                     = (2 << 4) + 8,
    RSP_PRECONDITION_FAILED_4_12                 = (2 << 4) + 12,
    RSP_REQUEST_ENTITY_TOO_LARGE_4_13            = (2 << 4) + 13,
    RSP_UNSUPPORTED_CONTENT_FORMAT_4_15          = (2 << 4) + 15,
    RSP_INTERNAL_SERVER_ERROR_5_00               = (2 << 5) + 0,
    RSP_NOT_IMPLEMENTED_5_01                     = (2 << 5) + 1,
    RSP_BAD_GATEWAY_5_02                         = (2 << 5) + 2,
    RSP_SERVICE_UNAVAILABLE_5_03                 = (2 << 5) + 3,
    RSP_GATEWAY_TIMEOUT_5_04                     = (2 << 5) + 4,
    RSP_PROXYING_NOT_SUPPORTED_5_05              = (2 << 5) + 5,



    REQ_BASE                                     = (2 << 6) + 0,
    REQ_GET                                      = (2 << 6) + 1,    
    REQ_POST                                     = (2 << 6) + 2, 
    REQ_PUT                                      = (2 << 6) + 3, 
    REQ_DELETE                                   = (2 << 6) + 4, 

    REQ_SUBSCRIBE                                = (2 << 6) + 6, 
    REQ_PUBLISH                                  = (2 << 6) + 7, 

    APT_CODE_MAX, 

} apt_code_t;

typedef struct {   
    struct {
        uint8_t sid;
        uint8_t rid;
    } uri;
    apt_content_type_t content_type;
    apt_code_t code;
    uint32_t payload_size;
    void *payload;
} apt_msg_t;

typedef struct {
    uint32_t timeout_ms;
    uint16_t alive_time_ms;
    uint8_t need_rsp;
} apt_ctrl_parm_t;


typedef struct {

    int32_t (*output)(const apt_t *apt, void *data, uint32_t len);

    void (*req_listener)(const apt_t *apt, const apt_msg_t *apt_msg, uint32_t msg_id);
    void (*rsp_listener)(const apt_t *apt, const apt_msg_t *apt_msg, uint32_t msg_id, uint32_t alive_ms);
} apt_interface_t;


typedef enum {
    APT_LOG_NONE = 0,
    
    APT_LOG_FAULT,
    APT_LOG_ERROR,
    APT_LOG_WARN,
    APT_LOG_INFO,
    APT_LOG_DEBUG,
    APT_LOG_TRACE,
    
} apt_log_level_t;

void apt_log_level_set(apt_log_level_t level);

void apt_log_output_register(void (*log_output)(apt_log_level_t level, const char *message));

void apt_adapter_port_init(const apt_adapter_port_t *apt_adapter_port);

apt_t *apt_create(const apt_parm_t *apt_parm, const apt_interface_t *apt_interface, const void *user_data);

void apt_destory(apt_t *apt);

void *apt_payload_mem_get(size_t size);

void apt_payload_mem_free(void *mem);

int32_t apt_req(const apt_t *apt, const apt_msg_t *apt_msg, const apt_ctrl_parm_t *ctrl_parm, uint32_t payload_use_apt_mem_flag);
int32_t apt_rsp(const apt_t *apt, const apt_msg_t *apt_msg, uint32_t msg_id, uint32_t payload_use_apt_mem_flag);

int32_t apt_input(const apt_t *apt, void *data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif