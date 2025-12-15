#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "apt_protocol.h"


//---------------------------------------------------------------------
// queue node definition                                                         
//---------------------------------------------------------------------
typedef struct node_head {
	struct node_head *next, *prev;
} queue_node_t;

//---------------------------------------------------------------------
// queue operations                                                         
//---------------------------------------------------------------------
#define QUEUE_HEAD_INIT(name) { &(name), &(name) }
#define QUEUE_HEAD(name) \
	struct IQUEUEHEAD name = QUEUE_HEAD_INIT(name)

#define QUEUE_INIT(ptr) ( \
	(ptr)->next = (ptr), (ptr)->prev = (ptr))

#define OFFSETOF(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

#define CONTAINEROF(ptr, type, member) ( \
		(type*)( ((char*)((type*)ptr)) - OFFSETOF(type, member)) )

#define QUEUE_ENTRY(ptr, type, member) CONTAINEROF(ptr, type, member)

#define QUEUE_ADD(node, head) ( \
	(node)->prev = (head), (node)->next = (head)->next, \
	(head)->next->prev = (node), (head)->next = (node))

#define QUEUE_ADD_TAIL(node, head) ( \
	(node)->prev = (head)->prev, (node)->next = (head), \
	(head)->prev->next = (node), (head)->prev = (node))

#define QUEUE_DEL_BETWEEN(p, n) ((n)->prev = (p), (p)->next = (n))

#define QUEUE_DEL(entry) (\
	(entry)->next->prev = (entry)->prev, \
	(entry)->prev->next = (entry)->next, \
	(entry)->next = 0, (entry)->prev = 0)

#define QUEUE_DEL_INIT(entry) do { \
	QUEUE_DEL(entry); QUEUE_INIT(entry); } while (0)

#define QUEUE_IS_EMPTY(entry) ((entry) == (entry)->next)

#define queue_init		QUEUE_INIT
#define queue_entry	    QUEUE_ENTRY
#define queue_add		QUEUE_ADD
#define queue_add_tail	QUEUE_ADD_TAIL
#define queue_del		QUEUE_DEL
#define queue_del_init	QUEUE_DEL_INIT
#define queue_is_empty  QUEUE_IS_EMPTY

#define LIST_FOR_EACH_SAFE(item, next_item, list) \
    for ((item) = (list)->next, (next_item) = (item)->next; (item) != (list); \
            (item) = (next_item), (next_item) = (item)->next)

#define LIST_FOR_EACH_ENTRY(item, list, type, member) \
    for ((item) = queue_entry((list)->next, type, member); \
            &(item)->member != (list); \
            (item) = queue_entry((item)->member.next, type, member))

#define LIST_FOR_EACH_ENTRY_SAFE(item, next_item, list, type, member) \
    for ((item) = queue_entry((list)->next, type, member), \
            (next_item) = queue_entry((item)->member.next, type, member); \
            &((item)->member) != (list); \
            (item) = (next_item), (next_item) = queue_entry((item)->member.next, type, member))

typedef struct s_node_head {
	struct s_node_head *next;
} s_node_t;

typedef struct mem_pool {                        
    uint16_t block_size;
    uint16_t block_num;  
    uint8_t *head;
    s_node_t pool_list;      
} mem_pool_t;

typedef struct {                        
    s_node_t block_node;       
    mem_pool_t *mem_pool;     
    uint8_t *data;             
} mem_block_t;
            
struct _priv_apt_t {                      

    queue_node_t req_list;
    queue_node_t rsp_list;

    uint32_t run_interval_ms;

    uint8_t exit_cmd;
    uint8_t exit_flag;
    uint16_t req_id;

    mem_pool_t frame_mem_pool; 
  
    
    void *critical_section;
    void *work_thread;
    void *queue;
    void *owner;

    void (*period_imp)(const apt_t *apt);

    int32_t (*output)(const apt_t *apt, void *data, uint32_t len);
    void (*req_listener)(const apt_t *apt, const apt_msg_t *apt_msg, uint32_t msg_id);
    void (*rsp_listener)(const apt_t *apt, const apt_msg_t *apt_msg, uint32_t msg_id, uint32_t alive_ms);
};


typedef struct {
    uint8_t sid;
    uint8_t rid;
    uint16_t msg_id;
    uint8_t code;
    uint8_t indicate;
    uint16_t alive_ms;
    uint32_t reserved;
    uint8_t payload[0];
} apt_payload_body_t;

typedef struct {
    queue_node_t node; 
    apt_ctrl_parm_t ctrl_parm;
    uint32_t payload_len;
    uint16_t msg_id;
    uint8_t sid;
    uint8_t rid;
    uint32_t alive_timeout_ms;
    apt_payload_body_t *apt_payload_body;
} apt_frame_t;


typedef struct {
    void *context;
    void (*event_handler)(apt_t *apt, const void *context);
    void (*context_free)(void *context);
} apt_context_t;


static void apt_period_imp(const apt_t *apt);

static apt_adapter_port_t apt_adapter;

//---------------------------------------------------------------------
// log            
//---------------------------------------------------------------------
static void (*log_hook)(apt_log_level_t, const char *) = NULL;
static apt_log_level_t log_level = APT_LOG_NONE;

void apt_log_output_register(void (*log_output)(apt_log_level_t level, const char *message)) 
{
    log_hook = log_output;
}

void apt_log_level_set(apt_log_level_t level) 
{
    log_level = level;
}

static void apt_log(apt_log_level_t level, const char *format, ...) 
{

    if (level > log_level) {
        return;
    }
    
    char buf[100];

    va_list ap;
    va_start(ap, format);
    vsnprintf(buf, 100, format, ap);
    va_end(ap);
    
    if (log_hook) {
        log_hook(level, buf);
    } else {
        printf("log level : %d", level);
        printf("%s\n", buf);
    }
}


void apt_adapter_port_init(const apt_adapter_port_t *apt_adapter_port)
{
    apt_adapter.apt_critical.critical_section_create = apt_adapter_port->apt_critical.critical_section_create;
    apt_adapter.apt_critical.critical_section_destory = apt_adapter_port->apt_critical.critical_section_destory;
    apt_adapter.apt_critical.enter_critical_section = apt_adapter_port->apt_critical.enter_critical_section;
    apt_adapter.apt_critical.leave_critical_section = apt_adapter_port->apt_critical.leave_critical_section;

    apt_adapter.apt_mem.malloc = apt_adapter_port->apt_mem.malloc;
    apt_adapter.apt_mem.free = apt_adapter_port->apt_mem.free;

    apt_adapter.apt_queue.queue_create = apt_adapter_port->apt_queue.queue_create;
    apt_adapter.apt_queue.queue_destory = apt_adapter_port->apt_queue.queue_destory;
    apt_adapter.apt_queue.queue_recv = apt_adapter_port->apt_queue.queue_recv;
    apt_adapter.apt_queue.queue_send = apt_adapter_port->apt_queue.queue_send;
    apt_adapter.apt_queue.queue_send_prior = apt_adapter_port->apt_queue.queue_send_prior;

    apt_adapter.apt_thread.thread_create = apt_adapter_port->apt_thread.thread_create;
    apt_adapter.apt_thread.thread_destory = apt_adapter_port->apt_thread.thread_destory;
    apt_adapter.apt_thread.thread_exit = apt_adapter_port->apt_thread.thread_exit;

    apt_adapter.apt_time.delay_ms = apt_adapter_port->apt_time.delay_ms;
    apt_adapter.apt_time.get_ms = apt_adapter_port->apt_time.get_ms;

}


static int32_t time_diff(uint32_t later, uint32_t earlier) {
    return ((int32_t)(later - earlier));
}


static int32_t mem_pool_init(mem_pool_t *mem_pool, uint32_t block_size, uint32_t block_num)
{
    mem_pool->block_size = block_size;
    mem_pool->block_num = block_num;
    mem_pool->pool_list.next = NULL;
    mem_pool->head = NULL;

    uint32_t total_size = (sizeof(mem_block_t) + block_size) * block_num;
    mem_pool->head = (uint8_t *)apt_adapter.apt_mem.malloc(total_size);
    if (mem_pool->head == NULL) {
        return -1;
    }
   
    uint8_t *ptr = mem_pool->head;
    memset(ptr, 0, total_size);
    mem_block_t *mem_block;
    for (uint32_t i = 0; i < block_num; i++) {
        mem_block = (mem_block_t *)ptr;
        mem_block->block_node.next = mem_pool->pool_list.next;
        mem_pool->pool_list.next = &mem_block->block_node;
        mem_block->mem_pool = mem_pool;
        mem_block->data = ptr + sizeof(mem_block_t);
        ptr += block_size + sizeof(mem_block_t);
    }

    return 0;
}


static int32_t mem_pool_deinit(mem_pool_t *mem_pool)
{
    apt_adapter.apt_mem.free(mem_pool->head);  
    mem_pool->head = NULL;
    mem_pool->block_size = 0;
    mem_pool->block_num = 0;
    mem_pool->pool_list.next = NULL;

    return 0;
}

static void *mem_get_from_pool(const apt_t *apt, mem_pool_t *mem_pool)
{
    void *ptr = NULL;

    if (apt == NULL || mem_pool == NULL) {
        return ptr;
    }

    apt_adapter.apt_critical.enter_critical_section(&apt->priv_apt->critical_section);

    if (mem_pool->pool_list.next != NULL) {
        mem_block_t *block = queue_entry(mem_pool->pool_list.next, mem_block_t, block_node);
        mem_pool->pool_list.next = block->block_node.next;
        block->block_node.next = NULL;
        ptr = block->data;
    }

    apt_adapter.apt_critical.leave_critical_section(&apt->priv_apt->critical_section);

    return ptr;
}

static void mem_free_to_pool(const apt_t *apt, void *mem)
{
    apt_adapter.apt_critical.enter_critical_section(&apt->priv_apt->critical_section);

    mem_block_t *block = (mem_block_t *)((uint8_t *)mem - sizeof(mem_block_t));
    mem_pool_t *mem_pool = block->mem_pool;
    block->block_node.next = mem_pool->pool_list.next;
    mem_pool->pool_list.next = &block->block_node;

    apt_adapter.apt_critical.leave_critical_section(&apt->priv_apt->critical_section);
}


static void apt_task_handler(void *arg)
{
    apt_t *apt = (apt_t *)arg;
    while (1) {

        apt_context_t apt_context;
        if (apt_adapter.apt_queue.queue_recv(&apt->priv_apt->queue, &apt_context, sizeof(apt_context_t), apt->priv_apt->run_interval_ms) == 0) {
            if (apt_context.event_handler) {
                apt_context.event_handler(apt, apt_context.context);
            } 

            if (apt_context.context_free) {
                apt_context.context_free(apt_context.context);
            }
        }

        if (apt->priv_apt->exit_cmd != 0) {
            break;
        }

        if (apt->priv_apt->period_imp) {
            apt->priv_apt->period_imp(apt);
        }
    }  

    apt->priv_apt->exit_flag = 1;
    apt_adapter.apt_thread.thread_exit(&apt->priv_apt->work_thread);
    
}

apt_t *apt_create(const apt_parm_t *apt_parm, const apt_interface_t *apt_interface, const void *user_data)
{
    apt_t *apt = (apt_t *)apt_adapter.apt_mem.malloc(sizeof(apt_t));
    if (apt == NULL) {
        apt_log(APT_LOG_ERROR, "apt create, apt get mem fail\n");
        return NULL;  
    }

    apt->priv_apt = (priv_apt_t *)apt_adapter.apt_mem.malloc(sizeof(priv_apt_t));
    if (apt->priv_apt == NULL) {
        apt_log(APT_LOG_ERROR, "apt create, priv_apt get mem fail\n");
        goto priv_apt_mem_fail; 
    }

    priv_apt_t *priv_apt = apt->priv_apt;
    apt->user_data = (void *)user_data;
    priv_apt->owner = apt;
    priv_apt->run_interval_ms = 0xffff;
    priv_apt->exit_cmd = 0;
    priv_apt->exit_flag = 0;
    priv_apt->req_id = 0;

    queue_init(&priv_apt->req_list);
    queue_init(&priv_apt->rsp_list);

    priv_apt->period_imp = apt_period_imp;
    priv_apt->output = apt_interface->output;
    priv_apt->req_listener = apt_interface->req_listener;
    priv_apt->rsp_listener = apt_interface->rsp_listener;

    if (apt_adapter.apt_critical.critical_section_create(&priv_apt->critical_section) != 0) {
        apt_log(APT_LOG_ERROR, "apt create, bcp critical create failed\n");
        goto critical_create_fail;
    }

    if (mem_pool_init(&priv_apt->frame_mem_pool, sizeof(apt_frame_t), 10) < 0) {
        apt_log(APT_LOG_ERROR, "apt create, frame_mem_pool init failed\n");
        goto frame_mem_pool_init_fail;
    }

    if (apt_adapter.apt_queue.queue_create(&priv_apt->queue, 10, sizeof(apt_context_t)) != 0) {
        apt_log(APT_LOG_ERROR, "apt create, queue create failed\n");
        goto apt_queue_create_fail;
    }

    apt_thread_config_t thread_config = {
        .thread_name = apt_parm->work_thread_name,
        .thread_priority = apt_parm->work_thread_priority,
        .thread_stack_size = apt_parm->work_thread_stack_size,
        .thread_func = apt_task_handler,
        .arg = apt,
    };
    if (apt_adapter.apt_thread.thread_create(&priv_apt->work_thread, &thread_config) != 0) {
        apt_log(APT_LOG_ERROR, "apt create, work thread create failed\n");
        goto apt_thread_create_fail;
    }

    apt_log(APT_LOG_TRACE, "apt create successful\n");
    
    return apt;

apt_thread_create_fail:
    apt_adapter.apt_queue.queue_destory(&priv_apt->queue);

apt_queue_create_fail:
    mem_pool_deinit(&priv_apt->frame_mem_pool);

frame_mem_pool_init_fail:
    apt_adapter.apt_critical.critical_section_destory(&priv_apt->critical_section);

critical_create_fail:
    apt_adapter.apt_mem.free(priv_apt);
    priv_apt = NULL;

priv_apt_mem_fail:
    apt_adapter.apt_mem.free(apt);
    apt = NULL;

    return NULL;
}


static inline int32_t apt_event_post(const apt_t *apt, void *context, void (*event_handler)(apt_t *apt, const void *context), void (*context_free)(void *context))
{
    apt_context_t apt_context;
    apt_context.context = context;
    apt_context.event_handler = event_handler;
    apt_context.context_free = context_free;

    return apt_adapter.apt_queue.queue_send(&apt->priv_apt->queue, &apt_context, sizeof(apt_context_t), 0);
}


static void apt_exit_handle(apt_t *apt, const void *context) 
{
    apt->priv_apt->exit_cmd = 1;
}

void apt_destory(apt_t *apt)
{
    if (apt == NULL) {
        apt_log(APT_LOG_INFO, "apt_destory, apt is null\n");
        return;
    }

    if (apt->priv_apt == NULL) {
        apt_adapter.apt_mem.free(apt);
        apt_log(APT_LOG_INFO, "apt_destory, priv_apt is null\n");
        return;
    }

    priv_apt_t *priv_apt = apt->priv_apt;

    if (apt_event_post(apt, NULL, apt_exit_handle, NULL) != 0) {
        apt_log(APT_LOG_ERROR, "apt_destory, post fail\n");
        priv_apt->exit_cmd = 1;
    }

    uint8_t count = 0;
    do {
        apt_adapter.apt_time.delay_ms(10);
    } while (count < 3 && priv_apt->exit_flag == 0);

    if (priv_apt->exit_flag == 0) {
        apt_adapter.apt_thread.thread_destory(&priv_apt->work_thread);
    }
    
    apt_adapter.apt_queue.queue_destory(&priv_apt->queue);
    apt_adapter.apt_mem.free(priv_apt);
    priv_apt = NULL;
    apt_adapter.apt_mem.free(apt);

    apt_log(APT_LOG_INFO, "apt_destory ok\n");
}



void *apt_payload_mem_get(size_t size)
{
    apt_payload_body_t *apt_payload_body = (apt_payload_body_t *)apt_adapter.apt_mem.malloc(sizeof(apt_payload_body_t) + size);
    if (apt_payload_body == NULL) {
        apt_log(APT_LOG_ERROR, "apt mem malloc fail\n");
        return NULL; 
    }

    return apt_payload_body->payload;
}

void apt_payload_mem_free(void *mem)
{
    if (mem == NULL) {
        return;
    }
    apt_payload_body_t *apt_payload_body = (apt_payload_body_t *)((uint8_t *)mem - sizeof(apt_payload_body_t));
    apt_adapter.apt_mem.free(apt_payload_body);
    apt_payload_body = NULL;
}

static void apt_req_frame_pack(const apt_t *apt, apt_frame_t *apt_frame, const apt_msg_t *apt_msg, const apt_ctrl_parm_t *ctrl_parm)
{
    memcpy(&apt_frame->ctrl_parm, ctrl_parm, sizeof(apt_ctrl_parm_t));
    apt_frame->ctrl_parm.timeout_ms = apt_adapter.apt_time.get_ms() + ctrl_parm->timeout_ms;
    apt_frame->payload_len = apt_msg->payload_size + 12;
    apt_frame->msg_id = apt->priv_apt->req_id;

    apt_adapter.apt_critical.enter_critical_section(&apt->priv_apt->critical_section);
    apt->priv_apt->req_id++;
    apt_adapter.apt_critical.leave_critical_section(&apt->priv_apt->critical_section);

    apt_frame->apt_payload_body->sid = apt_msg->uri.sid;
    apt_frame->apt_payload_body->rid = apt_msg->uri.rid;
    apt_frame->apt_payload_body->msg_id = apt_frame->msg_id;
    apt_frame->apt_payload_body->code = apt_msg->code;
    apt_frame->apt_payload_body->indicate = 0;
    if (ctrl_parm->need_rsp != 0) {
        apt_frame->apt_payload_body->indicate |= (1 << 7);
        apt_frame->apt_payload_body->alive_ms = ctrl_parm->alive_time_ms;
    }
    apt_frame->apt_payload_body->indicate |= apt_msg->content_type;
    
}

static void rsp_cb_error_notify(const apt_t *apt, const apt_frame_t *apt_frame, apt_code_t code)
{
    if (apt->priv_apt->rsp_listener) {

        apt_msg_t temp_msg;
        temp_msg.uri.sid = apt_frame->sid;
        temp_msg.uri.rid = apt_frame->rid;
        temp_msg.content_type = APT_OCTET_STREAM;
        temp_msg.code = code;
        temp_msg.payload_size = 0;

        apt->priv_apt->rsp_listener(apt, &temp_msg, apt_frame->msg_id, 0);
        
    }
}

static void apt_period_imp(const apt_t *apt)
{
    uint32_t cur_time_ms;

    apt_frame_t *frame = NULL, *next_frame = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(frame, next_frame, &apt->priv_apt->rsp_list, apt_frame_t, node) {
        cur_time_ms = apt_adapter.apt_time.get_ms();
        if (time_diff(cur_time_ms, frame->alive_timeout_ms) >= 0) {
            apt_log(APT_LOG_TRACE, "apt_period_imp, cur_time_ms : %d, alive_timeout_ms : %d\n", cur_time_ms, frame->alive_timeout_ms);
            queue_del(&frame->node);
            if (apt->priv_apt->output) {
                apt_payload_body_t apt_payload_body;
                apt_payload_body.alive_ms = 0;
                apt_payload_body.code = RSP_GATEWAY_TIMEOUT_5_04;
                apt_payload_body.msg_id = frame->msg_id;
                apt_payload_body.sid = frame->sid;
                apt_payload_body.rid = frame->rid;

                apt->priv_apt->output(apt, &apt_payload_body, 12);
            }
            mem_free_to_pool(apt, frame);
        }
    } 

    // rsp - wait app rsp
    frame = NULL, next_frame = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(frame, next_frame, &apt->priv_apt->req_list, apt_frame_t, node) {
        cur_time_ms = apt_adapter.apt_time.get_ms();
        if (time_diff(cur_time_ms, frame->ctrl_parm.timeout_ms) >= 0) {
            queue_del(&frame->node);
            rsp_cb_error_notify(apt, frame, RSP_REQUEST_TIMEOUT_4_08);
            mem_free_to_pool(apt, frame);
        }
    } 

    if (queue_is_empty(&apt->priv_apt->req_list) &&
        queue_is_empty(&apt->priv_apt->rsp_list)) {
        apt->priv_apt->run_interval_ms = 0xffff;
    }
}

static void apt_req_handle(apt_t *apt, const void *context)
{
    apt_frame_t *apt_frame = (apt_frame_t *)context;
    apt_payload_body_t *apt_payload_body = apt_frame->apt_payload_body;

    int32_t output_ret = 0;
    if (apt->priv_apt->output) {
        output_ret = apt->priv_apt->output(apt, apt_payload_body, apt_frame->payload_len);
    }
    
    if (output_ret != 0) {
        if (apt_frame->ctrl_parm.need_rsp != 0) {
            rsp_cb_error_notify(apt, apt_frame, RSP_BAD_GATEWAY_5_02);
        }

        mem_free_to_pool(apt, apt_frame);
    } else {
        if (apt_frame->ctrl_parm.need_rsp != 0) {
            queue_add_tail(&apt_frame->node, &apt->priv_apt->req_list);
            apt->priv_apt->run_interval_ms = 20;
        } else {
            mem_free_to_pool(apt, apt_frame);
        }
    }

    apt_adapter.apt_mem.free(apt_payload_body);
    apt_payload_body = NULL;
}

int32_t apt_req(const apt_t *apt, const apt_msg_t *apt_msg, const apt_ctrl_parm_t *ctrl_parm, uint32_t payload_use_apt_mem_flag)
{
    if (apt == NULL || apt_msg == NULL || ctrl_parm == NULL) {
        apt_log(APT_LOG_ERROR, "apt_req error, parm is null\n");
        return -1;
    }

    if (apt_msg->content_type >= APT_MAX) {
        apt_log(APT_LOG_ERROR, "apt_req error, content_type error, content_type : %d\n", apt_msg->content_type);
        return -2;
    }

    if (apt_msg->code <= REQ_BASE || apt_msg->code >= APT_CODE_MAX) {
        apt_log(APT_LOG_ERROR, "apt_req error, code error, code : %d\n", apt_msg->code);
        return -3;
    }

    int32_t ret = -3;
    apt_frame_t *apt_frame = (apt_frame_t *)mem_get_from_pool(apt, &apt->priv_apt->frame_mem_pool);
    if (apt_frame == NULL) {
        apt_log(APT_LOG_ERROR, "apt_req error, apt_frame get mem fail\n");
        ret--;
        return ret;
    }

    apt_payload_body_t *apt_payload_body = NULL;
    if (payload_use_apt_mem_flag == 0) {
        apt_payload_body = (apt_payload_body_t *)apt_adapter.apt_mem.malloc(sizeof(apt_payload_body_t) + apt_msg->payload_size);
        if (apt_payload_body == NULL) {
            apt_log(APT_LOG_ERROR, "apt_req error, mem get fail, size : %d\n", sizeof(apt_payload_body_t) + apt_msg->payload_size);
            ret--;
            goto apt_payload_body_fail;
        }
        memcpy(apt_payload_body->payload, apt_msg->payload, apt_msg->payload_size);
    } else {
        uint8_t *payload = apt_msg->payload;
        apt_payload_body = (apt_payload_body_t *)(payload - sizeof(apt_payload_body_t));
    }

    apt_frame->apt_payload_body = apt_payload_body;
    apt_req_frame_pack(apt, apt_frame, apt_msg, ctrl_parm);
    queue_init(&apt_frame->node);

    int32_t req_id = apt_frame->msg_id;
    if (apt_event_post(apt, apt_frame, apt_req_handle, NULL) != 0) {
        apt_log(APT_LOG_ERROR, "apt_req error, post fail\n");
        ret--;
        goto apt_post_fail;
    }

    return req_id;

apt_post_fail:
    apt_adapter.apt_mem.free(apt_payload_body);
    apt_payload_body = NULL;
    
apt_payload_body_fail:
    mem_free_to_pool(apt, apt_frame);

    return ret;
}


static void apt_rsp_handle(apt_t *apt, const void *context)
{
    apt_payload_body_t *apt_payload_body = (apt_payload_body_t *)context;

    apt_log(APT_LOG_DEBUG, "apt_rsp_handle, msg_id : %d\n", apt_payload_body->msg_id);

    uint16_t alive_time = 0;
    uint8_t find_flag = 0;
    apt_frame_t *frame = NULL, *next_frame = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(frame, next_frame, &apt->priv_apt->rsp_list, apt_frame_t, node) {
        if (frame->msg_id == apt_payload_body->msg_id) {
            queue_del(&frame->node);
            uint32_t cur_ms = apt_adapter.apt_time.get_ms();
            if (time_diff(frame->alive_timeout_ms, cur_ms) > 0) {
                alive_time = frame->alive_timeout_ms - cur_ms;
            } else {
                alive_time = 0;
            }
            mem_free_to_pool(apt, frame);
            find_flag = 1;
            break;
        }
    } 

    if (find_flag == 0) {
        apt_log(APT_LOG_WARN, "apt_rsp_handle, find rsp frame record fail\n");
        return;
    }

    apt_payload_body->alive_ms = alive_time;
    int32_t output_ret = apt->priv_apt->output(apt, apt_payload_body, apt_payload_body->reserved + 12);
    if (output_ret != 0) {
        apt_log(APT_LOG_ERROR, "apt_rsp_handle error, output fail, msg_id : %d\n", apt_payload_body->msg_id);
    } 
}

int32_t apt_rsp(const apt_t *apt, const apt_msg_t *apt_msg, uint32_t msg_id, uint32_t payload_use_apt_mem_flag)
{
    if (apt == NULL || apt_msg == NULL) {
        apt_log(APT_LOG_ERROR, "apt_rsp error, parm is null\n");
        return -1;
    }

    if (apt_msg->content_type >= APT_MAX) {
        apt_log(APT_LOG_ERROR, "apt_rsp error, content_type error, content_type : %d\n", apt_msg->content_type);
        return -2;
    }

    if (apt_msg->code >= REQ_BASE) {
        apt_log(APT_LOG_ERROR, "apt_rsp error, code error, code : %d\n", apt_msg->code);
        return -3;
    }

    int32_t ret = -3;

    apt_payload_body_t *apt_payload_body = NULL;
    if (payload_use_apt_mem_flag == 0) {
        apt_payload_body = (apt_payload_body_t *)apt_adapter.apt_mem.malloc(sizeof(apt_payload_body_t) + apt_msg->payload_size);
        if (apt_payload_body == NULL) {
            apt_log(APT_LOG_ERROR, "apt_rsp error, mem get fail, size : %d\n", sizeof(apt_payload_body_t) + apt_msg->payload_size);
            ret--;
            goto apt_payload_body_mem_fail;
        }
        if (apt_msg->payload_size > 0) {
            memcpy(apt_payload_body->payload, apt_msg->payload, apt_msg->payload_size);
        }
        
    } else {
        apt_payload_body = (apt_payload_body_t *)((uint8_t *)apt_msg->payload - sizeof(apt_payload_body_t));
    }

    apt_payload_body->sid = apt_msg->uri.sid;
    apt_payload_body->rid = apt_msg->uri.rid;
    apt_payload_body->msg_id = (uint16_t)msg_id;
    apt_payload_body->code = apt_msg->code;
    apt_payload_body->indicate = 0;
    apt_payload_body->indicate |= apt_msg->content_type;
    apt_payload_body->reserved = apt_msg->payload_size;
 
    if (apt_event_post(apt, apt_payload_body, apt_rsp_handle, apt_adapter.apt_mem.free) != 0) {
        apt_log(APT_LOG_ERROR, "apt_rsp error, post fail\n");
        ret--;
        goto apt_rsp_post_fail;
    }

    return 0;

apt_rsp_post_fail:
    apt_adapter.apt_mem.free(apt_payload_body);
    apt_payload_body = NULL;
    
apt_payload_body_mem_fail:

    return ret;
}


static void apt_input_handle(apt_t *apt, const void *context)
{
    apt_frame_t *apt_frame = (apt_frame_t *)context;
    apt_payload_body_t *apt_payload_body = apt_frame->apt_payload_body;
    if (apt_payload_body->code >= APT_CODE_MAX) {
        apt_adapter.apt_mem.free(apt_payload_body);
        apt_payload_body = NULL;
        mem_free_to_pool(apt, apt_frame);
        apt_log(APT_LOG_DEBUG, "apt_input handle, code error, code : %d\n", apt_payload_body->code);
        return;
    }

    apt_msg_t apt_msg = { 0 };
    apt_msg.uri.sid = apt_payload_body->sid;
    apt_msg.uri.rid = apt_payload_body->rid;
    apt_msg.content_type = apt_payload_body->indicate & (~(1 << 7));
    apt_msg.code = apt_payload_body->code;
    apt_msg.payload_size = apt_frame->payload_len - 12;
    apt_msg.payload = apt_payload_body->payload;
    uint16_t msg_id = apt_payload_body->msg_id;
    apt_frame->ctrl_parm.need_rsp = apt_payload_body->indicate & (1 << 7);

    if (apt_payload_body->code > REQ_BASE) {
        // req

        apt_log(APT_LOG_DEBUG, "apt_input handle, recv req, code : %d, alive_ms : %d\n", apt_payload_body->code, apt_payload_body->alive_ms);
        
        if (apt_frame->ctrl_parm.need_rsp != 0) {
            apt_frame->alive_timeout_ms = apt_adapter.apt_time.get_ms() + apt_payload_body->alive_ms;
            apt_frame->sid = apt_msg.uri.sid;
            apt_frame->rid = apt_msg.uri.rid;
            apt_frame->msg_id = msg_id;
            queue_add_tail(&apt_frame->node, &apt->priv_apt->rsp_list);
            apt->priv_apt->run_interval_ms = 20;
        } else {
            mem_free_to_pool(apt, apt_frame);
        }
        
        if (apt->priv_apt->req_listener) {
            apt->priv_apt->req_listener(apt, &apt_msg, msg_id);
        }

    } else {
        // rsp

        apt_log(APT_LOG_DEBUG, "apt_input handle, recv rsp, code : %d\n", apt_payload_body->code);

        apt_frame_t *cur_frame = NULL, *next_frame = NULL;
        LIST_FOR_EACH_ENTRY_SAFE(cur_frame, next_frame, &apt->priv_apt->req_list, apt_frame_t, node) {
 
            if (cur_frame->msg_id == msg_id) {
                queue_del(&cur_frame->node);
                mem_free_to_pool(apt, cur_frame);
                apt_log(APT_LOG_DEBUG, "apt_input handle, cur_frame free, msg_id : %d\n", msg_id);
                break;
            }
        } 

        if (apt->priv_apt->rsp_listener) {
            apt->priv_apt->rsp_listener(apt, &apt_msg, msg_id, apt_payload_body->alive_ms);
        }

        mem_free_to_pool(apt, apt_frame);
    }

    apt_adapter.apt_mem.free(apt_payload_body);
    apt_payload_body = NULL;
}

int32_t apt_input(const apt_t *apt, void *data, uint32_t len)
{
    apt_frame_t *apt_frame = (apt_frame_t *)mem_get_from_pool(apt, &apt->priv_apt->frame_mem_pool);
    if (apt_frame == NULL) {
        apt_log(APT_LOG_ERROR, "apt_input error, apt_frame get mem fail\n");
        return -1;
    }

    apt_payload_body_t *apt_payload_body = apt_adapter.apt_mem.malloc(len);
    if (apt_payload_body == NULL) {
        mem_free_to_pool(apt, apt_frame);
        apt_log(APT_LOG_ERROR, "apt_input error, mem get fail, len : %d\n", len);
        return -2;
    }

    apt_frame->payload_len = len;
    apt_frame->apt_payload_body = apt_payload_body;
    queue_init(&apt_frame->node);
    memcpy(apt_payload_body, data, len);
    if (apt_event_post(apt, apt_frame, apt_input_handle, NULL) != 0) {
        apt_adapter.apt_mem.free(apt_payload_body);
        apt_payload_body = NULL;
        mem_free_to_pool(apt, apt_frame);
        apt_log(APT_LOG_ERROR, "apt_input error, post fail\n");
        return -3;
    }

    return 0;
}











