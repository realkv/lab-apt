#include "os_adapter.h"

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
#include <time.h>
#include <sys/time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/queue.h"
#include "esp_timer.h"
#else
#include <pthread.h>
#include <semaphore.h>
#include <mqueue.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#include <sys/select.h>
#include <unistd.h>
#endif

#ifdef OSAL_PLATFORM_IOS
#include <dispatch/dispatch.h>
#endif

#include "apt_protocol.h"



#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
#define IS_INTER  xPortInIsrContext()
#endif
//---------------------------------------------------------------------
// queue                 
//---------------------------------------------------------------------
#ifndef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
typedef struct {
    char name[32];
    mqd_t mq;
} _mq_blk_t;
#endif

static int32_t apt_queue_create(void **queue, uint32_t item_num, uint32_t item_size)
{
	int32_t ret = -1;

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	*(QueueHandle_t *)queue = xQueueCreate(item_num, item_size);
	if (*(QueueHandle_t *)queue != NULL) {
		ret = 0;
	}
#else
    _mq_blk_t *mq_blk = (_mq_blk_t *)malloc(sizeof(_mq_blk_t));
    if (mq_blk == NULL) {
        return ret;
    }

    sprintf(mq_blk->name, "%s_%d", "apt_mq", (uint32_t)mq_blk);
    struct mq_attr attr;
    attr.mq_maxmsg = item_num;
    attr.mq_msgsize = item_size;
    mq_blk->mq = mq_open(mq_blk->name, O_CREAT | O_RDWR | O_EXCL, 0644, &attr);
    if (mq_blk->mq == (mqd_t)-1) {
        free(mq_blk);
        perror("apt mq_open fail");
        return ret - 1;
    }

    *(_mq_blk_t **)queue = mq_blk;
    ret = 0;
#endif

	return ret;
}

static int32_t apt_queue_send(void **queue, void *data, uint32_t size, uint32_t timeout)
{
	int32_t ret = -1;

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	if (IS_INTER) {
		static BaseType_t xHigherPriorityTaskWoken = pdFALSE;
		if (xQueueSendFromISR(*(QueueHandle_t *)queue, data, &xHigherPriorityTaskWoken) == pdTRUE) {
			ret = 0;
		}
	} else {
		if (xQueueSend(*(QueueHandle_t *)queue, data, timeout/portTICK_PERIOD_MS) == pdTRUE) {
			ret = 0;
		}
	}
#else
    _mq_blk_t *mq_blk = *(_mq_blk_t **)queue;
    ret = mq_send(mq_blk->mq, data, size, 0);
#endif

	return ret;
}


static int32_t apt_queue_send_prior(void **queue, void *data, uint32_t size, uint32_t timeout)
{
	int32_t ret = -1;

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	if (IS_INTER) {
		static BaseType_t xHigherPriorityTaskWoken = pdFALSE;
		if (xQueueSendToFrontFromISR(*(QueueHandle_t *)queue, data, &xHigherPriorityTaskWoken) == pdTRUE) {
			ret = 0;
		}
	} else {
		if (xQueueSendToFront(*(QueueHandle_t *)queue, data, timeout/portTICK_PERIOD_MS) == pdTRUE) {
			ret = 0;
		}
	}
#else
    _mq_blk_t *mq_blk = *(_mq_blk_t **)queue;
    ret = mq_send(mq_blk->mq, data, size, 1);
#endif

	return ret;
}

static int32_t apt_queue_recv(void **queue, void *data, uint32_t size, uint32_t timeout)
{
	int32_t ret = -1;

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	if (IS_INTER) {
		static BaseType_t xHigherPriorityTaskWoken = pdFALSE;
		if (xQueueReceiveFromISR(*(QueueHandle_t *)queue, data, &xHigherPriorityTaskWoken) == pdTRUE) {
			ret = 0;
		}
	} else {
		if (xQueueReceive(*(QueueHandle_t *)queue, data, timeout/portTICK_PERIOD_MS) == pdTRUE) {
			ret = 0;
		}
	}
#else
    _mq_blk_t *mq_blk = *(_mq_blk_t **)queue;
    uint32_t priority;
    ret = mq_receive(mq_blk->mq, data, size, &priority);
#endif

	return ret;

}

static void apt_queue_destory(void **queue)
{
#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	vQueueDelete(*(QueueHandle_t *)queue);
	*(QueueHandle_t *)queue = NULL;
#else
    _mq_blk_t *mq_blk = *(_mq_blk_t **)queue;
    mq_close(mq_blk->mq);
    mq_unlink(mq_blk->name);
    free(mq_blk);
    mq_blk = NULL;
#endif
}


//---------------------------------------------------------------------
// timer                 
//---------------------------------------------------------------------
static int32_t apt_timer_create(void **timer, void (*period_cb)(void *arg), void *arg)
{
    int ret = -1;
#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
    esp_timer_handle_t *periodic_timer = (esp_timer_handle_t *)malloc(sizeof(esp_timer_handle_t));
    if (periodic_timer != NULL) {
        const esp_timer_create_args_t periodic_timer_args = {
            .callback = period_cb,
            /* name is optional, but may help identify the timer when debugging */
            .name = "periodic",
			.arg = arg,
        };

        ret = esp_timer_create(&periodic_timer_args, periodic_timer);
        *(esp_timer_handle_t **)timer = periodic_timer;
    }
#elif defined OSAL_PLATFORM_IOS
    dispatch_source_t *periodic_timer = (dispatch_source_t *)malloc(sizeof(dispatch_source_t));
    if (periodic_timer != NULL) {
        dispatch_queue_t queue = dispatch_get_global_queue(0, 0);
        *periodic_timer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0, queue);
        dispatch_source_set_event_handler(*periodic_timer , ^{
            period_cb(arg);
        });

        ret = 0;
        *(dispatch_source_t **)timer = periodic_timer;
    }
#else
    timer_t *periodic_timer = (timer_t *)malloc(sizeof(timer_t));
    if (periodic_timer != NULL) {
        struct sigevent evp;
        memset(&evp, 0, sizeof(struct sigevent));
        evp.sigev_value.sival_int = 111;
		evp.sigev_value.sival_ptr = arg; 
        evp.sigev_notify = SIGEV_THREAD;
        evp.sigev_notify_function = period_cb;

        ret = timer_create(CLOCK_REALTIME, &evp, periodic_timer);
        *(timer_t **)timer = periodic_timer;
    }
#endif

    return ret;
}


static int32_t apt_timer_start(void **timer, uint32_t period_ms)
{
    int ret = 0;

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
    esp_timer_handle_t *periodic_timer = *(esp_timer_handle_t **)timer;
    ret = esp_timer_start_periodic(*periodic_timer, period_ms*1000);
#elif defined OSAL_PLATFORM_IOS
    dispatch_source_t *periodic_timer = *(dispatch_source_t **)timer;
	dispatch_time_t start = dispatch_walltime(NULL, 0);
    dispatch_source_set_timer(*periodic_timer, start, period_ms*NSEC_PER_MSEC, 0);
    dispatch_resume(*periodic_timer);
#else
    timer_t *periodic_timer = *(timer_t **)timer;
    struct itimerspec it;
    it.it_interval.tv_sec = period_ms/1000;
    it.it_interval.tv_nsec = (period_ms%1000) * 1000 * 1000;
    it.it_value.tv_sec = period_ms/1000;
    it.it_value.tv_nsec = (period_ms%1000) * 1000 * 1000;
    ret = timer_settime(*periodic_timer, 0, &it, NULL);
#endif

    return ret;
}


static int32_t apt_timer_stop(void **timer)
{
    int ret = 0;

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
    esp_timer_handle_t *periodic_timer = *(esp_timer_handle_t **)timer;
    ret = esp_timer_stop(*periodic_timer);
#elif defined OSAL_PLATFORM_IOS
    dispatch_source_t *periodic_timer = *(dispatch_source_t **)timer;
    dispatch_suspend(*periodic_timer);
#else
    timer_t *periodic_timer = *(timer_t **)timer;
    struct itimerspec it;
    it.it_interval.tv_sec = 0;
    it.it_interval.tv_nsec = 0;
    it.it_value.tv_sec = 0;
    it.it_value.tv_nsec = 0;
    ret = timer_settime(*periodic_timer, 0, &it, NULL);
#endif

    return ret;
}


static int32_t apt_timer_destory(void **timer)
{
    int ret = 0;

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
    esp_timer_handle_t *periodic_timer = *(esp_timer_handle_t **)timer;
    ret = esp_timer_delete(*periodic_timer);
    free(periodic_timer);
    periodic_timer = NULL;
#elif defined OSAL_PLATFORM_IOS
    dispatch_source_t *periodic_timer = *(dispatch_source_t **)timer;
    dispatch_source_cancel(*periodic_timer);
    free(periodic_timer);
    periodic_timer = NULL;
#else
    timer_t *periodic_timer = *(timer_t **)timer;
    ret = timer_delete(*periodic_timer);
    free(periodic_timer);
    periodic_timer = NULL;
#endif

    return ret;
}


//---------------------------------------------------------------------
// time                 
//---------------------------------------------------------------------
static uint32_t apt_get_ms(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (tv.tv_sec * 1000 + tv.tv_usec/1000);
}

static void apt_delay_ms(uint32_t ms)
{
#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	vTaskDelay(ms);
#else
	struct timeval delay;
	delay.tv_sec = ms/1000;
	delay.tv_usec = (ms%1000) *1000; 
	select(0, NULL, NULL, NULL, &delay);
#endif
}

//---------------------------------------------------------------------
// thread                 
//---------------------------------------------------------------------

static int32_t apt_thread_create(void **thread, apt_thread_config_t *thread_config)
{   
    int ret = -1;

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	TaskHandle_t *thread_handle = (TaskHandle_t *)malloc(sizeof(TaskHandle_t));
    if (thread_handle != NULL) {

        ret = xTaskCreate(thread_config->thread_func, thread_config->thread_name, thread_config->thread_stack_size/4, 
        thread_config->arg, thread_config->thread_priority, thread_handle);

		ret = ret == pdPASS ? 0 : -1;

        *(TaskHandle_t **)thread = thread_handle;
    }
#else
    pthread_t *thread_handle = (pthread_t *)osal_malloc(sizeof(pthread_t));
    if (thread_handle != NULL) {
		ret = pthread_create(thread_handle, NULL, thread_config->thread_func, thread_config->arg);
        pthread_detach(*thread_handle);

        *(pthread_t **)thread = thread_handle;
    }
#endif

    return ret;
}

static int32_t apt_thread_destory(void **thread)
{   
    int ret = 0;

#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	TaskHandle_t *thread_handle = *(TaskHandle_t **)thread;
    vTaskDelete(*thread_handle); 
#else
    pthread_t *thread_handle = *(pthread_t **)thread;
#endif
    free(thread_handle);
    thread_handle = NULL;

    return ret;
}

static void apt_thread_exit(void **thread)
{   
#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	TaskHandle_t *thread_handle = *(TaskHandle_t **)thread;
    vTaskDelete(NULL);
#else
    pthread_t *thread_handle = *(pthread_t **)thread;
    pthread_exit(NULL);
#endif

    free(thread_handle);
    thread_handle = NULL;
}


//---------------------------------------------------------------------
// critical section             
//---------------------------------------------------------------------
#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;
#endif

static int32_t apt_create_critical(void **section)
{
    int32_t ret = 0;

#ifndef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
    pthread_mutex_t *x_mutext = (pthread_mutex_t *)malloc(sizeof(pthread_mutex_t));
	if (x_mutext != NULL) {
		if (pthread_mutex_init(x_mutext, NULL) != 0) {
			free(x_mutext);
			x_mutext = NULL;
			ret = -1;
		} else {
			*(pthread_mutex_t **)section = x_mutext;
		}
	}
#endif

    return ret;
}


static void apt_destory_critical(void **section)
{
#ifndef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
    pthread_mutex_t *x_mutext = *(pthread_mutex_t **)section;
	pthread_mutex_destroy(x_mutext);
	free(x_mutext);
	x_mutext = NULL;
#endif 
}
static void apt_enter_critical(void **section)
{
#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	taskENTER_CRITICAL(&mux);
#else
    struct timespec tout;
    clock_gettime(CLOCK_REALTIME, &tout);
    uint32_t diff_sec = 2;
    uint32_t diff_ms = 0;

    unsigned long long ns = tout.tv_nsec + diff_ms * 1000 * 1000;
    tout.tv_sec += diff_sec;
    tout.tv_sec += ns/1000000000;
    tout.tv_nsec = ns%1000000000;

    pthread_mutex_t *x_mutext = *(pthread_mutex_t **)section;
    pthread_mutex_timedlock(x_mutext, &tout);
#endif
    
}

static void apt_exit_critical(void **section)
{
#ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
	taskEXIT_CRITICAL(&mux);
#else
    pthread_mutex_t *x_mutext = *(pthread_mutex_t **)section;
	pthread_mutex_unlock(x_mutext);
#endif
}



// static int32_t apt_thread_create(void **thread, apt_thread_config_t *thread_config)
// {   
//     int ret = -1;

// #ifdef OSAL_PLATFORM_EMBEDDED_FREERTOS_ESP32
// 	TaskHandle_t *thread_handle = (TaskHandle_t *)malloc(sizeof(TaskHandle_t));
//     if (thread_handle != NULL) {

//         ret = xTaskCreate(thread_config->thread_func, thread_config->thread_name, thread_config->thread_stack_size/4, 
//         thread_config->arg, thread_config->thread_priority, thread_handle);

// 		ret = ret == pdPASS ? 0 : -1;

//         *(TaskHandle_t **)thread = thread_handle;
//     }
// #else
//     pthread_t *thread_handle = (pthread_t *)osal_malloc(sizeof(pthread_t));
//     if (thread_handle != NULL) {
// 		ret = pthread_create(thread_handle, NULL, thread_config->thread_func, thread_config->arg);
//         pthread_detach(*thread_handle);

//         *(pthread_t **)thread = thread_handle;
//     }
// #endif

//     return ret;
// }

void apt_pre_init(void)
{
    apt_adapter_port_t apt_adapter_port;

    apt_adapter_port.apt_thread.thread_create = apt_thread_create;
    apt_adapter_port.apt_thread.thread_destory = apt_thread_destory;
    apt_adapter_port.apt_thread.thread_exit = apt_thread_exit;

    apt_adapter_port.apt_queue.queue_create = apt_queue_create;
    apt_adapter_port.apt_queue.queue_send = apt_queue_send;
    apt_adapter_port.apt_queue.queue_send_prior = apt_queue_send_prior;
    apt_adapter_port.apt_queue.queue_recv = apt_queue_recv;
    apt_adapter_port.apt_queue.queue_destory = apt_queue_destory;

    apt_adapter_port.apt_time.delay_ms = apt_delay_ms;
    apt_adapter_port.apt_time.get_ms = apt_get_ms;

    apt_adapter_port.apt_mem.malloc = malloc;
    apt_adapter_port.apt_mem.free = free;

    apt_adapter_port.apt_critical.enter_critical_section = apt_enter_critical;
    apt_adapter_port.apt_critical.leave_critical_section = apt_exit_critical;
    apt_adapter_port.apt_critical.critical_section_create = apt_create_critical;
    apt_adapter_port.apt_critical.critical_section_destory = apt_destory_critical;
    
    apt_adapter_port_init(&apt_adapter_port);
}