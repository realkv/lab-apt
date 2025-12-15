<!--
 * @LastEditors: auto
-->

# apt ：用于 IoT 通信的 RESTful 风格的应用协议
![Platform](https://img.shields.io/badge/Platform-RTOS%2FAndroid%2FiOS-green) ![protocol](https://img.shields.io/badge/protocol-BLE-brightgreen)


apt 是一个用于 IoT 通信的应用层协议，借鉴了 RESTful 的设计理念，同时考虑了嵌入式资源受限特性和高实时要求，
可用于 BLE、串口和局域网 UDP 等

## 优势

- RESTful 风格
- 高可扩展性，兼容裸数据、Protobuf、Json 等多种载体格式
- 自带异常通信检测，可通过回包参数感知对端处理速率
- 内存池设计，无内存碎片顾虑，对嵌入式平台友好
- 异步串行设计模式，避免外部使用者处理复杂的资源竞争问题
- 可应用于嵌入式 RTOS、Android 和 iOS 多平台

## 快速开始


### 注册外部依赖

apt 需要访问平台相关的函数。您需要实现并注册一个 `apt_adapter_port_t` 结构体，该结构体包含了平台适配所需的**回调函数**

```c
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

    // ...

    
} apt_adapter_port_t;

// 初始化平台适配层
void apt_adapter_port_init(const apt_adapter_port_t *adapter_port);
```

### 开始使用

1. 创建 apt 
   
        // 创建一个 apt_t 对象，创建成功会返回指向 apt_t 对象的指针
        // 外部可以建立此对象和实际通信实体（如 GATT Service）的一一对应关系
        apt_t *apt = apt_create(const apt_parm_t *apt_parm, const apt_interface_t *apt_interface, const void *user_data)

    对于 BLE 来说，创建 apt_t 对象的时机在 connenct 成功之后

2. 输入一个底层数据包
   
        // 收到底层数据（如 BLE 数据）时调用
        apt_input(apt, data, len);

3. 请求或回复数据
   
        apt_req();
        apt_rsp();


## 示例

详见 example 目录，目前仅有 ESP32 下的示例

