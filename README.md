<!--
 * @LastEditors: auto
-->

# apt : A RESTful-style Application Protocol for IoT Communication
![Platform](https://img.shields.io/badge/Platform-RTOS%2FAndroid%2FiOS-green) ![protocol](https://img.shields.io/badge/protocol-BLE-brightgreen)


apt is an application-layer protocol for IoT communication. It is inspired by RESTful design principles, tailored for the resource-constrained nature and high real-time demands of embedded systems. It can be used over various transport layers like BLE, serial ports, and LAN UDP.

## Features
- RESTful-style architecture
- Highly extensible, compatible with multiple payload formats such as raw data, Protobuf, and JSON
- Built-in abnormal communication detection, allowing you to gauge the peer's processing speed through response parameters
- Memory pool design eliminates concerns about memory fragmentation, making it friendly for embedded platforms
- Asynchronous and serialized design pattern simplifies development by freeing the user from handling complex resource - contention issues
- Multi-platform support for embedded RTOS, Android, and iOS

## Quick Start

### Registering External Dependencies

apt needs to access platform-specific functions. You must implement and register an apt_adapter_port_t struct, which contains the callback functions required for platform adaptation

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

// Initialize the platform adaptation layer
void apt_adapter_port_init(const apt_adapter_port_t *adapter_port);
```

### Getting Started

1.  Create an apt instance

        // Create an apt_t object. On success, it returns a pointer to the apt_t object.
        // The user can map this object to an actual communication entity (e.g., a GATT Service).
        apt_t *apt = apt_create(const apt_parm_t *apt_parm, const apt_interface_t *apt_interface, const void *user_data);

    For BLE, the apt_t object should be created after a connection is successfully established.

2.  Input a low-level data packet

        // Call this when low-level data (e.g., BLE data) is received.
        apt_input(apt, data, len);

3.  Request or respond with data

        apt_req();
        apt_rsp();

## Examples

See the `example` directory. Currently, only an ESP32 example is available.
