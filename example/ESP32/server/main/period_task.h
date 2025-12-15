/*
 * @Author: your name
 * @Date: 2021-10-12 11:52:40
 * @LastEditTime: 2025-12-15 20:46:11
 * @LastEditors: auto
 * @Description: In User Settings Edit
 * @FilePath: 
 */

#ifndef __PERIOD_TASK_H__
#define __PERIOD_TASK_H__

void period_task_create(uint32_t stack_size, uint8_t priority);


void period_task_register(void (*func)(void));

#endif /* __PERIOD_TASK_H__ */