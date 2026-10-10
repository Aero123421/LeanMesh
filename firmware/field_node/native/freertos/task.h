#pragma once
#include <stdint.h>
typedef void *TaskHandle_t;
int xTaskCreate(void (*)(void *), const char *, uint32_t, void *, unsigned, TaskHandle_t *);
void vTaskDelay(unsigned);
