#ifndef APP_FREERTOS_H
#define APP_FREERTOS_H

#include <stdbool.h>

void MX_FREERTOS_Init(void);

bool arming_handle_json(const char *json, int len);
bool maint_handle_json(const char *json, int len);
void diag_publish_now(void);

#endif
