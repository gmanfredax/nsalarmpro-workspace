/* USER CODE BEGIN Header */
/**
  * @file    app_freertos.c
  * @brief   FreeRTOS application tasks for NSAlarmPro.
  */
/* USER CODE END Header */

#include "FreeRTOS.h"
#include "task.h"
#include "cmsis_os.h"
#include "config.h"
#include "net_lwip.h"
#include "http_prov.h"
#include "mqtt_cli.h"
#include "zones.h"
#include "tamper_bus.h"
#include "can_bus.h"
#include "outputs.h"
#include "led_rgb.h"
#include "led_status.h"
#include "battery.h"
#include "adc_frontend.h"
#include "cpu_temp.h"

/* USER CODE BEGIN Includes */
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <inttypes.h>
#include "flash_store.h"
#include "stm32f4xx_hal.h"
#include "pins.h"
extern void nsap_watchdog_kick(void);
/* USER CODE END Includes */

/* USER CODE BEGIN PV */
static osThreadId httpTaskHandle;
static osThreadId mqttTaskHandle;
static osThreadId zonesTaskHandle;
static osThreadId tamperTaskHandle;
static osThreadId canTaskHandle;
static osThreadId outputsTaskHandle;
static osThreadId diagTaskHandle;
static osThreadId ledTaskHandle;

typedef enum
{
  ARM_MODE_NONE = 0,
  ARM_MODE_AWAY,
  ARM_MODE_IN_CASA,
  ARM_MODE_NOTTE,
  ARM_MODE_PERSONALIZZATO
} arming_mode_t;

static bool system_armed = false;
static arming_mode_t current_arming_mode = ARM_MODE_NONE;
static char current_mode_label[16] = "disarmed";
static bool arming_pending = false;
static arming_mode_t arming_pending_mode = ARM_MODE_NONE;
static bool arming_pending_force = false;
static uint32_t arming_pending_delay_s = 0U;
static TickType_t arming_deadline_tick = 0U;

static void ProvisioningTask(void const *argument);
static void MqttTask(void const *argument);
static void ZonesTask(void const *argument);
static void TamperTask(void const *argument);
static void CanTask(void const *argument);
static void OutputsTask(void const *argument);
static void DiagnosticTask(void const *argument);
static void LedTask(void const *argument);
static void arming_process_pending(void);
static bool arming_apply_mode(arming_mode_t mode, bool force, uint32_t exit_delay_s);
static bool arming_mode_from_string(const char *value, arming_mode_t *mode);
static const char *arming_mode_to_string(arming_mode_t mode);
static void to_lowercase(char *str);
static const char *skip_ws_cmd(const char *ptr);
static const char *json_find_value_cmd(const char *json, const char *key);
static bool json_get_str_cmd(const char *json, const char *key, char *out, size_t out_len);
static bool json_get_int_cmd(const char *json, const char *key, int *value);
static bool json_get_bool_cmd(const char *json, const char *key, bool *value);
static const char *diag_zone_state_to_string(zone_state_t state);
static const char *diag_zone_mode_to_string(zone_mode_t mode);
static const char *diag_zone_profile_to_string(zone_profile_t profile);
static const char *diag_tamper_state_to_string(tamper_state_t state);
#define FACTORY_RESET_HOLD_MS       5000U
static TickType_t reset_button_press_tick = 0U;
static bool factory_reset_pending = false;
static bool factory_reset_sequence_started = false;
static TickType_t factory_reset_reboot_tick = 0U;
static void factory_reset_monitor(void);
static void factory_reset_execute(void);
/* USER CODE END PV */

void MX_FREERTOS_Init(void)
{
  /* USER CODE BEGIN Init */
  http_prov_init();
  mqtt_cli_init();
  zones_init();
  tamper_bus_init();
  can_bus_init();
  outputs_init();
  led_rgb_init();
  led_status_init();
  net_lwip_start_udp_discovery();
  /* USER CODE END Init */

  /* USER CODE BEGIN RTOS_THREADS */
  osThreadDef(prov_http, ProvisioningTask, NSAP_TASK_PRIO_MED, 0, NSAP_TASK_STACK_HTTP);
  httpTaskHandle = osThreadCreate(osThread(prov_http), NULL);

  osThreadDef(mqtt, MqttTask, NSAP_TASK_PRIO_HIGH, 0, NSAP_TASK_STACK_MQTT);
  mqttTaskHandle = osThreadCreate(osThread(mqtt), NULL);

  osThreadDef(zones, ZonesTask, NSAP_TASK_PRIO_MED, 0, NSAP_TASK_STACK_ZONES);
  zonesTaskHandle = osThreadCreate(osThread(zones), NULL);

  osThreadDef(tamper, TamperTask, NSAP_TASK_PRIO_MED, 0, NSAP_TASK_STACK_TAMPER);
  tamperTaskHandle = osThreadCreate(osThread(tamper), NULL);

  osThreadDef(can, CanTask, NSAP_TASK_PRIO_LOW, 0, NSAP_TASK_STACK_CAN);
  canTaskHandle = osThreadCreate(osThread(can), NULL);

  osThreadDef(outputs, OutputsTask, NSAP_TASK_PRIO_LOW, 0, NSAP_TASK_STACK_OUTPUTS);
  outputsTaskHandle = osThreadCreate(osThread(outputs), NULL);

  osThreadDef(diag, DiagnosticTask, NSAP_TASK_PRIO_BACKGROUND, 0, NSAP_TASK_STACK_DIAG);
  diagTaskHandle = osThreadCreate(osThread(diag), NULL);

  osThreadDef(led, LedTask, NSAP_TASK_PRIO_LOW, 0, NSAP_TASK_STACK_LED);
  ledTaskHandle = osThreadCreate(osThread(led), NULL);
  /* USER CODE END RTOS_THREADS */
}

/* USER CODE BEGIN Application */
static void ProvisioningTask(void const *argument)
{
  (void)argument;
  TickType_t lastWake = xTaskGetTickCount();
  for (;;)
  {
    net_lwip_poll();
    http_prov_stream_tick();
    nsap_watchdog_kick();
    vTaskDelayUntil(&lastWake, pdMS_TO_TICKS(100));
  }
}

static void MqttTask(void const *argument)
{
  (void)argument;
  for (;;)
  {
    mqtt_cli_tick();
    nsap_watchdog_kick();
    vTaskDelay(pdMS_TO_TICKS(100));
  }
}

static void ZonesTask(void const *argument)
{
  (void)argument;
  TickType_t last = xTaskGetTickCount();
  for (;;)
  {
    adc_frontend_poll();
    zones_process();
    nsap_watchdog_kick();
    vTaskDelayUntil(&last, pdMS_TO_TICKS(50));
  }
}

static void TamperTask(void const *argument)
{
  (void)argument;
  TickType_t last = xTaskGetTickCount();
  for (;;)
  {
    tamper_bus_process();
    nsap_watchdog_kick();
    vTaskDelayUntil(&last, pdMS_TO_TICKS(50));
  }
}

static void CanTask(void const *argument)
{
  (void)argument;
  TickType_t last = xTaskGetTickCount();
  for (;;)
  {
    can_bus_process();
    nsap_watchdog_kick();
    vTaskDelayUntil(&last, pdMS_TO_TICKS(100));
  }
}

static void OutputsTask(void const *argument)
{
  (void)argument;
  TickType_t last = xTaskGetTickCount();
  for (;;)
  {
    outputs_process();
    nsap_watchdog_kick();
    vTaskDelayUntil(&last, pdMS_TO_TICKS(20));
  }
}

static void DiagnosticTask(void const *argument)
{
  (void)argument;
  TickType_t last = xTaskGetTickCount();
  for (;;)
  {
    factory_reset_execute();
    mqtt_cli_publish_telemetry();
    nsap_watchdog_kick();
    vTaskDelayUntil(&last, pdMS_TO_TICKS(1000));
  }
}

static void LedTask(void const *argument)
{
  (void)argument;
  TickType_t last = xTaskGetTickCount();
  for (;;)
  {
    factory_reset_monitor();
    arming_process_pending();
    led_status_process();
    led_rgb_process();
    nsap_watchdog_kick();
    vTaskDelayUntil(&last, pdMS_TO_TICKS(50));
  }
}

bool arming_handle_json(const char *json, int len)
{
  (void)len;
  if (json == NULL)
  {
    return false;
  }

  char mode_buffer[20];
  if (!json_get_str_cmd(json, "mode", mode_buffer, sizeof(mode_buffer)))
  {
    return false;
  }

  to_lowercase(mode_buffer);

  arming_mode_t requested_mode = ARM_MODE_NONE;
  if (!arming_mode_from_string(mode_buffer, &requested_mode))
  {
    return false;
  }

  bool force = false;
  (void)json_get_bool_cmd(json, "force", &force);

  int exit_delay_val = 0;
  uint32_t exit_delay_s = 0U;
  if (json_get_int_cmd(json, "exit_delay_s", &exit_delay_val) && exit_delay_val > 0)
  {
    exit_delay_s = (uint32_t)exit_delay_val;
  }

  if (requested_mode == ARM_MODE_NONE)
  {
    return arming_apply_mode(requested_mode, force, 0U);
  }

  if (!force && exit_delay_s > 0U)
  {
    arming_pending = true;
    arming_pending_mode = requested_mode;
    arming_pending_force = force;
    arming_pending_delay_s = exit_delay_s;
    arming_deadline_tick = xTaskGetTickCount() + pdMS_TO_TICKS(exit_delay_s * 1000U);

    const char *mode_label = arming_mode_to_string(requested_mode);
    char payload[96];
    snprintf(payload, sizeof(payload), "{\"mode\":\"%s\",\"exit_delay_s\":%lu,\"source\":\"cmd\"}",
             mode_label != NULL ? mode_label : "", (unsigned long)exit_delay_s);
    mqtt_cli_publish_event("arming_pending", payload, 1, false);
    return true;
  }

  return arming_apply_mode(requested_mode, force, exit_delay_s);
}

bool maint_handle_json(const char *json, int len)
{
  (void)json;
  (void)len;
  return true;
}

void diag_publish_now(void)
{
  if (!mqtt_cli_is_connected())
  {
    return;
  }

  adc_sample_t v12_sample = {0};
  adc_sample_t vbat_sample = {0};
  cpu_temp_sample_t temp_sample = {0};
  battery_snapshot_t battery_snapshot = {BATTERY_STATE_UNKNOWN, 0.0f, 0U};
  tamper_bus_snapshot_t tamper_snapshot;
  memset(&tamper_snapshot, 0, sizeof(tamper_snapshot));
  can_node_info_t nodes[CAN_MAX_NODES];
  uint8_t node_count = 0U;

  bool have_v12 = adc_frontend_get_v12(&v12_sample);
  adc_frontend_get_vbat(&vbat_sample);
  cpu_temp_get(&temp_sample);
  battery_get(&battery_snapshot);
  tamper_bus_get_snapshot(&tamper_snapshot);
  can_bus_get_snapshot(nodes, &node_count);

  float v12_voltage = have_v12 ? (v12_sample.value_mv / 1000.0f) : 0.0f;
  float vbat_voltage = (vbat_sample.value_mv > 0.0f) ? (vbat_sample.value_mv / 1000.0f) : battery_snapshot.voltage;
  float cpu_celsius = temp_sample.celsius;

  float tamper_short_v = 0.0f;
  float tamper_open_v = 0.0f;
  tamper_bus_get_thresholds(&tamper_short_v, &tamper_open_v);

  char ip_buffer[32];
  if (!net_lwip_get_ip(ip_buffer, sizeof(ip_buffer)))
  {
    strncpy(ip_buffer, "0.0.0.0", sizeof(ip_buffer));
    ip_buffer[sizeof(ip_buffer) - 1U] = '\0';
  }

  net_state_t net_state = net_lwip_get_state();
  bool link_ready = (net_state == NET_STATE_READY);

  uint64_t timestamp = 0ULL;
  const char *ts_source = "uptime";
  if (net_lwip_time_get(&timestamp))
  {
    ts_source = "sntp";
  }
  else
  {
    timestamp = (uint64_t)(xTaskGetTickCount() / configTICK_RATE_HZ);
  }

  uint32_t uptime_s = xTaskGetTickCount() / configTICK_RATE_HZ;
  size_t heap_free = xPortGetFreeHeapSize();
  uint32_t now_tick = xTaskGetTickCount();

  char payload[1536];
  char *cursor = payload;
  size_t remaining = sizeof(payload);
  bool success = true;

#define APPEND_FMT(...)                                                                 \
  do                                                                                    \
  {                                                                                     \
    if (!success)                                                                       \
    {                                                                                   \
      break;                                                                            \
    }                                                                                   \
    int __w = snprintf(cursor, remaining, __VA_ARGS__);                                 \
    if (__w < 0 || (size_t)__w >= remaining)                                            \
    {                                                                                   \
      success = false;                                                                  \
      break;                                                                            \
    }                                                                                   \
    cursor += (size_t)__w;                                                              \
    remaining -= (size_t)__w;                                                           \
  } while (0)

  APPEND_FMT("{\"fw\":\"%s\",\"voltages\":{\"v12\":%.2f,\"vbat\":%.2f,\"cpu_temp\":%.2f},",
             NSAP_FW_VERSION,
             (double)v12_voltage,
             (double)vbat_voltage,
             (double)cpu_celsius);

  APPEND_FMT("\"zones\":[");
  bool first_zone = true;
  for (uint8_t i = 0U; i < NSAP_MAX_ZONES; i++)
  {
    zone_snapshot_t snapshot;
    if (!zones_get_snapshot(i, &snapshot))
    {
      continue;
    }
    const char *state_str = diag_zone_state_to_string(snapshot.state);
    const char *mode_str = diag_zone_mode_to_string(snapshot.wiring_mode);
    const char *profile_str = diag_zone_profile_to_string(snapshot.profile);
    APPEND_FMT("%s{\"id\":%u,\"state\":\"%s\",\"v\":%.2f,\"mode\":\"%s\",\"profile\":\"%s\"}",
               first_zone ? "" : ",",
               snapshot.id,
               state_str,
               (double)(snapshot.voltage_mv / 1000.0f),
               mode_str,
               profile_str);
    first_zone = false;
  }
  APPEND_FMT("],");

  const char *tamper_state = diag_tamper_state_to_string(tamper_snapshot.state);
  APPEND_FMT("\"tamper_bus\":{\"state\":\"%s\",\"analog\":%s,\"th\":{\"short_max\":%.3f,\"open_min\":%.3f}},",
             tamper_state,
             tamper_snapshot.analog_source ? "true" : "false",
             (double)tamper_short_v,
             (double)tamper_open_v);

  APPEND_FMT("\"can\":{\"nodes\":[");
  for (uint8_t n = 0U; n < node_count; n++)
  {
    uint32_t age_ticks = now_tick - nodes[n].last_heartbeat;
    uint32_t age_seconds = age_ticks / configTICK_RATE_HZ;
    APPEND_FMT("%s{\"id\":%u,\"hb\":%lu,\"errors\":{\"TEC\":%u,\"REC\":%u}}",
               (n == 0U) ? "" : ",",
               nodes[n].node_id,
               (unsigned long)age_seconds,
               nodes[n].tec,
               nodes[n].rec);
  }
  APPEND_FMT("]},");

  APPEND_FMT("\"net\":{\"ip\":\"%s\",\"link\":%s},",
             ip_buffer,
             link_ready ? "true" : "false");

  APPEND_FMT("\"storage\":{\"selftest\":\"%s\"},",
             flash_store_selftest() ? "ok" : "fail");

  APPEND_FMT("\"uptime_s\":%lu,\"heap_free\":%lu,\"ts\":%" PRIu64 ",\"ts_src\":\"%s\"}",
             (unsigned long)uptime_s,
             (unsigned long)heap_free,
             timestamp,
             ts_source);

#undef APPEND_FMT

  if (!success)
  {
    return;
  }

  mqtt_cli_publish_diag_report(payload);
}
/* USER CODE END Application */

/* USER CODE BEGIN PrivateFunctions */
static void factory_reset_monitor(void)
{
  GPIO_PinState state = HAL_GPIO_ReadPin(PIN_BUTTON_RESET_PORT, PIN_BUTTON_RESET_PIN);
  TickType_t now = xTaskGetTickCount();

  if (state == GPIO_PIN_RESET)
  {
    if (reset_button_press_tick == 0U)
    {
      reset_button_press_tick = now;
    }
    else if (!factory_reset_pending)
    {
      if ((int32_t)(now - reset_button_press_tick) >= (int32_t)pdMS_TO_TICKS(FACTORY_RESET_HOLD_MS))
      {
        factory_reset_pending = true;
        reset_button_press_tick = 0U;
      }
    }
  }
  else
  {
    reset_button_press_tick = 0U;
  }
}

static void factory_reset_execute(void)
{
  if (!factory_reset_pending && !factory_reset_sequence_started)
  {
    return;
  }

  if (factory_reset_pending && !factory_reset_sequence_started)
  {
    factory_reset_sequence_started = true;
    factory_reset_pending = false;

    bool erased = flash_store_erase();
    http_prov_factory_reset();

    char payload[80];
    snprintf(payload, sizeof(payload), "{\"source\":\"button\",\"result\":\"%s\"}", erased ? "ok" : "error");
    mqtt_cli_publish_event("factory_reset", payload, 1, false);

    nsap_watchdog_kick();
    factory_reset_reboot_tick = xTaskGetTickCount() + pdMS_TO_TICKS(3000);
  }

  if (factory_reset_sequence_started)
  {
    if ((int32_t)(xTaskGetTickCount() - factory_reset_reboot_tick) >= 0)
    {
      NVIC_SystemReset();
    }
  }
}

static void arming_process_pending(void)
{
  if (!arming_pending)
  {
    return;
  }
  TickType_t now = xTaskGetTickCount();
  if ((int32_t)(now - arming_deadline_tick) >= 0)
  {
    arming_apply_mode(arming_pending_mode, arming_pending_force, arming_pending_delay_s);
  }
}

static bool arming_apply_mode(arming_mode_t mode, bool force, uint32_t exit_delay_s)
{
  arming_pending = false;
  arming_pending_delay_s = 0U;

  if (mode == ARM_MODE_NONE)
  {
    bool was_armed = system_armed;
    arming_mode_t previous_mode = current_arming_mode;
    system_armed = false;
    current_arming_mode = ARM_MODE_NONE;
    strncpy(current_mode_label, "disarmed", sizeof(current_mode_label) - 1U);
    current_mode_label[sizeof(current_mode_label) - 1U] = '\0';

    const char *prev_label = arming_mode_to_string(previous_mode);
    char payload[120];
    snprintf(payload, sizeof(payload), "{\"source\":\"cmd\",\"previous_mode\":\"%s\"}",
             (was_armed && prev_label != NULL) ? prev_label : "none");
    mqtt_cli_publish_event("disarmed", payload, 1, false);
    return true;
  }

  const char *mode_label = arming_mode_to_string(mode);
  system_armed = true;
  current_arming_mode = mode;
  if (mode_label != NULL)
  {
    strncpy(current_mode_label, mode_label, sizeof(current_mode_label) - 1U);
    current_mode_label[sizeof(current_mode_label) - 1U] = '\0';
  }

  char payload[160];
  snprintf(payload, sizeof(payload), "{\"mode\":\"%s\",\"force\":%s,\"exit_delay_s\":%lu,\"source\":\"cmd\"}",
           mode_label != NULL ? mode_label : "", force ? "true" : "false",
           (unsigned long)exit_delay_s);
  mqtt_cli_publish_event("armed", payload, 1, false);

  return true;
}

static bool arming_mode_from_string(const char *value, arming_mode_t *mode)
{
  if (value == NULL || mode == NULL)
  {
    return false;
  }
  if (strcmp(value, "away") == 0)
  {
    *mode = ARM_MODE_AWAY;
    return true;
  }
  if (strcmp(value, "in_casa") == 0)
  {
    *mode = ARM_MODE_IN_CASA;
    return true;
  }
  if (strcmp(value, "notte") == 0)
  {
    *mode = ARM_MODE_NOTTE;
    return true;
  }
  if (strcmp(value, "personalizzato") == 0)
  {
    *mode = ARM_MODE_PERSONALIZZATO;
    return true;
  }
  if (strcmp(value, "disarm") == 0 || strcmp(value, "disarmed") == 0 || strcmp(value, "off") == 0)
  {
    *mode = ARM_MODE_NONE;
    return true;
  }
  return false;
}

static const char *arming_mode_to_string(arming_mode_t mode)
{
  switch (mode)
  {
  case ARM_MODE_AWAY:
    return "away";
  case ARM_MODE_IN_CASA:
    return "in_casa";
  case ARM_MODE_NOTTE:
    return "notte";
  case ARM_MODE_PERSONALIZZATO:
    return "personalizzato";
  default:
    return NULL;
  }
}

static const char *diag_zone_state_to_string(zone_state_t state)
{
  switch (state)
  {
  case ZONE_STATE_OK:
    return "OK";
  case ZONE_STATE_OPEN:
    return "OPEN";
  case ZONE_STATE_SHORT:
    return "SHORT";
  case ZONE_STATE_TAMPER1:
    return "TAMPER1";
  case ZONE_STATE_TAMPER2:
    return "TAMPER2";
  case ZONE_STATE_FAULT:
    return "FAULT";
  default:
    return "UNKNOWN";
  }
}

static const char *diag_zone_mode_to_string(zone_mode_t mode)
{
  switch (mode)
  {
  case ZONE_MODE_EOL:
    return "EOL";
  case ZONE_MODE_2EOL:
    return "2EOL";
  case ZONE_MODE_3EOL:
    return "3EOL";
  default:
    return "EOL";
  }
}

static const char *diag_zone_profile_to_string(zone_profile_t profile)
{
  switch (profile)
  {
  case ZONE_PROFILE_INSTANT:
    return "istantanea";
  case ZONE_PROFILE_DELAYED:
    return "ritardata";
  case ZONE_PROFILE_EXCLUDED:
    return "esclusa";
  case ZONE_PROFILE_AUTO_EXCLUDE:
    return "auto_esclusione";
  default:
    return "istantanea";
  }
}

static const char *diag_tamper_state_to_string(tamper_state_t state)
{
  switch (state)
  {
  case TAMPER_STATE_NORMAL:
    return "CLOSED";
  case TAMPER_STATE_OPEN:
    return "OPEN";
  case TAMPER_STATE_SHORT:
    return "SHORT";
  default:
    return "UNKNOWN";
  }
}

static void to_lowercase(char *str)
{
  if (str == NULL)
  {
    return;
  }
  for (size_t i = 0U; str[i] != '\0'; i++)
  {
    str[i] = (char)tolower((unsigned char)str[i]);
  }
}

static const char *skip_ws_cmd(const char *ptr)
{
  while (ptr != NULL && *ptr != '\0' && isspace((unsigned char)*ptr))
  {
    ptr++;
  }
  return ptr;
}

static const char *json_find_value_cmd(const char *json, const char *key)
{
  if (json == NULL || key == NULL)
  {
    return NULL;
  }
  char pattern[32];
  int written = snprintf(pattern, sizeof(pattern), "\"%s\"", key);
  if (written <= 0 || (size_t)written >= sizeof(pattern))
  {
    return NULL;
  }
  const char *pos = json;
  while ((pos = strstr(pos, pattern)) != NULL)
  {
    pos += written;
    pos = skip_ws_cmd(pos);
    if (pos == NULL || *pos != ':')
    {
      continue;
    }
    pos++;
    pos = skip_ws_cmd(pos);
    return pos;
  }
  return NULL;
}

static bool json_get_str_cmd(const char *json, const char *key, char *out, size_t out_len)
{
  if (json == NULL || key == NULL || out == NULL || out_len == 0U)
  {
    return false;
  }
  const char *value = json_find_value_cmd(json, key);
  if (value == NULL || *value != '"')
  {
    return false;
  }
  value++;
  size_t i = 0U;
  while (value[i] != '\0' && value[i] != '"' && i < (out_len - 1U))
  {
    out[i] = value[i];
    i++;
  }
  out[i] = '\0';
  if (value[i] != '"')
  {
    return false;
  }
  return true;
}

static bool json_get_int_cmd(const char *json, const char *key, int *value)
{
  if (json == NULL || key == NULL || value == NULL)
  {
    return false;
  }
  const char *ptr = json_find_value_cmd(json, key);
  if (ptr == NULL)
  {
    return false;
  }
  char *endptr = NULL;
  long parsed = strtol(ptr, &endptr, 10);
  if (ptr == endptr)
  {
    return false;
  }
  *value = (int)parsed;
  return true;
}

static bool json_get_bool_cmd(const char *json, const char *key, bool *value)
{
  if (json == NULL || key == NULL || value == NULL)
  {
    return false;
  }
  const char *ptr = json_find_value_cmd(json, key);
  if (ptr == NULL)
  {
    return false;
  }
  if (strncmp(ptr, "true", 4) == 0)
  {
    *value = true;
    return true;
  }
  if (strncmp(ptr, "false", 5) == 0)
  {
    *value = false;
    return true;
  }
  return false;
}
/* USER CODE END PrivateFunctions */
