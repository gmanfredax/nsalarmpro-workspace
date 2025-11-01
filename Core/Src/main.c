/* USER CODE BEGIN Header */
/**
  * @file    main.c
  * @brief   Entry point for NSAlarmPro central unit.
  */
/* USER CODE END Header */

#include "main.h"
#include "stm32f4xx_hal.h"
#include "cmsis_os.h"
#include "app_freertos.h"
#include "config.h"
#include "pins.h"
#include "net_lwip.h"

/* Private variables ---------------------------------------------------------*/
ADC_HandleTypeDef hadc1;
CAN_HandleTypeDef hcan1;
ETH_HandleTypeDef heth;
TIM_HandleTypeDef htim4;
DMA_HandleTypeDef hdma_adc1;

/* USER CODE BEGIN PV */
static void NSAP_PreOSInit(void);
static void NSAP_WatchdogInit(void);
IWDG_HandleTypeDef hiwdg;
void nsap_watchdog_kick(void);
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_DMA_Init(void);
static void MX_ADC1_Init(void);
static void MX_CAN1_Init(void);
static void MX_ETH_Init(void);
static void MX_TIM4_Init(void);

int main(void)
{
  /* USER CODE BEGIN 1 */
  HAL_Init();
  SystemClock_Config();
  MX_GPIO_Init();
  MX_DMA_Init();
  MX_ADC1_Init();
  MX_CAN1_Init();
  MX_ETH_Init();
  MX_TIM4_Init();
  NSAP_WatchdogInit();
  NSAP_PreOSInit();
  MX_FREERTOS_Init();
  osKernelStart();
  while (1)
  {
  }
  /* USER CODE END 1 */
}

void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 8;
  RCC_OscInitStruct.PLL.PLLN = 336;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5) != HAL_OK)
  {
    Error_Handler();
  }
}

static void MX_ADC1_Init(void)
{
  ADC_ChannelConfTypeDef sConfig = {0};

  hadc1.Instance = ADC1;
  hadc1.Init.ClockPrescaler = ADC_CLOCK_SYNC_PCLK_DIV4;
  hadc1.Init.Resolution = ADC_RESOLUTION_12B;
  hadc1.Init.ScanConvMode = ENABLE;
  hadc1.Init.ContinuousConvMode = ENABLE;
  hadc1.Init.DiscontinuousConvMode = DISABLE;
  hadc1.Init.ExternalTrigConvEdge = ADC_EXTERNALTRIGCONVEDGE_NONE;
  hadc1.Init.ExternalTrigConv = ADC_SOFTWARE_START;
  hadc1.Init.DataAlign = ADC_DATAALIGN_RIGHT;
  hadc1.Init.NbrOfConversion = 15;
  hadc1.Init.DMAContinuousRequests = ENABLE;
  hadc1.Init.EOCSelection = ADC_EOC_SEQ_CONV;
  if (HAL_ADC_Init(&hadc1) != HAL_OK)
  {
    Error_Handler();
  }

  for (uint32_t channel = 0; channel < 10; channel++)
  {
    sConfig.Channel = ADC_CHANNEL_0 + channel;
    sConfig.Rank = channel + 1;
    sConfig.SamplingTime = ADC_SAMPLETIME_480CYCLES;
    if (HAL_ADC_ConfigChannel(&hadc1, &sConfig) != HAL_OK)
    {
      Error_Handler();
    }
  }

  sConfig.Channel = ADC_CHANNEL_10;
  sConfig.Rank = 11;
  if (HAL_ADC_ConfigChannel(&hadc1, &sConfig) != HAL_OK)
  {
    Error_Handler();
  }

  sConfig.Channel = ADC_CHANNEL_11;
  sConfig.Rank = 12;
  if (HAL_ADC_ConfigChannel(&hadc1, &sConfig) != HAL_OK)
  {
    Error_Handler();
  }

  sConfig.Channel = ADC_CHANNEL_12;
  sConfig.Rank = 13;
  if (HAL_ADC_ConfigChannel(&hadc1, &sConfig) != HAL_OK)
  {
    Error_Handler();
  }

  sConfig.Channel = ADC_CHANNEL_TEMPSENSOR;
  sConfig.Rank = 14;
  if (HAL_ADC_ConfigChannel(&hadc1, &sConfig) != HAL_OK)
  {
    Error_Handler();
  }

  sConfig.Channel = ADC_CHANNEL_VREFINT;
  sConfig.Rank = 15;
  if (HAL_ADC_ConfigChannel(&hadc1, &sConfig) != HAL_OK)
  {
    Error_Handler();
  }
}

static void MX_CAN1_Init(void)
{
  hcan1.Instance = CAN1;
  hcan1.Init.Prescaler = 16;
  hcan1.Init.Mode = CAN_MODE_NORMAL;
  hcan1.Init.SyncJumpWidth = CAN_SJW_1TQ;
  hcan1.Init.TimeSeg1 = CAN_BS1_13TQ;
  hcan1.Init.TimeSeg2 = CAN_BS2_2TQ;
  hcan1.Init.TimeTriggeredMode = DISABLE;
  hcan1.Init.AutoBusOff = ENABLE;
  hcan1.Init.AutoWakeUp = DISABLE;
  hcan1.Init.AutoRetransmission = ENABLE;
  hcan1.Init.ReceiveFifoLocked = DISABLE;
  hcan1.Init.TransmitFifoPriority = DISABLE;
  if (HAL_CAN_Init(&hcan1) != HAL_OK)
  {
    Error_Handler();
  }
}

static void MX_ETH_Init(void)
{
  uint8_t MACAddr[6] = {0x02, 0x80, 0xE1, 0x00, 0x00, 0x00};
  heth.Instance = ETH;
  heth.Init.AutoNegotiation = ETH_AUTONEGOTIATION_ENABLE;
  heth.Init.PhyAddress = 0;
  heth.Init.MACAddr = MACAddr;
  heth.Init.RxMode = ETH_RXINTERRUPT_MODE;
  heth.Init.ChecksumMode = ETH_CHECKSUM_BY_HARDWARE;
  heth.Init.MediaInterface = ETH_MEDIA_INTERFACE_RMII;
  if (HAL_ETH_Init(&heth) != HAL_OK)
  {
    Error_Handler();
  }
}

static void MX_TIM4_Init(void)
{
  TIM_OC_InitTypeDef sConfigOC = {0};

  htim4.Instance = TIM4;
  htim4.Init.Prescaler = 0;
  htim4.Init.CounterMode = TIM_COUNTERMODE_UP;
  htim4.Init.Period = 8399;
  htim4.Init.ClockDivision = TIM_CLOCKDIVISION_DIV1;
  htim4.Init.AutoReloadPreload = TIM_AUTORELOAD_PRELOAD_DISABLE;
  if (HAL_TIM_PWM_Init(&htim4) != HAL_OK)
  {
    Error_Handler();
  }

  sConfigOC.OCMode = TIM_OCMODE_PWM1;
  sConfigOC.Pulse = 0;
  sConfigOC.OCPolarity = TIM_OCPOLARITY_HIGH;
  sConfigOC.OCFastMode = TIM_OCFAST_DISABLE;
  if (HAL_TIM_PWM_ConfigChannel(&htim4, &sConfigOC, TIM_CHANNEL_1) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_TIM_PWM_ConfigChannel(&htim4, &sConfigOC, TIM_CHANNEL_2) != HAL_OK)
  {
    Error_Handler();
  }
  if (HAL_TIM_PWM_ConfigChannel(&htim4, &sConfigOC, TIM_CHANNEL_3) != HAL_OK)
  {
    Error_Handler();
  }
}

static void MX_DMA_Init(void)
{
  __HAL_RCC_DMA2_CLK_ENABLE();
  HAL_NVIC_SetPriority(DMA2_Stream0_IRQn, 5, 0);
  HAL_NVIC_EnableIRQ(DMA2_Stream0_IRQn);
}

static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};

  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();

  HAL_GPIO_WritePin(PIN_LED_POWER_GPIO_PORT, PIN_LED_POWER_PIN, GPIO_PIN_RESET);
  HAL_GPIO_WritePin(PIN_LED_ARMED_GPIO_PORT, PIN_LED_ARMED_PIN, GPIO_PIN_RESET);
  HAL_GPIO_WritePin(PIN_LED_MAINT_GPIO_PORT, PIN_LED_MAINT_PIN, GPIO_PIN_RESET);
  HAL_GPIO_WritePin(PIN_LED_ALARM_GPIO_PORT, PIN_LED_ALARM_PIN, GPIO_PIN_RESET);
  HAL_GPIO_WritePin(PIN_RELAY_SIREN_INT_PORT, PIN_RELAY_SIREN_INT_PIN, GPIO_PIN_RESET);
  HAL_GPIO_WritePin(PIN_RELAY_SIREN_EXT_PORT, PIN_RELAY_SIREN_EXT_PIN, GPIO_PIN_RESET);
  HAL_GPIO_WritePin(PIN_RELAY_NEBBIOGENO_PORT, PIN_RELAY_NEBBIOGENO_PIN, GPIO_PIN_RESET);
  HAL_GPIO_WritePin(PIN_RELAY_OUT1_PORT, PIN_RELAY_OUT1_PIN, GPIO_PIN_RESET);
  HAL_GPIO_WritePin(PIN_RELAY_OUT2_PORT, PIN_RELAY_OUT2_PIN, GPIO_PIN_RESET);

  GPIO_InitStruct.Pin = PIN_LED_POWER_PIN | PIN_LED_ARMED_PIN | PIN_LED_MAINT_PIN | PIN_LED_ALARM_PIN;
  GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
  HAL_GPIO_Init(PIN_LED_POWER_GPIO_PORT, &GPIO_InitStruct);

  GPIO_InitStruct.Pin = PIN_RELAY_SIREN_INT_PIN | PIN_RELAY_SIREN_EXT_PIN | PIN_RELAY_NEBBIOGENO_PIN | PIN_RELAY_OUT1_PIN;
  HAL_GPIO_Init(PIN_RELAY_SIREN_INT_PORT, &GPIO_InitStruct);

  GPIO_InitStruct.Pin = PIN_RELAY_OUT2_PIN;
  HAL_GPIO_Init(PIN_RELAY_OUT2_PORT, &GPIO_InitStruct);

  GPIO_InitStruct.Pin = PIN_TAMPER_BUS_DIGITAL_PIN;
  GPIO_InitStruct.Mode = GPIO_MODE_INPUT;
  GPIO_InitStruct.Pull = GPIO_PULLUP;
  HAL_GPIO_Init(PIN_TAMPER_BUS_DIGITAL_PORT, &GPIO_InitStruct);
}

/* USER CODE BEGIN 4 */
void HAL_ADC_ConvHalfCpltCallback(ADC_HandleTypeDef *hadc)
{
  if (hadc->Instance == ADC1)
  {
    adc_frontend_on_dma_half_complete();
  }
}

void HAL_ADC_ConvCpltCallback(ADC_HandleTypeDef *hadc)
{
  if (hadc->Instance == ADC1)
  {
    adc_frontend_on_dma_complete();
  }
}

void HAL_ETH_RxCpltCallback(ETH_HandleTypeDef *heth)
{
  LWIP_Pkt_Handle();
}

void HAL_ETH_TxCpltCallback(ETH_HandleTypeDef *heth)
{
  LWIP_Pkt_Handle();
}

void HAL_CAN_RxFifo0MsgPendingCallback(CAN_HandleTypeDef *hcan)
{
  CAN_RxHeaderTypeDef rxHeader;
  uint8_t data[8];
  if (HAL_CAN_GetRxMessage(hcan, CAN_RX_FIFO0, &rxHeader, data) == HAL_OK)
  {
    can_bus_on_rx(rxHeader.StdId, data, rxHeader.DLC);
  }
}

void HAL_CAN_ErrorCallback(CAN_HandleTypeDef *hcan)
{
  if ((hcan->ErrorCode & HAL_CAN_ERROR_BOF) != 0U)
  {
    can_bus_handle_bus_off();
  }
}

static void NSAP_PreOSInit(void)
{
  adc_frontend_init();
  adc_frontend_start();
  net_lwip_init();
}

static void NSAP_WatchdogInit(void)
{
  hiwdg.Instance = IWDG;
  hiwdg.Init.Prescaler = IWDG_PRESCALER_64;
  hiwdg.Init.Reload = 1999;
  hiwdg.Init.Window = IWDG_WINDOW_DISABLE;
  if (HAL_IWDG_Init(&hiwdg) != HAL_OK)
  {
    Error_Handler();
  }
  HAL_IWDG_Refresh(&hiwdg);
}

void nsap_watchdog_kick(void)
{
  if (hiwdg.Instance == IWDG)
  {
    HAL_IWDG_Refresh(&hiwdg);
  }
}

void Error_Handler(void)
{
  __disable_irq();
  while (1)
  {
  }
}
/* USER CODE END 4 */

#ifdef  USE_FULL_ASSERT
void assert_failed(uint8_t *file, uint32_t line)
{
}
#endif
