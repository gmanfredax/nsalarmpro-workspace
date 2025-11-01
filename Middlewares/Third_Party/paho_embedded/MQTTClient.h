#ifndef MQTTCLIENT_H
#define MQTTCLIENT_H

#include <stdint.h>

typedef struct {
    int dummy;
} MQTTClient;

typedef struct {
    const char *clientID;
    uint16_t keepAliveInterval;
    uint8_t cleansession;
} MQTTPacket_connectData;

static inline MQTTPacket_connectData MQTTPacket_connectData_initializer(void)
{
    MQTTPacket_connectData data;
    data.clientID = "";
    data.keepAliveInterval = 60;
    data.cleansession = 1;
    return data;
}

#endif
