# NSAlarmPro STM32F407 Centrale

Questo repository contiene il progetto STM32CubeIDE per la centrale NSAlarmPro basata su STM32F407VET6 con FreeRTOS, LwIP, mbedTLS e MQTT sicuro.

## Struttura

```
NSAlarmPro_F407.ioc
Core/
  Inc/
  Src/
Middlewares/Third_Party/
  mbedtls/
  paho_embedded/
lwipopts.h
tools/apply_post_gen.sh
```

## Funzionalità principali

- Rete Ethernet RMII con DHCP, hostname dinamico `nsalarmpro-<device_id>` e discovery UDP su porta 17123.
- Provisioning HTTP locale (LwIP httpd) con SSE e progressi guidati dai pattern LED RGB.
- Gestione claim MQTTS con memorizzazione credenziali in Flash, retry/backoff e pubblicazione Birth/LWT.
- Telemetria MQTT: tensioni, zone analogiche, stato tamper 24h, diagnostica CAN ed eventi dedicati.
- Zone locali (10 ingressi analogici EOL) con filtri, profili e auto-esclusione persistente.
- Tamper bus analogico continuo con soglie SHORT/NORMAL/OPEN e fallback digitale.
- Gestione bus CAN 125 kbps per espansioni con heartbeat, auto-discovery e pubblicazione diagnostica.
- Uscite locali (sirene, nebbiogeno, OUT1/2) con timeout.
- Monitoraggio batteria, temperatura CPU e log MQTT di eventi critici.
- Task FreeRTOS dedicati (HTTP provisioning, MQTT, zone, tamper, CAN, uscite, diagnostica, LED).

## Costruzione

1. Aprire `NSAlarmPro_F407.ioc` con STM32CubeIDE (versione 1.14 o superiore consigliata).
2. Generare il codice; gli hook di questo repository rispettano le sezioni `/* USER CODE BEGIN */`.
3. Copiare le librerie complete di mbedTLS e Paho Embedded C nelle rispettive cartelle se necessarie per la build reale.
4. Compilare con il toolchain GCC fornito da CubeIDE.

## Provisioning e claim

- Caricare tramite interfaccia HTTP locale l'host MQTT, porta 8883, certificato CA (PEM) e claim code.
- La sequenza di stato SSE segue: `VALIDATING_CA → BOOTSTRAP_CONNECTED → CLAIM_OK → MQTT_CONNECTED → DONE`.
- Dopo il successo il server HTTP viene disattivato e la scheda pubblica `status="online"` (QoS1, retained) su `nsalarmpro/<id>/status`.
- Esempio verifica Birth/LWT con Mosquitto:

  ```bash
  mosquitto_sub -h <host> -p 8883 --cafile ca.pem -u <utente> -P '<password>' -t 'nsalarmpro/<device_id>/status' -v
  ```
  L'output atteso è `nsalarmpro/<device_id>/status online` dopo la connessione.

## Comandi MQTT

Gli esempi assumono una CA salvata come `ca.pem` e le credenziali definitive ottenute dal claim. Sostituire `<host>` e `<device_id>` con i valori reali.

- Armo/disarmo con eventuale forzatura:

  ```bash
  mosquitto_pub -h <host> -p 8883 --cafile ca.pem -u <utente> -P '<password>' \
    -t 'nsalarmpro/<device_id>/cmd/arming' -m '{"mode":"away","force":false}'
  ```

- Pilotaggio uscite e sirene con timeout opzionale (esempio sirena interna 60 s):

  ```bash
  mosquitto_pub -h <host> -p 8883 --cafile ca.pem -u <utente> -P '<password>' \
    -t 'nsalarmpro/<device_id>/cmd/output' -m '{"name":"SIREN_INT","action":"on","timeout_s":60}'
  ```

- Bypass di una zona (zona 3 esclusa):

  ```bash
  mosquitto_pub -h <host> -p 8883 --cafile ca.pem -u <utente> -P '<password>' \
    -t 'nsalarmpro/<device_id>/cmd/bypass' -m '{"zone_id":3,"enable":true}'
  ```

- Aggiornamento profilo e cablaggio zona (zona 4 in 2EOL ritardata):

  ```bash
  mosquitto_pub -h <host> -p 8883 --cafile ca.pem -u <utente> -P '<password>' \
    -t 'nsalarmpro/<device_id>/cmd/config/zone' \
    -m '{"id":4,"mode":"2EOL","profile":"ritardata","debounce_ms":150,"auto_excl_on":true}'
  ```

- Attivazione modalità manutenzione:

  ```bash
  mosquitto_pub -h <host> -p 8883 --cafile ca.pem -u <utente> -P '<password>' \
    -t 'nsalarmpro/<device_id>/cmd/maint' -m '{"enable":true}'
  ```

- Richiesta diagnostica immediata:

  ```bash
  mosquitto_pub -h <host> -p 8883 --cafile ca.pem -u <utente> -P '<password>' \
    -t 'nsalarmpro/<device_id>/cmd/diag' -n
  ```

- Calibrazione tamper analogico (tutti i micro chiusi):

  ```bash
  mosquitto_pub -h <host> -p 8883 --cafile ca.pem -u <utente> -P '<password>' \
    -t 'nsalarmpro/<device_id>/cmd/tamper_cal' -n
  ```

## Diagnostica rapida

- Tamper bus: telemetria `nsalarmpro/<id>/telemetry/tamper_bus` e eventi `nsalarmpro/<id>/event/tamper_bus_*`.
- Zone: telemetria aggregata su `nsalarmpro/<id>/telemetry/zones` ed eventi di stato su `nsalarmpro/<id>/event/zone_*`.
- CAN: `nsalarmpro/<id>/telemetry/can` con nodi rilevati e contatori TEC/REC.
- Diagnostica puntuale: `nsalarmpro/<id>/diag/report` con tensioni, canali e `ts_src` (`sntp` oppure `uptime`).
- Comandi MQTT: namespace `nsalarmpro/<id>/cmd/*` per dashboard o strumenti di test.

## Cablaggio tamper

- **Digitale (fallback)**: ingresso `PIN_TAMPER_BUS` con pull-up interno. Cablaggio NC in serie: contatto chiuso mantiene il livello alto, apertura porta il pin a `LOW` generando evento `tamper_bus_open`.
- **Analogico EOL 24h**: canale ADC dedicato con resistenza `R_EOL` (tipicamente 2k2–3k3) in fondo linea. In chiusura nominale il partitore fornisce ~0,6 V; cortocircuito scende sotto 0,2 V; filo aperto sale oltre 2,5 V. Le soglie vengono ottimizzate dalla calibrazione (`cmd/tamper_cal`) e memorizzate in Flash.

## Test rapidi consigliati

1. Alimentare la scheda, completare il provisioning e verificare il Birth tramite `mosquitto_sub` sul topic `status` (payload `online`).
2. Pubblicare i comandi di esempio (`arming`, `output`, `bypass`, `config/zone`, `maint`, `diag`, `tamper_cal`) e verificare gli eventi di risposta (`event/*`).
3. Forzare il tamper: apertura (OPEN), richiusura (RESTORE) e cortocircuito (SHORT se analogico) monitorando `telemetry/tamper_bus`.
4. Eseguire `cmd/diag` e controllare che `diag/report` riporti timestamp SNTP (`ts_src":"sntp"`) dopo la sincronizzazione.
5. Tenere premuto il pulsante `RESET` >5 s: attendere l'evento `event/factory_reset`, il riavvio e la riapertura del provisioning HTTP.

## Note operative

- Il file `flash_store.c` gestisce due slot Flash A/B (settori 7-8, indirizzi `0x08060000-0x0809FFFF`) con header/CRC32 e sequenza: assicurarsi che il linker non collochi codice in quell'intervallo.
- Aggiornare `pins.h` in base al layout definitivo della scheda (relè, LED, ingressi).
- Il modulo MQTT integra una sessione TLS mbedTLS con publish/subscribe QoS1 e backoff esponenziale; verificare in campo le tempistiche di handshake e gli eventuali certificati intermedi.

## Changelog

- v1.0.0: prima emissione del progetto CubeMX con stack FreeRTOS/LwIP/mbedTLS, provisioning HTTP e pipeline MQTT.
