# Brief per Codex — Workspace 2 firmware (ESP-IDF + STM32CubeIDE)
**ATTENZIONE: segui alla lettera. Se qualcosa non è chiaro, fermati e chiedi i PERCORSI FILE esatti; non inventare file o linguaggi nuovi.**

## Struttura del workspace
- `centrale/` — firmware **Centrale** ESP32-WROOM-32D 16 MB (ESP-IDF 5.5.1)
- `nodi/Alarm Pro Exp/` — progetto **Nodi** STM32F103C8T6 (STM32CubeIDE)

**Protocollo CAN**: è definito nel file esistente `can_bus_protocol.h` in **entrambi** i progetti  
(percorso preciso all’interno di ciascun progetto: individua e usa quello già presente; se i percorsi differiscono, mantienili).

## Requisiti funzionali (da realizzare)
- La Centrale seleziona il backend zone da **menuconfig**:  
  - **MCP23017** → 12 input digitali locali + **tamper**.  
  - **ADS1115** → 10 input analogici locali + **vbias 12 V** + **tamper** con EOL/2EOL/3EOL.  
- I **Nodi** gestiscono **8 zone EOL/2EOL/3EOL** + **2 Output**.  
- **Indipendentemente** dal backend della Centrale, le zone provenienti dai **Nodi** vanno trattate come EOL/2EOL/3EOL (coerenti con quanto inviano i nodi).  
- Con il firmware attuale, Centrale e Nodi **non comunicano** → **va ripristinata e stabilizzata** la comunicazione CAN bidirezionale.

## Cosa devi fare (tu decidi i dettagli tecnici)
Adegua **tu** la parte di comunicazione canbus **in base alle caratteristiche dei chip** (ESP32-WROOM-32D 16 MB + STM32F103C8T6) e delle rispettive HAL/driver, **senza** introdurre nuovi linguaggi o nuovi file di protocollo.

### Vincoli OBBLIGATORI
1. **Linguaggi**: SOLO C/C++ embedded per ESP-IDF e STM32CubeIDE. **Vietato** creare Python/Script/Markdown extra.  
2. **Protocollo**: usa e modifica **ESCLUSIVAMENTE** i `can_bus_protocol.h` già presenti (uno in `centrale`, uno in `nodi/Alarm Pro Exp`). Devono rimanere **speculari** (macro/enum/struct identiche, stesso packing). **Non creare** un secondo file protocollo.
3. **Modalità zone**:
   - Se Centrale=**MCP23017**: le **zone locali** sono digitali, ma le **zone dei Nodi** restano EOL (non reinterpretarle come digitali).
   - Se Centrale=**ADS1115**: tutta l’interpretazione zone segue EOL/2EOL/3EOL della Centrale; i Nodi inviano già stato EOL.

