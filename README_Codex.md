# Brief per Codex — Workspace a 2 repo (ESP-IDF + STM32CubeIDE, protocollo in `can_bus_protocol.h`)

## Contesto
Questo workspace contiene due firmware che **devono rimanere compatibili**:
- `centrale/` — firmware **centrale** ESP32 (ESP-IDF 5.5.1)
- `nodi/`     — firmware **nodo** STM32F103 (**STM32CubeIDE** progetto gestito)

Il **protocollo CAN** è definito in un file **per ciascun repo**:
- `centrale/main/can_bus_protocol.h`
- `nodi/Alarm Pro Exp/Core/Inc/can_bus_protocol.h`

> **Vincolo forte:** qualunque modifica al protocollo va applicata **in modo speculare** a *entrambi* i file `can_bus_protocol.h` (stesso contenuto byte-per-byte, stesse macro, enum, struct, packing).

---

## Regole & vincoli
1. **Niente rinomini** o ristrutturazioni massicce: tocca solo ciò che serve dentro `centrale/` e `nodi/`.
2. Se tocchi il **protocollo**:
   - Aggiorna **entrambi** i `can_bus_protocol.h`.
3. **CRC/framing/opcode**: se cambi il framing o introduci opcode:
   - Documenta i nuovi valori **hex** e lo schema **byte-level**.
   - Replica dispatcher/handler su entrambe le parti.
4. Build-system:
   - **ESP32**: lascia il layout IDF; se aggiungi `.c/.h`, assicurati che siano compilati.
   - **STM32 (CubeIDE)**: non cambiare il tipo di progetto; aggiungi i file nelle **cartelle codice** del progetto CubeIDE (non creare CMake custom).
5. **Robustezza**:
   - Gestisci errori/timeout e payload invalidi.
   - Nessuna dipendenza esterna non necessaria.
   - **Zero warning nuovi** in compilazione.
