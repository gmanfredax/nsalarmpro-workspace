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
Progetta/adegua **tu** la parte di comunicazione (ID CAN standard/extended, bitrate, opcodes, payload, handshake, filtri, retry/timeout) **in base alle caratteristiche dei chip** (ESP32-WROOM-32D 16 MB + STM32F103C8T6) e delle rispettive HAL/driver, **senza** introdurre nuovi linguaggi o nuovi file di protocollo.

### Vincoli OBBLIGATORI
1. **Linguaggi**: SOLO C/C++ embedded per ESP-IDF e STM32CubeIDE. **Vietato** creare Python/Script/Markdown extra.  
2. **Protocollo**: usa e modifica **ESCLUSIVAMENTE** i `can_bus_protocol.h` già presenti (uno in `centrale`, uno in `nodi/Alarm Pro Exp`). Devono rimanere **speculari** (macro/enum/struct identiche, stesso packing). **Non creare** un secondo file protocollo.
3. **Struttura progetti**: rispetta layout e build system esistenti (ESP-IDF per Centrale; STM32CubeIDE per Nodi). Se aggiungi `.c/.h`, mettili nelle cartelle già previste dai progetti (es. `centrale/main/…`, `nodi/Alarm Pro Exp/Core/Src|Inc`).
4. **Affidabilità**:
   - Handshake **versione** (MAJOR/MINOR) su entrambi; se mismatch → log chiaro e rifiuto comandi non compatibili.
   - Filtri CAN **coerenti**: i Nodi accettano i frame destinati al proprio NodeID; la Centrale accetta le risposte dei Nodi.
   - Timeout/retry robusti; nessun deadlock; gestione errori bus (bus-off/tx fail).
5. **Modalità zone**:
   - Se Centrale=**MCP23017**: le **zone locali** sono digitali, ma le **zone dei Nodi** restano EOL (non reinterpretarle come digitali).
   - Se Centrale=**ADS1115**: tutta l’interpretazione zone segue EOL/2EOL/3EOL della Centrale; i Nodi inviano già stato EOL.
6. **Output formattato**: restituisci **solo**:
   - **Patch in diff unificato** applicabili dalla **radice** del workspace, con path relativi corretti (es. `a/centrale/main/...`, `a/nodi/Alarm Pro Exp/Core/...`).  
   - **Messaggi di commit** concisi (uno per `centrale/`, uno per `nodi/` se toccati).  
   - **Test Plan** da banco e **Note di Migrazione**.  
   Nessun altro testo o file al di fuori di questi.

### Obiettivo minimo (Definition of Done)
- Entrambi i firmware **compilano senza nuovi warning**:
  - Centrale: `cd centrale && idf.py build`
  - Nodi (CubeIDE): build del progetto in `nodi/Alarm Pro Exp` (GUI) o headless builder CubeIDE.  
- Handshake iniziale **passa** (Centrale <→ Nodo, con version match).  
- La Centrale **scopre** e **interroga** almeno 1 Nodo, riceve le 8 zone in modo consistente e può **pilotare i 2 output** del Nodo con conferma.  
- Funziona in entrambe le modalità della Centrale (MCP23017 e ADS1115) come descritto sopra.  
- `can_bus_protocol.h` è **identico** (salvo include/guard) nelle due codebase.

---

## Implementa ora la modifica
> **Scopo:** Ripristinare e stabilizzare la comunicazione CAN Centrale↔Nodi scegliendo tu: bitrate, ID (standard/extended), schema messaggi, handshake versione, polling/eventi, filtri hardware e gestione errori, nel rispetto dei vincoli sopra.  
>
> **Nota:** Se non trovi uno dei `can_bus_protocol.h` nei due progetti, fermati e chiedi il percorso preciso. In assenza di chiarimenti, **non creare** file alternativi.

## Output atteso
1) **Patch diff unificate** (dalla radice) in questo ordine:
   - Prima le modifiche sotto `centrale/…`
   - Poi le modifiche sotto `nodi/Alarm Pro Exp/…`
2) **Messaggi di commit** (uno per Centrale, uno per Nodi se toccati).
3) **Test Plan** (passi di prova su banco: flash, handshake, lettura zone, comandi output, errori/timeout).
4) **Note di Migrazione** (bump PROTO_VERSION, eventuali settaggi menuconfig/filtri CAN e valori bitrate scelti).

## Linee guida tecniche (a tua discrezione, ma motivate nei commenti/commit)
- Scegli un **bitrate CAN** stabile per STM32F103 + transceiver tipici (es. 250 k o 500 k).  
- Decidi **ID standard vs extended** e schema di indirizzamento NodeID (coerenti Centrale/Nodi).  
- Handshake: versione MAJOR/MINOR; keep-alive o polling periodico (a scelta tua).  
- Packing: usa `#pragma pack(push,1)`/`pop` o equivalenti; evita padding.  
- STM32: configura **filtri** in modo da accettare comandi al proprio NodeID e inviare risposte alla Centrale.  
- ESP32 (IDF): usa driver CAN/TWAI stabile con task RTOS dedicato e code per RX/TX; priorità adeguate per non impattare MCP23017/ADS1115.
