/*
 *  TTY server: a telnet bridge onto the emulated machine's character console.
 *
 *  Output: every character the guest prints through BIOS INT 10h AH=0Eh or
 *  through the DOS CON device is mirrored to the connected TCP clients.
 *  Input: bytes received from a client are decoded (telnet option negotiation
 *  and VT100/ANSI key sequences) and pushed into the BIOS keyboard buffer, so
 *  the guest sees them as ordinary keystrokes.
 *
 *  Configured through the [ttyserver] section of the configuration file.
 */

#ifndef DOSBOX_TTYSERVER_H
#define DOSBOX_TTYSERVER_H

#include <stdint.h>

/* Set up the [ttyserver] section handlers. Called once from the init sequence. */
void TTYSERVER_Init(void);

/* Report one character printed by the guest. Emulation thread only. */
void TTYSERVER_CharOut(uint8_t chr);

/* While an instance of this guard is alive TTYSERVER_CharOut() does nothing.
 *
 * A single DOS console write funnels into INT 29h and/or INT 10h AH=0Eh, all of
 * which are capture points of their own. The outermost capture point takes the
 * character and suppresses the inner ones, so each character is reported once.
 * Emulation thread only; not reentrancy safe across threads. */
class TTYServerSuppress {
public:
    TTYServerSuppress();
    ~TTYServerSuppress();
private:
    TTYServerSuppress(const TTYServerSuppress&);
    TTYServerSuppress& operator=(const TTYServerSuppress&);
};

#endif
