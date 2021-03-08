#ifndef HANDLERS_H_
#define HANDLERS_H_

#include "libc/types.h"
#include "libu2f2.h"

/*
 * Local handlers to FIDO events
 */
mbed_error_t handle_wink(uint16_t timeout_ms, int usb_msq);

mbed_error_t handle_apdu_request(int usb_msq);

bool handle_userpresence_backend(uint16_t timeout);

/*
 * Low level handlers (HW events)
 */
void exti_button_handler (void);

#endif/*HANDLERS_H_*/
