#ifndef MAIN_H_
#define MAIN_H_

#define FIDO_DEBUG 0

#if FIDO_DEBUG
# define log_printf(...) printf(__VA_ARGS__)
#else
# define log_printf(...)
#endif

int get_fido_msq(void);
int get_usb_msq(void);

#endif/*MAIN_H_*/
