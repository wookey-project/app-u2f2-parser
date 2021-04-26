#include "libc/syscall.h"
#include "libc/stdio.h"
#include "libc/time.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/malloc.h"
#include "libc/sys/msg.h"
#include "libc/errno.h"

#include "libu2f2.h"

#include "autoconf.h"
#include "libfido.h"
#include "libu2fapdu.h"
#include "generated/led0.h"
#include "generated/led1.h"
#include "generated/dfu_button.h"
#include "main.h"
#include "handlers.h"


device_t    up;
int    desc_up = 0;

int fido_msq = 0;
int usb_msq = 0;

int get_fido_msq(void) {
    return fido_msq;
}
int get_usb_msq(void) {
    return usb_msq;
}

/*
 * Entrypoint
 */
int _main(uint32_t task_id)
{
    task_id = task_id;
    char *wellcome_msg = "hello, I'm USB HID frontend";
    uint8_t ret;

    printf("%s\n", wellcome_msg);

    wmalloc_init();
    int usb_msq = 0;

    /* Posix SystemV message queue init */
    printf("initialize Posix SystemV message queue with USB task\n");
    usb_msq = msgget("usb", IPC_CREAT | IPC_EXCL);
    if (usb_msq == -1) {
        printf("error while requesting SysV message queue. Errno=%x\n", errno);
        goto err;
    }
    printf("initialize Posix SystemV message queue with FIDO task\n");
    fido_msq = msgget("fido", IPC_CREAT | IPC_EXCL);
    if (usb_msq == -1) {
        printf("error while requesting SysV message queue. Errno=%x\n", errno);
        goto err;
    }



    ret = sys_init(INIT_DONE);
    if (ret != 0) {
        printf("failure while leaving init mode !!! err:%d\n", ret);
    }
    printf("sys_init DONE returns %x !\n", ret);


    /* backend_ready received and trasmitted back to usb. We can continue... */

    /*U2FAPDU & FIDO are handled here, direct callback access */
#if CONFIG_APP_PARSER_PARSERS_APDU
    u2fapdu_register_callback(u2f_fido_handle_cmd);
#endif

    /*******************************************
     * End of init sequence, let's wait for USB 'backend_ready' request
     *******************************************/

    /* wait for requests from USB task */
    int msqr;
    struct msgbuf mbuf = { 0 };
    size_t msgsz = 64;

    /* no additional intelligence by now here */
    transmit_signal_to_backend_with_acknowledge(usb_msq, fido_msq, MAGIC_IS_BACKEND_READY, MAGIC_BACKEND_IS_READY);

    /* synchro done, waiting for events from USB from now */
    do {
        msqr = msgrcv(usb_msq, &mbuf, msgsz, MAGIC_WINK_REQ, IPC_NOWAIT);
        if (msqr >= 0) {
            /* Wink request received */
            log_printf("[PARSER] received MAGIC_WINK_REQ from USB\n");
            /* check for other waiting msg before sleeping */
            handle_wink(1000, usb_msq);

            goto endloop;
        }
        msqr = msgrcv(usb_msq, &mbuf, msgsz, MAGIC_APDU_CMD_INIT, IPC_NOWAIT);
        if (msqr >= 0) {
            /* APDU message handling eceived */
            log_printf("[PARSER] received MAGIC_APDU_CMD_INIT from USB\n");
            /* and stard handling cmd locally */
            handle_apdu_request(usb_msq);
            /* check for other waiting msg before sleeping */
            goto endloop;
        }
        /* no message received ? As FIDO is a slave task, sleep for a moment... */
        sys_sleep(500, SLEEP_MODE_INTERRUPTIBLE);
endloop:
        continue;
    } while (1);

err:
    printf("Going to error state!\n");
    return 1;
}
