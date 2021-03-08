#include "autoconf.h"
#include "libc/types.h"
#include "libc/sys/msg.h"
#include "libc/stdio.h"
#include "libc/errno.h"
#include "libc/nostd.h"
#include "libc/string.h"
#include "libc/syscall.h"
#include "libu2f2.h"

#include "libu2fapdu.h"

#include "handlers.h"
#include "main.h"


/*
 * glue fonction, emulate the 'real' u2f_fido_handle_cmd, but transmit to FIDO app and get back content instead.
 */
mbed_error_t u2f_fido_handle_cmd(uint32_t metadata, uint8_t *buf, uint16_t buf_len, uint8_t *resp, uint16_t *resp_len)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    int fido_msq = get_fido_msq();
    int ret;
    struct msgbuf msgbuf;
    size_t msgsz = 64; /* max msg buf size */

    /* request APDU CMD initialization to Fido backend */
    printf("[PARSER] sending data to FIDO\n");
    hexdump(buf, buf_len);

    printf("[PARSER] Send APDU_CMD_INIT to Fido\n");
    msgbuf.mtype = MAGIC_APDU_CMD_INIT;
    msgsnd(fido_msq, &msgbuf, 0, 0);

    printf("[PARSER] Send APDU_CMD_META to Fido : %x\n", metadata);
    msgbuf.mtype = MAGIC_APDU_CMD_META;
    msgbuf.mtext.u32[0] = metadata;
    msgsnd(fido_msq, &msgbuf, sizeof(uint32_t), 0);

    printf("[PARSER] Send APDU_CMD_MSG_LEN (len is %d) to Fido\n", buf_len);
    msgbuf.mtype = MAGIC_APDU_CMD_MSG_LEN;
    msgbuf.mtext.u16[0] = buf_len;
    msgsnd(fido_msq, &msgbuf, sizeof(uint32_t), 0);

    uint32_t num_full_msg = buf_len / 64;
    uint8_t residual_msg = buf_len % 64;
    uint32_t offset = 0;


    uint32_t i;
    for (i = 0; i < num_full_msg; ++i) {
        printf("[PARSER] Send APDU_CMD_MSG (pkt %d) to Fido\n", i);
        msgbuf.mtype = MAGIC_APDU_CMD_MSG;
        memcpy(&msgbuf.mtext.u8[0], &buf[offset], msgsz);
        msgsnd(fido_msq, &msgbuf, msgsz, 0);
        offset += msgsz;
    }
    if (residual_msg) {
        printf("[PARSER] Send APDU_CMD_MSG (pkt %d, residual, %d bytes) to Fido\n", i, residual_msg);
        msgbuf.mtype = MAGIC_APDU_CMD_MSG;
        memcpy(&msgbuf.mtext.u8[0], &buf[offset], residual_msg);
        msgsnd(fido_msq, &msgbuf, residual_msg, 0);
        offset += residual_msg;
    }
    /* APDU request fully send... */

    /* get back APDU response */
    msgrcv(fido_msq, &msgbuf.mtext, msgsz, MAGIC_APDU_RESP_INIT, 0);
    printf("[PARSER] received APDU_RESP_INIT from Fido\n");
    msgrcv(fido_msq, &msgbuf.mtext, msgsz, MAGIC_APDU_RESP_MSG_LEN, 0);
    printf("[PARSER] received APDU_RESP_MSG_LEN from Fido\n");

    /* FIXME: use u16 instead of u32 */
    *resp_len = (uint16_t)msgbuf.mtext.u32[0];

    num_full_msg = *resp_len / 64;
    residual_msg = *resp_len % 64;
    offset = 0;

    for (i = 0; i < num_full_msg; ++i) {
        ret = msgrcv(fido_msq, &msgbuf.mtext, msgsz, MAGIC_APDU_RESP_MSG, 0);
        printf("[PARSER] received APDU_RESP_MSG (pkt %d) from Fido\n", i);
        memcpy(&resp[offset], &msgbuf.mtext.u8[0], msgsz);
        offset += msgsz;
    }
    if (residual_msg) {
        ret = msgrcv(fido_msq, &msgbuf.mtext, residual_msg, MAGIC_APDU_RESP_MSG, 0);
        printf("[PARSER] received APDU_RESP_MSG (pkt %d, residual, %d bytes) from Fido\n", i, ret);
        memcpy(&resp[offset], &msgbuf.mtext.u8[0], residual_msg);
        offset += residual_msg;
    }
    /* received overall APDU response from APDU/FIDO backend, get back return value */
    ret = msgrcv(fido_msq, &msgbuf.mtext, 1, MAGIC_CMD_RETURN, 0);

    errcode = msgbuf.mtext.u8[0];
    printf("[PARSER] received errcode %x from Fido\n", errcode);

    return errcode;
}

mbed_error_t handle_wink(uint16_t timeout_ms, int usb_msq)
{
    timeout_ms = timeout_ms;
    /* send wink to FIDO */
    send_signal_with_acknowledge(get_fido_msq(), MAGIC_WINK_REQ, MAGIC_ACKNOWLEDGE);
    printf("[Parser] wink done by FIDO, ack to USB\n");
    uint32_t mtype = MAGIC_ACKNOWLEDGE;
    msgsnd(usb_msq, &mtype, 0, 0);

    return MBED_ERROR_NONE;
}

uint8_t cmd_buf[1024] = { 0 };
uint8_t resp_buf[1024] = { 0 };

/*
 * handle APDU request reception from USB, execute it, and send response to USB
 *
 */
mbed_error_t handle_apdu_request(int usb_msq)
{
    mbed_error_t errcode = MBED_ERROR_NONE;
    int ret;
    size_t msgsz = 64; /* max msg buf size */
    uint32_t mtype = MAGIC_ACKNOWLEDGE;
    uint32_t msg_size = 0;
    uint16_t resp_len = 1024;
    uint32_t metadata = 0;
    struct msgbuf msgbuf = { 0 };


    /* now wait for APDU_CMD_MSG_META, to calculate the number of needed msg */
    ret = msgrcv(usb_msq, &msgbuf.mtext, msgsz, MAGIC_APDU_CMD_META, 0);
    if (ret == -1) {
        log_printf("[FIDO] Unable to get back CMD_MSG_META with errno %x\n", errno);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    metadata = msgbuf.mtext.u32[0];
    printf("[FIDO] received APDU_CMD_META from USB: %x\n", metadata);

    /* now wait for APDU_CMD_MSG_LEN, to calculate the number of needed msg */
    ret = msgrcv(usb_msq, &msgbuf.mtext, msgsz, MAGIC_APDU_CMD_MSG_LEN, 0);
    if (ret == -1) {
        log_printf("[FIDO] Unable to get back CMD_MSG_LEN with errno %x\n", errno);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }
    msg_size = msgbuf.mtext.u16[0];
    printf("[FIDO] received APDU_CMD_MSG_LEN from USB (len is %d)\n", msg_size);

    /* calculating number of messages */
    uint32_t num_full_msg = msg_size / 64;
    uint8_t residual_msg = msg_size % 64;
    /* there is num_full_msg msg of size 64 + 1 residual msg of size residal_msg to get from USB to
     * fullfill the buffer */
    uint32_t offset = 0;
    uint32_t i;
    for (i = 0; i < num_full_msg; ++i) {
        ret = msgrcv(usb_msq, &cmd_buf[offset], msgsz, MAGIC_APDU_CMD_MSG, 0);
        if (ret == -1) {
            log_printf("[FIDO] Unable to get back CMD_MSG_LEN with errno %x\n", errno);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        printf("[FIDO] received APDU_CMD_MSG (pkt %d) from USB\n", i);
        offset += ret;
    }
    if (residual_msg) {
        ret = msgrcv(usb_msq, &cmd_buf[offset], residual_msg, MAGIC_APDU_CMD_MSG, 0);
        if (ret == -1) {
            log_printf("[FIDO] Unable to get back CMD_MSG_LEN with errno %x\n", errno);
            errcode = MBED_ERROR_RDERROR;
            goto err;
        }
        printf("[FIDO] received APDU_CMD_MSG (pkt %d, residual, %d bytes) from USB\n", i, ret);
        offset += ret;
    }
    if (offset != msg_size) {
        log_printf("[FIDO] Received data size %x does not match specified one %x\n", offset, msg_size);
        errcode = MBED_ERROR_RDERROR;
        goto err;
    }

    /* ready to execute the effective content */

    printf("[FIDO] received APDU from USB\n");
    hexdump(cmd_buf, msg_size);
    cmd_buf[msg_size] = 0x0;

    errcode = u2fapdu_handle_cmd(metadata, &cmd_buf[0], msg_size, &resp_buf[0], &resp_len);

    /* return back content */

    printf("[FIDO] Send APDU_RESP_INIT to USB\n");
    mtype = MAGIC_APDU_RESP_INIT;
    msgsnd(usb_msq, &mtype, 0, 0);

    msgbuf.mtype = MAGIC_APDU_RESP_MSG_LEN;
    msgbuf.mtext.u32[0] = resp_len;
    printf("[FIDO] Send APDU_RESP_MSG_LEN to USB\n");
    msgsnd(usb_msq, &msgbuf, sizeof(uint32_t), 0);

    num_full_msg = resp_len / 64;
    residual_msg = resp_len % 64;
    offset = 0;
    for (i = 0; i < num_full_msg; ++i) {
        msgbuf.mtype = MAGIC_APDU_RESP_MSG;
        memcpy(&msgbuf.mtext.u8[0], &resp_buf[offset], msgsz);
        printf("[FIDO] Send APDU_RESP_MSG (pkt %d) to USB\n", i);
        msgsnd(usb_msq, &msgbuf, msgsz, 0);
        offset += msgsz;
    }
    if (residual_msg != 0) {
        msgbuf.mtype = MAGIC_APDU_RESP_MSG;
        memcpy(&msgbuf.mtext.u8[0], &resp_buf[offset], residual_msg);
        printf("[FIDO] Send APDU_RESP_MSG (pkt %d, residual) to USB\n", i);
        msgsnd(usb_msq, &msgbuf, residual_msg, 0);
        offset += residual_msg;
    }
    /* response transmission done, sending local call return from u2fapdu_handle_cmd() */
    msgbuf.mtype = MAGIC_CMD_RETURN;
    msgbuf.mtext.u8[0] = errcode;
    msgsnd(usb_msq, &msgbuf, 1, 0);

err:
    return errcode;
}

volatile bool button_pushed = false;

void exti_button_handler (void)
{
    button_pushed = true;
}

