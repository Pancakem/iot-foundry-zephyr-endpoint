#include <zephyr/types.h>
#include <zephyr/pmci/mctp/mctp_uart.h>
#include <libmctp.h>

#ifndef INCLUDE_PROCESS_PLDM_H
#define INCLUDE_PROCESS_PLDM_H

int init_pldm();
int handle_pldm_message(struct mctp *mctp, uint8_t remote_eid, bool tag_owner, uint8_t msg_tag, const void *msg, size_t msg_len);

#endif /* INCLUDE_PROCESS_PLD_H */