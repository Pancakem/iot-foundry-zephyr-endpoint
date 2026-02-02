#include <zephyr/types.h>
#include <libmctp.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <string.h>
#include <libpldm/base.h>
#include <libpldm/platform.h>
#include <libpldm/control.h>
#include <libpldm/fru.h>
#include <libpldm/pdr.h>
#include <../pldm/src/control-internal.h>
#include "pdrs/config.h"
#include "mctp_control.h"

int handle_platform_set_state_sensor_enables(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_state_sensor_readings(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_init_state_sensor(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}
