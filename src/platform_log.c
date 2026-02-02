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

int handle_platform_get_pldm_event_log_info(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_enable_pldm_event_logging(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_clear_pldm_event_log(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_pldm_event_log_timestamp(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_pldm_event_log_timestamp(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_read_pldm_event_log(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_get_pldm_event_log_policy_info(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_set_pldm_event_log_policy(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}

int handle_platform_find_pldm_event_log_entry(struct pldm_header_info *hdr, const void *req_msg, size_t req_len, void *resp, size_t *resp_len)
{
	// TODO: implement
	return PLDM_ERROR_UNSUPPORTED_PLDM_CMD;
}
