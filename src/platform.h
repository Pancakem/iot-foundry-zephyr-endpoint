/* platform.h - declarations for platform and FRU handlers
 *
 * This header exposes the PLDM platform handler entry points implemented
 * across the `src/platform_*.c` files and the FRU helpers in `src/fru.c`.
 */
#pragma once

#include <stddef.h>
#include <libpldm/base.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Platform handler prototypes (implemented in src/platform_*.c) */
int handle_platform_get_terminus_uid(struct pldm_header_info *hdr,
                                     const void *req_msg, size_t req_len,
                                     void *resp, size_t *resp_len);

int handle_platform_set_event_receiver(struct pldm_header_info *hdr,
                                       const void *req_msg, size_t req_len,
                                       void *resp, size_t *resp_len);

int handle_platform_get_event_receiver(struct pldm_header_info *hdr,
                                       const void *req_msg, size_t req_len,
                                       void *resp, size_t *resp_len);

int handle_platform_platform_event_message(struct pldm_header_info *hdr,
                                           const void *req_msg, size_t req_len,
                                           void *resp, size_t *resp_len);

int handle_platform_poll_for_platform_event_message(struct pldm_header_info *hdr,
                                                    const void *req_msg, size_t req_len,
                                                    void *resp, size_t *resp_len);

int handle_platform_event_message_supported(struct pldm_header_info *hdr,
                                            const void *req_msg, size_t req_len,
                                            void *resp, size_t *resp_len);

int handle_platform_event_message_buffer_size(struct pldm_header_info *hdr,
                                              const void *req_msg, size_t req_len,
                                              void *resp, size_t *resp_len);

int handle_platform_set_numeric_sensor_enable(struct pldm_header_info *hdr,
                                              const void *req_msg, size_t req_len,
                                              void *resp, size_t *resp_len);

int handle_platform_get_sensor_reading(struct pldm_header_info *hdr,
                                       const void *req_msg, size_t req_len,
                                       void *resp, size_t *resp_len);

int handle_platform_get_sensor_thresholds(struct pldm_header_info *hdr,
                                          const void *req_msg, size_t req_len,
                                          void *resp, size_t *resp_len);

int handle_platform_set_sensor_thresholds(struct pldm_header_info *hdr,
                                          const void *req_msg, size_t req_len,
                                          void *resp, size_t *resp_len);

int handle_platform_restore_sensor_thresholds(struct pldm_header_info *hdr,
                                             const void *req_msg, size_t req_len,
                                             void *resp, size_t *resp_len);

int handle_platform_get_sensor_hysteresis(struct pldm_header_info *hdr,
                                          const void *req_msg, size_t req_len,
                                          void *resp, size_t *resp_len);

int handle_platform_set_sensor_hysteresis(struct pldm_header_info *hdr,
                                          const void *req_msg, size_t req_len,
                                          void *resp, size_t *resp_len);

int handle_platform_init_numeric_sensor(struct pldm_header_info *hdr,
                                        const void *req_msg, size_t req_len,
                                        void *resp, size_t *resp_len);

int handle_platform_set_state_sensor_enables(struct pldm_header_info *hdr,
                                             const void *req_msg, size_t req_len,
                                             void *resp, size_t *resp_len);

int handle_platform_get_state_sensor_readings(struct pldm_header_info *hdr,
                                              const void *req_msg, size_t req_len,
                                              void *resp, size_t *resp_len);

int handle_platform_init_state_sensor(struct pldm_header_info *hdr,
                                      const void *req_msg, size_t req_len,
                                      void *resp, size_t *resp_len);

int handle_platform_set_numeric_effecter_enable(struct pldm_header_info *hdr,
                                               const void *req_msg, size_t req_len,
                                               void *resp, size_t *resp_len);

int handle_platform_set_numeric_effecter_value(struct pldm_header_info *hdr,
                                              const void *req_msg, size_t req_len,
                                              void *resp, size_t *resp_len);

int handle_platform_get_numeric_effecter_value(struct pldm_header_info *hdr,
                                               const void *req_msg, size_t req_len,
                                               void *resp, size_t *resp_len);

int handle_platform_set_state_effecter_enables(struct pldm_header_info *hdr,
                                              const void *req_msg, size_t req_len,
                                              void *resp, size_t *resp_len);

int handle_platform_set_state_effecter_states(struct pldm_header_info *hdr,
                                             const void *req_msg, size_t req_len,
                                             void *resp, size_t *resp_len);

int handle_platform_get_state_effecter_states(struct pldm_header_info *hdr,
                                              const void *req_msg, size_t req_len,
                                              void *resp, size_t *resp_len);

int handle_platform_get_pldm_event_log_info(struct pldm_header_info *hdr,
                                           const void *req_msg, size_t req_len,
                                           void *resp, size_t *resp_len);

int handle_platform_enable_pldm_event_logging(struct pldm_header_info *hdr,
                                              const void *req_msg, size_t req_len,
                                              void *resp, size_t *resp_len);

int handle_platform_clear_pldm_event_log(struct pldm_header_info *hdr,
                                        const void *req_msg, size_t req_len,
                                        void *resp, size_t *resp_len);

int handle_platform_get_pldm_event_log_timestamp(struct pldm_header_info *hdr,
                                                 const void *req_msg, size_t req_len,
                                                 void *resp, size_t *resp_len);

int handle_platform_set_pldm_event_log_timestamp(struct pldm_header_info *hdr,
                                                 const void *req_msg, size_t req_len,
                                                 void *resp, size_t *resp_len);

int handle_platform_read_pldm_event_log(struct pldm_header_info *hdr,
                                       const void *req_msg, size_t req_len,
                                       void *resp, size_t *resp_len);

int handle_platform_get_pldm_event_log_policy_info(struct pldm_header_info *hdr,
                                                   const void *req_msg, size_t req_len,
                                                   void *resp, size_t *resp_len);

int handle_platform_set_pldm_event_log_policy(struct pldm_header_info *hdr,
                                              const void *req_msg, size_t req_len,
                                              void *resp, size_t *resp_len);

int handle_platform_find_pldm_event_log_entry(struct pldm_header_info *hdr,
                                              const void *req_msg, size_t req_len,
                                              void *resp, size_t *resp_len);

int handle_platform_get_pdr_repository_info(struct pldm_header_info *hdr,
                                           const void *req_msg, size_t req_len,
                                           void *resp, size_t *resp_len);

int handle_platform_get_pdr(struct pldm_header_info *hdr,
                            const void *req_msg, size_t req_len,
                            void *resp, size_t *resp_len);

int handle_platform_find_pdr(struct pldm_header_info *hdr,
                             const void *req_msg, size_t req_len,
                             void *resp, size_t *resp_len);

int handle_platform_run_init_agent(struct pldm_header_info *hdr,
                                   const void *req_msg, size_t req_len,
                                   void *resp, size_t *resp_len);

int handle_platform_get_pdr_repository_signature(struct pldm_header_info *hdr,
                                                 const void *req_msg, size_t req_len,
                                                 void *resp, size_t *resp_len);

/* FRU helpers (implemented in src/fru.c) */
int fru_get_metadata(struct pldm_header_info *hdr,
                     const void *req_msg, size_t req_len,
                     void *resp, size_t *resp_len);

int fru_get_record_table(struct pldm_header_info *hdr,
                         const void *req_msg, size_t req_len,
                         void *resp, size_t *resp_len);

int fru_set_record_table(struct pldm_header_info *hdr,
                         const void *req_msg, size_t req_len,
                         void *resp, size_t *resp_len);

int fru_get_record_by_option(struct pldm_header_info *hdr,
                             const void *req_msg, size_t req_len,
                             void *resp, size_t *resp_len);

#ifdef __cplusplus
}
#endif
