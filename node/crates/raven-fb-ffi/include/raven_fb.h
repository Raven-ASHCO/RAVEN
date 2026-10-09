#ifndef RAVEN_FB_H
#define RAVEN_FB_H

#include <stddef.h>
#include <stdint.h>

/*
 * LAB ONLY. Release and App Store builds must not link raven-fb-ffi.
 *
 * Measure/write C ABI for Hybrid Ratchet V2 Full Braid (design §8).
 * Every buffer is caller-owned pointer + length/capacity. On error or
 * caught panic, non-null outputs are zeroed within their capacity caps.
 *
 * Output buffers and out-parameters MUST NOT overlap any input or each other
 * (inputs may share memory). An overlapping call returns RAVEN_FB_ERR_PARSE
 * and writes nothing, so never pass the live state buffer as an output.
 * Input lengths above RAVEN_FB_MAX_RVBJ1 return RAVEN_FB_ERR_PARSE.
 *
 * Sizing: every *_measure call fills a RavenFbSizes; size each output buffer
 * from the field named below and pass that as the matching *_cap of the
 * *_write call. Fields a call does not produce are 0 (not "unknown"):
 *
 *   measure call                         fields populated
 *   raven_fb_init_measure                candidate_len
 *   raven_fb_transition_measure          candidate_len, outputs_len, intent_len
 *   raven_fb_promote_measure             candidate_len
 *   raven_fb_rvor_materialize_measure    outputs_len   (the RVOR1 record; NOT candidate_len)
 *   raven_fb_clear_pending_measure       candidate_len
 *   raven_fb_recover_measure             candidate_len
 *   raven_fb_terminalize_conflict_measure  candidate_len, intent_len
 *   raven_fb_terminalize_expired_measure   candidate_len, intent_len
 *
 * "candidate_len" is the size of the (single) RVFB1 state output; for the
 * terminalize calls it is the terminal candidate and intent_len the repair
 * RVBJ1. A binder must not assume candidate_len for every single-output call.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define RAVEN_FB_SIZES_LEN 16
#define RAVEN_FB_META_LEN 64
#define RAVEN_FB_MAX_STATE 262144
#define RAVEN_FB_MAX_RVBO1 16545
#define RAVEN_FB_MAX_RVBJ1 279055
#define RAVEN_FB_MAX_RVOR_RECORD 16741

enum {
    RAVEN_FB_OK = 0,
    RAVEN_FB_ERR_NEED_CAPACITY = 1,
    RAVEN_FB_ERR_PARSE = 2,
    RAVEN_FB_ERR_EPOCH = 3,
    RAVEN_FB_ERR_CAS = 8,
    RAVEN_FB_ERR_TERMINAL_STATE_OP = 9,
    RAVEN_FB_ERR_INTERNAL = 10
};

/* Which fields a given *_measure fills is tabled in the header comment above. */
typedef struct RavenFbSizes {
    uint32_t candidate_len; /* RVFB1 state output (terminal candidate for terminalize_*) */
    uint32_t outputs_len;   /* transition: RVBO1; rvor_materialize: the RVOR1 record */
    uint32_t intent_len;    /* transition / terminalize_*: RVBJ1 */
    uint32_t reserved0;     /* always 0 */
} RavenFbSizes;

typedef struct RavenFbResultMeta {
    uint64_t sending_epoch;
    uint64_t receiving_epoch;
    uint64_t output_key_epoch;
    uint32_t flags;
    uint16_t terminal_reason;
    uint16_t pending_phase;
    uint8_t transition_id[32];
} RavenFbResultMeta;

size_t raven_fb_ffi_keep_alive(void);
size_t raven_fb_len_sizes(void);
size_t raven_fb_len_meta(void);
size_t raven_fb_max_state(void);
size_t raven_fb_max_rvbo1(void);
size_t raven_fb_max_rvbj1(void);
size_t raven_fb_max_rvor_record(void);

int32_t raven_fb_init_measure(
    const uint8_t *init_ptr,
    size_t init_len,
    RavenFbSizes *out_need);

int32_t raven_fb_init_write(
    const uint8_t *init_ptr,
    size_t init_len,
    uint8_t *state_out_ptr,
    size_t state_cap,
    RavenFbResultMeta *meta_out);

int32_t raven_fb_transition_measure(
    const uint8_t *state_in_ptr,
    size_t state_in_len,
    const uint8_t *input_ptr,
    size_t input_len,
    const uint8_t *env_ptr,
    size_t env_len,
    RavenFbSizes *out_need);

int32_t raven_fb_transition_write(
    const uint8_t *state_in_ptr,
    size_t state_in_len,
    const uint8_t *input_ptr,
    size_t input_len,
    const uint8_t *env_ptr,
    size_t env_len,
    uint8_t *candidate_out_ptr,
    size_t candidate_cap,
    uint8_t *outputs_out_ptr,
    size_t outputs_cap,
    uint8_t *intent_out_ptr,
    size_t intent_cap,
    RavenFbResultMeta *meta_out);

int32_t raven_fb_promote_measure(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *intent_ptr,
    size_t intent_len,
    RavenFbSizes *out_need);

int32_t raven_fb_promote_write(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *intent_ptr,
    size_t intent_len,
    uint8_t *state_out_ptr,
    size_t state_cap,
    RavenFbResultMeta *meta_out);

int32_t raven_fb_rvor_materialize_measure(
    const uint8_t *intent_ptr,
    size_t intent_len,
    RavenFbSizes *out_need);

int32_t raven_fb_rvor_materialize_write(
    const uint8_t *intent_ptr,
    size_t intent_len,
    uint8_t *rvor_out_ptr,
    size_t rvor_cap,
    RavenFbResultMeta *meta_out);

int32_t raven_fb_clear_pending_measure(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *intent_ptr,
    size_t intent_len,
    const uint8_t *rvor_ptr,
    size_t rvor_len,
    uint64_t now_ms,
    RavenFbSizes *out_need);

int32_t raven_fb_clear_pending_write(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *intent_ptr,
    size_t intent_len,
    const uint8_t *rvor_ptr,
    size_t rvor_len,
    uint64_t now_ms,
    uint8_t *state_out_ptr,
    size_t state_cap,
    RavenFbResultMeta *meta_out);

int32_t raven_fb_recover_measure(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *intent_ptr,
    size_t intent_len,
    RavenFbSizes *out_need);

int32_t raven_fb_recover_write(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *intent_ptr,
    size_t intent_len,
    uint8_t *state_out_ptr,
    size_t state_cap,
    RavenFbResultMeta *meta_out);

int32_t raven_fb_terminalize_conflict_measure(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *original_intent_ptr,
    size_t original_intent_len,
    uint64_t now_ms,
    RavenFbSizes *out_need);

int32_t raven_fb_terminalize_conflict_write(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *original_intent_ptr,
    size_t original_intent_len,
    uint64_t now_ms,
    uint8_t *terminal_candidate_out_ptr,
    size_t terminal_candidate_cap,
    uint8_t *repair_intent_out_ptr,
    size_t repair_intent_cap,
    RavenFbResultMeta *meta_out);

int32_t raven_fb_terminalize_expired_measure(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *original_intent_ptr,
    size_t original_intent_len,
    const uint8_t *rvor_ptr,
    size_t rvor_len,
    uint64_t now_ms,
    RavenFbSizes *out_need);

int32_t raven_fb_terminalize_expired_write(
    const uint8_t *live_state_ptr,
    size_t live_state_len,
    const uint8_t *original_intent_ptr,
    size_t original_intent_len,
    const uint8_t *rvor_ptr,
    size_t rvor_len,
    uint64_t now_ms,
    uint8_t *terminal_candidate_out_ptr,
    size_t terminal_candidate_cap,
    uint8_t *repair_intent_out_ptr,
    size_t repair_intent_cap,
    RavenFbResultMeta *meta_out);

#ifdef __cplusplus
}
#endif

#endif /* RAVEN_FB_H */
