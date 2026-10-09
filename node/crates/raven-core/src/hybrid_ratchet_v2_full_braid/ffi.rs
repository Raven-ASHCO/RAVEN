//! Complete lab-only C ABI for the Full Braid durable pipeline (design §8).

use core::ptr;
use std::panic::{catch_unwind, AssertUnwindSafe};

use zeroize::Zeroize;

use crate::hybrid_ratchet_v2_full_braid::constants::{
    BRAID_MAX_CANONICAL_STATE_BYTES, BRAID_MAX_RVOR_RECORD_BYTES, ERR_INTERNAL, ERR_NEED_CAPACITY,
    ERR_OK, ERR_PARSE, MAX_RVBO1,
};
use crate::hybrid_ratchet_v2_full_braid::init::init_write;
use crate::hybrid_ratchet_v2_full_braid::pipeline::{
    clear_pending, materialize_rvor, promote_state, recover_state, terminalize_conflict,
    terminalize_expired, transition_prepare, PipelineMeta, PipelineResult, StateResult, MAX_RVBJ1,
};
use crate::hybrid_ratchet_v2_full_braid::state_codec::decode_rvfb1;
use crate::hybrid_ratchet_v2_full_braid::transition::LabCrypto;

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RavenFbSizes {
    pub candidate_len: u32,
    pub outputs_len: u32,
    pub intent_len: u32,
    pub reserved0: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct RavenFbResultMeta {
    pub sending_epoch: u64,
    pub receiving_epoch: u64,
    pub output_key_epoch: u64,
    pub flags: u32,
    pub terminal_reason: u16,
    pub pending_phase: u16,
    pub transition_id: [u8; 32],
}

const _: [(); 16] = [(); core::mem::size_of::<RavenFbSizes>()];
const _: [(); 64] = [(); core::mem::size_of::<RavenFbResultMeta>()];

#[derive(Clone, Copy)]
struct OutBuf {
    ptr: *mut u8,
    cap: usize,
    required_max: usize,
}

unsafe fn zero_out(out: OutBuf) {
    if out.ptr.is_null() || out.cap == 0 {
        return;
    }
    let count = out.cap.min(out.required_max);
    // SAFETY: the C caller promises `ptr` addresses `cap` writable bytes.
    unsafe { ptr::write_bytes(out.ptr, 0, count) };
}

unsafe fn zero_sizes(sizes: *mut RavenFbSizes) {
    if !sizes.is_null() {
        // SAFETY: the C caller supplies a writable out-parameter when non-null.
        unsafe { ptr::write(sizes, RavenFbSizes::default()) };
    }
}

unsafe fn zero_meta(meta: *mut RavenFbResultMeta) {
    if !meta.is_null() {
        // SAFETY: the C caller supplies a writable out-parameter when non-null.
        unsafe { ptr::write(meta, RavenFbResultMeta::default()) };
    }
}

#[cfg(test)]
std::thread_local! {
    static FORCE_PANIC: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

#[cfg(test)]
pub(crate) fn force_panic_once_for_test() {
    FORCE_PANIC.with(|flag| flag.set(true));
}

fn maybe_force_panic() {
    #[cfg(test)]
    FORCE_PANIC.with(|flag| {
        if flag.replace(false) {
            panic!("forced FFI panic");
        }
    });
}

/// Caller-provided input region (`ptr`, `len`).
type InBuf = (*const u8, usize);

/// Largest object any entry point accepts (RVBJ1); longer inputs are PARSE
/// before a slice is formed, which also keeps `len <= isize::MAX`.
const MAX_FFI_INPUT_LEN: usize = MAX_RVBJ1;

/// `[start, end)` of a non-empty caller region; `Err` if it wraps the address space.
fn span(ptr: *const u8, len: usize) -> Result<Option<(usize, usize)>, ()> {
    if ptr.is_null() || len == 0 {
        return Ok(None);
    }
    let start = ptr as usize;
    start
        .checked_add(len)
        .map(|end| Some((start, end)))
        .ok_or(())
}

/// Inputs, outputs and out-parameters must be pairwise disjoint (inputs may
/// share memory with each other). An aliased output would otherwise be
/// overwritten — or zeroed on error — while it is still the caller's only copy
/// of the live state.
fn regions_alias(
    ins: &[InBuf],
    outs: &[OutBuf],
    sizes: *mut RavenFbSizes,
    meta: *mut RavenFbResultMeta,
) -> bool {
    let mut writable = Vec::with_capacity(outs.len() + 2);
    for out in outs {
        match span(out.ptr, out.cap) {
            Ok(Some(region)) => writable.push(region),
            Ok(None) => {}
            Err(()) => return true,
        }
    }
    for (ptr, len) in [
        (sizes as *const u8, core::mem::size_of::<RavenFbSizes>()),
        (meta as *const u8, core::mem::size_of::<RavenFbResultMeta>()),
    ] {
        match span(ptr, len) {
            Ok(Some(region)) => writable.push(region),
            Ok(None) => {}
            Err(()) => return true,
        }
    }
    let overlaps = |a: (usize, usize), b: (usize, usize)| a.0 < b.1 && b.0 < a.1;
    for (i, &w) in writable.iter().enumerate() {
        if writable[..i].iter().any(|&other| overlaps(w, other)) {
            return true;
        }
    }
    for &(ptr, len) in ins {
        match span(ptr, len) {
            Ok(Some(region)) => {
                if writable.iter().any(|&w| overlaps(region, w)) {
                    return true;
                }
            }
            Ok(None) => {}
            Err(()) => return true,
        }
    }
    false
}

unsafe fn execute<F>(
    ins: &[InBuf],
    outs: &[OutBuf],
    sizes: *mut RavenFbSizes,
    meta: *mut RavenFbResultMeta,
    work: F,
) -> i32
where
    F: FnOnce() -> i32,
{
    if regions_alias(ins, outs, sizes, meta) {
        // Write nothing: zeroing an aliased output would destroy an input.
        return ERR_PARSE;
    }
    let code = match catch_unwind(AssertUnwindSafe(|| {
        maybe_force_panic();
        work()
    })) {
        Ok(code) => code,
        Err(_) => ERR_INTERNAL,
    };
    if code != ERR_OK {
        for out in outs {
            // SAFETY: each output is bounded by its caller-provided capacity.
            unsafe { zero_out(*out) };
        }
        // SAFETY: nullable out-parameters are checked before writing.
        unsafe {
            zero_sizes(sizes);
            zero_meta(meta);
        }
    }
    code
}

unsafe fn input_slice<'a>(input: *const u8, len: usize) -> Result<&'a [u8], i32> {
    if len == 0 {
        return Ok(&[]);
    }
    if input.is_null() || len > MAX_FFI_INPUT_LEN {
        return Err(ERR_PARSE);
    }
    // SAFETY: the C caller promises a readable region of `len` bytes.
    Ok(unsafe { core::slice::from_raw_parts(input, len) })
}

fn output_contract(output: *mut u8, cap: usize, required: usize) -> Result<(), i32> {
    if output.is_null() && cap > 0 {
        return Err(ERR_PARSE);
    }
    if cap < required {
        return Err(ERR_NEED_CAPACITY);
    }
    if required > 0 && output.is_null() {
        return Err(ERR_NEED_CAPACITY);
    }
    Ok(())
}

unsafe fn copy_output(output: *mut u8, bytes: &[u8]) {
    if !bytes.is_empty() {
        // SAFETY: output_contract validated sufficient writable capacity.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len()) };
    }
}

/// Rust-side copies of canonical state / RVBJ1 bytes hold every ratchet secret;
/// wipe them once they have been copied to the caller (on every path).
trait WipeSecrets {
    fn wipe(&mut self);
}

impl WipeSecrets for Vec<u8> {
    fn wipe(&mut self) {
        self.zeroize();
    }
}

impl WipeSecrets for PipelineResult {
    fn wipe(&mut self) {
        self.candidate_bytes.zeroize();
        self.intent_bytes.zeroize();
    }
}

impl WipeSecrets for StateResult {
    fn wipe(&mut self) {
        self.state_bytes.zeroize();
    }
}

struct Wiped<T: WipeSecrets>(T);

impl<T: WipeSecrets> core::ops::Deref for Wiped<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: WipeSecrets> Drop for Wiped<T> {
    fn drop(&mut self) {
        self.0.wipe();
    }
}

fn sizes_for(candidate: usize, outputs: usize, intent: usize) -> Result<RavenFbSizes, i32> {
    Ok(RavenFbSizes {
        candidate_len: candidate.try_into().map_err(|_| ERR_PARSE)?,
        outputs_len: outputs.try_into().map_err(|_| ERR_PARSE)?,
        intent_len: intent.try_into().map_err(|_| ERR_PARSE)?,
        reserved0: 0,
    })
}

fn ffi_meta(meta: PipelineMeta) -> RavenFbResultMeta {
    RavenFbResultMeta {
        sending_epoch: meta.sending_epoch,
        receiving_epoch: meta.receiving_epoch,
        output_key_epoch: meta.output_key_epoch,
        flags: meta.flags,
        terminal_reason: meta.terminal_reason,
        pending_phase: meta.pending_phase,
        transition_id: meta.transition_id,
    }
}

unsafe fn require_sizes(out_need: *mut RavenFbSizes) -> Result<(), i32> {
    if out_need.is_null() {
        Err(ERR_PARSE)
    } else {
        Ok(())
    }
}

unsafe fn require_meta(meta_out: *mut RavenFbResultMeta) -> Result<(), i32> {
    if meta_out.is_null() {
        Err(ERR_PARSE)
    } else {
        Ok(())
    }
}

unsafe fn write_sizes(out_need: *mut RavenFbSizes, sizes: RavenFbSizes) {
    // SAFETY: require_sizes validated the writable out-parameter.
    unsafe { ptr::write(out_need, sizes) };
}

unsafe fn write_result_meta(meta_out: *mut RavenFbResultMeta, meta: PipelineMeta) {
    // SAFETY: require_meta validated the writable out-parameter.
    unsafe { ptr::write(meta_out, ffi_meta(meta)) };
}

fn init_pipeline_meta(state_bytes: &[u8]) -> Result<PipelineMeta, i32> {
    let state = decode_rvfb1(state_bytes).map_err(|_| ERR_PARSE)?;
    Ok(PipelineMeta {
        sending_epoch: state.prefix.braid_send_epoch,
        receiving_epoch: state.prefix.braid_recv_epoch,
        output_key_epoch: 0,
        flags: 0,
        terminal_reason: state.prefix.terminal_reason,
        pending_phase: state.prefix.pending_phase as u16,
        transition_id: [0; 32],
    })
}

/// Measure the canonical state produced by RVFI1 initialization.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_init_measure(
    init_ptr: *const u8,
    init_len: usize,
    out_need: *mut RavenFbSizes,
) -> i32 {
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[(init_ptr, init_len)],
            &[],
            out_need,
            ptr::null_mut(),
            || {
                let result = (|| {
                    require_sizes(out_need)?;
                    let init = input_slice(init_ptr, init_len)?;
                    let state = Wiped(init_write(init)?);
                    let sizes = sizes_for(state.len(), 0, 0)?;
                    write_sizes(out_need, sizes);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Write the canonical state produced by RVFI1 initialization.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_init_write(
    init_ptr: *const u8,
    init_len: usize,
    state_out_ptr: *mut u8,
    state_cap: usize,
    meta_out: *mut RavenFbResultMeta,
) -> i32 {
    let outs = [OutBuf {
        ptr: state_out_ptr,
        cap: state_cap,
        required_max: BRAID_MAX_CANONICAL_STATE_BYTES,
    }];
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[(init_ptr, init_len)],
            &outs,
            ptr::null_mut(),
            meta_out,
            || {
                let result = (|| {
                    require_meta(meta_out)?;
                    output_contract(state_out_ptr, state_cap, 0)?;
                    let init = input_slice(init_ptr, init_len)?;
                    let state = Wiped(init_write(init)?);
                    output_contract(state_out_ptr, state_cap, state.len())?;
                    let meta = init_pipeline_meta(&state)?;
                    copy_output(state_out_ptr, &state);
                    write_result_meta(meta_out, meta);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Measure a transition result (candidate, RVBO1, and RVBJ1).
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_transition_measure(
    state_in_ptr: *const u8,
    state_in_len: usize,
    input_ptr: *const u8,
    input_len: usize,
    env_ptr: *const u8,
    env_len: usize,
    out_need: *mut RavenFbSizes,
) -> i32 {
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[
                (state_in_ptr, state_in_len),
                (input_ptr, input_len),
                (env_ptr, env_len),
            ],
            &[],
            out_need,
            ptr::null_mut(),
            || {
                let result = (|| {
                    require_sizes(out_need)?;
                    let state = input_slice(state_in_ptr, state_in_len)?;
                    let input = input_slice(input_ptr, input_len)?;
                    let env = input_slice(env_ptr, env_len)?;
                    let mut crypto = LabCrypto::default();
                    let output = Wiped(transition_prepare(state, input, env, &mut crypto)?);
                    write_sizes(
                        out_need,
                        sizes_for(
                            output.candidate_bytes.len(),
                            output.outputs_bytes.len(),
                            output.intent_bytes.len(),
                        )?,
                    );
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Write a transition result (candidate, RVBO1, and RVBJ1).
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn raven_fb_transition_write(
    state_in_ptr: *const u8,
    state_in_len: usize,
    input_ptr: *const u8,
    input_len: usize,
    env_ptr: *const u8,
    env_len: usize,
    candidate_out_ptr: *mut u8,
    candidate_cap: usize,
    outputs_out_ptr: *mut u8,
    outputs_cap: usize,
    intent_out_ptr: *mut u8,
    intent_cap: usize,
    meta_out: *mut RavenFbResultMeta,
) -> i32 {
    let outs = [
        OutBuf {
            ptr: candidate_out_ptr,
            cap: candidate_cap,
            required_max: BRAID_MAX_CANONICAL_STATE_BYTES,
        },
        OutBuf {
            ptr: outputs_out_ptr,
            cap: outputs_cap,
            required_max: MAX_RVBO1,
        },
        OutBuf {
            ptr: intent_out_ptr,
            cap: intent_cap,
            required_max: MAX_RVBJ1,
        },
    ];
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[
                (state_in_ptr, state_in_len),
                (input_ptr, input_len),
                (env_ptr, env_len),
            ],
            &outs,
            ptr::null_mut(),
            meta_out,
            || {
                let result = (|| {
                    require_meta(meta_out)?;
                    output_contract(candidate_out_ptr, candidate_cap, 0)?;
                    output_contract(outputs_out_ptr, outputs_cap, 0)?;
                    output_contract(intent_out_ptr, intent_cap, 0)?;
                    let state = input_slice(state_in_ptr, state_in_len)?;
                    let input = input_slice(input_ptr, input_len)?;
                    let env = input_slice(env_ptr, env_len)?;
                    let mut crypto = LabCrypto::default();
                    let output = Wiped(transition_prepare(state, input, env, &mut crypto)?);
                    output_contract(
                        candidate_out_ptr,
                        candidate_cap,
                        output.candidate_bytes.len(),
                    )?;
                    output_contract(outputs_out_ptr, outputs_cap, output.outputs_bytes.len())?;
                    output_contract(intent_out_ptr, intent_cap, output.intent_bytes.len())?;
                    copy_output(candidate_out_ptr, &output.candidate_bytes);
                    copy_output(outputs_out_ptr, &output.outputs_bytes);
                    copy_output(intent_out_ptr, &output.intent_bytes);
                    write_result_meta(meta_out, output.meta);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Measure a promote CAS transform.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_promote_measure(
    live_state_ptr: *const u8,
    live_state_len: usize,
    intent_ptr: *const u8,
    intent_len: usize,
    out_need: *mut RavenFbSizes,
) -> i32 {
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[(live_state_ptr, live_state_len), (intent_ptr, intent_len)],
            &[],
            out_need,
            ptr::null_mut(),
            || {
                let result = (|| {
                    require_sizes(out_need)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let intent = input_slice(intent_ptr, intent_len)?;
                    let output = Wiped(promote_state(live, intent)?);
                    write_sizes(out_need, sizes_for(output.state_bytes.len(), 0, 0)?);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Write a promote CAS transform.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_promote_write(
    live_state_ptr: *const u8,
    live_state_len: usize,
    intent_ptr: *const u8,
    intent_len: usize,
    state_out_ptr: *mut u8,
    state_cap: usize,
    meta_out: *mut RavenFbResultMeta,
) -> i32 {
    let outs = [OutBuf {
        ptr: state_out_ptr,
        cap: state_cap,
        required_max: BRAID_MAX_CANONICAL_STATE_BYTES,
    }];
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[(live_state_ptr, live_state_len), (intent_ptr, intent_len)],
            &outs,
            ptr::null_mut(),
            meta_out,
            || {
                let result = (|| {
                    require_meta(meta_out)?;
                    output_contract(state_out_ptr, state_cap, 0)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let intent = input_slice(intent_ptr, intent_len)?;
                    let output = Wiped(promote_state(live, intent)?);
                    output_contract(state_out_ptr, state_cap, output.state_bytes.len())?;
                    copy_output(state_out_ptr, &output.state_bytes);
                    write_result_meta(meta_out, output.meta);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Measure deterministic RVOR1 materialization.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_rvor_materialize_measure(
    intent_ptr: *const u8,
    intent_len: usize,
    out_need: *mut RavenFbSizes,
) -> i32 {
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[(intent_ptr, intent_len)],
            &[],
            out_need,
            ptr::null_mut(),
            || {
                let result = (|| {
                    require_sizes(out_need)?;
                    let intent = input_slice(intent_ptr, intent_len)?;
                    let output = materialize_rvor(intent)?;
                    write_sizes(out_need, sizes_for(0, output.rvor_bytes.len(), 0)?);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Write deterministic RVOR1 materialization.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_rvor_materialize_write(
    intent_ptr: *const u8,
    intent_len: usize,
    rvor_out_ptr: *mut u8,
    rvor_cap: usize,
    meta_out: *mut RavenFbResultMeta,
) -> i32 {
    let outs = [OutBuf {
        ptr: rvor_out_ptr,
        cap: rvor_cap,
        required_max: BRAID_MAX_RVOR_RECORD_BYTES,
    }];
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[(intent_ptr, intent_len)],
            &outs,
            ptr::null_mut(),
            meta_out,
            || {
                let result = (|| {
                    require_meta(meta_out)?;
                    output_contract(rvor_out_ptr, rvor_cap, 0)?;
                    let intent = input_slice(intent_ptr, intent_len)?;
                    let output = materialize_rvor(intent)?;
                    output_contract(rvor_out_ptr, rvor_cap, output.rvor_bytes.len())?;
                    copy_output(rvor_out_ptr, &output.rvor_bytes);
                    write_result_meta(meta_out, output.meta);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Measure clear after RVBJ1↔RVOR1 evidence verification.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn raven_fb_clear_pending_measure(
    live_state_ptr: *const u8,
    live_state_len: usize,
    intent_ptr: *const u8,
    intent_len: usize,
    rvor_ptr: *const u8,
    rvor_len: usize,
    now_ms: u64,
    out_need: *mut RavenFbSizes,
) -> i32 {
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[
                (live_state_ptr, live_state_len),
                (intent_ptr, intent_len),
                (rvor_ptr, rvor_len),
            ],
            &[],
            out_need,
            ptr::null_mut(),
            || {
                let result = (|| {
                    require_sizes(out_need)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let intent = input_slice(intent_ptr, intent_len)?;
                    let rvor = input_slice(rvor_ptr, rvor_len)?;
                    let output = Wiped(clear_pending(live, intent, rvor, now_ms)?);
                    write_sizes(out_need, sizes_for(output.state_bytes.len(), 0, 0)?);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Write clear after RVBJ1↔RVOR1 evidence verification.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn raven_fb_clear_pending_write(
    live_state_ptr: *const u8,
    live_state_len: usize,
    intent_ptr: *const u8,
    intent_len: usize,
    rvor_ptr: *const u8,
    rvor_len: usize,
    now_ms: u64,
    state_out_ptr: *mut u8,
    state_cap: usize,
    meta_out: *mut RavenFbResultMeta,
) -> i32 {
    let outs = [OutBuf {
        ptr: state_out_ptr,
        cap: state_cap,
        required_max: BRAID_MAX_CANONICAL_STATE_BYTES,
    }];
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[
                (live_state_ptr, live_state_len),
                (intent_ptr, intent_len),
                (rvor_ptr, rvor_len),
            ],
            &outs,
            ptr::null_mut(),
            meta_out,
            || {
                let result = (|| {
                    require_meta(meta_out)?;
                    output_contract(state_out_ptr, state_cap, 0)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let intent = input_slice(intent_ptr, intent_len)?;
                    let rvor = input_slice(rvor_ptr, rvor_len)?;
                    let output = Wiped(clear_pending(live, intent, rvor, now_ms)?);
                    output_contract(state_out_ptr, state_cap, output.state_bytes.len())?;
                    copy_output(state_out_ptr, &output.state_bytes);
                    write_result_meta(meta_out, output.meta);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Measure classify-only recovery.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_recover_measure(
    live_state_ptr: *const u8,
    live_state_len: usize,
    intent_ptr: *const u8,
    intent_len: usize,
    out_need: *mut RavenFbSizes,
) -> i32 {
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[(live_state_ptr, live_state_len), (intent_ptr, intent_len)],
            &[],
            out_need,
            ptr::null_mut(),
            || {
                let result = (|| {
                    require_sizes(out_need)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let intent = input_slice(intent_ptr, intent_len)?;
                    let output = Wiped(recover_state(live, intent)?);
                    write_sizes(out_need, sizes_for(output.state_bytes.len(), 0, 0)?);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Write classify-only recovery, echoing live state bit-for-bit.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_recover_write(
    live_state_ptr: *const u8,
    live_state_len: usize,
    intent_ptr: *const u8,
    intent_len: usize,
    state_out_ptr: *mut u8,
    state_cap: usize,
    meta_out: *mut RavenFbResultMeta,
) -> i32 {
    let outs = [OutBuf {
        ptr: state_out_ptr,
        cap: state_cap,
        required_max: BRAID_MAX_CANONICAL_STATE_BYTES,
    }];
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[(live_state_ptr, live_state_len), (intent_ptr, intent_len)],
            &outs,
            ptr::null_mut(),
            meta_out,
            || {
                let result = (|| {
                    require_meta(meta_out)?;
                    output_contract(state_out_ptr, state_cap, 0)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let intent = input_slice(intent_ptr, intent_len)?;
                    let output = Wiped(recover_state(live, intent)?);
                    output_contract(state_out_ptr, state_cap, output.state_bytes.len())?;
                    copy_output(state_out_ptr, &output.state_bytes);
                    write_result_meta(meta_out, output.meta);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Measure conflict terminalization and its repair RVBJ1.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
pub unsafe extern "C" fn raven_fb_terminalize_conflict_measure(
    live_state_ptr: *const u8,
    live_state_len: usize,
    original_intent_ptr: *const u8,
    original_intent_len: usize,
    now_ms: u64,
    out_need: *mut RavenFbSizes,
) -> i32 {
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[
                (live_state_ptr, live_state_len),
                (original_intent_ptr, original_intent_len),
            ],
            &[],
            out_need,
            ptr::null_mut(),
            || {
                let result = (|| {
                    require_sizes(out_need)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let original = input_slice(original_intent_ptr, original_intent_len)?;
                    let output = Wiped(terminalize_conflict(live, original, now_ms)?);
                    write_sizes(
                        out_need,
                        sizes_for(output.candidate_bytes.len(), 0, output.intent_bytes.len())?,
                    );
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Write conflict terminalization and its repair RVBJ1.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn raven_fb_terminalize_conflict_write(
    live_state_ptr: *const u8,
    live_state_len: usize,
    original_intent_ptr: *const u8,
    original_intent_len: usize,
    now_ms: u64,
    terminal_candidate_out_ptr: *mut u8,
    terminal_candidate_cap: usize,
    repair_intent_out_ptr: *mut u8,
    repair_intent_cap: usize,
    meta_out: *mut RavenFbResultMeta,
) -> i32 {
    let outs = [
        OutBuf {
            ptr: terminal_candidate_out_ptr,
            cap: terminal_candidate_cap,
            required_max: BRAID_MAX_CANONICAL_STATE_BYTES,
        },
        OutBuf {
            ptr: repair_intent_out_ptr,
            cap: repair_intent_cap,
            required_max: MAX_RVBJ1,
        },
    ];
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[
                (live_state_ptr, live_state_len),
                (original_intent_ptr, original_intent_len),
            ],
            &outs,
            ptr::null_mut(),
            meta_out,
            || {
                let result = (|| {
                    require_meta(meta_out)?;
                    output_contract(terminal_candidate_out_ptr, terminal_candidate_cap, 0)?;
                    output_contract(repair_intent_out_ptr, repair_intent_cap, 0)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let original = input_slice(original_intent_ptr, original_intent_len)?;
                    let output = Wiped(terminalize_conflict(live, original, now_ms)?);
                    output_contract(
                        terminal_candidate_out_ptr,
                        terminal_candidate_cap,
                        output.candidate_bytes.len(),
                    )?;
                    output_contract(
                        repair_intent_out_ptr,
                        repair_intent_cap,
                        output.intent_bytes.len(),
                    )?;
                    copy_output(terminal_candidate_out_ptr, &output.candidate_bytes);
                    copy_output(repair_intent_out_ptr, &output.intent_bytes);
                    write_result_meta(meta_out, output.meta);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Measure expired terminalization and its repair RVBJ1.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn raven_fb_terminalize_expired_measure(
    live_state_ptr: *const u8,
    live_state_len: usize,
    original_intent_ptr: *const u8,
    original_intent_len: usize,
    rvor_ptr: *const u8,
    rvor_len: usize,
    now_ms: u64,
    out_need: *mut RavenFbSizes,
) -> i32 {
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[
                (live_state_ptr, live_state_len),
                (original_intent_ptr, original_intent_len),
                (rvor_ptr, rvor_len),
            ],
            &[],
            out_need,
            ptr::null_mut(),
            || {
                let result = (|| {
                    require_sizes(out_need)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let original = input_slice(original_intent_ptr, original_intent_len)?;
                    let rvor = input_slice(rvor_ptr, rvor_len)?;
                    let output = Wiped(terminalize_expired(live, original, rvor, now_ms)?);
                    write_sizes(
                        out_need,
                        sizes_for(output.candidate_bytes.len(), 0, output.intent_bytes.len())?,
                    );
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

/// Write expired terminalization and its repair RVBJ1.
///
/// # Safety
/// Non-null pointers must address readable/writable regions described by the signature.
#[no_mangle]
#[allow(clippy::too_many_arguments)]
pub unsafe extern "C" fn raven_fb_terminalize_expired_write(
    live_state_ptr: *const u8,
    live_state_len: usize,
    original_intent_ptr: *const u8,
    original_intent_len: usize,
    rvor_ptr: *const u8,
    rvor_len: usize,
    now_ms: u64,
    terminal_candidate_out_ptr: *mut u8,
    terminal_candidate_cap: usize,
    repair_intent_out_ptr: *mut u8,
    repair_intent_cap: usize,
    meta_out: *mut RavenFbResultMeta,
) -> i32 {
    let outs = [
        OutBuf {
            ptr: terminal_candidate_out_ptr,
            cap: terminal_candidate_cap,
            required_max: BRAID_MAX_CANONICAL_STATE_BYTES,
        },
        OutBuf {
            ptr: repair_intent_out_ptr,
            cap: repair_intent_cap,
            required_max: MAX_RVBJ1,
        },
    ];
    // SAFETY: all raw-pointer access remains inside checked helpers.
    unsafe {
        execute(
            &[
                (live_state_ptr, live_state_len),
                (original_intent_ptr, original_intent_len),
                (rvor_ptr, rvor_len),
            ],
            &outs,
            ptr::null_mut(),
            meta_out,
            || {
                let result = (|| {
                    require_meta(meta_out)?;
                    output_contract(terminal_candidate_out_ptr, terminal_candidate_cap, 0)?;
                    output_contract(repair_intent_out_ptr, repair_intent_cap, 0)?;
                    let live = input_slice(live_state_ptr, live_state_len)?;
                    let original = input_slice(original_intent_ptr, original_intent_len)?;
                    let rvor = input_slice(rvor_ptr, rvor_len)?;
                    let output = Wiped(terminalize_expired(live, original, rvor, now_ms)?);
                    output_contract(
                        terminal_candidate_out_ptr,
                        terminal_candidate_cap,
                        output.candidate_bytes.len(),
                    )?;
                    output_contract(
                        repair_intent_out_ptr,
                        repair_intent_cap,
                        output.intent_bytes.len(),
                    )?;
                    copy_output(terminal_candidate_out_ptr, &output.candidate_bytes);
                    copy_output(repair_intent_out_ptr, &output.intent_bytes);
                    write_result_meta(meta_out, output.meta);
                    Ok::<(), i32>(())
                })();
                result.map_or_else(|code| code, |()| ERR_OK)
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hybrid_ratchet_v2_full_braid::constants::{
        ERR_INTERNAL, ERR_NEED_CAPACITY, ERR_OK, ERR_PARSE,
    };
    use crate::hybrid_ratchet_v2_full_braid::init::{ROLE_ALICE, RVFI1_MAGIC, RVFI1_SCHEMA};
    use crate::hybrid_ratchet_v2_full_braid::state_codec::{decode_rvfb1, encode_rvfb1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbe1::{encode_rvbe1, Rvbe1};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbi1::{encode_rvbi1, Rvbi1, OP_SEND};
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbj1::decode_rvbj1;
    use crate::hybrid_ratchet_v2_full_braid::wire_rvbm1::Rvbm1;
    use crate::hybrid_ratchet_v2_full_braid::wire_util::{
        write_array32, write_bytes, write_u16be, write_u32be, write_u8,
    };
    use crate::hybrid_ratchet_v2_tr::x25519_public;
    use crate::mlkem768_incremental as mlkem;
    use core::mem::{offset_of, size_of};
    use core::ptr::{null, null_mut};

    fn sample_init_bytes() -> Vec<u8> {
        let bob_spk_pub = x25519_public(&[0x33; 32]).unwrap();
        let mut out = Vec::new();
        write_bytes(&mut out, RVFI1_MAGIC);
        write_u16be(&mut out, RVFI1_SCHEMA);
        write_array32(&mut out, &[0x53; 32]);
        write_u8(&mut out, ROLE_ALICE);
        write_u8(&mut out, 0);
        write_array32(&mut out, &[0x11; 32]);
        write_array32(&mut out, &[0x22; 32]);
        write_array32(&mut out, &bob_spk_pub);
        write_array32(&mut out, &[0x44; 32]);
        write_u32be(&mut out, 0);
        out
    }

    fn send_input_bytes() -> Vec<u8> {
        encode_rvbi1(&Rvbi1 {
            op: OP_SEND,
            direction: 0,
            ch: None,
            expected_ch: None,
            object_digest: None,
            frame: None,
            mutation: Rvbm1::no_aead(),
        })
        .unwrap()
    }

    fn env_bytes(clock: u64) -> Vec<u8> {
        let mut env = Rvbe1::default_caps(clock);
        env.keygen_seed = vec![0x5A; mlkem::SEED_LEN];
        encode_rvbe1(&env).unwrap()
    }

    fn ffi_init() -> Vec<u8> {
        let init = sample_init_bytes();
        let mut need = RavenFbSizes::default();
        assert_eq!(
            unsafe { raven_fb_init_measure(init.as_ptr(), init.len(), &mut need) },
            ERR_OK
        );
        let mut state = vec![0u8; need.candidate_len as usize];
        let mut meta = RavenFbResultMeta::default();
        assert_eq!(
            unsafe {
                raven_fb_init_write(
                    init.as_ptr(),
                    init.len(),
                    state.as_mut_ptr(),
                    state.len(),
                    &mut meta,
                )
            },
            ERR_OK
        );
        state
    }

    fn ffi_prepare() -> (Vec<u8>, Vec<u8>, RavenFbResultMeta) {
        let state = ffi_init();
        let input = send_input_bytes();
        let env = env_bytes(1_000);
        let mut need = RavenFbSizes::default();
        assert_eq!(
            unsafe {
                raven_fb_transition_measure(
                    state.as_ptr(),
                    state.len(),
                    input.as_ptr(),
                    input.len(),
                    env.as_ptr(),
                    env.len(),
                    &mut need,
                )
            },
            ERR_OK
        );
        let mut candidate = vec![0u8; need.candidate_len as usize];
        let mut outputs = vec![0u8; need.outputs_len as usize];
        let mut intent = vec![0u8; need.intent_len as usize];
        let mut meta = RavenFbResultMeta::default();
        assert_eq!(
            unsafe {
                raven_fb_transition_write(
                    state.as_ptr(),
                    state.len(),
                    input.as_ptr(),
                    input.len(),
                    env.as_ptr(),
                    env.len(),
                    candidate.as_mut_ptr(),
                    candidate.len(),
                    outputs.as_mut_ptr(),
                    outputs.len(),
                    intent.as_mut_ptr(),
                    intent.len(),
                    &mut meta,
                )
            },
            ERR_OK
        );
        assert_eq!(meta.pending_phase, 1);
        assert_eq!(candidate, decode_rvbj1(&intent).unwrap().candidate_bytes);
        (state, intent, meta)
    }

    #[test]
    fn c_struct_layouts_are_exact() {
        assert_eq!(size_of::<RavenFbSizes>(), 16);
        assert_eq!(offset_of!(RavenFbSizes, candidate_len), 0);
        assert_eq!(offset_of!(RavenFbSizes, outputs_len), 4);
        assert_eq!(offset_of!(RavenFbSizes, intent_len), 8);
        assert_eq!(offset_of!(RavenFbSizes, reserved0), 12);

        assert_eq!(size_of::<RavenFbResultMeta>(), 64);
        assert_eq!(offset_of!(RavenFbResultMeta, sending_epoch), 0);
        assert_eq!(offset_of!(RavenFbResultMeta, receiving_epoch), 8);
        assert_eq!(offset_of!(RavenFbResultMeta, output_key_epoch), 16);
        assert_eq!(offset_of!(RavenFbResultMeta, flags), 24);
        assert_eq!(offset_of!(RavenFbResultMeta, terminal_reason), 28);
        assert_eq!(offset_of!(RavenFbResultMeta, pending_phase), 30);
        assert_eq!(offset_of!(RavenFbResultMeta, transition_id), 32);
    }

    #[test]
    fn init_measure_write_roundtrip_and_capacity_zeroing() {
        let init = sample_init_bytes();
        let mut need = RavenFbSizes::default();
        assert_eq!(
            unsafe { raven_fb_init_measure(init.as_ptr(), init.len(), &mut need) },
            ERR_OK
        );
        assert!(need.candidate_len > 0);
        assert_eq!(need.outputs_len, 0);
        assert_eq!(need.intent_len, 0);
        assert_eq!(need.reserved0, 0);

        let state = ffi_init();
        assert!(decode_rvfb1(&state).is_ok());

        let short_len = need.candidate_len as usize - 1;
        let mut short = vec![0xA5; short_len];
        let mut meta = RavenFbResultMeta {
            flags: u32::MAX,
            ..RavenFbResultMeta::default()
        };
        assert_eq!(
            unsafe {
                raven_fb_init_write(
                    init.as_ptr(),
                    init.len(),
                    short.as_mut_ptr(),
                    short.len(),
                    &mut meta,
                )
            },
            ERR_NEED_CAPACITY
        );
        assert!(short.iter().all(|byte| *byte == 0));
        assert_eq!(meta, RavenFbResultMeta::default());
    }

    #[test]
    fn null_with_nonzero_length_is_parse_and_zeroes_sizes() {
        let mut need = RavenFbSizes {
            candidate_len: 1,
            outputs_len: 2,
            intent_len: 3,
            reserved0: 4,
        };
        assert_eq!(
            unsafe { raven_fb_init_measure(null(), 176, &mut need) },
            ERR_PARSE
        );
        assert_eq!(need, RavenFbSizes::default());

        // A null zero-length input is safe to inspect, then fails strict parsing.
        assert_eq!(
            unsafe { raven_fb_init_measure(null(), 0, &mut need) },
            ERR_PARSE
        );
        assert_eq!(need, RavenFbSizes::default());
    }

    #[test]
    fn null_output_with_nonzero_capacity_precedes_domain_errors() {
        let (before, intent, _) = ffi_prepare();
        let mut conflict = decode_rvfb1(&before).unwrap();
        conflict.prefix.generation += 9;
        let conflict = encode_rvfb1(&conflict).unwrap();
        let mut meta = RavenFbResultMeta {
            flags: u32::MAX,
            ..RavenFbResultMeta::default()
        };

        assert_eq!(
            unsafe {
                raven_fb_promote_write(
                    conflict.as_ptr(),
                    conflict.len(),
                    intent.as_ptr(),
                    intent.len(),
                    null_mut(),
                    1,
                    &mut meta,
                )
            },
            ERR_PARSE
        );
        assert_eq!(meta, RavenFbResultMeta::default());
    }

    #[test]
    fn aliased_output_is_rejected_without_touching_the_live_state() {
        let (before, original_intent, _) = ffi_prepare();
        // Recover "echoes live state", so writing it in place is tempting; an
        // error must not zero the caller's only copy through the alias.
        let mut live = before.clone();
        let len = live.len();
        let mut meta = RavenFbResultMeta::default();
        let bogus_intent = [0xEE; 64];
        let code = unsafe {
            raven_fb_recover_write(
                live.as_ptr(),
                len,
                bogus_intent.as_ptr(),
                bogus_intent.len(),
                live.as_mut_ptr(),
                len,
                &mut meta,
            )
        };
        assert_eq!(code, ERR_PARSE);
        assert_eq!(live, before);

        // Even a call that would otherwise succeed is refused while aliased.
        let code = unsafe {
            raven_fb_recover_write(
                live.as_ptr(),
                len,
                original_intent.as_ptr(),
                original_intent.len(),
                live.as_mut_ptr(),
                len,
                &mut meta,
            )
        };
        assert_eq!(code, ERR_PARSE);
        assert_eq!(live, before);

        // Overlapping outputs are rejected too.
        let mut outputs = vec![0u8; MAX_RVBJ1];
        let base = outputs.as_mut_ptr();
        let code = unsafe {
            raven_fb_terminalize_conflict_write(
                before.as_ptr(),
                before.len(),
                original_intent.as_ptr(),
                original_intent.len(),
                2_000,
                base,
                BRAID_MAX_CANONICAL_STATE_BYTES,
                base.add(16),
                MAX_RVBJ1 - 16,
                &mut meta,
            )
        };
        assert_eq!(code, ERR_PARSE);
    }

    #[test]
    fn oversized_input_length_is_parse_before_slicing() {
        let init = sample_init_bytes();
        let mut need = RavenFbSizes::default();
        assert_eq!(
            unsafe { raven_fb_init_measure(init.as_ptr(), usize::MAX, &mut need) },
            ERR_PARSE
        );
        let big = vec![0u8; MAX_FFI_INPUT_LEN + 1];
        assert_eq!(
            unsafe { raven_fb_init_measure(big.as_ptr(), big.len(), &mut need) },
            ERR_PARSE
        );
        assert_eq!(need, RavenFbSizes::default());
    }

    #[test]
    fn caught_panic_returns_internal_and_zeroes_outputs() {
        let init = sample_init_bytes();
        let mut need = RavenFbSizes {
            candidate_len: 1,
            outputs_len: 2,
            intent_len: 3,
            reserved0: 4,
        };
        force_panic_once_for_test();
        assert_eq!(
            unsafe { raven_fb_init_measure(init.as_ptr(), init.len(), &mut need) },
            ERR_INTERNAL
        );
        assert_eq!(need, RavenFbSizes::default());
    }

    #[test]
    fn ffi_prepare_promote_materialize_clear_and_recover_roundtrip() {
        let (before, intent, transition_meta) = ffi_prepare();
        let transition_id = decode_rvbj1(&intent).unwrap().header.transition_id;
        assert_eq!(transition_meta.transition_id, transition_id);

        let mut promote_need = RavenFbSizes::default();
        assert_eq!(
            unsafe {
                raven_fb_promote_measure(
                    before.as_ptr(),
                    before.len(),
                    intent.as_ptr(),
                    intent.len(),
                    &mut promote_need,
                )
            },
            ERR_OK
        );
        let mut promoted = vec![0u8; promote_need.candidate_len as usize];
        let mut promote_meta = RavenFbResultMeta::default();
        assert_eq!(
            unsafe {
                raven_fb_promote_write(
                    before.as_ptr(),
                    before.len(),
                    intent.as_ptr(),
                    intent.len(),
                    promoted.as_mut_ptr(),
                    promoted.len(),
                    &mut promote_meta,
                )
            },
            ERR_OK
        );
        assert_eq!(promote_meta.pending_phase, 2);

        let mut rvor_need = RavenFbSizes::default();
        assert_eq!(
            unsafe {
                raven_fb_rvor_materialize_measure(intent.as_ptr(), intent.len(), &mut rvor_need)
            },
            ERR_OK
        );
        let mut rvor = vec![0u8; rvor_need.outputs_len as usize];
        let mut rvor_meta = RavenFbResultMeta::default();
        assert_eq!(
            unsafe {
                raven_fb_rvor_materialize_write(
                    intent.as_ptr(),
                    intent.len(),
                    rvor.as_mut_ptr(),
                    rvor.len(),
                    &mut rvor_meta,
                )
            },
            ERR_OK
        );

        let mut clear_need = RavenFbSizes::default();
        assert_eq!(
            unsafe {
                raven_fb_clear_pending_measure(
                    promoted.as_ptr(),
                    promoted.len(),
                    intent.as_ptr(),
                    intent.len(),
                    rvor.as_ptr(),
                    rvor.len(),
                    1_001,
                    &mut clear_need,
                )
            },
            ERR_OK
        );
        let mut cleared = vec![0u8; clear_need.candidate_len as usize];
        let mut clear_meta = RavenFbResultMeta::default();
        assert_eq!(
            unsafe {
                raven_fb_clear_pending_write(
                    promoted.as_ptr(),
                    promoted.len(),
                    intent.as_ptr(),
                    intent.len(),
                    rvor.as_ptr(),
                    rvor.len(),
                    1_001,
                    cleared.as_mut_ptr(),
                    cleared.len(),
                    &mut clear_meta,
                )
            },
            ERR_OK
        );
        assert_eq!(clear_meta.pending_phase, 0);

        let mut recover_need = RavenFbSizes::default();
        assert_eq!(
            unsafe {
                raven_fb_recover_measure(
                    cleared.as_ptr(),
                    cleared.len(),
                    intent.as_ptr(),
                    intent.len(),
                    &mut recover_need,
                )
            },
            ERR_OK
        );
        let mut echoed = vec![0u8; recover_need.candidate_len as usize];
        let mut recover_meta = RavenFbResultMeta::default();
        assert_eq!(
            unsafe {
                raven_fb_recover_write(
                    cleared.as_ptr(),
                    cleared.len(),
                    intent.as_ptr(),
                    intent.len(),
                    echoed.as_mut_ptr(),
                    echoed.len(),
                    &mut recover_meta,
                )
            },
            ERR_OK
        );
        assert_eq!(echoed, cleared);
        assert_eq!(
            recover_meta.flags,
            crate::hybrid_ratchet_v2_full_braid::pipeline::RECOVER_CLEARED
        );
    }

    #[test]
    fn terminalize_conflict_measure_write_produces_repair_intent() {
        let (before, original_intent, _) = ffi_prepare();
        let mut conflict = decode_rvfb1(&before).unwrap();
        conflict.prefix.auth_root[0] ^= 1;
        let conflict = encode_rvfb1(&conflict).unwrap();

        let mut need = RavenFbSizes::default();
        assert_eq!(
            unsafe {
                raven_fb_terminalize_conflict_measure(
                    conflict.as_ptr(),
                    conflict.len(),
                    original_intent.as_ptr(),
                    original_intent.len(),
                    2_000,
                    &mut need,
                )
            },
            ERR_OK
        );
        assert!(need.candidate_len > 0);
        assert_eq!(need.outputs_len, 0);
        assert!(need.intent_len > 0);
        let mut candidate = vec![0u8; need.candidate_len as usize];
        let mut repair_intent = vec![0u8; need.intent_len as usize];
        let mut meta = RavenFbResultMeta::default();
        assert_eq!(
            unsafe {
                raven_fb_terminalize_conflict_write(
                    conflict.as_ptr(),
                    conflict.len(),
                    original_intent.as_ptr(),
                    original_intent.len(),
                    2_000,
                    candidate.as_mut_ptr(),
                    candidate.len(),
                    repair_intent.as_mut_ptr(),
                    repair_intent.len(),
                    &mut meta,
                )
            },
            ERR_OK
        );
        assert_eq!(decode_rvfb1(&candidate).unwrap().prefix.terminal_reason, 6);
        assert_eq!(decode_rvbj1(&repair_intent).unwrap().header.intent_kind, 1);
    }

    #[test]
    fn terminalize_expired_measure_write_requires_and_verifies_rvor() {
        let (before, original_intent, _) = ffi_prepare();
        let promoted = promote_state(&before, &original_intent)
            .unwrap()
            .state_bytes;
        let rvor = materialize_rvor(&original_intent).unwrap().rvor_bytes;
        let expiry = decode_rvbj1(&original_intent)
            .unwrap()
            .header
            .retention_expiry_ms;
        let mut need = RavenFbSizes::default();

        assert_eq!(
            unsafe {
                raven_fb_terminalize_expired_measure(
                    promoted.as_ptr(),
                    promoted.len(),
                    original_intent.as_ptr(),
                    original_intent.len(),
                    null(),
                    0,
                    expiry + 1,
                    &mut need,
                )
            },
            ERR_PARSE
        );
        assert_eq!(need, RavenFbSizes::default());
        assert_eq!(
            unsafe {
                raven_fb_terminalize_expired_measure(
                    promoted.as_ptr(),
                    promoted.len(),
                    original_intent.as_ptr(),
                    original_intent.len(),
                    rvor.as_ptr(),
                    rvor.len(),
                    expiry + 1,
                    &mut need,
                )
            },
            ERR_OK
        );

        let mut candidate = vec![0u8; need.candidate_len as usize];
        let mut repair_intent = vec![0u8; need.intent_len as usize];
        let mut meta = RavenFbResultMeta::default();
        assert_eq!(
            unsafe {
                raven_fb_terminalize_expired_write(
                    promoted.as_ptr(),
                    promoted.len(),
                    original_intent.as_ptr(),
                    original_intent.len(),
                    rvor.as_ptr(),
                    rvor.len(),
                    expiry + 1,
                    candidate.as_mut_ptr(),
                    candidate.len(),
                    repair_intent.as_mut_ptr(),
                    repair_intent.len(),
                    &mut meta,
                )
            },
            ERR_OK
        );
        assert_eq!(decode_rvfb1(&candidate).unwrap().prefix.terminal_reason, 7);
        assert_eq!(decode_rvbj1(&repair_intent).unwrap().header.intent_kind, 2);
        assert_eq!(meta.terminal_reason, 7);
    }

    #[test]
    fn zeroing_helper_never_writes_past_required_max() {
        let mut bytes = vec![0xA5; 32];
        unsafe {
            zero_out(OutBuf {
                ptr: bytes.as_mut_ptr(),
                cap: bytes.len(),
                required_max: 17,
            });
        }
        assert!(bytes[..17].iter().all(|byte| *byte == 0));
        assert!(bytes[17..].iter().all(|byte| *byte == 0xA5));

        unsafe {
            zero_meta(null_mut());
            zero_sizes(null_mut());
        }
    }
}
