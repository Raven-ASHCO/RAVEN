//! Platform IPC client: shared length-prefixed JSON I/O, cfg-gated connect.
//!
//! Unix connects a UDS; Windows connects the per-user pipe
//! `\\.\pipe\raven-node-<SID>` and verifies the server runs as this user.
//! Framing is always [`encode_request`] / [`decode_response`] (`IPC_VERSION=1`).

use std::io::{Read, Write};
use std::path::Path;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

use raven_core::ipc::{
    decode_response, encode_request, ipc_endpoint, IpcEndpoint, IpcRequest, IpcResponse,
    IPC_VERSION,
};

/// I/O timeout of [`ipc_ping`] / [`ipc_request`], which `ash ipc-ping`,
/// `ash status` and `ash doctor` use. A healthy service answers these at once
/// (it serves Ping / Status even while it is busy dialing), so waiting longer
/// only made a hung service look like a frozen ash (10 s of silence).
const IPC_IO_TIMEOUT: Duration = Duration::from_secs(3);

/// How long a dial request keeps retrying a *refused/absent* socket connect
/// (the daemon was just auto-started or is restarting). Only the connect is
/// retried: once a request byte has been written it is never replayed.
const IPC_CONNECT_RETRY_BUDGET: Duration = Duration::from_secs(3);

/// Common start of every "nothing is listening" text, so callers can tell a
/// service that is not running from one that is stuck ([`error_means_not_running`]).
const NOT_RUNNING: &str = "raven-node is not running";

/// What to do about it. `ash listen` starts the service in the foreground; a
/// message sent with `ash send` (or typed in a chat) starts it in the background.
const START_HINT: &str = "start it with `ash listen`, or send a message (that starts it too)";

/// Ping→Pong over the platform endpoint. Presence only — not ready / send_path.
pub fn ipc_ping(data_dir: &Path) -> Result<IpcResponse, String> {
    ipc_request(data_dir, &IpcRequest::Ping { v: IPC_VERSION })
}

/// Ping with the default I/O timeout. Production code polls with
/// [`ipc_daemon_up_within`] (a wedged daemon must not stall each probe that
/// long), so this is only the default-timeout reference the (unix) tests compare to.
#[cfg(all(test, unix))]
pub fn ipc_daemon_up(data_dir: &Path) -> bool {
    matches!(ipc_ping(data_dir), Ok(IpcResponse::Pong { .. }))
}

/// Ping with a caller-chosen I/O timeout, for readiness polling where a wedged
/// daemon must not stall each probe for the full default timeout.
pub fn ipc_daemon_up_within(data_dir: &Path, timeout: Duration) -> bool {
    matches!(
        ipc_request_timeout(data_dir, &IpcRequest::Ping { v: IPC_VERSION }, timeout),
        Ok(IpcResponse::Pong { .. })
    )
}

pub fn ipc_request(data_dir: &Path, req: &IpcRequest) -> Result<IpcResponse, String> {
    ipc_request_timeout(data_dir, req, IPC_IO_TIMEOUT)
}

/// Single-shot connect: liveness probes (`ipc_ping`, daemon preflight) must
/// fail fast when nothing is listening.
pub fn ipc_request_timeout(
    data_dir: &Path,
    req: &IpcRequest,
    timeout: Duration,
) -> Result<IpcResponse, String> {
    let endpoint = ipc_endpoint(data_dir);
    connect_and_transact(&endpoint, req, timeout, Duration::ZERO)
}

/// Like [`ipc_request_timeout`], but a connect that is refused or finds no
/// socket yet (daemon just auto-started, or restarting) is retried with a short
/// backoff for [`IPC_CONNECT_RETRY_BUDGET`]. For dial requests only.
pub fn ipc_request_retrying_connect(
    data_dir: &Path,
    req: &IpcRequest,
    timeout: Duration,
) -> Result<IpcResponse, String> {
    let endpoint = ipc_endpoint(data_dir);
    connect_and_transact(&endpoint, req, timeout, IPC_CONNECT_RETRY_BUDGET)
}

fn connect_and_transact(
    endpoint: &IpcEndpoint,
    req: &IpcRequest,
    timeout: Duration,
    connect_budget: Duration,
) -> Result<IpcResponse, String> {
    match endpoint {
        IpcEndpoint::UnixSocket(path) => connect_unix(path, req, timeout, connect_budget),
        IpcEndpoint::NamedPipe(name) => connect_named_pipe(name, req, timeout),
        IpcEndpoint::Unsupported => Err("ipc_transport_missing".into()),
    }
}

#[cfg(unix)]
fn connect_unix(
    path: &Path,
    req: &IpcRequest,
    timeout: Duration,
    connect_budget: Duration,
) -> Result<IpcResponse, String> {
    use std::os::unix::net::UnixStream;
    let mut stream = connect_with_retry(connect_budget, || UnixStream::connect(path))
        .map_err(|e| ipc_connect_error(&e, &path.display().to_string()))?;
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));
    transact(&mut stream, req)
}

/// Connect errors that mean "the daemon is not accepting yet": no socket file
/// (ENOENT), nobody listening (ECONNREFUSED), backlog full (EAGAIN) or EINTR.
#[cfg(unix)]
fn transient_connect_error(e: &std::io::Error) -> bool {
    use std::io::ErrorKind;
    matches!(
        e.kind(),
        ErrorKind::NotFound
            | ErrorKind::ConnectionRefused
            | ErrorKind::WouldBlock
            | ErrorKind::Interrupted
    )
}

/// Run `connect` until it succeeds, fails with a non-transient error, or the
/// `budget` is spent (exponential backoff, 25 ms to 250 ms). A zero budget is
/// exactly one attempt. Returns the last error on exhaustion.
#[cfg(unix)]
fn connect_with_retry<T>(
    budget: Duration,
    mut connect: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    let deadline = Instant::now() + budget;
    let mut delay = Duration::from_millis(25);
    loop {
        match connect() {
            Ok(v) => return Ok(v),
            Err(e) if transient_connect_error(&e) && Instant::now() + delay < deadline => {
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(250));
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(not(unix))]
fn connect_unix(
    _path: &Path,
    _req: &IpcRequest,
    _timeout: Duration,
    _connect_budget: Duration,
) -> Result<IpcResponse, String> {
    Err("ipc_transport_missing".into())
}

/// A `std::fs::File` pipe handle has no read/write timeout, so the whole
/// connect + transact runs on a worker thread and is abandoned after `timeout`
/// (a wedged daemon must not hang ash forever). The blocked worker is leaked
/// until process exit, which is acceptable for this short-lived CLI.
#[cfg(windows)]
fn connect_named_pipe(
    name: &str,
    req: &IpcRequest,
    timeout: Duration,
) -> Result<IpcResponse, String> {
    use std::sync::mpsc::{channel, RecvTimeoutError};
    let (tx, rx) = channel();
    let worker_name = name.to_string();
    let worker_req = req.clone();
    std::thread::spawn(move || {
        let result = open_named_pipe(&worker_name)
            .map_err(|e| ipc_connect_error(&e, &worker_name))
            .and_then(|mut stream| transact(&mut stream, &worker_req));
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => Err(format!(
            "{NO_ANSWER} (no answer within {timeout:?} on {name})"
        )),
        Err(RecvTimeoutError::Disconnected) => Err("ipc worker exited unexpectedly".into()),
    }
}

#[cfg(windows)]
fn open_named_pipe(name: &str) -> std::io::Result<std::fs::File> {
    use std::fs::OpenOptions;
    use std::io::{Error, ErrorKind};
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use std::thread;

    // ERROR_PIPE_BUSY — server is between instances; retry instead of fail-open.
    const ERROR_PIPE_BUSY: i32 = 231;
    const ATTEMPTS: u32 = 40;
    // SECURITY_IDENTIFICATION: the pipe server may identify but never
    // impersonate this client (default for pipes is SecurityImpersonation).
    const SECURITY_IDENTIFICATION: u32 = 0x0001_0000;

    for attempt in 0..ATTEMPTS {
        match OpenOptions::new()
            .read(true)
            .write(true)
            .security_qos_flags(SECURITY_IDENTIFICATION)
            .open(name)
        {
            Ok(f) => {
                // The pipe namespace is machine-wide: another user can squat the
                // name. Verify the server's process owner before sending bytes.
                raven_core::ipc::verify_named_pipe_server_is_current_user(f.as_raw_handle())
                    .map_err(|e| Error::new(ErrorKind::PermissionDenied, e))?;
                return Ok(f);
            }
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempt + 1 < ATTEMPTS => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(e),
        }
    }
    Err(Error::new(ErrorKind::TimedOut, "named pipe busy"))
}

#[cfg(not(windows))]
fn connect_named_pipe(
    _name: &str,
    _req: &IpcRequest,
    _timeout: Duration,
) -> Result<IpcResponse, String> {
    Err("ipc_transport_missing".into())
}

/// The service accepted the connection but never answered: stopped (SIGSTOP),
/// deadlocked, or blocked on an OS keystore dialog.
const NO_ANSWER: &str = "raven-node did not answer in time: it is busy or stuck; try again in a \
     moment, or run `ash doctor`";

/// True for the text [`ipc_connect_error`] gives a service that is not running
/// (as opposed to one that is running but stuck, or an unrelated error).
pub(crate) fn error_means_not_running(err: &str) -> bool {
    err.contains(NOT_RUNNING)
}

/// True for the text of a request the service accepted but did not answer
/// within the caller's timeout ([`NO_ANSWER`]).
pub(crate) fn error_means_no_answer(err: &str) -> bool {
    err.starts_with(NO_ANSWER)
}

/// Text for a failed *connect* to the service endpoint `target` (a socket path
/// or pipe name). The OS text ("No such file or directory (os error 2)",
/// "Connection refused (os error 61)") means "no service" to an engineer and
/// nothing to anyone else, so say that and the next step, and keep the OS text
/// at the end where a log search still finds it.
fn ipc_connect_error(e: &std::io::Error, target: &str) -> String {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::NotFound => {
            format!("{NOT_RUNNING}; {START_HINT} (nothing is listening at {target}: {e})")
        }
        ErrorKind::ConnectionRefused => format!(
            "{NOT_RUNNING}; {START_HINT} (a socket left over from an earlier run is harmless: {e})"
        ),
        ErrorKind::PermissionDenied => format!(
            "ash may not use the raven-node endpoint {target} (permission denied): is the \
             service running as another user? ({e})"
        ),
        ErrorKind::WouldBlock | ErrorKind::TimedOut => format!("{NO_ANSWER} ({e})"),
        _ => e.to_string(),
    }
}

/// Text for an I/O error on an *established* IPC connection. A daemon that dies
/// (crash, `kill`, restart) mid-request just closes the socket: `read_exact` then
/// reports the opaque "failed to fill whole buffer" and a write reports a bare
/// "Broken pipe", which read as a protocol bug inside otherwise good error text
/// (for instance a queued send). A daemon that is stuck makes the read time out
/// ("Resource temporarily unavailable (os error 35)", which means nothing to
/// most readers). Say what happened; every other kind keeps the OS text.
fn ipc_io_error(e: &std::io::Error) -> String {
    use std::io::ErrorKind;
    match e.kind() {
        ErrorKind::UnexpectedEof
        | ErrorKind::BrokenPipe
        | ErrorKind::ConnectionReset
        | ErrorKind::ConnectionAborted => "the local raven-node service stopped during the \
             request (the connection closed before it answered)"
            .to_string(),
        ErrorKind::WouldBlock | ErrorKind::TimedOut => format!("{NO_ANSWER} ({e})"),
        _ => e.to_string(),
    }
}

fn transact<S: Read + Write>(stream: &mut S, req: &IpcRequest) -> Result<IpcResponse, String> {
    let frame = encode_request(req)?;
    stream.write_all(&frame).map_err(|e| ipc_io_error(&e))?;
    stream.flush().map_err(|e| ipc_io_error(&e))?;
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .map_err(|e| ipc_io_error(&e))?;
    let n = u32::from_be_bytes(len_buf) as usize;
    if n == 0 || n > raven_core::MAX_IPC_FRAME {
        return Err("IPC_FRAME".into());
    }
    let mut body = vec![0u8; n];
    stream.read_exact(&mut body).map_err(|e| ipc_io_error(&e))?;
    let mut resp = Vec::with_capacity(4 + n);
    resp.extend_from_slice(&len_buf);
    resp.extend_from_slice(&body);
    decode_response(&resp)
}

/// Test-only IPC peers shared with the other ash modules' tests.
#[cfg(all(test, unix))]
pub(crate) mod test_support {
    use super::*;
    use std::os::unix::net::UnixListener;

    /// Bind `sock` and answer every well-framed request with `Pong` until the
    /// process exits. Enough of a daemon for readiness probes and pings.
    pub(crate) fn spawn_pong_server(sock: &Path) {
        let listener = UnixListener::bind(sock).expect("bind test socket");
        std::thread::spawn(move || {
            let pong = raven_core::encode_response(&IpcResponse::Pong { v: IPC_VERSION }).unwrap();
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut body = vec![0u8; u32::from_be_bytes(len) as usize];
                if stream.read_exact(&mut body).is_err() {
                    continue;
                }
                let _ = stream.write_all(&pong);
            }
        });
    }

    /// Bind `sock` and answer Ping with `Pong` and Status with the
    /// `capabilities()` of that moment (read per request, so a test can make the
    /// listener "come up" later), until the process exits.
    pub(crate) fn spawn_status_server(
        sock: &Path,
        capabilities: impl Fn() -> Vec<String> + Send + 'static,
    ) {
        let listener = UnixListener::bind(sock).expect("bind test socket");
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { return };
                let mut len = [0u8; 4];
                if stream.read_exact(&mut len).is_err() {
                    continue;
                }
                let mut frame = len.to_vec();
                frame.resize(4 + u32::from_be_bytes(len) as usize, 0);
                if stream.read_exact(&mut frame[4..]).is_err() {
                    continue;
                }
                let response = match raven_core::decode_request(&frame) {
                    Ok(IpcRequest::Status { .. }) => IpcResponse::Status {
                        v: IPC_VERSION,
                        bridge: false,
                        store: false,
                        relay: false,
                        forward_pending: 0,
                        capabilities: capabilities(),
                    },
                    _ => IpcResponse::Pong { v: IPC_VERSION },
                };
                let _ = stream.write_all(&raven_core::encode_response(&response).unwrap());
            }
        });
    }

    /// A tempdir whose socket path stays under the AF_UNIX `sun_path` limit
    /// even when `$TMPDIR` is long.
    pub(crate) fn short_tempdir() -> tempfile::TempDir {
        let dir = tempfile::tempdir().expect("tempdir");
        if dir.path().as_os_str().len() <= 60 {
            return dir;
        }
        tempfile::Builder::new()
            .prefix("rv")
            .tempdir_in("/tmp")
            .expect("tempdir in /tmp")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// In-memory duplex: reads come from `read`, writes are captured.
    struct Pair {
        read: Cursor<Vec<u8>>,
        write: Vec<u8>,
    }
    impl Pair {
        fn replying(bytes: Vec<u8>) -> Self {
            Self {
                read: Cursor::new(bytes),
                write: Vec::new(),
            }
        }
    }
    impl Read for Pair {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.read.read(buf)
        }
    }
    impl Write for Pair {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.write.write(buf)
        }
        fn flush(&mut self) -> std::io::Result<()> {
            self.write.flush()
        }
    }

    fn ping() -> IpcRequest {
        IpcRequest::Ping { v: IPC_VERSION }
    }

    #[test]
    fn transact_roundtrip_ping_over_memory() {
        let req = ping();
        let resp = IpcResponse::Pong { v: IPC_VERSION };
        let resp_frame = raven_core::encode_response(&resp).unwrap();
        let mut pair = Pair::replying(resp_frame);
        assert_eq!(transact(&mut pair, &req).unwrap(), resp);
        assert_eq!(pair.write, encode_request(&req).unwrap());
    }

    #[test]
    fn unsupported_endpoint_is_transport_missing() {
        let err = connect_and_transact(
            &IpcEndpoint::Unsupported,
            &ping(),
            IPC_IO_TIMEOUT,
            Duration::ZERO,
        )
        .unwrap_err();
        assert_eq!(err, "ipc_transport_missing");
    }

    #[test]
    fn transact_rejects_zero_and_oversize_length_before_reading_a_body() {
        // The length prefix alone decides: no body bytes follow, so a guard that
        // allocated first (or read a body) would fail differently.
        for n in [0u32, raven_core::MAX_IPC_FRAME as u32 + 1, u32::MAX] {
            let mut pair = Pair::replying(n.to_be_bytes().to_vec());
            assert_eq!(
                transact(&mut pair, &ping()).unwrap_err(),
                "IPC_FRAME",
                "{n}"
            );
        }
    }

    #[test]
    fn transact_accepts_the_maximum_frame_length_prefix() {
        // MAX_IPC_FRAME itself is within bounds: the failure is the missing body.
        let mut pair = Pair::replying((raven_core::MAX_IPC_FRAME as u32).to_be_bytes().to_vec());
        let err = transact(&mut pair, &ping()).unwrap_err();
        assert_ne!(err, "IPC_FRAME");
        assert!(err.contains("service stopped during the request"), "{err}");
    }

    #[test]
    fn transact_reports_truncated_prefix_and_truncated_body() {
        // A daemon that dies mid-request closes the socket: say so, not the
        // opaque "failed to fill whole buffer".
        let eof = "the local raven-node service stopped during the request";
        // Empty reply and a 3-byte (short) length prefix.
        for short in [vec![], vec![0u8, 0, 0]] {
            let mut pair = Pair::replying(short);
            let err = transact(&mut pair, &ping()).unwrap_err();
            assert!(err.contains(eof), "{err}");
        }
        // Prefix promises 16 bytes, only 5 follow.
        let mut reply = 16u32.to_be_bytes().to_vec();
        reply.extend_from_slice(&[b'{'; 5]);
        let mut pair = Pair::replying(reply);
        let err = transact(&mut pair, &ping()).unwrap_err();
        assert!(err.contains(eof), "{err}");
    }

    #[test]
    fn transact_rejects_undecodable_and_wrong_shape_bodies() {
        for body in [
            &b"not json at all"[..],
            br#"{"op":"no_such_response"}"#,
            b"[]",
        ] {
            let mut reply = (body.len() as u32).to_be_bytes().to_vec();
            reply.extend_from_slice(body);
            let mut pair = Pair::replying(reply);
            assert!(
                transact(&mut pair, &ping()).is_err(),
                "{}",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// A transport error from the stream is surfaced verbatim, not swallowed.
    #[test]
    fn transact_surfaces_stream_timeout_error() {
        struct TimesOut;
        impl Read for TimesOut {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out",
                ))
            }
        }
        impl Write for TimesOut {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let err = transact(&mut TimesOut, &ping()).unwrap_err();
        assert!(err.contains("did not answer in time"), "{err}");
        assert!(
            err.ends_with("(timed out)"),
            "the OS text stays at the end: {err}"
        );
        assert!(!error_means_not_running(&err), "stuck is not absent: {err}");
    }

    /// A hang-up in any phase (write, flush, read) is "the service stopped",
    /// never the raw OS wording; unrelated errors keep their text.
    #[test]
    fn transact_names_a_daemon_that_closed_the_connection() {
        use std::io::ErrorKind;
        struct Failing {
            write_kind: Option<ErrorKind>,
        }
        impl Read for Failing {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::from(ErrorKind::ConnectionReset))
            }
        }
        impl Write for Failing {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                match self.write_kind {
                    Some(kind) => Err(std::io::Error::from(kind)),
                    None => Ok(buf.len()),
                }
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        for kind in [
            ErrorKind::BrokenPipe,
            ErrorKind::ConnectionReset,
            ErrorKind::ConnectionAborted,
            ErrorKind::UnexpectedEof,
        ] {
            let err = transact(
                &mut Failing {
                    write_kind: Some(kind),
                },
                &ping(),
            )
            .unwrap_err();
            assert!(
                err.contains("service stopped during the request"),
                "{kind:?}: {err}"
            );
            assert!(!err.contains("Broken pipe"), "{err}");
        }
        // Written fine, then the daemon reset the connection while we waited.
        let err = transact(&mut Failing { write_kind: None }, &ping()).unwrap_err();
        assert!(err.contains("service stopped during the request"), "{err}");
        // Other errors are not relabelled.
        let denied = std::io::Error::from(ErrorKind::PermissionDenied);
        assert_eq!(ipc_io_error(&denied), denied.to_string());
        // A stuck service (the read timed out) is named as such, the OS wording
        // ("Resource temporarily unavailable") is kept only at the end.
        for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock] {
            let text = ipc_io_error(&std::io::Error::from(kind));
            assert!(text.contains("did not answer in time"), "{kind:?}: {text}");
            assert!(text.contains("ash doctor"), "{kind:?}: {text}");
        }
        let other = std::io::Error::new(ErrorKind::InvalidData, "garbled");
        assert_eq!(ipc_io_error(&other), "garbled");
    }

    /// A hung service must be reported within seconds, not 10 s of silence.
    #[test]
    fn probe_timeout_is_short_enough_not_to_look_like_a_frozen_ash() {
        assert!(
            IPC_IO_TIMEOUT <= Duration::from_secs(3),
            "{IPC_IO_TIMEOUT:?}"
        );
    }

    #[test]
    fn connect_errors_say_what_to_do_and_keep_the_os_text_at_the_end() {
        use std::io::{Error, ErrorKind};
        let target = "/data/raven-node.sock";
        let gone = ipc_connect_error(&Error::from(ErrorKind::NotFound), target);
        assert!(error_means_not_running(&gone), "{gone}");
        assert!(gone.contains(target), "{gone}");
        assert!(gone.contains("ash listen"), "{gone}");
        assert!(gone.contains("send a message"), "{gone}");
        let stale = ipc_connect_error(&Error::from(ErrorKind::ConnectionRefused), target);
        assert!(error_means_not_running(&stale), "{stale}");
        assert!(stale.contains("ash listen"), "{stale}");
        let denied = ipc_connect_error(&Error::from(ErrorKind::PermissionDenied), target);
        assert!(denied.contains("permission denied"), "{denied}");
        assert!(!error_means_not_running(&denied), "{denied}");
        for kind in [ErrorKind::TimedOut, ErrorKind::WouldBlock] {
            let busy = ipc_connect_error(&Error::from(kind), target);
            assert!(busy.contains("did not answer in time"), "{busy}");
            assert!(!error_means_not_running(&busy), "{busy}");
        }
        // Anything else is left alone.
        let odd = Error::new(ErrorKind::InvalidInput, "path must be shorter than SUN_LEN");
        assert_eq!(ipc_connect_error(&odd, target), odd.to_string());
        // A plain "stopped" text is not "not running" either.
        assert!(!error_means_not_running(&ipc_io_error(&Error::from(
            ErrorKind::BrokenPipe
        ))));
    }

    #[cfg(unix)]
    mod unix {
        use super::super::test_support::{short_tempdir, spawn_pong_server};
        use super::*;
        use std::cell::Cell;
        use std::io::{Error, ErrorKind};

        #[test]
        fn zero_budget_is_a_single_attempt() {
            let attempts = Cell::new(0u32);
            let err = connect_with_retry::<()>(Duration::ZERO, || {
                attempts.set(attempts.get() + 1);
                Err(Error::from(ErrorKind::ConnectionRefused))
            })
            .unwrap_err();
            assert_eq!(attempts.get(), 1);
            assert_eq!(err.kind(), ErrorKind::ConnectionRefused);
        }

        #[test]
        fn transient_connect_errors_are_retried_until_success() {
            let attempts = Cell::new(0u32);
            let got = connect_with_retry(Duration::from_secs(30), || {
                attempts.set(attempts.get() + 1);
                match attempts.get() {
                    1 => Err(Error::from(ErrorKind::NotFound)),
                    2 => Err(Error::from(ErrorKind::ConnectionRefused)),
                    3 => Err(Error::from(ErrorKind::WouldBlock)),
                    _ => Ok(attempts.get()),
                }
            })
            .unwrap();
            assert_eq!(got, 4);
        }

        #[test]
        fn non_transient_connect_errors_are_not_retried() {
            let attempts = Cell::new(0u32);
            let err = connect_with_retry::<()>(Duration::from_secs(30), || {
                attempts.set(attempts.get() + 1);
                Err(Error::from(ErrorKind::PermissionDenied))
            })
            .unwrap_err();
            assert_eq!(attempts.get(), 1);
            assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        }

        #[test]
        fn retry_is_bounded_by_the_budget() {
            let attempts = Cell::new(0u32);
            let err = connect_with_retry::<()>(Duration::from_millis(400), || {
                attempts.set(attempts.get() + 1);
                Err(Error::from(ErrorKind::NotFound))
            })
            .unwrap_err();
            assert!(attempts.get() >= 2, "retried at least once");
            assert_eq!(err.kind(), ErrorKind::NotFound, "last error is returned");
        }

        #[test]
        fn missing_socket_fails_fast_without_retry_budget() {
            let dir = short_tempdir();
            let err = ipc_request_timeout(dir.path(), &ping(), Duration::from_secs(1)).unwrap_err();
            assert!(err.contains("No such file"), "{err}");
            assert!(error_means_not_running(&err), "{err}");
            assert!(err.contains("ash listen"), "{err}");
            assert!(!ipc_daemon_up(dir.path()));
        }

        /// A crashed service leaves its socket file behind: connecting is refused.
        /// Same verdict as a missing socket, never "Connection refused (os error 61)"
        /// on its own.
        #[test]
        fn stale_socket_is_reported_as_not_running() {
            let dir = short_tempdir();
            let sock = raven_core::default_socket_path(dir.path());
            drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
            assert!(sock.exists(), "dropping a listener leaves the socket file");
            let err = ipc_request_timeout(dir.path(), &ping(), Duration::from_secs(1)).unwrap_err();
            assert!(error_means_not_running(&err), "{err}");
            assert!(err.contains("ash listen"), "{err}");
            assert!(
                err.contains("Connection refused"),
                "OS text kept at the end: {err}"
            );
        }

        #[test]
        fn client_round_trips_against_a_live_socket() {
            let dir = short_tempdir();
            spawn_pong_server(&raven_core::default_socket_path(dir.path()));
            assert!(ipc_daemon_up(dir.path()));
            assert!(ipc_daemon_up_within(dir.path(), Duration::from_secs(2)));
            assert_eq!(
                ipc_request_retrying_connect(dir.path(), &ping(), Duration::from_secs(2)).unwrap(),
                IpcResponse::Pong { v: IPC_VERSION }
            );
        }

        /// A daemon that accepts and reads the request but never answers must
        /// not hang the client past its read timeout.
        #[test]
        fn stalled_server_times_out_instead_of_hanging() {
            use std::os::unix::net::UnixListener;
            use std::sync::mpsc::channel;
            let dir = short_tempdir();
            let listener = UnixListener::bind(raven_core::default_socket_path(dir.path())).unwrap();
            let (done_tx, done_rx) = channel::<()>();
            let request_len = encode_request(&ping()).unwrap().len();
            let server = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                let mut buf = vec![0u8; request_len];
                stream.read_exact(&mut buf).unwrap();
                // Hold the connection open, silent, until the client gave up.
                let _ = done_rx.recv();
            });
            let result = ipc_request_timeout(dir.path(), &ping(), Duration::from_millis(150));
            let _ = done_tx.send(());
            server.join().unwrap();
            let err = result.expect_err("silent server must yield a timeout error");
            assert!(err.contains("did not answer in time"), "{err}");
            assert!(!error_means_not_running(&err), "stuck is not absent: {err}");
        }
    }
}
