//! Task 0A.2 — SQLCipher lab linkage integration test.
//!
//! Requires:
//!   RAVEN_EXPECT_SQLCIPHER_4_17_0=1
//!   --features full-braid-durable-lab

#![cfg(feature = "full-braid-durable-lab")]

use raven_core::full_braid_durable_lab::{
    probe_sqlcipher_lab_linkage, run_temp_store_probe, scan_profile_files_for_plaintext,
    RavenSqlCipherConnection, RavenSqlCipherFirstInstallProof, RavenSqlCipherOpenError,
    RavenSqlCipherRawKey, EXPECTED_CIPHER_VERSION, EXPECTED_CIPHER_VERSION_COMMUNITY,
    EXPECTED_SQLITE_VERSION, RAVEN_SQLCIPHER_APP_GROUP_PLAINTEXT_HEADER_SIZE,
    RAVEN_SQLCIPHER_BUSY_TIMEOUT_MS, RAVEN_SQLCIPHER_HMAC_ALGORITHM, RAVEN_SQLCIPHER_KDF_ALGORITHM,
    RAVEN_SQLCIPHER_PAGE_SIZE, RAVEN_SQLCIPHER_TERMINAL_PLAINTEXT_HEADER_SIZE,
};
use rusqlite::config::DbConfig;
use std::fs;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

// SQLCipher cipher_memory_security and temp-directory controls have process-
// global provider state. Keep this profile integration suite serialized.
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn test_lock() -> std::sync::MutexGuard<'static, ()> {
    TEST_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[test]
fn sqlcipher_4_17_0_lab_linkage_probe() {
    let _guard = test_lock();
    let report = probe_sqlcipher_lab_linkage().expect("SQLCipher lab linkage probe");
    assert!(
        report.cipher_version == EXPECTED_CIPHER_VERSION
            || report.cipher_version == EXPECTED_CIPHER_VERSION_COMMUNITY,
        "cipher_version={}",
        report.cipher_version
    );
    assert_eq!(report.sqlite_libversion, EXPECTED_SQLITE_VERSION);
    assert!(
        report.has_codec_compile_option,
        "SQLITE_HAS_CODEC must be compiled in"
    );
    assert!(report.has_temp_store_2, "TEMP_STORE=2 must be compiled in");
    assert_eq!(report.cipher_provider, "openssl");
}

fn profile_key() -> RavenSqlCipherRawKey {
    RavenSqlCipherRawKey::ios_app_group(&[0x41; 32], [0x53; 16])
}

fn raw_key_sql(key: u8, salt: u8) -> String {
    format!(
        "PRAGMA key=\"x'{}{}'\";",
        hex::encode([key; 32]),
        hex::encode([salt; 16])
    )
}

fn create_nonstandard_profile(path: &Path, profile_sql: &str) {
    let conn = rusqlite::Connection::open(path).expect("nonstandard open");
    conn.execute_batch(&raw_key_sql(0x41, 0x53))
        .expect("nonstandard key");
    conn.execute_batch(profile_sql)
        .expect("nonstandard profile");
    conn.execute_batch(
        "CREATE TABLE profile_mismatch(v INTEGER); INSERT INTO profile_mismatch VALUES(1);",
    )
    .expect("nonstandard write");
    drop(conn);
}

#[test]
fn full_open_profile_create_reopen_and_no_plaintext_spill() {
    let _guard = test_lock();
    let cipher_log_sentinel = Path::new(env!("CARGO_MANIFEST_DIR")).join("NONE");
    assert!(
        !cipher_log_sentinel.exists(),
        "SQLCipher logging must not create a file named NONE"
    );
    let root = tempfile::tempdir().expect("tempdir");
    let temp = root.path().join("sqlite-temp");
    fs::create_dir(&temp).expect("temp probe dir");
    let path = root.path().join("profile.db");
    let proof = RavenSqlCipherFirstInstallProof::acquire(&path).expect("first install proof");
    let key = profile_key();
    let opened = RavenSqlCipherConnection::create(proof, &key).expect("create profile");
    let report = opened.report();
    assert_eq!(report.cipher_page_size, RAVEN_SQLCIPHER_PAGE_SIZE);
    assert_eq!(report.cipher_hmac_algorithm, RAVEN_SQLCIPHER_HMAC_ALGORITHM);
    assert_eq!(report.cipher_kdf_algorithm, RAVEN_SQLCIPHER_KDF_ALGORITHM);
    assert_eq!(
        report.cipher_plaintext_header_size,
        RAVEN_SQLCIPHER_APP_GROUP_PLAINTEXT_HEADER_SIZE
    );
    assert_eq!(report.journal_mode, "wal");
    assert_eq!(report.synchronous, 2);
    assert!(report.foreign_keys);
    assert_eq!(report.temp_store, 2);
    assert_eq!(report.mmap_size, 0);
    assert_eq!(report.locking_mode, "normal");
    assert_eq!(report.busy_timeout_ms, RAVEN_SQLCIPHER_BUSY_TIMEOUT_MS);

    let sentinel = b"RAVEN_0A4_HIGH_ENTROPY_6F6B2D0C8F22A1F4_61B73E090D44C938";
    opened
        .connection_for_lab()
        .execute(
            "CREATE TABLE IF NOT EXISTS raven_profile_probe(id INTEGER PRIMARY KEY, body BLOB NOT NULL)",
            [],
        )
        .expect("create table");
    opened
        .connection_for_lab()
        .execute(
            "INSERT INTO raven_profile_probe(body) VALUES (?1)",
            [sentinel.as_slice()],
        )
        .expect("insert sentinel");
    run_temp_store_probe(&opened, &temp).expect("temp store memory probe");
    opened.checkpoint_truncate().expect("checkpoint");
    scan_profile_files_for_plaintext(&path, &temp, sentinel).expect("sentinel encrypted");
    drop(opened);

    let reopened = RavenSqlCipherConnection::open_existing(&path, &key).expect("reopen profile");
    let got: Vec<u8> = reopened
        .connection_for_lab()
        .query_row("SELECT body FROM raven_profile_probe", [], |row| row.get(0))
        .expect("read sentinel");
    assert_eq!(got, sentinel);
    reopened.checkpoint_truncate().expect("reopen checkpoint");
    scan_profile_files_for_plaintext(&path, &temp, sentinel).expect("reopen remains encrypted");

    let bytes = fs::read(&path).expect("read encrypted file");
    assert!(bytes.len() >= 32);
    assert_eq!(&bytes[..16], b"SQLite format 3\0");
    assert!(
        !cipher_log_sentinel.exists(),
        "cipher_log=off must not create a disk log"
    );
}

#[test]
fn terminal_profile_uses_key_only_and_an_encrypted_header() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("terminal.db");
    let key = RavenSqlCipherRawKey::terminal(&[0x31; 32]);
    let proof = RavenSqlCipherFirstInstallProof::acquire(&path).expect("first install proof");
    let opened = RavenSqlCipherConnection::create(proof, &key).expect("terminal create");
    assert_eq!(
        opened.report().cipher_plaintext_header_size,
        RAVEN_SQLCIPHER_TERMINAL_PLAINTEXT_HEADER_SIZE
    );
    opened
        .connection_for_lab()
        .execute_batch(
            "CREATE TABLE terminal_profile(v INTEGER); INSERT INTO terminal_profile VALUES(9);",
        )
        .expect("terminal write");
    opened.checkpoint_truncate().expect("terminal checkpoint");
    drop(opened);

    let encrypted = fs::read(&path).expect("terminal bytes");
    assert_ne!(&encrypted[..16], b"SQLite format 3\0");
    let reopened = RavenSqlCipherConnection::open_existing(&path, &key).expect("terminal reopen");
    let value: i64 = reopened
        .connection_for_lab()
        .query_row("SELECT v FROM terminal_profile", [], |row| row.get(0))
        .expect("terminal read");
    assert_eq!(value, 9);
    drop(reopened);

    let before = fs::read(&path).expect("terminal before mismatch");
    let app_group_key = RavenSqlCipherRawKey::ios_app_group(&[0x31; 32], [0x41; 16]);
    assert!(RavenSqlCipherConnection::open_existing(&path, &app_group_key).is_err());
    assert_eq!(fs::read(&path).expect("terminal after mismatch"), before);
}

#[test]
fn first_install_proof_is_single_use_and_existing_open_never_creates() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("profile.db");
    let proof = RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof");
    fs::write(&path, b"occupied").expect("occupy after proof");
    let key = profile_key();
    assert!(RavenSqlCipherConnection::create(proof, &key).is_err());

    let missing = root.path().join("missing.db");
    assert!(RavenSqlCipherConnection::open_existing(&missing, &key).is_err());
    assert!(!missing.exists());
}

/// The SQLCipher profile never loads extensions: the dlopen-based code is
/// compiled out (not merely disabled per connection), so there is nothing for
/// a later caller or injected SQL to switch back on.
#[test]
fn extension_loading_is_compiled_out_of_the_sqlcipher_profile() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("noext.db");
    let key = RavenSqlCipherRawKey::terminal(&[0x88; 32]);
    let opened = RavenSqlCipherConnection::create(
        RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof"),
        &key,
    )
    .expect("create");
    let options = &opened.report().compile_options;
    assert!(
        options.iter().any(|option| option == "OMIT_LOAD_EXTENSION"),
        "compile options: {options:?}"
    );
    assert!(
        !options
            .iter()
            .any(|option| option.contains("ENABLE_LOAD_EXTENSION")),
        "compile options: {options:?}"
    );
    let error = opened
        .connection_for_lab()
        .query_row("SELECT load_extension('/nonexistent/raven')", [], |row| {
            row.get::<_, i64>(0)
        })
        .expect_err("load_extension must not exist");
    assert!(
        error.to_string().contains("no such function"),
        "unexpected error: {error}"
    );
}

/// A truncated store must not be re-initialised by `open_existing`: only
/// `create` may turn an empty file into a database.
#[test]
fn zero_byte_and_sub_page_existing_files_are_refused_without_mutation() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let terminal = RavenSqlCipherRawKey::terminal(&[0x31; 32]);
    let app_group = profile_key();
    for (key_name, key) in [("terminal", &terminal), ("app_group", &app_group)] {
        for (size, reason) in [(0usize, "empty"), (100, "short"), (4095, "short")] {
            let path = root.path().join(format!("{key_name}-{size}.db"));
            let content = vec![0xA5u8; size];
            fs::write(&path, &content).expect("fixture");
            let result = RavenSqlCipherConnection::open_existing(&path, key);
            assert!(
                matches!(&result, Err(RavenSqlCipherOpenError::PathRejected(got)) if *got == reason),
                "{key_name} {size}: expected PathRejected({reason}), got {:?}",
                result.err()
            );
            assert_eq!(fs::read(&path).expect("untouched"), content);
            for suffix in ["-wal", "-shm", "-journal"] {
                let sidecar = root.path().join(format!("{key_name}-{size}.db{suffix}"));
                assert!(!sidecar.exists(), "{key_name} {size}: {suffix} created");
            }
        }
    }
}

/// `-shm` is volatile and SQLite rebuilds it from the WAL, so an `-shm` that
/// never got its header onto disk must not make a recoverable store
/// unopenable. (A valid-looking but foreign `-shm` stays rejected: see the
/// swapped-sidecar test.)
#[test]
fn uninitialised_shm_next_to_a_valid_wal_does_not_block_reopen() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let source = root.path().join("source.db");
    let key = RavenSqlCipherRawKey::terminal(&[0x44; 32]);
    let opened = RavenSqlCipherConnection::create(
        RavenSqlCipherFirstInstallProof::acquire(&source).expect("proof"),
        &key,
    )
    .expect("create");
    opened
        .connection_for_lab()
        .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .expect("preserve wal");
    opened
        .connection_for_lab()
        .execute_batch(
            "CREATE TABLE payload(v BLOB); INSERT INTO payload VALUES(randomblob(24000));",
        )
        .expect("write wal");
    let wal = fs::read(root.path().join("source.db-wal")).expect("wal bytes");
    assert!(wal.len() > 32, "fixture needs a non-empty WAL");
    let main = fs::read(&source).expect("main bytes");
    drop(opened);

    for (name, shm) in [
        ("shm-missing", None),
        ("shm-empty", Some(Vec::new())),
        ("shm-short", Some(vec![0x5Au8; 95])),
        ("shm-zeroed", Some(vec![0u8; 32768])),
    ] {
        let path = root.path().join(format!("{name}.db"));
        fs::write(&path, &main).expect("main copy");
        fs::write(root.path().join(format!("{name}.db-wal")), &wal).expect("wal copy");
        if let Some(shm) = shm {
            fs::write(root.path().join(format!("{name}.db-shm")), shm).expect("shm fixture");
        }
        let reopened = RavenSqlCipherConnection::open_existing(&path, &key)
            .unwrap_or_else(|error| panic!("{name}: {error}"));
        let rows: i64 = reopened
            .connection_for_lab()
            .query_row("SELECT count(*) FROM payload", [], |row| row.get(0))
            .expect("recovered wal");
        assert_eq!(rows, 1, "{name}");
    }

    // Same for an empty WAL next to a header-less `-shm`.
    let path = root.path().join("empty-wal.db");
    fs::write(&path, &main).expect("main copy");
    fs::write(root.path().join("empty-wal.db-wal"), b"").expect("empty wal");
    fs::write(root.path().join("empty-wal.db-shm"), [0u8; 10]).expect("short shm");
    RavenSqlCipherConnection::open_existing(&path, &key)
        .expect("empty WAL with a header-less -shm reopens");
}

#[test]
fn checkpoint_truncate_fails_closed_while_a_reader_blocks_it() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("busy.db");
    let key = RavenSqlCipherRawKey::terminal(&[0x55; 32]);
    let writer = RavenSqlCipherConnection::create(
        RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof"),
        &key,
    )
    .expect("create");
    writer
        .connection_for_lab()
        .execute_batch("CREATE TABLE busy(v INTEGER); INSERT INTO busy VALUES(1);")
        .expect("seed");
    let reader = RavenSqlCipherConnection::open_existing(&path, &key).expect("second connection");
    reader
        .connection_for_lab()
        .execute_batch("BEGIN; SELECT count(*) FROM busy;")
        .expect("hold a read snapshot");
    writer
        .connection_for_lab()
        .execute_batch("INSERT INTO busy VALUES(2);")
        .expect("advance the WAL past the reader");
    // The 5 s profile timeout would only slow this down; the result is the same.
    writer
        .connection_for_lab()
        .busy_timeout(Duration::ZERO)
        .expect("no wait");
    assert!(
        matches!(
            writer.checkpoint_truncate(),
            Err(RavenSqlCipherOpenError::Sqlite {
                stage: "checkpoint_busy",
                ..
            })
        ),
        "a blocked checkpoint must not read as success"
    );
    reader
        .connection_for_lab()
        .execute_batch("COMMIT;")
        .expect("release the reader");
    writer
        .checkpoint_truncate()
        .expect("checkpoint succeeds once unblocked");
}

#[test]
fn plaintext_scan_fails_closed_on_unreadable_inputs() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let temp = root.path().join("temp");
    fs::create_dir(&temp).expect("temp");
    let path = root.path().join("scan.db");
    let key = RavenSqlCipherRawKey::terminal(&[0x66; 32]);
    let opened = RavenSqlCipherConnection::create(
        RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof"),
        &key,
    )
    .expect("create");
    opened.checkpoint_truncate().expect("checkpoint");
    drop(opened);
    let sentinel = b"RAVEN_SCAN_FAIL_CLOSED_SENTINEL_0123456789ABCDEF";

    scan_profile_files_for_plaintext(&path, &temp, sentinel)
        .expect("existing database, absent sidecars and an empty temp dir are a clean scan");
    assert!(matches!(
        scan_profile_files_for_plaintext(&root.path().join("absent.db"), &temp, sentinel),
        Err(RavenSqlCipherOpenError::PathRejected("scan_missing"))
    ));
    assert!(matches!(
        scan_profile_files_for_plaintext(&path, &root.path().join("absent-temp"), sentinel),
        Err(RavenSqlCipherOpenError::TempDirectoryRejected)
    ));
    // A directory where the database should be is unreadable, not "clean".
    assert!(matches!(
        scan_profile_files_for_plaintext(&temp, &temp, sentinel),
        Err(RavenSqlCipherOpenError::PathRejected("scan_read"))
    ));
    // Spill in a nested temp directory is found, not skipped as a non-file.
    let nested = temp.join("a").join("b");
    fs::create_dir_all(&nested).expect("nested temp");
    fs::write(nested.join("leak.tmp"), sentinel).expect("nested leak");
    assert!(matches!(
        scan_profile_files_for_plaintext(&path, &temp, sentinel),
        Err(RavenSqlCipherOpenError::PlaintextSentinelFound)
    ));
}

/// `cipher_memory_security` is process-global and sticky, so the order can
/// only be observed in a fresh process: a wrong-key open never reaches the
/// post-integrity step, yet the flag must already be on because it is set
/// before the key is applied.
#[test]
fn memory_security_is_enabled_before_the_key_is_applied() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("memsec.db");
    let key = RavenSqlCipherRawKey::terminal(&[0x01; 32]);
    drop(
        RavenSqlCipherConnection::create(
            RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof"),
            &key,
        )
        .expect("create"),
    );
    let executable = std::env::current_exe().expect("current test executable");
    let status = std::process::Command::new(&executable)
        .args(["--exact", "memory_security_wrong_key_helper", "--nocapture"])
        .env("RAVEN_MEMSEC_CHILD_PATH", &path)
        .status()
        .expect("spawn memory-security child");
    assert!(status.success(), "child observed memory security off");
}

#[test]
fn memory_security_wrong_key_helper() {
    let Some(path) = std::env::var_os("RAVEN_MEMSEC_CHILD_PATH") else {
        return;
    };
    let wrong_key = RavenSqlCipherRawKey::terminal(&[0x02; 32]);
    assert!(RavenSqlCipherConnection::open_existing(Path::new(&path), &wrong_key).is_err());
    let probe = rusqlite::Connection::open_in_memory().expect("probe connection");
    let state: String = probe
        .query_row("PRAGMA cipher_memory_security", [], |row| row.get(0))
        .expect("read cipher_memory_security");
    assert_eq!(state, "1", "memory security must precede the key");
}

/// macOS/iOS: plain fsync does not flush the drive cache, so durability needs
/// F_FULLFSYNC for both commits and checkpoints.
#[cfg(target_vendor = "apple")]
#[test]
fn apple_profile_requests_full_fsync_for_commits_and_checkpoints() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("fullfsync.db");
    let key = RavenSqlCipherRawKey::terminal(&[0x77; 32]);
    let opened = RavenSqlCipherConnection::create(
        RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof"),
        &key,
    )
    .expect("create");
    for pragma in ["fullfsync", "checkpoint_fullfsync"] {
        let value: i64 = opened
            .connection_for_lab()
            .query_row(&format!("PRAGMA {pragma}"), [], |row| row.get(0))
            .expect("read pragma");
        assert_eq!(value, 1, "{pragma}");
    }
    opened
        .reverify_profile_for_lab()
        .expect("reverify requires both");
}

#[test]
fn planted_empty_file_after_proof_is_refused_not_adopted() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("profile.db");
    let proof = RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof");
    // Another local process races the proof with an empty, permissive file.
    fs::write(&path, b"").expect("plant empty file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).expect("chmod");
    }
    let key = profile_key();
    assert!(matches!(
        RavenSqlCipherConnection::create(proof, &key),
        Err(raven_core::full_braid_durable_lab::RavenSqlCipherOpenError::FirstInstallProofStale)
    ));
    assert_eq!(fs::read(&path).expect("planted file untouched"), b"");
}

#[cfg(unix)]
#[test]
fn created_database_and_sidecars_are_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("profile.db");
    let proof = RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof");
    let key = profile_key();
    let opened = RavenSqlCipherConnection::create(proof, &key).expect("create");
    opened
        .connection_for_lab()
        .execute_batch("CREATE TABLE owner_only(v INTEGER); INSERT INTO owner_only VALUES(1);")
        .expect("write");
    let mode = |p: &Path| fs::metadata(p).expect("metadata").permissions().mode() & 0o777;
    assert_eq!(mode(&path), 0o600);
    for suffix in ["-wal", "-shm"] {
        let sidecar = root.path().join(format!("profile.db{suffix}"));
        assert!(sidecar.exists(), "{suffix} expected in WAL mode");
        assert_eq!(mode(&sidecar), 0o600, "{suffix}");
    }
}

#[test]
fn wrong_key_and_plaintext_database_fail_closed_without_recreation() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let path = root.path().join("encrypted.db");
    let proof = RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof");
    let key = profile_key();
    let opened = RavenSqlCipherConnection::create(proof, &key).expect("create");
    opened
        .connection_for_lab()
        .execute_batch("CREATE TABLE protected(v INTEGER); INSERT INTO protected VALUES(7);")
        .expect("write");
    opened.checkpoint_truncate().expect("checkpoint");
    drop(opened);
    let before = fs::read(&path).expect("before");

    let wrong_key = RavenSqlCipherRawKey::ios_app_group(&[0x42; 32], [0x53; 16]);
    assert!(RavenSqlCipherConnection::open_existing(&path, &wrong_key).is_err());
    assert_eq!(fs::read(&path).expect("after wrong key"), before);

    let plaintext = root.path().join("plaintext.db");
    let plain = rusqlite::Connection::open(&plaintext).expect("plain open");
    plain
        .execute_batch("CREATE TABLE plaintext(v INTEGER); INSERT INTO plaintext VALUES(1);")
        .expect("plain write");
    drop(plain);
    let plain_before = fs::read(&plaintext).expect("plain bytes");
    assert!(RavenSqlCipherConnection::open_existing(&plaintext, &key).is_err());
    assert_eq!(fs::read(&plaintext).expect("plain after"), plain_before);
}

#[test]
fn wrong_salt_and_nonstandard_cipher_profiles_are_rejected() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let good_path = root.path().join("good.db");
    let key = profile_key();
    let proof = RavenSqlCipherFirstInstallProof::acquire(&good_path).expect("proof");
    let good = RavenSqlCipherConnection::create(proof, &key).expect("good create");
    good.connection_for_lab()
        .execute_batch("CREATE TABLE ok(v INTEGER); INSERT INTO ok VALUES(1);")
        .expect("good write");
    good.checkpoint_truncate().expect("checkpoint");
    drop(good);
    let wrong_salt = RavenSqlCipherRawKey::ios_app_group(&[0x41; 32], [0x54; 16]);
    assert!(RavenSqlCipherConnection::open_existing(&good_path, &wrong_salt).is_err());

    for (name, profile) in [
        (
            "header0.db",
            "PRAGMA cipher_page_size=4096; PRAGMA cipher_hmac_algorithm=HMAC_SHA512; \
             PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512; PRAGMA cipher_use_hmac=ON; \
             PRAGMA cipher_plaintext_header_size=0;",
        ),
        (
            "page1024.db",
            "PRAGMA cipher_page_size=1024; PRAGMA cipher_hmac_algorithm=HMAC_SHA512; \
             PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512; PRAGMA cipher_use_hmac=ON; \
             PRAGMA cipher_plaintext_header_size=32;",
        ),
        (
            "hmac256.db",
            "PRAGMA cipher_page_size=4096; PRAGMA cipher_hmac_algorithm=HMAC_SHA256; \
             PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512; PRAGMA cipher_use_hmac=ON; \
             PRAGMA cipher_plaintext_header_size=32;",
        ),
        (
            "no_hmac.db",
            "PRAGMA cipher_page_size=4096; PRAGMA cipher_hmac_algorithm=HMAC_SHA512; \
             PRAGMA cipher_kdf_algorithm=PBKDF2_HMAC_SHA512; PRAGMA cipher_use_hmac=OFF; \
             PRAGMA cipher_plaintext_header_size=32;",
        ),
    ] {
        let path = root.path().join(name);
        create_nonstandard_profile(&path, profile);
        let before = fs::read(&path).expect("mismatch before");
        assert!(
            RavenSqlCipherConnection::open_existing(&path, &key).is_err(),
            "profile unexpectedly accepted: {name}"
        );
        assert_eq!(fs::read(&path).expect("mismatch after"), before, "{name}");
    }
}

#[test]
fn truncated_and_corrupt_encrypted_pages_are_rejected_without_repair() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let source = root.path().join("source.db");
    let key = profile_key();
    let proof = RavenSqlCipherFirstInstallProof::acquire(&source).expect("proof");
    let opened = RavenSqlCipherConnection::create(proof, &key).expect("create");
    opened
        .connection_for_lab()
        .execute_batch(
            "CREATE TABLE protected(v BLOB); INSERT INTO protected VALUES(randomblob(12000));",
        )
        .expect("write pages");
    opened.checkpoint_truncate().expect("checkpoint");
    drop(opened);
    let original = fs::read(&source).expect("source bytes");
    assert!(original.len() > 4096);

    let truncated = root.path().join("truncated.db");
    fs::write(&truncated, &original[..original.len() - 97]).expect("truncate fixture");
    let truncated_before = fs::read(&truncated).expect("truncated before");
    assert!(RavenSqlCipherConnection::open_existing(&truncated, &key).is_err());
    assert_eq!(
        fs::read(&truncated).expect("truncated after"),
        truncated_before
    );

    let corrupt = root.path().join("corrupt.db");
    let mut corrupted = original.clone();
    corrupted[4096 + 73] ^= 0x80;
    fs::write(&corrupt, &corrupted).expect("corrupt fixture");
    assert!(RavenSqlCipherConnection::open_existing(&corrupt, &key).is_err());
    assert_eq!(fs::read(&corrupt).expect("corrupt after"), corrupted);
}

#[cfg(unix)]
#[test]
fn symlink_relative_and_uri_paths_are_refused_before_open() {
    let _guard = test_lock();
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().expect("tempdir");
    let real = root.path().join("real.db");
    fs::write(&real, b"not a database").expect("real file");
    let link = root.path().join("link.db");
    symlink(&real, &link).expect("symlink");
    let key = profile_key();
    assert!(RavenSqlCipherConnection::open_existing(&link, &key).is_err());
    assert!(RavenSqlCipherFirstInstallProof::acquire(Path::new("relative.db")).is_err());
    assert!(RavenSqlCipherFirstInstallProof::acquire(Path::new("file:/tmp/uri.db")).is_err());
}

#[test]
fn report_compile_options_are_sorted_and_plaintext_scan_is_fail_closed() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let temp = root.path().join("temp");
    fs::create_dir(&temp).expect("temp");
    let path = root.path().join("profile.db");
    let key = profile_key();
    let proof = RavenSqlCipherFirstInstallProof::acquire(&path).expect("proof");
    let opened = RavenSqlCipherConnection::create(proof, &key).expect("create");
    assert!(opened
        .report()
        .compile_options
        .windows(2)
        .all(|pair| pair[0] <= pair[1]));
    let sentinel = b"RAVEN_0A4_SENTINEL_7B359CEAC2C0E8A2DB871C90F51D";
    fs::write(temp.join("leak.tmp"), sentinel).expect("write leak");
    assert!(scan_profile_files_for_plaintext(&path, &temp, sentinel).is_err());

    opened
        .connection_for_lab()
        .execute_batch("PRAGMA temp_store=FILE")
        .expect("weaken temp profile in lab");
    assert!(opened.reverify_profile_for_lab().is_err());
}

#[test]
fn independently_swapped_wal_and_shm_are_rejected_without_mutation() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let a = root.path().join("a.db");
    let b = root.path().join("b.db");
    let key_a = RavenSqlCipherRawKey::ios_app_group(&[0x71; 32], [0x72; 16]);
    let key_b = RavenSqlCipherRawKey::ios_app_group(&[0x81; 32], [0x82; 16]);

    let opened_a = RavenSqlCipherConnection::create(
        RavenSqlCipherFirstInstallProof::acquire(&a).expect("a proof"),
        &key_a,
    )
    .expect("create a");
    opened_a
        .connection_for_lab()
        .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .expect("preserve a wal");
    opened_a
        .connection_for_lab()
        .execute_batch(
            "CREATE TABLE payload(v BLOB); INSERT INTO payload VALUES(randomblob(24000));",
        )
        .expect("write a wal");

    let opened_b = RavenSqlCipherConnection::create(
        RavenSqlCipherFirstInstallProof::acquire(&b).expect("b proof"),
        &key_b,
    )
    .expect("create b");
    opened_b
        .connection_for_lab()
        .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .expect("preserve b wal");
    opened_b
        .connection_for_lab()
        .execute_batch(
            "CREATE TABLE payload(v BLOB); INSERT INTO payload VALUES(randomblob(26000));",
        )
        .expect("write b wal");

    fn sidecar(path: &Path, suffix: &str) -> std::path::PathBuf {
        std::path::PathBuf::from(format!("{}{}", path.display(), suffix))
    }
    fn copy_triplet(source: &Path, destination: &Path) {
        fs::copy(source, destination).expect("copy main");
        for suffix in ["-wal", "-shm"] {
            fs::copy(sidecar(source, suffix), sidecar(destination, suffix)).expect("copy sidecar");
        }
    }

    let good = root.path().join("good.db");
    let wal_swap = root.path().join("wal-swap.db");
    let shm_swap = root.path().join("shm-swap.db");
    copy_triplet(&a, &good);
    copy_triplet(&a, &wal_swap);
    copy_triplet(&a, &shm_swap);
    fs::copy(sidecar(&b, "-wal"), sidecar(&wal_swap, "-wal")).expect("swap wal");
    fs::copy(sidecar(&b, "-shm"), sidecar(&shm_swap, "-shm")).expect("swap shm");
    drop(opened_a);
    drop(opened_b);

    let good_open = RavenSqlCipherConnection::open_existing(&good, &key_a)
        .expect("consistent copied WAL/SHM reopens");
    let rows: i64 = good_open
        .connection_for_lab()
        .query_row("SELECT count(*) FROM payload", [], |row| row.get(0))
        .expect("read recovered wal");
    assert_eq!(rows, 1);

    for candidate in [&wal_swap, &shm_swap] {
        let before = [
            fs::read(candidate).expect("main before"),
            fs::read(sidecar(candidate, "-wal")).expect("wal before"),
            fs::read(sidecar(candidate, "-shm")).expect("shm before"),
        ];
        assert!(RavenSqlCipherConnection::open_existing(candidate, &key_a).is_err());
        assert_eq!(fs::read(candidate).expect("main after"), before[0]);
        assert_eq!(
            fs::read(sidecar(candidate, "-wal")).expect("wal after"),
            before[1]
        );
        assert_eq!(
            fs::read(sidecar(candidate, "-shm")).expect("shm after"),
            before[2]
        );
    }
}

#[test]
fn crash_writer_helper() {
    let Some(path) = std::env::var_os("RAVEN_0A4_CRASH_CHILD_PATH") else {
        return;
    };
    let boundary = std::env::var("RAVEN_0A4_CRASH_BOUNDARY").expect("crash boundary");
    let path = std::path::PathBuf::from(path);
    let key = RavenSqlCipherRawKey::ios_app_group(&[0x91; 32], [0x92; 16]);
    let opened = RavenSqlCipherConnection::create(
        RavenSqlCipherFirstInstallProof::acquire(&path).expect("crash proof"),
        &key,
    )
    .expect("crash fixture create");
    opened
        .connection_for_lab()
        .set_db_config(DbConfig::SQLITE_DBCONFIG_NO_CKPT_ON_CLOSE, true)
        .expect("crash wal retention");
    opened
        .connection_for_lab()
        .execute_batch("CREATE TABLE crash_probe(v INTEGER NOT NULL); PRAGMA wal_checkpoint(FULL);")
        .expect("crash fixture schema");
    match boundary.as_str() {
        "uncommitted" => opened
            .connection_for_lab()
            .execute_batch("BEGIN IMMEDIATE; INSERT INTO crash_probe VALUES(1);")
            .expect("uncommitted write"),
        "committed" => opened
            .connection_for_lab()
            .execute_batch("INSERT INTO crash_probe VALUES(1);")
            .expect("committed write"),
        "checkpointed" => opened
            .connection_for_lab()
            .execute_batch("INSERT INTO crash_probe VALUES(1); PRAGMA wal_checkpoint(FULL);")
            .expect("checkpointed write"),
        other => panic!("unknown crash boundary {other}"),
    }
    // Model SIGKILL ordering: process::exit runs no Rust destructors, so the
    // SQLCipher connection cannot checkpoint or clean WAL/SHM on close.
    std::process::exit(86);
}

#[test]
fn crash_after_transaction_boundaries_reopens_only_valid_state() {
    let _guard = test_lock();
    let root = tempfile::tempdir().expect("tempdir");
    let executable = std::env::current_exe().expect("current test executable");
    for (boundary, expected_rows) in [
        ("uncommitted", 0i64),
        ("committed", 1i64),
        ("checkpointed", 1i64),
    ] {
        let path = root.path().join(format!("crash-{boundary}.db"));
        let status = std::process::Command::new(&executable)
            .args(["--exact", "crash_writer_helper", "--nocapture"])
            .env("RAVEN_0A4_CRASH_CHILD_PATH", &path)
            .env("RAVEN_0A4_CRASH_BOUNDARY", boundary)
            .status()
            .expect("spawn crash child");
        assert_eq!(status.code(), Some(86), "boundary={boundary}");
        let key = RavenSqlCipherRawKey::ios_app_group(&[0x91; 32], [0x92; 16]);
        let reopened = RavenSqlCipherConnection::open_existing(&path, &key)
            .unwrap_or_else(|error| panic!("boundary={boundary}: {error}"));
        let rows: i64 = reopened
            .connection_for_lab()
            .query_row("SELECT count(*) FROM crash_probe", [], |row| row.get(0))
            .expect("crash recovery row count");
        assert_eq!(rows, expected_rows, "boundary={boundary}");
    }
}

/// Orchestrated by the Task 0A.4 gate between two signed Simulator phases.
/// Ignored by default so a normal Rust suite never consumes mutable App Group
/// fixtures or silently claims cross-provider coverage.
#[test]
#[ignore = "requires the signed Swift CommonCrypto interop phases"]
fn commoncrypto_openssl_reciprocal_interop_phase() {
    let _guard = test_lock();
    let directory = std::path::PathBuf::from(
        std::env::var_os("RAVEN_0A4_INTEROP_DIR").expect("RAVEN_0A4_INTEROP_DIR"),
    );
    let phase = std::env::var("RAVEN_0A4_INTEROP_PHASE").expect("RAVEN_0A4_INTEROP_PHASE");
    let swift_path = directory.join("swift-commoncrypto.db");
    let rust_path = directory.join("rust-openssl.db");
    let key = RavenSqlCipherRawKey::ios_app_group(&[0x61; 32], [0x73; 16]);
    let sentinel = b"RAVEN-0A4-HIGH-ENTROPY-SENTINEL-04f65e46b7d8803a9c0289d9c70663d9";

    match phase.as_str() {
        "rust-middle" => {
            let swift = RavenSqlCipherConnection::open_existing(&swift_path, &key)
                .expect("OpenSSL opens CommonCrypto fixture");
            let (provider, step, marker): (String, i64, Vec<u8>) = swift
                .connection_for_lab()
                .query_row("SELECT provider,step,marker FROM interop", [], |row| {
                    Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                })
                .expect("read Swift fixture");
            assert_eq!(provider, "commoncrypto");
            assert_eq!(step, 1);
            assert_eq!(marker, sentinel);
            swift
                .connection_for_lab()
                .execute("UPDATE interop SET step=2", [])
                .expect("mutate Swift fixture");
            swift
                .checkpoint_truncate()
                .expect("Swift fixture checkpoint");
            drop(swift);

            let proof = RavenSqlCipherFirstInstallProof::acquire(&rust_path)
                .expect("Rust fixture first-install proof");
            let rust = RavenSqlCipherConnection::create(proof, &key).expect("create Rust fixture");
            rust.connection_for_lab()
                .execute_batch(
                    "CREATE TABLE interop(provider TEXT NOT NULL, step INTEGER NOT NULL, marker BLOB NOT NULL);",
                )
                .expect("Rust fixture schema");
            rust.connection_for_lab()
                .execute(
                    "INSERT INTO interop(provider,step,marker) VALUES('openssl',1,?1)",
                    [sentinel.as_slice()],
                )
                .expect("Rust fixture insert");
            rust.checkpoint_truncate().expect("Rust fixture checkpoint");
            let temp = directory.join("rust-temp");
            fs::create_dir(&temp).expect("Rust temp directory");
            scan_profile_files_for_plaintext(&rust_path, &temp, sentinel)
                .expect("Rust fixture has no plaintext sentinel");
        }
        "rust-final" => {
            let swift = RavenSqlCipherConnection::open_existing(&swift_path, &key)
                .expect("reopen Swift fixture after CommonCrypto mutation");
            let swift_step: i64 = swift
                .connection_for_lab()
                .query_row("SELECT step FROM interop", [], |row| row.get(0))
                .expect("Swift final step");
            assert_eq!(swift_step, 3);

            let rust = RavenSqlCipherConnection::open_existing(&rust_path, &key)
                .expect("OpenSSL reopens its CommonCrypto-mutated fixture");
            let (step, marker): (i64, Vec<u8>) = rust
                .connection_for_lab()
                .query_row("SELECT step,marker FROM interop", [], |row| {
                    Ok((row.get(0)?, row.get(1)?))
                })
                .expect("Rust final row");
            assert_eq!(step, 2);
            assert_eq!(marker, sentinel);
        }
        other => panic!("unsupported RAVEN_0A4_INTEROP_PHASE={other}"),
    }
}

/// storage-durable#6 negative test (the "CI grep" for `ALG_PLAIN`). The lab
/// Secret Service client still opens a `plain` session instead of the audited
/// fork's DH-only session. Keep code and audit docs in sync: while any plain
/// session code exists, it must stay inside the lab, the Linux lab must stay
/// `PRODUCTION_ENABLED = false`, and the module docs must say it misses hard
/// stop #1. No other raven-core source may open a plain session.
#[test]
fn secret_service_plain_session_stays_confined_to_the_held_lab() {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let lab = src.join("full_braid_durable_lab");
    let ss_client = fs::read_to_string(lab.join("protected_anchor_linux_ss.rs")).unwrap();
    let linux_lab = fs::read_to_string(lab.join("protected_anchor_linux.rs")).unwrap();

    let plain_markers = [
        "EncryptionType::Plain",
        "ALG_PLAIN",
        "open_session(\"plain\"",
    ];
    if plain_markers
        .iter()
        .any(|marker| ss_client.contains(marker))
    {
        assert!(
            linux_lab.contains("pub const PRODUCTION_ENABLED: bool = false;"),
            "plain Secret Service session requires the Linux lab to stay production-disabled"
        );
        assert!(
            ss_client.contains("does NOT meet hard stop #1"),
            "plain-session module docs must record the hard stop #1 gap"
        );
    }

    let mut stack = vec![src.clone()];
    let mut offenders = Vec::new();
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                if path != lab {
                    stack.push(path);
                }
                continue;
            }
            if path.extension().is_some_and(|ext| ext == "rs") {
                let text = fs::read_to_string(&path).unwrap();
                if plain_markers.iter().any(|marker| text.contains(marker)) {
                    offenders.push(path.display().to_string());
                }
            }
        }
    }
    assert!(
        offenders.is_empty(),
        "plain Secret Service session outside the held lab: {offenders:?}"
    );
}
