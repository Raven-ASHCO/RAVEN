//! No-prompt Secret Service client for Task 0B.3 (lab-only).
//!
//! Opens a **plain** session: the installation seed and RVFA1 anchors cross
//! the per-user session bus unencrypted. That is acceptable only because this
//! module is lab-only (`PRODUCTION_ENABLED = false`, release builds held); it
//! does NOT meet hard stop #1 of the audited no-prompt fork (negotiate
//! `dh-ietf1024-sha256-aes128-cbc-pkcs7`, never `plain`). Any R1/production
//! use must replace this client with a DH-session implementation first.
//! CreateItem/Delete that return a prompt path map to
//! `LockedOrPromptRequired` without calling `Prompt.Prompt`.
//! Only the existing unlocked default collection is used (no create_collection).
//! Secret buffers are zeroized on drop and never printed via `Debug`.

#![cfg(all(target_os = "linux", target_env = "gnu"))]

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zbus::dbus_proxy;
use zeroize::{Zeroize, Zeroizing};
use zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zvariant_derive::Type;

const SS_NAME: &str = "org.freedesktop.secrets";
const SS_ITEM_LABEL: &str = "org.freedesktop.Secret.Item.Label";
const SS_ITEM_ATTRIBUTES: &str = "org.freedesktop.Secret.Item.Attributes";
const ALG_PLAIN: &str = "plain";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NopromptError {
    Unavailable,
    LockedOrPromptRequired,
    Capacity,
    Io,
    /// The default collection is one the seed and anchors would not survive
    /// logout in (see [`is_volatile_collection_path`]).
    VolatileCollection,
}

#[derive(Serialize, Deserialize, Type)]
struct SecretStruct {
    session: OwnedObjectPath,
    parameters: Vec<u8>,
    value: Vec<u8>,
    content_type: String,
}

impl Drop for SecretStruct {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl std::fmt::Debug for SecretStruct {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecretStruct")
            .field("session", &self.session)
            .field("value", &"<redacted>")
            .field("content_type", &self.content_type)
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize, Type)]
struct OpenSessionResult {
    output: OwnedValue,
    result: OwnedObjectPath,
}

#[derive(Debug, Serialize, Deserialize, Type)]
struct SearchItemsResult {
    unlocked: Vec<OwnedObjectPath>,
    locked: Vec<OwnedObjectPath>,
}

#[derive(Debug, Serialize, Deserialize, Type)]
struct CreateItemResult {
    item: OwnedObjectPath,
    prompt: OwnedObjectPath,
}

#[dbus_proxy(
    interface = "org.freedesktop.Secret.Service",
    default_service = "org.freedesktop.secrets",
    default_path = "/org/freedesktop/secrets"
)]
trait Service {
    fn open_session(&self, algorithm: &str, input: Value<'_>) -> zbus::Result<OpenSessionResult>;
    fn read_alias(&self, name: &str) -> zbus::Result<OwnedObjectPath>;
    fn search_items(&self, attributes: HashMap<&str, &str>) -> zbus::Result<SearchItemsResult>;
}

#[dbus_proxy(
    interface = "org.freedesktop.Secret.Collection",
    default_service = "org.freedesktop.secrets"
)]
trait Collection {
    fn create_item(
        &self,
        properties: HashMap<&str, Value<'_>>,
        secret: SecretStruct,
        replace: bool,
    ) -> zbus::Result<CreateItemResult>;
    #[dbus_proxy(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;
}

#[dbus_proxy(
    interface = "org.freedesktop.Secret.Item",
    default_service = "org.freedesktop.secrets"
)]
trait Item {
    fn delete(&self) -> zbus::Result<OwnedObjectPath>;
    fn get_secret(&self, session: &ObjectPath<'_>) -> zbus::Result<SecretStruct>;
    #[dbus_proxy(property)]
    fn locked(&self) -> zbus::fdo::Result<bool>;
    #[dbus_proxy(property)]
    fn attributes(&self) -> zbus::fdo::Result<HashMap<String, String>>;
    #[dbus_proxy(property)]
    fn label(&self) -> zbus::fdo::Result<String>;
}

pub struct NopromptSs {
    conn: zbus::Connection,
    session_path: OwnedObjectPath,
    default_collection: OwnedObjectPath,
}

impl NopromptSs {
    pub fn connect() -> Result<Self, NopromptError> {
        let conn = zbus::Connection::new_session().map_err(|_| NopromptError::Unavailable)?;
        let service = ServiceProxy::new(&conn).map_err(|_| NopromptError::Unavailable)?;
        let session = service
            .open_session(ALG_PLAIN, Value::from(""))
            .map_err(map_connect_err)?;
        let default_collection = service
            .read_alias("default")
            .map_err(|_| NopromptError::Unavailable)?;
        if default_collection.as_str() == "/" {
            return Err(NopromptError::Unavailable);
        }
        if is_volatile_collection_path(default_collection.as_str()) {
            return Err(NopromptError::VolatileCollection);
        }
        let coll = CollectionProxy::new_for(&conn, SS_NAME, default_collection.as_str())
            .map_err(|_| NopromptError::Unavailable)?;
        match coll.locked() {
            Ok(true) => return Err(NopromptError::LockedOrPromptRequired),
            Ok(false) => {}
            Err(_) => return Err(NopromptError::Unavailable),
        }
        Ok(Self {
            conn,
            session_path: session.result,
            default_collection,
        })
    }

    pub fn default_collection_path(&self) -> &str {
        self.default_collection.as_str()
    }

    pub fn search(
        &self,
        attrs: HashMap<&str, &str>,
    ) -> Result<Vec<OwnedObjectPath>, NopromptError> {
        let service = ServiceProxy::new(&self.conn).map_err(|_| NopromptError::Unavailable)?;
        let res = service.search_items(attrs).map_err(map_connect_err)?;
        if !res.locked.is_empty() {
            return Err(NopromptError::LockedOrPromptRequired);
        }
        Ok(res.unlocked)
    }

    pub fn item_locked(&self, path: &str) -> Result<bool, NopromptError> {
        let item = ItemProxy::new_for(&self.conn, SS_NAME, path).map_err(|_| NopromptError::Io)?;
        item.locked().map_err(|_| NopromptError::Io)
    }

    pub fn item_label(&self, path: &str) -> Result<String, NopromptError> {
        let item = ItemProxy::new_for(&self.conn, SS_NAME, path).map_err(|_| NopromptError::Io)?;
        item.label().map_err(|_| NopromptError::Io)
    }

    pub fn item_attributes(&self, path: &str) -> Result<HashMap<String, String>, NopromptError> {
        let item = ItemProxy::new_for(&self.conn, SS_NAME, path).map_err(|_| NopromptError::Io)?;
        item.attributes().map_err(|_| NopromptError::Io)
    }

    pub fn item_secret(&self, path: &str) -> Result<(Zeroizing<Vec<u8>>, String), NopromptError> {
        let item = ItemProxy::new_for(&self.conn, SS_NAME, path).map_err(|_| NopromptError::Io)?;
        if item.locked().map_err(|_| NopromptError::Io)? {
            return Err(NopromptError::LockedOrPromptRequired);
        }
        let mut secret = item
            .get_secret(&self.session_path)
            .map_err(map_connect_err)?;
        let value = Zeroizing::new(std::mem::take(&mut secret.value));
        Ok((value, std::mem::take(&mut secret.content_type)))
    }

    /// CreateItem (`replace=false`). Never executes Prompt.
    pub fn create_item_noprompt(
        &self,
        label: &str,
        attributes: HashMap<&str, &str>,
        secret: &[u8],
        content_type: &str,
    ) -> Result<OwnedObjectPath, NopromptError> {
        let coll = CollectionProxy::new_for(&self.conn, SS_NAME, self.default_collection.as_str())
            .map_err(|_| NopromptError::Io)?;
        match coll.locked() {
            Ok(true) => return Err(NopromptError::LockedOrPromptRequired),
            Ok(false) => {}
            Err(_) => return Err(NopromptError::Unavailable),
        }

        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert(SS_ITEM_LABEL, Value::from(label));
        properties.insert(SS_ITEM_ATTRIBUTES, Value::from(attributes));

        // Zeroized on drop once CreateItem has serialized it.
        let secret_struct = SecretStruct {
            session: self.session_path.clone(),
            parameters: Vec::new(),
            value: secret.to_vec(),
            content_type: content_type.to_string(),
        };
        let created = coll
            .create_item(properties, secret_struct, false)
            .map_err(map_mutate_err)?;
        if created.item.as_str() == "/" || created.prompt.as_str() != "/" {
            return Err(NopromptError::LockedOrPromptRequired);
        }
        Ok(created.item)
    }

    /// Item.Delete without Prompt.Prompt.
    pub fn delete_item_noprompt(&self, path: &str) -> Result<(), NopromptError> {
        let item = ItemProxy::new_for(&self.conn, SS_NAME, path).map_err(|_| NopromptError::Io)?;
        match item.locked() {
            Ok(true) => return Err(NopromptError::LockedOrPromptRequired),
            Ok(false) => {}
            Err(_) => return Err(NopromptError::Io),
        }
        let prompt = item.delete().map_err(map_mutate_err)?;
        if prompt.as_str() != "/" {
            return Err(NopromptError::LockedOrPromptRequired);
        }
        Ok(())
    }
}

/// gnome-keyring's in-memory `session` collection is the one volatile
/// collection recognisable from its path: a seed or anchor stored there
/// vanishes at logout while the SQLCipher store it protects stays on disk.
/// The Secret Service spec exposes no persistence attribute, so persistence of
/// any other default collection remains an unverified provider assumption.
fn is_volatile_collection_path(path: &str) -> bool {
    path.rsplit('/').next() == Some("session")
}

fn map_connect_err(err: zbus::Error) -> NopromptError {
    let msg = err.to_string();
    if msg.contains("NoSpace") || msg.contains("ENOSPC") {
        NopromptError::Capacity
    } else if msg.contains("Locked") || msg.contains("Prompt") || msg.contains("prompt") {
        NopromptError::LockedOrPromptRequired
    } else {
        NopromptError::Unavailable
    }
}

fn map_mutate_err(err: zbus::Error) -> NopromptError {
    let msg = err.to_string();
    if msg.contains("NoSpace") || msg.contains("ENOSPC") || msg.contains("NoMemory") {
        NopromptError::Capacity
    } else if msg.contains("Locked") || msg.contains("Prompt") || msg.contains("prompt") {
        NopromptError::LockedOrPromptRequired
    } else {
        NopromptError::Io
    }
}

#[cfg(test)]
mod tests {
    use super::is_volatile_collection_path;

    #[test]
    fn only_the_session_collection_is_volatile() {
        assert!(is_volatile_collection_path(
            "/org/freedesktop/secrets/collection/session"
        ));
        for path in [
            "/org/freedesktop/secrets/collection/login",
            "/org/freedesktop/secrets/collection/Default_keyring",
            "/org/freedesktop/secrets/collection/my_session",
            "/org/freedesktop/secrets/collection/session/12",
            "/org/freedesktop/secrets/aliases/default",
        ] {
            assert!(!is_volatile_collection_path(path), "{path}");
        }
    }
}
