//! Keepass data types
//!
//! A database is made up of two primary parts, a set of meta
//! information about the database itself, like the name or description
//! and a tree structure of groups and database entries. Groups can also
//! be nested within other groups.
//!
//! ## Meta information
//!
//! You can access the entire [`Meta`] struct using [`Database::meta()`].
//! For the most common information the following shortcut methods are provided:
//!
//! * [`Database::name`] / [`Database::set_name`]
//! * [`Database::description`] / [`Database::set_description`]
//!
//! ## Example operations
//!
//! ### Add a entry to the root group
//!
//! ```
//! # use kdbx_rs::database::{Database,Entry};
//! let mut database = Database::default();
//! let entry = Entry::default();
//! database.add_entry(entry);
//! ```
//!
//! ### Add a child group to the root group
//!
//! ```
//! # use kdbx_rs::database::{Database,Group};
//! let mut database = Database::default();
//! let group = Group::new("Child group");
//! database.add_group(group);
//! ```
//!
//! ### Updating a password for a given URL
//!
//! ```
//! # let mut database = kdbx_rs::database::doc_sample_db();
//! database.find_entry_mut(|f| f.url() == Some("http://example.com"))
//!     .unwrap()
//!     .set_password("password2")
//! ```
//!
//! ### Moving an entry from one folder to another
//!
//! [`Group::find_entry_mut()`] gives us a reference, while moving a folder to
//! another group requires an owned [`Entry`]. So instead we take its UUID
//! and remove it from the source group first.
//!
//! ```
//! # let mut database = kdbx_rs::database::doc_sample_db();
//! let uuid = database.find_entry_mut(|f| f.title() == Some("Foo"))
//!     .unwrap()
//!     .uuid();
//! # let mut source_group = database.root_mut();
//! let entry = source_group.remove_entry(uuid).unwrap();
//!
//! let mut target_group = database.find_group_mut(|g| g.name() == "Child Group").unwrap();
//! target_group.add_entry(entry);
//! ```

use chrono::{NaiveDateTime, Timelike};
use std::borrow::Cow;
use std::ops::{Index, IndexMut};
use uuid::Uuid;

#[doc(hidden)]
pub fn doc_sample_db() -> Database {
    let mut database = Database::default();

    let mut root_entry = Entry::default();
    root_entry.set_title("Foo");
    root_entry.set_url("http://example.com");
    root_entry.set_password("password1");

    database.add_entry(root_entry);

    let child_group = Group::new("Child Group");
    database.add_group(child_group);

    let mut child_entry = Entry::default();
    child_entry.set_title("Bar");
    child_entry.set_url("http://example.com");
    child_entry.set_password("password2");
    database
        .find_group_mut(|g: &Group| g.name == "Child Group")
        .unwrap()
        .add_entry(child_entry);

    database
}

/// A value for a `Field` stored in an `Entry`
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Value {
    /// A value using in-memory encryption
    Protected(String),
    /// A value that's unencrypted in the database
    Standard(String),
    /// A empty value
    Empty,
    /// A empty value that should be protected if filled
    ProtectEmpty,
}

impl Default for Value {
    fn default() -> Value {
        Value::Empty
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// A key value pair
pub struct Field {
    /// The name of this field
    pub(crate) key: String,
    /// The (optionally encrypted) value of this field
    pub(crate) value: Value,
}

impl Field {
    /// Create a new field without memory protection
    pub fn new(key: &str, value: &str) -> Field {
        Field {
            key: key.to_string(),
            value: Value::Standard(value.to_string()),
        }
    }

    /// Create a new field without memory protection
    pub fn new_protected(key: &str, value: &str) -> Field {
        Field {
            key: key.to_string(),
            value: Value::Protected(value.to_string()),
        }
    }

    /// Key for this field
    pub fn key(&self) -> &str {
        &self.key
    }

    /// Set a new key for this field
    pub fn set_key(&mut self, new_key: &str) {
        self.key = new_key.to_string();
    }

    /// Value for this field
    pub fn value(&self) -> Option<&str> {
        match self.value {
            Value::Protected(ref s) => Some(s),
            Value::Standard(ref s) => Some(s),
            _ => None,
        }
    }

    /// Set a new value for this field
    pub fn set_value(&mut self, value: &str) {
        if self.protected() {
            self.value = Value::Protected(value.to_string());
        } else {
            self.value = Value::Standard(value.to_string());
        }
    }

    /// Empty out the field stored in this value
    pub fn clear(&mut self) {
        if self.protected() {
            self.value = Value::ProtectEmpty;
        } else {
            self.value = Value::Empty;
        }
    }

    /// Get whether memory protection and extra encryption should be applied
    ///
    /// Note: This is instructional for official clients, this library does not
    /// support memory protection
    pub fn protected(&self) -> bool {
        matches!(self.value, Value::Protected(_))
    }

    /// Set whether memory protection and extra encryption should be applied
    ///
    /// Note: This is instructional for official clients, this library does not
    /// support memory protection
    pub fn set_protected(&mut self, protected: bool) {
        let existing_value = std::mem::take(&mut self.value);
        self.value = match (protected, existing_value) {
            (true, Value::Standard(s)) => Value::Protected(s),
            (false, Value::Protected(s)) => Value::Standard(s),
            (true, Value::Empty) => Value::ProtectEmpty,
            (false, Value::ProtectEmpty) => Value::Empty,
            (_, v) => v,
        }
    }
}

/// Historical versions of a single entry
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct History {
    entries: Vec<Entry>,
}

impl History {
    /// Get a history entry by its index
    pub fn get(&self, index: usize) -> Option<&Entry> {
        self.entries.get(index)
    }

    /// Get a history entry mutably by its index
    pub fn get_mut(&mut self, index: usize) -> Option<&mut Entry> {
        self.entries.get_mut(index)
    }

    /// Add a new version of an entry to the history
    pub fn push(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    /// Count of entries in this history
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Count of entries in this history
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Remove a historical version by index
    pub fn remove(&mut self, idx: usize) -> Entry {
        self.entries.remove(idx)
    }

    /// Iterate over all historical entries
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    /// Iterate mutably over all historical entries
    pub fn entries_mut(&mut self) -> impl Iterator<Item = &mut Entry> {
        self.entries.iter_mut()
    }
}

impl Index<usize> for History {
    type Output = Entry;
    fn index(&self, index: usize) -> &Self::Output {
        self.get(index).unwrap()
    }
}

impl IndexMut<usize> for History {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        self.get_mut(index).unwrap()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A single password entry
pub struct Entry {
    /// Identifier for this entry
    uuid: Uuid,
    /// Key-value pairs of current data for this entry
    fields: Vec<Field>,
    /// Previous versions of this entry
    pub(crate) history: History,
    /// Information about access times
    pub(crate) times: Times,
}

impl Entry {
    /// Add a new field to the entry
    pub fn add_field(&mut self, field: Field) {
        self.fields.push(field);
    }

    /// Remove a field by its key
    ///
    /// If there are duplicate fields, removes them all
    pub fn remove_field(&mut self, key: &str) {
        let mut matching_field_indices: Vec<_> = self
            .fields
            .iter()
            .enumerate()
            .filter_map(|(idx, field)| if field.key == key { Some(idx) } else { None })
            .collect();
        matching_field_indices.sort();
        matching_field_indices.reverse();
        for index in matching_field_indices {
            self.fields.remove(index);
        }
    }

    /// Generate a new version of this entry, pushing the current state to history
    pub fn new_version(&mut self) {
        let mut new_entry = self.clone();
        new_entry.history = History::default();
        self.history.push(new_entry);
    }

    /// Iterate through all the fields
    pub fn fields(&self) -> impl Iterator<Item = &Field> {
        self.fields.iter()
    }

    /// Iterate through all the field mutably
    pub fn fields_mut(&mut self) -> impl Iterator<Item = &mut Field> {
        self.fields.iter_mut()
    }

    /// History for this entry
    pub fn history(&self) -> &History {
        &self.history
    }

    /// Mutable history for this entry
    pub fn history_mut(&mut self) -> &mut History {
        &mut self.history
    }

    /// Find a field in this entry with a given key
    pub fn find(&self, key: &str) -> Option<&Field> {
        self.fields.iter().find(|i| i.key.as_str() == key)
    }

    /// Find a field in this entry with a given key
    pub fn find_mut(&mut self, key: &str) -> Option<&mut Field> {
        self.fields.iter_mut().find(|i| i.key.as_str() == key)
    }

    /// Audit times for this entry
    pub fn times(&self) -> &Times {
        &self.times
    }

    /// Mutable audit times for this entry
    pub fn times_mut(&mut self) -> &mut Times {
        &mut self.times
    }

    fn find_string_value(&self, key: &str) -> Option<&str> {
        self.find(key).and_then(|f| f.value())
    }

    /// Set the identifier for this item
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// Get the identifier for this item
    pub fn set_uuid(&mut self, uuid: Uuid) {
        self.uuid = uuid;
    }

    /// Return the title of this item
    pub fn title(&self) -> Option<&str> {
        self.find_string_value("Title")
    }

    /// Set the title of this entry
    pub fn set_title<S: ToString>(&mut self, title: S) {
        let title = title.to_string();
        match self.find_mut("Title") {
            Some(f) => f.value = Value::Standard(title),
            None => self.fields.push(Field::new("Title", &title)),
        }
    }

    /// Return the username of this item
    pub fn username(&self) -> Option<&str> {
        self.find_string_value("UserName")
    }

    /// Set the username of this entry
    pub fn set_username<S: ToString>(&mut self, username: S) {
        let username = username.to_string();
        match self.find_mut("UserName") {
            Some(f) => f.value = Value::Standard(username),
            None => self.fields.push(Field::new("UserName", &username)),
        }
    }

    /// Return the URL of this item
    pub fn url(&self) -> Option<&str> {
        self.find_string_value("URL")
    }

    /// Set the URL of this entry
    pub fn set_url<S: ToString>(&mut self, url: S) {
        let url = url.to_string();
        match self.find_mut("URL") {
            Some(f) => f.value = Value::Standard(url),
            None => self.fields.push(Field::new("URL", &url)),
        }
    }

    /// Return the TOTP of this item, as stored by KeepassXC
    pub fn otp(&self) -> Option<Otp> {
        self.find_string_value("otp").map(|url| Otp {
            url: Cow::Borrowed(url),
        })
    }

    /// Return the TOTP of this item, as stored by KeepassXC
    pub fn set_otp(&mut self, otp: Otp) {
        match self.find_mut("otp") {
            Some(f) => f.value = Value::Protected(otp.url.to_string()),
            None => self
                .fields
                .push(Field::new_protected("otp", otp.url.as_ref())),
        }
    }

    /// Return the password of this item
    pub fn password(&self) -> Option<&str> {
        self.find_string_value("Password")
    }

    /// Set the password of this entry
    pub fn set_password<S: ToString>(&mut self, password: S) {
        let password = password.to_string();
        match self.find_mut("Password") {
            Some(f) => f.value = Value::Protected(password),
            None => self
                .fields
                .push(Field::new_protected("Password", &password)),
        }
    }
}

impl Default for Entry {
    fn default() -> Entry {
        Entry {
            uuid: Uuid::new_v4(),
            fields: Vec::new(),
            history: History::default(),
            times: Times::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A group or folder of password entries and child groups
pub struct Group {
    /// Identifier for this group
    uuid: Uuid,
    /// Name of this group
    name: String,
    /// Password items within this group
    entries: Vec<Entry>,
    /// Subfolders of this group
    groups: Vec<Group>,
    /// Access times for this group
    pub(crate) times: Times,
}

impl Group {
    /// Create a new group with the given name
    pub fn new<S: ToString>(name: S) -> Group {
        Group {
            uuid: Uuid::new_v4(),
            name: name.to_string(),
            entries: Vec::new(),
            groups: Vec::new(),
            times: Times::default(),
        }
    }

    /// Identifier for this group
    pub fn uuid(&self) -> Uuid {
        self.uuid
    }

    /// Set identifier for this group
    pub fn set_uuid(&mut self, uuid: Uuid) {
        self.uuid = uuid
    }

    /// Display name for this group
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Set display name for this group
    pub fn set_name<S: ToString>(&mut self, name: S) {
        self.name = name.to_string();
    }

    /// Add a new entry to this group
    pub fn add_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    /// Remove an entry by its UUID
    ///
    /// This is a no-op if the no direct child of this group has the
    /// given UUID
    pub fn remove_entry(&mut self, uuid: Uuid) -> Option<Entry> {
        let index = self
            .entries
            .iter()
            .enumerate()
            .find(|(_, entry)| entry.uuid() == uuid)
            .map(|(index, _)| index);

        if let Some(index) = index {
            Some(self.entries.remove(index))
        } else {
            None
        }
    }

    /// Add a new child group to this group
    pub fn add_group(&mut self, group: Group) {
        self.groups.push(group);
    }

    /// Remove an child group by its UUID
    ///
    /// This is a no-op if the no direct child of this group has the
    /// given UUID
    pub fn remove_group(&mut self, uuid: Uuid) -> Option<Group> {
        let index = self
            .groups
            .iter()
            .enumerate()
            .find(|(_, group)| group.uuid() == uuid)
            .map(|(index, _)| index);

        if let Some(index) = index {
            Some(self.groups.remove(index))
        } else {
            None
        }
    }

    /// Iterate through all the direct child groups of this group
    pub fn groups(&self) -> impl Iterator<Item = &Group> {
        self.groups.iter()
    }

    /// Iterate mutably through all the direct child groups of this group
    pub fn groups_mut(&mut self) -> impl Iterator<Item = &mut Group> {
        self.groups.iter_mut()
    }

    /// Count of direct child groups of this group
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }

    /// Count of direct entries of this group
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    /// Iterate through all the direct entries of this group
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.iter()
    }

    /// Iterate mutably through all the direct entries of this group
    pub fn entries_mut(&mut self) -> impl Iterator<Item = &mut Entry> {
        self.entries.iter_mut()
    }

    /// Iterator through all entries in this group or children
    pub fn recursive_entries<'a>(&'a self) -> Box<dyn Iterator<Item = &Entry> + 'a> {
        Box::new(
            self.groups
                .iter()
                .flat_map(|c| c.recursive_entries())
                .chain(self.entries.iter()),
        )
    }

    /// Mutable Iterator through all entries in this group or children
    pub fn recursive_entries_mut<'a>(&'a mut self) -> Box<dyn Iterator<Item = &mut Entry> + 'a> {
        Box::new(
            self.groups
                .iter_mut()
                .flat_map(|c| c.recursive_entries_mut())
                .chain(self.entries.iter_mut()),
        )
    }

    /// Iterator through all child groups of this group
    pub fn recursive_groups<'a>(&'a self) -> Box<dyn Iterator<Item = &Group> + 'a> {
        Box::new(
            self.groups
                .iter()
                .flat_map(|g| g.recursive_groups())
                .chain(self.groups.iter()),
        )
    }

    /// Find a group in this group's children or it's children's children
    pub fn find_group<F: FnMut(&Group) -> bool>(&self, mut f: F) -> Option<&Group> {
        self.find_group_internal(&mut f)
    }

    fn find_group_internal<F: FnMut(&Group) -> bool>(&self, f: &mut F) -> Option<&Group> {
        for group in self.groups() {
            if f(group) {
                return Some(group);
            } else if let Some(g) = group.find_group_internal(f) {
                return Some(g);
            }
        }
        None
    }

    /// Find a mutable group in this group's children or it's children's children
    pub fn find_group_mut<F: FnMut(&Group) -> bool>(&mut self, mut f: F) -> Option<&mut Group> {
        self.find_group_mut_internal(&mut f)
    }

    fn find_group_mut_internal<F: FnMut(&Group) -> bool>(
        &mut self,
        f: &mut F,
    ) -> Option<&mut Group> {
        for group in self.groups_mut() {
            if f(group) {
                return Some(group);
            } else if let Some(g) = group.find_group_mut_internal(f) {
                return Some(g);
            }
        }
        None
    }

    /// Find a entry in this group's children or it's children's children
    pub fn find_entry<F: FnMut(&Entry) -> bool>(&self, mut f: F) -> Option<&Entry> {
        self.find_entry_internal(&mut f)
    }

    fn find_entry_internal<F: FnMut(&Entry) -> bool>(&self, f: &mut F) -> Option<&Entry> {
        for entry in self.entries() {
            if f(entry) {
                return Some(entry);
            }
        }
        for group in self.groups() {
            if let Some(e) = group.find_entry_internal(f) {
                return Some(e);
            }
        }
        None
    }

    /// Find a mutable entry in this group's children or it's children's children
    pub fn find_entry_mut<F: FnMut(&Entry) -> bool>(&mut self, mut f: F) -> Option<&mut Entry> {
        self.find_entry_mut_internal(&mut f)
    }

    fn find_entry_mut_internal<F: FnMut(&Entry) -> bool>(
        &mut self,
        f: &mut F,
    ) -> Option<&mut Entry> {
        let found_in_entries = self
            .entries()
            .enumerate()
            .find(|(_, e)| f(e))
            .map(|(idx, _)| idx);

        if let Some(idx) = found_in_entries {
            return Some(&mut self.entries[idx]);
        } else {
            for group in self.groups_mut() {
                if let Some(e) = group.find_entry_mut_internal(f) {
                    return Some(e);
                }
            }
        }
        None
    }

    /// Audit times for this group
    pub fn times(&self) -> &Times {
        &self.times
    }

    /// Mutable audit times for this group
    pub fn times_mut(&mut self) -> &mut Times {
        &mut self.times
    }
}

impl Default for Group {
    fn default() -> Group {
        Group {
            uuid: Uuid::new_v4(),
            name: String::new(),
            entries: Vec::new(),
            groups: Vec::new(),
            times: Times::default(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// Identifies which fields are encrypted in memory for official clients
pub struct MemoryProtection {
    /// Whether title fields should be encrypted
    pub protect_title: bool,
    /// Whether username fields should be encrypted
    pub protect_user_name: bool,
    /// Whether password fields should be encrypted
    pub protect_password: bool,
    /// Whether URL fields should be encrypted
    pub protect_url: bool,
    /// Whether Notes fields should be encrypted
    pub protect_notes: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// Meta information about this database
pub struct Meta {
    /// Application used to generate this database
    pub generator: String,
    /// Short name for the database
    pub database_name: String,
    /// Longer description of the database
    pub database_description: String,
    /// Non standard information from plugins and other clients
    pub custom_data: Vec<Field>,
    /// Memory protection configuration for this client
    pub memory_protection: MemoryProtection,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Audit times for this item
pub struct Times {
    /// Time last edited
    pub last_modification_time: NaiveDateTime,
    /// Time created
    pub creation_time: NaiveDateTime,
    /// Time last accessed
    pub last_access_time: NaiveDateTime,
    /// Time at which this password needs rotation
    pub expiry_time: NaiveDateTime,
    /// Time at which this password was last moved within the database
    pub location_changed: NaiveDateTime,
    /// Whether this password expires
    pub expires: bool,
    /// Count of usages with autofill functions
    pub usage_count: u32,
}

impl Default for Times {
    fn default() -> Times {
        let now = chrono::Local::now()
            .naive_local()
            .with_nanosecond(0)
            .unwrap();
        Times {
            expires: false,
            usage_count: 0,
            last_modification_time: now,
            creation_time: now,
            last_access_time: now,
            expiry_time: now,
            location_changed: now,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Decrypted password database
///
/// See the [module-level documentation][crate::database] for more information.
pub struct Database {
    /// Meta information about this database
    pub(crate) meta: Meta,
    /// Trees of items in this database
    pub(crate) groups: Vec<Group>,
}

impl Default for Database {
    fn default() -> Self {
        let root = Group::new("Root");
        Database {
            meta: Meta::default(),
            groups: vec![root],
        }
    }
}

impl Database {
    /// Return meta information about the database like name and access times
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// Mutable meta information about the database like name and access times
    pub fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }

    /// Get the database name
    pub fn name(&self) -> &str {
        &self.meta.database_name
    }

    /// Set the database name
    pub fn set_name<S: ToString>(&mut self, name: S) {
        self.meta.database_name = name.to_string();
    }

    /// Get the database description
    pub fn description(&self) -> &str {
        &self.meta.database_description
    }

    /// Set the database name
    pub fn set_description<S: ToString>(&mut self, desc: S) {
        self.meta.database_description = desc.to_string();
    }

    /// Add a entry to the root group
    pub fn add_entry(&mut self, entry: Entry) {
        self.groups[0].entries.push(entry);
    }

    /// Add a child group to the root group
    pub fn add_group(&mut self, entry: Group) {
        self.groups[0].groups.push(entry);
    }

    /// Replace the root group (and therefore all entries!) with a custom tree
    pub fn replace_root(&mut self, group: Group) {
        self.groups = vec![group];
    }

    /// Recursively searches for the first group matching a filter
    pub fn find_group<F: FnMut(&Group) -> bool>(&self, f: F) -> Option<&Group> {
        self.root().find_group(f)
    }

    /// Recursively searches for the first group matching a filter, returns it mutably
    pub fn find_group_mut<F: FnMut(&Group) -> bool>(&mut self, f: F) -> Option<&mut Group> {
        self.root_mut().find_group_mut(f)
    }

    /// Recursively searches for the first entry matching a filter
    pub fn find_entry<F: FnMut(&Entry) -> bool>(&self, f: F) -> Option<&Entry> {
        self.root().find_entry(f)
    }

    /// Recursively searches for the first entry matching a filter, returns it mutably
    pub fn find_entry_mut<F: FnMut(&Entry) -> bool>(&mut self, f: F) -> Option<&mut Entry> {
        self.root_mut().find_entry_mut(f)
    }

    /// Top level group for database entries
    pub fn root(&self) -> &Group {
        &self.groups[0]
    }

    /// Mutable top level group for database entries
    pub fn root_mut(&mut self) -> &mut Group {
        &mut self.groups[0]
    }
}

/// TOTP one time password secret in KeepassXC format
pub struct Otp<'a> {
    url: Cow<'a, str>,
}

impl<'a> Otp<'a> {
    /// Create a new OTP password from the given details
    pub fn new<S: ToString>(secret: S, period: u32, digits: u32) -> Otp<'static> {
        let url = format!(
            "otpauth://totp/kdbxrs:kdbxrs?secret={}&period={}&digits={}",
            secret.to_string(),
            period,
            digits
        );
        Otp {
            url: Cow::Owned(url),
        }
    }

    fn find_url_param(&self, key: &str) -> Option<&str> {
        let mut parts = self.url.split('?');
        let _path = parts.next()?;
        let params = parts.next()?;
        let params = params.split('&');

        for param in params {
            let mut param_parts = param.split('=');
            let pkey = param_parts.next()?;
            if pkey == key {
                return param_parts.next();
            }
        }
        None
    }

    /// Retrieve the secret used to generate one time passwords
    pub fn secret(&self) -> Option<&str> {
        self.find_url_param("secret")
    }

    /// Return the period for which passwords are valid
    pub fn period(&self) -> Option<u32> {
        self.find_url_param("secret").and_then(|p| p.parse().ok())
    }

    /// Return the number of digits in the resulting code
    pub fn digits(&self) -> Option<u32> {
        self.find_url_param("digits").and_then(|p| p.parse().ok())
    }
}
