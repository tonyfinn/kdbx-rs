//! Keepass data types

use chrono::{NaiveDateTime,Timelike};
use uuid::Uuid;

/// A value for a `Field` stored in an `Entry`
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// A value using in-memory encryption
    Protected(String),
    /// A value that's unencrypted in the database
    Standard(String),
    /// A empty value
    Empty,
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
    pub key: String,
    /// The (optionally encrypted) value of this field
    pub value: Value,
}

impl Field {
    /// Create a new field without memory protection
    pub fn new(key: &str, value: &str) -> Field {
        Field {
            key: key.to_string(),
            value: Value::Standard(value.to_string()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A single password entry
pub struct Entry {
    /// Identifier for this entry
    pub uuid: Uuid,
    /// Key-value pairs of current data for this entry
    pub fields: Vec<Field>,
    /// Previous versions of this entry
    pub history: Vec<Entry>,
    /// Information about access times
    pub times: Times,
}

impl Entry {
    /// Add a new field to the entry
    pub fn add_field(&mut self, field: Field) {
        self.fields.push(field);
    }

    /// Find a field in this entry with a given key
    pub fn find(&self, key: &str) -> Option<&Field> {
        self.fields.iter()
            .find(|i| i.key.as_str() == key)

    }

    /// Find a field in this entry with a given key
    pub fn find_mut(&mut self, key: &str) -> Option<&mut Field> {
        self.fields.iter_mut()
            .find(|i| i.key.as_str() == key)
    }

    fn find_string_value(&self, key: &str) -> Option<&str> {
        self.find(key).and_then(|f| match &f.value {
            Value::Empty => None,
            Value::Standard(s) => Some(s.as_ref()),
            Value::Protected(p) => Some(p.as_ref()),
        })
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
            None => self.fields.push(Field::new("Title", &title))
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
            None => self.fields.push(Field::new("UserName", &username))
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
            None => self.fields.push(Field::new("URL", &url))
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
            Some(f) => f.value = Value::Standard(password),
            None => self.fields.push(Field::new("Password", &password))
        }
    }
}

impl Default for Entry {
    fn default() -> Entry {
        Entry {
            uuid: Uuid::new_v4(),
            fields: Vec::new(),
            history: Vec::new(),
            times: Times::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A group or folder of password entries and child groups
pub struct Group {
    /// Identifier for this group
    pub uuid: Uuid,
    /// Name of this group
    pub name: String,
    /// Password items within this group
    pub entries: Vec<Entry>,
    /// Subfolders of this group
    pub children: Vec<Group>,
    /// Access times for this group
    pub times: Times,
}

impl Group {
    /// Add a new entry to this group
    pub fn add_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
    }
}

impl Default for Group {
    fn default() -> Group {
        Group {
            uuid: Uuid::new_v4(),
            name: String::new(),
            entries: Vec::new(),
            children: Vec::new(),
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
        let now = chrono::Local::now().naive_local().with_nanosecond(0).unwrap();
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// Decrypted database structure
pub struct Database {
    /// Meta information about this database
    pub meta: Meta,
    /// Trees of items in this database
    pub groups: Vec<Group>,
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
    ///
    /// Creates a root group if none exist
    pub fn add_entry(&mut self, entry: Entry) {
        if self.groups.len() == 0 {
            self.groups.push(Group::default());
        }
        self.groups[0].entries.push(entry);
    }

    /// Top level group for database entries
    pub fn root(&self) -> Option<&Group> {
        self.groups.get(0)
    }

    /// Mutable top level group for database entries
    pub fn root_mut(&mut self) -> Option<&mut Group> {
        self.groups.get_mut(0)
    }
}