use chrono::NaiveDateTime;
use uuid::Uuid;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// A key value pair
pub struct Field {
    /// The name of this field
    pub key: String,
    /// The (optionally encrypted) value of this field
    pub value: String,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// A group or folder of password entries
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

#[derive(Debug, Default, Clone, PartialEq, Eq)]
/// Identifies which fields are encrypted in memory for official clients
pub struct MemoryProtection {
    protect_title: bool,
    protect_user_name: bool,
    protect_password: bool,
    protect_url: bool,
    protet_notes: bool,
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
        let now = chrono::Local::now().naive_local();
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
pub struct XmlDatabase {
    /// Meta information about this database
    pub meta: Meta,
    /// Trees of items in this database
    pub groups: Vec<Group>,
}
