use super::types::{Entry, Field, Group, Meta, Times, XmlDatabase};
use std::io::Read;
use thiserror::Error;
use uuid::Uuid;
use xml::reader::{EventReader, XmlEvent};

#[derive(Debug, Error)]
/// Error encountered parsing XML
pub enum Error {
    /// Error from the underlying XML parser
    #[error("Error parsing database XML: {0}")]
    Xml(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<xml::reader::Error> for Error {
    fn from(e: xml::reader::Error) -> Error {
        Error::Xml(e.msg().to_string())
    }
}

trait XmlState {
    fn database(self: Box<Self>) -> XmlDatabase;
    fn handle_xml_event(self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState>;
}

struct InitialState {
    database: XmlDatabase,
}

impl XmlState for InitialState {
    fn database(self: Box<Self>) -> XmlDatabase {
        self.database
    }

    fn handle_xml_event(self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        if let XmlEvent::StartElement { name, ..} = event {
            if name.local_name == "KeePassFile" {
                return Box::new(FileState { parent: self });
            }
        }
        self
    }
}

struct FileState {
    parent: Box<InitialState>,
}

impl XmlState for FileState {
    fn database(self: Box<Self>) -> XmlDatabase {
        self.parent.database()
    }

    fn handle_xml_event(self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        if let XmlEvent::StartElement { name, ..} = event {
            if name.local_name == "Root" {
                return Box::new(RootState::new(self));
            }
        } else if let XmlEvent::EndElement { name, .. } = event {
            if name.local_name == "KeePassFile" {
                return self.parent
            }
        }
        self
    }
}

struct RootState {
    parent: Box<FileState>,
    groups: Vec<Group>,
}

impl RootState {
    fn new(parent: Box<FileState>) -> RootState {
        RootState {
            parent,
            groups: Vec::new(),
        }
    }
}

impl XmlState for RootState {
    fn database(self: Box<Self>) -> XmlDatabase {
        self.parent.database()
    }

    fn handle_xml_event(mut self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        if let XmlEvent::StartElement { name, ..} = event {
            if name.local_name == "Group" {
                return Box::new(GroupState::new(self));
            }
        } else if let XmlEvent::EndElement { name, .. } = event {
            if name.local_name == "Root" {
                self.parent.parent.database.groups = self.groups;
                return self.parent
            }
        }
        self
    }
}

trait GroupStateParent: XmlState {
    fn add_group(&mut self, group: Group);
}

impl XmlState for Box<dyn GroupStateParent> {
    fn database(self: Box<Self>) -> XmlDatabase {
        (*self).database()
    }

    fn handle_xml_event(self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        (*self).handle_xml_event(event)
    }
}

impl GroupStateParent for RootState {
    fn add_group(&mut self, group: Group) {
        self.groups.push(group);
    }
}

struct GroupState {
    parent: Box<dyn GroupStateParent>,
    group: Group,
}

impl GroupState {
    fn new(parent: Box<dyn GroupStateParent>) -> GroupState {
        GroupState {
            parent,
            group: Group::default(),
        }
    }
}

impl XmlState for GroupState {
    fn database(self: Box<Self>) -> XmlDatabase {
        self.parent.database()
    }

    fn handle_xml_event(mut self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        if let XmlEvent::StartElement { name, ..} = event {
            if name.local_name == "Group" {
                return Box::new(GroupState::new(self));
            } else if name.local_name == "Entry" {
                return Box::new(EntryState::new(self));
            }
        } else if let XmlEvent::EndElement { name, .. } = event {
            if name.local_name == "Group" {
                self.parent.add_group(self.group);
                return Box::new(self.parent);
            }
        }
        self
    }
}

impl GroupStateParent for GroupState
{
    fn add_group(&mut self, group: Group) {
        self.group.children.push(group);
    }
}

struct EntryState {
    parent: Box<dyn EntryStateParent>,
    entry: Entry,
}

impl EntryState {
    fn new(parent: Box<dyn EntryStateParent>) -> EntryState {
        EntryState {
            parent,
            entry: Entry::default(),
        }
    }
}

impl XmlState for EntryState {
    fn database(self: Box<Self>) -> XmlDatabase {
        self.parent.database()
    }

    fn handle_xml_event(mut self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        if let XmlEvent::StartElement { name, ..} = event {
            if name.local_name == "String" {
                return Box::new(FieldState::new(self));
            } else if name.local_name == "History" {
                return Box::new(HistoryState::new(self));
            }
        } else if let XmlEvent::EndElement { name, .. } = event {
            if name.local_name == "Entry" {
                self.parent.add_entry(self.entry);
                return Box::new(self.parent);
            }
        }
        self
    }
}
struct HistoryState {
    parent: Box<EntryState>,
}

impl HistoryState {
    fn new(parent: Box<EntryState>) -> HistoryState {
        HistoryState {
            parent,
        }
    }
}

impl XmlState for HistoryState {
    fn database(self: Box<Self>) -> XmlDatabase {
        self.parent.database()
    }

    fn handle_xml_event(self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        if let XmlEvent::StartElement { name, ..} = event {
            if name.local_name == "Entry" {
                return Box::new(EntryState::new(self));
            }
        } else if let XmlEvent::EndElement { name, .. } = event {
            if name.local_name == "History" {
                return self.parent;
            }
        }
        self
    }
}

struct FieldState {
    parent: Box<dyn FieldStateParent>,
    field: Field,
    characters: Option<String>,
}

impl FieldState {
    fn new(parent: Box<dyn FieldStateParent>) -> FieldState {
        FieldState {
            parent,
            characters: None,
            field: Field::default(),
        }
    }
}

impl XmlState for FieldState {
    fn database(self: Box<Self>) -> XmlDatabase {
        self.parent.database()
    }

    fn handle_xml_event(mut self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        if let XmlEvent::Characters(chars) = event {
            self.characters = Some(chars);
        } else if let XmlEvent::EndElement { name, .. } = event {
            if name.local_name == "String" {
                self.parent.add_field(self.field);
                return Box::new(self.parent);
            } else if name.local_name == "Key" {
                self.field.key = self.characters.take().unwrap_or("".to_string());
            } else if name.local_name == "Value" {
                self.field.value = self.characters.take().unwrap_or("".to_string());
            }
        }
        self
    }
}

trait EntryStateParent: XmlState {
    fn add_entry(&mut self, entry: Entry);
}

impl XmlState for Box<dyn EntryStateParent> {
    fn database(self: Box<Self>) -> XmlDatabase {
        (*self).database()
    }

    fn handle_xml_event(self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        (*self).handle_xml_event(event)
    }
}

impl EntryStateParent for GroupState
{
    fn add_entry(&mut self, entry: Entry) {
        self.group.entries.push(entry);
    }
}

impl EntryStateParent for HistoryState
{
    fn add_entry(&mut self, entry: Entry) {
        self.parent.entry.history.push(entry);
    }
}

trait FieldStateParent: XmlState {
    fn add_field(&mut self, field: Field);
}

impl XmlState for Box<dyn FieldStateParent> {
    fn database(self: Box<Self>) -> XmlDatabase {
        (*self).database()
    }

    fn handle_xml_event(self: Box<Self>, event: XmlEvent) -> Box<dyn XmlState> {
        (*self).handle_xml_event(event)
    }
}

impl FieldStateParent for EntryState
{
    fn add_field(&mut self, field: Field) {
        self.entry.fields.push(field);
    }
}

/// Parse decrypted XML into a database
pub fn parse_xml<R: Read>(xml_data: R) -> Result<XmlDatabase> {
    let database = XmlDatabase::default();
    let xml_config = xml::ParserConfig::new()
        .trim_whitespace(true)
        .cdata_to_characters(true);
    let xml_event_reader = EventReader::new_with_config(xml_data, xml_config);
    let mut parser_state: Box<dyn XmlState> = Box::new(InitialState { database });

    for evt in xml_event_reader {
        match evt {
            Ok(evt) => {
                parser_state = parser_state.handle_xml_event(evt);
            }
            Err(e) => return Err(e.into()),
        }
    }

    Ok(parser_state.database())
}
