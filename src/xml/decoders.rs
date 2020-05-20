use chrono::{Duration, NaiveDate, NaiveDateTime};
use uuid::Uuid;

pub fn keepass_epoch() -> NaiveDateTime {
    NaiveDate::from_ymd(0, 1, 1).and_hms(0, 0, 0)
}

pub(crate) fn decode_uuid(b64uuid: &str) -> Option<Uuid> {
    let decoded = base64::decode(b64uuid).ok()?;
    Uuid::from_slice(&decoded).ok()
}

pub(crate) fn decode_datetime(b64date: &str) -> Option<NaiveDateTime> {
    let decoded = base64::decode(b64date).ok()?;
    let mut bytes = [0u8; 8];
    for i in 0..usize::min(bytes.len(), decoded.len()) {
        bytes[i] = decoded[i];
    }
    let timestamp = Duration::seconds(i64::from_le_bytes(bytes));

    keepass_epoch().checked_add_signed(timestamp)
}

pub(crate) fn encode_uuid(uuid: &Uuid) -> String {
    base64::encode(uuid.as_bytes())
}

pub(crate) fn encode_datetime(date: NaiveDateTime) -> String {
    let epoch_seconds = date.signed_duration_since(keepass_epoch()).num_seconds();
    base64::encode(epoch_seconds.to_le_bytes())
}
