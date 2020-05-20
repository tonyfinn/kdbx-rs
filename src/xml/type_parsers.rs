use chrono::{Duration, NaiveDate, NaiveDateTime};
use uuid::Uuid;

fn parse_uuid(b64uuid: &str) -> Option<Uuid> {
    let decoded = base64::decode(b64uuid).ok()?;
    Uuid::from_slice(&decoded).ok()
}

fn parse_datetime(b64date: &str) -> Option<NaiveDateTime> {
    let decoded = base64::decode(b64date).ok()?;
    let mut bytes = [0u8; 8];
    for i in 0..usize::min(bytes.len(), decoded.len()) {
        bytes[i] = decoded[i];
    }
    let timestamp = Duration::seconds(i64::from_le_bytes(bytes));

    NaiveDate::from_ymd(0, 1, 1)
        .and_hms(0, 0, 0)
        .checked_add_signed(timestamp)
}
