use chrono::{DateTime, Duration, NaiveDate, NaiveDateTime};
use uuid::Uuid;

pub fn keepass_epoch() -> NaiveDateTime {
    NaiveDate::from_ymd_opt(1, 1, 1)
        .unwrap()
        .and_hms_opt(0, 0, 0)
        .unwrap()
}

/// Decode a UUID from a Keepass XML file
///
/// The UUID in Keepass XML files is stored base 64 encoded
pub fn decode_uuid(b64uuid: &str) -> Option<Uuid> {
    let decoded = base64::decode(b64uuid).ok()?;
    Uuid::from_slice(&decoded).ok()
}

pub(crate) fn decode_datetime_b64(b64date: &str) -> Option<NaiveDateTime> {
    let decoded = base64::decode(b64date).ok()?;
    let mut bytes = [0u8; 8];
    let copy_size = usize::min(bytes.len(), decoded.len());
    bytes[..copy_size].copy_from_slice(&decoded[..copy_size]);
    let timestamp = Duration::seconds(i64::from_le_bytes(bytes));

    keepass_epoch().checked_add_signed(timestamp)
}

/// Decode a Datetime from a Keepass XML file
///
/// This handles either ISO8601 date strings (as used in KDBX3)
/// or base64 encoded seconds since 1/1/1 00:00:00 as used in KDBX 4
pub fn decode_datetime(strdate: &str) -> Option<NaiveDateTime> {
    if strdate.contains('-') {
        let dt = DateTime::parse_from_rfc3339(strdate).ok()?;
        Some(dt.naive_utc())
    } else {
        decode_datetime_b64(strdate)
    }
}

/// Encode a UUID for a Keepass XML file for kdbx4
pub fn encode_uuid(uuid: Uuid) -> String {
    base64::encode(uuid.as_bytes())
}

/// Encode a datetime for a Keepass XML file for kdbx4
pub fn encode_datetime(date: NaiveDateTime) -> String {
    let epoch_seconds = date.signed_duration_since(keepass_epoch()).num_seconds();
    base64::encode(epoch_seconds.to_le_bytes())
}
