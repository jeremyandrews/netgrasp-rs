use std::time::{SystemTime, UNIX_EPOCH};

pub fn timestamp_now() -> u64 {
    let start = SystemTime::now();
    start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}

pub fn elapsed(timestamp: u64) -> u64 {
    timestamp_now() - timestamp
}