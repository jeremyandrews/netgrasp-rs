use std::time::{SystemTime, UNIX_EPOCH};

pub fn timestamp_now() -> u64 {
    let start = SystemTime::now();
    start.duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_secs()
}