use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use crate::statics;

// Return path to local OUI database file.
pub fn get_path() -> std::path::PathBuf {
    let data_local_dir = statics::PROJECT_DIRS.data_local_dir();
    let mut oui_db_path = PathBuf::from(data_local_dir);
    oui_db_path.push("manuf.txt");
    oui_db_path
}

// Download OUI database file to specified path.
pub fn download_file(oui_db_path: &str) {
    let manuf_url: &str = "https://code.wireshark.org/review/gitweb?p=wireshark.git;a=blob_plain;f=manuf";
    info!("Downloading new oui database from: {:?}", &manuf_url);
    let body = reqwest::get(manuf_url).unwrap().text();
    info!("Download complete, writing to file: {:?}", &oui_db_path);
    let new_file = File::create(&oui_db_path).expect("Unable to create oui database file.");
    let mut new_file = BufWriter::new(new_file);
    new_file.write_all(body.unwrap().as_bytes()).expect("Unable to write data");
}
