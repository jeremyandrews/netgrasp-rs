use directories::ProjectDirs;

lazy_static! {
    pub static ref PROJECT_DIRS: ProjectDirs = ProjectDirs::from("org", "Netgrasp", "Netgrasp")
        .expect("Failed to determine project configuration directory");
}
