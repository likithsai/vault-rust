use gtk4::gdk::{ContentFormats, Display, DragAction, FileList, Texture};
use gtk4::gio;
use gtk4::glib;
use gtk4::prelude::*;
use gtk4::{CssProvider, DropTarget};
use relm4::factory::FactoryVecDeque;
use relm4::prelude::*;
use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use uuid::Uuid;

mod db;
use db::{EncryptedDb, FileMetadata, FolderMetadata, SortColumn, SortDirection, VaultStats, CHUNK_SIZE};

const PAGE_SIZE: usize = 500;

fn format_bytes(bytes: usize) -> String {
    const KB: usize = 1024;
    const MB: usize = KB * 1024;
    const GB: usize = MB * 1024;
    const TB: usize = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

fn format_timestamp(timestamp: i64) -> String {
    if timestamp == 0 {
        return "-".to_string();
    }
    let total_secs = timestamp;
    let days = total_secs / 86400;
    let rem_secs = total_secs % 86400;
    let hours = rem_secs / 3600;
    let minutes = (rem_secs % 3600) / 60;
    format!("Day {}, {:02}:{:02} UTC", days, hours, minutes)
}

fn get_file_details(name: &str) -> (&'static str, &'static str) {
    let ext = name.split('.').last().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "txt" | "md" | "rtf" | "doc" | "docx" => ("📝", "Document"),
        "pdf" => ("📕", "PDF Document"),
        "png" | "jpg" | "jpeg" | "webp" | "svg" | "gif" => ("🖼️", "Image"),
        "zip" | "tar" | "gz" | "7z" | "rar" => ("🗜️", "Archive"),
        "rs" | "js" | "ts" | "py" | "json" | "c" | "cpp" | "html" | "css" => ("💻", "Source Code"),
        "mp3" | "wav" | "flac" | "aac" => ("🎵", "Audio Track"),
        "mp4" | "mkv" | "mov" | "avi" => ("🎬", "Video File"),
        _ => ("📄", "Generic File"),
    }
}

fn is_previewable_image(name: &str) -> bool {
    let ext = name.split('.').last().unwrap_or("").to_lowercase();
    matches!(ext.as_str(), "png" | "jpg" | "jpeg" | "webp" | "svg")
}

fn run_on_db<F, R>(db_arc: &Arc<Mutex<EncryptedDb>>, f: F) -> Result<R, String>
where
    F: FnOnce(&mut EncryptedDb) -> rusqlite::Result<R>,
{
    match db_arc.lock() {
        Ok(mut db) => f(&mut *db).map_err(|e| e.to_string()),
        Err(_) => Err("Database lock poisoned".to_string()),
    }
}

fn clean_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let p = path.as_ref();
    let s = p.to_string_lossy();
    if s.starts_with(r"\\?\") {
        PathBuf::from(&s[4..])
    } else {
        p.to_path_buf()
    }
}

fn compute_file_hash_binary<P: AsRef<Path>>(path: P) -> std::io::Result<[u8; 32]> {
    let f = File::open(path)?;
    let mut reader = BufReader::with_capacity(CHUNK_SIZE, f);
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0u8; CHUNK_SIZE];
    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
    }
    Ok(*hasher.finalize().as_bytes())
}

fn parse_uri_list(uri_data: &str) -> Vec<PathBuf> {
    uri_data
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|uri_str| {
            let file = gio::File::for_uri(uri_str);
            if let Some(path) = file.path() {
                return Some(clean_path(path));
            }

            if let Some(stripped) = uri_str.strip_prefix("file://") {
                let unescaped = glib::uri_unescape_string(stripped, None::<&str>)
                    .map(|s| s.to_string())
                    .unwrap_or_else(|| stripped.to_string());

                #[cfg(target_os = "windows")]
                {
                    let trimmed = unescaped.trim_start_matches('/');
                    if trimmed.len() >= 2 && trimmed.chars().nth(1) == Some(':') {
                        return Some(clean_path(trimmed.replace('/', "\\")));
                    }
                    return Some(clean_path(unescaped.replace('/', "\\")));
                }

                #[cfg(not(target_os = "windows"))]
                {
                    return Some(clean_path(unescaped));
                }
            }
            None
        })
        .collect()
}

const WINZIP_CSS: &str = "
window {
    background-color: #2b2d30;
    color: #dfdfdf;
    font-size: 13px;
}
.ribbon-bar {
    background-color: #1e1f22;
    border-bottom: 1px solid #3c3f41;
    padding: 6px 10px;
}
.ribbon-btn {
    background: transparent;
    border: 1px solid transparent;
    border-radius: 4px;
    padding: 4px 8px;
    color: #dfdfdf;
}
.ribbon-btn:hover {
    background-color: #35373c;
    border-color: #4e5157;
}
.ribbon-btn:disabled {
    opacity: 0.35;
}
.ribbon-icon {
    font-size: 18px;
    margin-bottom: 2px;
}
.ribbon-text {
    font-size: 11px;
    font-weight: 500;
}
.ribbon-sep {
    background-color: #3c3f41;
    margin: 4px 6px;
}
.path-bar {
    background-color: #26282b;
    border-bottom: 1px solid #3c3f41;
    padding: 4px 10px;
}
.path-entry {
    background-color: #1e1f22;
    border: 1px solid #3c3f41;
    border-radius: 3px;
    color: #89b4fa;
    padding: 2px 8px;
    font-family: monospace;
    font-size: 12px;
}
.search-entry {
    background-color: #1e1f22;
    border: 1px solid #3c3f41;
    border-radius: 4px;
    color: #ffffff;
    font-size: 12px;
    padding: 2px 8px;
}
.table-header {
    background-color: #212225;
    border-bottom: 1px solid #3c3f41;
    padding: 6px 12px;
    font-weight: bold;
    font-size: 11px;
    color: #9da5b4;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
.sort-header-btn {
    background: transparent;
    border: none;
    font-weight: bold;
    font-size: 11px;
    color: #9da5b4;
    text-transform: uppercase;
    padding: 0;
}
.sort-header-btn:hover {
    color: #89b4fa;
}
.simple-list-row {
    padding: 6px 12px;
    border-bottom: 1px solid #323538;
}
.simple-list-row:hover {
    background-color: #35383f;
}
.simple-list-row:selected {
    background-color: #264f78;
    color: #ffffff;
}
.entry-icon {
    font-size: 16px;
}
.winzip-status-bar {
    background-color: #1e1f22;
    border-top: 1px solid #3c3f41;
    padding: 4px 12px;
    font-size: 11px;
    color: #abb2bf;
}
.preview-pane {
    background-color: #1e1f22;
    border-left: 1px solid #3c3f41;
    padding: 12px;
}
.preview-text {
    font-family: monospace;
    font-size: 11px;
    color: #a6adc8;
}
.error-dialog-title {
    font-size: 14px;
    font-weight: bold;
    color: #f38ba8;
}
.error-dialog-msg {
    font-size: 13px;
    color: #dfdfdf;
}
.error-btn {
    background-color: #cdd6f4;
    color: #1e1e2e;
    font-weight: bold;
    border-radius: 4px;
    padding: 4px 16px;
}
.error-btn:hover {
    background-color: #ffffff;
}
.duplicate-btn-skip {
    background-color: #45475a;
    color: #cdd6f4;
    font-weight: bold;
    border-radius: 4px;
    padding: 4px 14px;
    border: none;
}
.duplicate-btn-skip:hover {
    background-color: #585b70;
}
.duplicate-btn-keep {
    background-color: #89b4fa;
    color: #11111b;
    font-weight: bold;
    border-radius: 4px;
    padding: 4px 14px;
    border: none;
}
.duplicate-btn-keep:hover {
    background-color: #b4befe;
}
";

#[derive(Clone, Debug)]
enum ArchiveEntry {
    Folder(FolderMetadata),
    File(FileMetadata),
}

#[derive(Debug)]
struct EntryRow {
    entry: ArchiveEntry,
    display_icon: &'static str,
    display_name: String,
    display_type: String,
    display_size: String,
    display_encrypted: String,
    display_modified: String,
    index: usize,
}

#[derive(Debug)]
enum EntryRowInput {}

#[derive(Debug)]
enum EntryRowOutput {
    Open(usize),
    Extract(usize),
    Rename(usize),
    Delete(usize),
    Preview(usize),
}

#[relm4::factory]
impl FactoryComponent for EntryRow {
    type Init = (ArchiveEntry, usize);
    type Input = EntryRowInput;
    type Output = EntryRowOutput;
    type CommandOutput = ();
    type ParentWidget = gtk::ListBox;

    view! {
        #[root]
        row_widget = gtk::ListBoxRow {
            add_css_class: "simple-list-row",

            gtk::Box {
                set_orientation: gtk::Orientation::Horizontal,
                set_spacing: 12,

                gtk::Box {
                    set_hexpand: true,
                    set_spacing: 8,

                    gtk::Label {
                        #[watch]
                        set_text: self.display_icon,
                        add_css_class: "entry-icon",
                    },
                    gtk::Label {
                        #[watch]
                        set_text: &self.display_name,
                        set_xalign: 0.0,
                        set_hexpand: true,
                        set_ellipsize: gtk::pango::EllipsizeMode::End,
                    },
                },

                gtk::Label {
                    set_width_request: 130,
                    set_xalign: 0.0,
                    #[watch]
                    set_text: &self.display_type,
                },

                gtk::Label {
                    set_width_request: 90,
                    set_xalign: 1.0,
                    #[watch]
                    set_text: &self.display_size,
                },

                gtk::Label {
                    set_width_request: 90,
                    set_xalign: 1.0,
                    #[watch]
                    set_text: &self.display_encrypted,
                },

                gtk::Label {
                    set_width_request: 160,
                    set_xalign: 0.0,
                    #[watch]
                    set_text: &self.display_modified,
                },
            }
        }
    }

    fn init_model(init: Self::Init, _index: &DynamicIndex, _sender: FactorySender<Self>) -> Self {
        let (entry, index) = init;
        let (display_icon, display_name, display_type, display_size, display_encrypted, display_modified) = match &entry {
            ArchiveEntry::Folder(f) => (
                "📁",
                f.name.clone(),
                "File Folder".into(),
                "-".into(),
                "-".into(),
                "-".into(),
            ),
            ArchiveEntry::File(f) => {
                let (icon, typ) = get_file_details(&f.name);
                (
                    icon,
                    f.name.clone(),
                    typ.into(),
                    format_bytes(f.size),
                    format_bytes(f.compressed_size),
                    format_timestamp(f.created_at),
                )
            }
        };

        Self {
            entry,
            display_icon,
            display_name,
            display_type,
            display_size,
            display_encrypted,
            display_modified,
            index,
        }
    }

    fn init_widgets(
        &mut self,
        _index: &DynamicIndex,
        root: Self::Root,
        _returned_widget: &<Self::ParentWidget as relm4::factory::FactoryView>::ReturnedWidget,
        sender: FactorySender<Self>,
    ) -> Self::Widgets {
        let widgets = view_output!();

        let action_group = gio::SimpleActionGroup::new();
        let idx = self.index;
        let is_folder = matches!(self.entry, ArchiveEntry::Folder(_));

        let s_open = sender.clone();
        let act_open = gio::SimpleAction::new("open", None);
        act_open.connect_activate(move |_, _| {
            let _ = s_open.output(EntryRowOutput::Open(idx));
        });
        action_group.add_action(&act_open);

        let s_prev = sender.clone();
        let act_prev = gio::SimpleAction::new("preview", None);
        act_prev.connect_activate(move |_, _| {
            let _ = s_prev.output(EntryRowOutput::Preview(idx));
        });
        action_group.add_action(&act_prev);

        let s_ext = sender.clone();
        let act_extract = gio::SimpleAction::new("extract", None);
        act_extract.connect_activate(move |_, _| {
            let _ = s_ext.output(EntryRowOutput::Extract(idx));
        });
        action_group.add_action(&act_extract);

        let s_ren = sender.clone();
        let act_rename = gio::SimpleAction::new("rename", None);
        act_rename.connect_activate(move |_, _| {
            let _ = s_ren.output(EntryRowOutput::Rename(idx));
        });
        action_group.add_action(&act_rename);

        let s_del = sender.clone();
        let act_delete = gio::SimpleAction::new("delete", None);
        act_delete.connect_activate(move |_, _| {
            let _ = s_del.output(EntryRowOutput::Delete(idx));
        });
        action_group.add_action(&act_delete);

        widgets.row_widget.insert_action_group("row", Some(&action_group));

        let menu_model = gio::Menu::new();
        if is_folder {
            menu_model.append(Some("Open Folder"), Some("row.open"));
        } else {
            menu_model.append(Some("Quick Look / Preview"), Some("row.preview"));
            menu_model.append(Some("Extract File..."), Some("row.extract"));
        }
        menu_model.append(Some("Rename..."), Some("row.rename"));
        menu_model.append(Some("Delete"), Some("row.delete"));

        let popover = gtk::PopoverMenu::from_model(Some(&menu_model));
        popover.set_parent(&widgets.row_widget);
        popover.set_has_arrow(false);

        let click_gesture = gtk::GestureClick::new();
        click_gesture.set_button(3);

        let popover_clone = popover.clone();
        click_gesture.connect_pressed(move |_, _, x, y| {
            let rect = gtk::gdk::Rectangle::new(x as i32, y as i32, 1, 1);
            popover_clone.set_pointing_to(Some(&rect));
            popover_clone.popup();
        });

        widgets.row_widget.add_controller(click_gesture);

        widgets
    }
}

struct VaultModel {
    db: Option<Arc<Mutex<EncryptedDb>>>,
    active_vault_path: Option<PathBuf>,
    current_folder_id: Option<Uuid>,
    folder_path_stack: Vec<(Option<Uuid>, String)>,
    entries: FactoryVecDeque<EntryRow>,
    selected_index: Option<usize>,
    stats: VaultStats,
    is_loading: bool,
    progress_fraction: f64,
    status: String,
    search_query: String,
    sort_column: SortColumn,
    sort_direction: SortDirection,

    preview_name: String,
    preview_meta: String,
    preview_buffer: gtk::TextBuffer,
    preview_has_image: bool,
    preview_texture: Option<Texture>,
    show_preview_pane: bool,

    // Ingestion queue for processing and prompting duplicates sequentially
    import_queue: VecDeque<(PathBuf, Option<Uuid>)>,
}

#[derive(Debug)]
enum VaultMsg {
    PromptCreateVault,
    PromptOpenVault,
    PromptExportVault,
    ExecuteUnlock(PathBuf, String, bool),
    VaultUnlocked(Arc<Mutex<EncryptedDb>>, PathBuf, VaultStats),
    LoadCurrentDirectory,
    DirectoryInitialized(Vec<FolderMetadata>, Vec<FileMetadata>),
    LockVault,

    PromptCreateFolder,
    PromptAddFile,
    ImportFilesList(Vec<PathBuf>),
    ProcessNextImportQueue,
    PromptDuplicateEncountered {
        path: PathBuf,
        folder_id: Option<Uuid>,
        existing_file_name: String,
    },
    ResolveDuplicate {
        path: PathBuf,
        folder_id: Option<Uuid>,
        keep: bool,
    },
    CommitSingleFileImport(PathBuf, Option<Uuid>),

    SelectEntry(Option<usize>),
    ActivateEntry(usize),
    NavigateUp,
    PromptRenameSelected(Option<usize>),
    DeleteSelectedItem(Option<usize>),
    PromptExtractFile(Option<usize>),

    SetSearchQuery(String),
    ToggleSort(SortColumn),
    PromptChangePassword,
    ExecuteRekey(String),
    TriggerCompact,
    TriggerIntegrityTest,
    IntegrityVerified(Vec<(String, bool)>),
    ShowQuickLook(usize),
    CloseQuickLook,
    PreviewLoaded(String, String, Option<Vec<u8>>, bool),

    UpdateProgress(f64, String),
    SetStatus(String),
    SetError(String),
}

#[relm4::component]
impl SimpleComponent for VaultModel {
    type Init = ();
    type Input = VaultMsg;
    type Output = ();

    view! {
        main_window = gtk::Window {
            set_title: Some("IronVault Enterprise - Pro Archive Engine"),
            set_default_width: 1100,
            set_default_height: 680,

            gtk::Box {
                set_orientation: gtk::Orientation::Vertical,

                // --- 1. RIBBON TOOLBAR ---
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 2,
                    add_css_class: "ribbon-bar",

                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: !model.is_loading,
                        connect_clicked[sender, main_window] => move |_| {
                            let chooser = gtk::FileChooserNative::new(
                                Some("New Zstd Encrypted Archive (.ivault)"),
                                Some(&main_window),
                                gtk::FileChooserAction::Save,
                                Some("Create"),
                                Some("Cancel"),
                            );
                            chooser.set_current_name("Archive.ivault");

                            let s = sender.clone();
                            let win = main_window.clone();
                            chooser.connect_response(move |dialog, res| {
                                if res == gtk::ResponseType::Accept {
                                    if let Some(file) = dialog.file() {
                                        if let Some(raw_path) = file.path() {
                                            let path = clean_path(raw_path);
                                            spawn_password_dialog(
                                                "Set Master Key",
                                                "Set archive encryption password:",
                                                Some(&win),
                                                s.clone(),
                                                move |pwd, snd| {
                                                    snd.input(VaultMsg::ExecuteUnlock(path.clone(), pwd, true));
                                                },
                                            );
                                        }
                                    }
                                }
                            });
                            chooser.show();
                        },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "📄", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "New", add_css_class: "ribbon-text" }
                        }
                    },
                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: !model.is_loading,
                        connect_clicked[sender, main_window] => move |_| {
                            let chooser = gtk::FileChooserNative::new(
                                Some("Open Encrypted Archive"),
                                Some(&main_window),
                                gtk::FileChooserAction::Open,
                                Some("Open"),
                                Some("Cancel"),
                            );

                            let s = sender.clone();
                            let win = main_window.clone();
                            chooser.connect_response(move |dialog, res| {
                                if res == gtk::ResponseType::Accept {
                                    if let Some(file) = dialog.file() {
                                        if let Some(raw_path) = file.path() {
                                            let path = clean_path(raw_path);
                                            spawn_password_dialog(
                                                "Enter Password",
                                                "Enter archive password:",
                                                Some(&win),
                                                s.clone(),
                                                move |pwd, snd| {
                                                    snd.input(VaultMsg::ExecuteUnlock(path.clone(), pwd, false));
                                                },
                                            );
                                        }
                                    }
                                }
                            });
                            chooser.show();
                        },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "📂", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "Open", add_css_class: "ribbon-text" }
                        }
                    },
                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: model.db.is_some() && !model.is_loading,
                        connect_clicked[sender] => move |_| { sender.input(VaultMsg::PromptExportVault); },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "💾", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "Backup", add_css_class: "ribbon-text" }
                        }
                    },
                    gtk::Separator { set_orientation: gtk::Orientation::Vertical, add_css_class: "ribbon-sep" },
                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: model.db.is_some() && !model.is_loading,
                        connect_clicked[sender, main_window] => move |_| {
                            let s = sender.clone();
                            spawn_entry_dialog("New Folder", "Folder name:", "NewFolder", Some(&main_window), move |_name| {
                                s.input(VaultMsg::PromptCreateFolder);
                            });
                        },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "📁", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "Folder", add_css_class: "ribbon-text" }
                        }
                    },
                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: model.db.is_some() && !model.is_loading,
                        connect_clicked[sender, main_window] => move |_| {
                            let chooser = gtk::FileChooserNative::new(
                                Some("Add Files"),
                                Some(&main_window),
                                gtk::FileChooserAction::Open,
                                Some("Add"),
                                Some("Cancel"),
                            );

                            let s = sender.clone();
                            chooser.connect_response(move |dialog, res| {
                                if res == gtk::ResponseType::Accept {
                                    if let Some(file) = dialog.file() {
                                        if let Some(raw_path) = file.path() {
                                            s.input(VaultMsg::ImportFilesList(vec![clean_path(raw_path)]));
                                        }
                                    }
                                }
                            });
                            chooser.show();
                        },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "➕", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "Add Files", add_css_class: "ribbon-text" }
                        }
                    },
                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: model.selected_index.is_some() && !model.is_loading,
                        connect_clicked[sender] => move |_| { sender.input(VaultMsg::PromptExtractFile(None)); },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "📦", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "Extract", add_css_class: "ribbon-text" }
                        }
                    },
                    gtk::Separator { set_orientation: gtk::Orientation::Vertical, add_css_class: "ribbon-sep" },
                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: model.db.is_some() && !model.is_loading,
                        connect_clicked[sender] => move |_| { sender.input(VaultMsg::TriggerIntegrityTest); },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "🛡️", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "Verify", add_css_class: "ribbon-text" }
                        }
                    },
                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: model.db.is_some() && !model.is_loading,
                        connect_clicked[sender, main_window] => move |_| {
                            spawn_password_dialog(
                                "Rekey Archive",
                                "Enter new master password:",
                                Some(&main_window),
                                sender.clone(),
                                move |new_pwd, snd| {
                                    snd.input(VaultMsg::ExecuteRekey(new_pwd));
                                },
                            );
                        },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "🔑", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "Rekey", add_css_class: "ribbon-text" }
                        }
                    },
                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: model.db.is_some() && !model.is_loading,
                        connect_clicked[sender] => move |_| { sender.input(VaultMsg::TriggerCompact); },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "🧹", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "Compact", add_css_class: "ribbon-text" }
                        }
                    },
                    gtk::Button {
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: model.db.is_some() && !model.is_loading,
                        connect_clicked[sender] => move |_| { sender.input(VaultMsg::LockVault); },
                        gtk::Box {
                            set_orientation: gtk::Orientation::Vertical,
                            set_halign: gtk::Align::Center,
                            gtk::Label { set_text: "🔒", add_css_class: "ribbon-icon" },
                            gtk::Label { set_text: "Lock", add_css_class: "ribbon-text" }
                        }
                    },

                    gtk::Box { set_hexpand: true },

                    gtk::SearchEntry {
                        set_width_request: 220,
                        add_css_class: "search-entry",
                        set_placeholder_text: Some("Filter archive (Ctrl+F)..."),
                        connect_search_changed[sender] => move |entry| {
                            sender.input(VaultMsg::SetSearchQuery(entry.text().to_string()));
                        }
                    },

                    gtk::Spinner {
                        #[watch]
                        set_spinning: model.is_loading,
                    }
                },

                // --- 2. ADDRESS / PATH BAR ---
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 8,
                    add_css_class: "path-bar",

                    gtk::Button {
                        set_label: "⬆️",
                        add_css_class: "ribbon-btn",
                        #[watch]
                        set_sensitive: model.current_folder_id.is_some() && !model.is_loading,
                        connect_clicked[sender] => move |_| { sender.input(VaultMsg::NavigateUp); }
                    },
                    gtk::Label { set_text: "Location:" },
                    gtk::Entry {
                        set_hexpand: true,
                        set_editable: false,
                        add_css_class: "path-entry",
                        #[watch]
                        set_text: &model.folder_path_stack.iter()
                            .map(|(_, name)| name.clone())
                            .collect::<Vec<_>>()
                            .join("/"),
                    }
                },

                // --- 3. SORTABLE COLUMN HEADERS ---
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 12,
                    add_css_class: "table-header",

                    gtk::Button {
                        set_hexpand: true,
                        add_css_class: "sort-header-btn",
                        #[watch]
                        set_label: match (model.sort_column, model.sort_direction) {
                            (SortColumn::Name, SortDirection::Asc) => "NAME ▲",
                            (SortColumn::Name, SortDirection::Desc) => "NAME ▼",
                            _ => "NAME",
                        },
                        connect_clicked[sender] => move |_| {
                            sender.input(VaultMsg::ToggleSort(SortColumn::Name));
                        }
                    },
                    gtk::Label {
                        set_width_request: 130,
                        set_xalign: 0.0,
                        set_text: "TYPE",
                    },
                    gtk::Button {
                        set_width_request: 90,
                        add_css_class: "sort-header-btn",
                        #[watch]
                        set_label: match (model.sort_column, model.sort_direction) {
                            (SortColumn::Size, SortDirection::Asc) => "SIZE ▲",
                            (SortColumn::Size, SortDirection::Desc) => "SIZE ▼",
                            _ => "SIZE",
                        },
                        connect_clicked[sender] => move |_| {
                            sender.input(VaultMsg::ToggleSort(SortColumn::Size));
                        }
                    },
                    gtk::Button {
                        set_width_request: 90,
                        add_css_class: "sort-header-btn",
                        #[watch]
                        set_label: match (model.sort_column, model.sort_direction) {
                            (SortColumn::EncryptedSize, SortDirection::Asc) => "ENCR ▲",
                            (SortColumn::EncryptedSize, SortDirection::Desc) => "ENCR ▼",
                            _ => "ENCRYPTED",
                        },
                        connect_clicked[sender] => move |_| {
                            sender.input(VaultMsg::ToggleSort(SortColumn::EncryptedSize));
                        }
                    },
                    gtk::Button {
                        set_width_request: 160,
                        add_css_class: "sort-header-btn",
                        #[watch]
                        set_label: match (model.sort_column, model.sort_direction) {
                            (SortColumn::Modified, SortDirection::Asc) => "MODIFIED ▲",
                            (SortColumn::Modified, SortDirection::Desc) => "MODIFIED ▼",
                            _ => "MODIFIED",
                        },
                        connect_clicked[sender] => move |_| {
                            sender.input(VaultMsg::ToggleSort(SortColumn::Modified));
                        }
                    },
                },

                // --- 4. MAIN SPLIT VIEW (LIST + QUICK LOOK PREVIEW) ---
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_vexpand: true,

                    gtk::ScrolledWindow {
                        set_hexpand: true,

                        #[local_ref]
                        file_list_box -> gtk::ListBox {
                            set_selection_mode: gtk::SelectionMode::Single,
                            connect_row_selected[sender] => move |_, row| {
                                if let Some(r) = row {
                                    let idx = r.index() as usize;
                                    let _ = sender.input_sender().send(VaultMsg::SelectEntry(Some(idx)));
                                }
                            },
                            connect_row_activated[sender] => move |_, row| {
                                let _ = sender.input_sender().send(VaultMsg::ActivateEntry(row.index() as usize));
                            }
                        }
                    },

                    gtk::Box {
                        set_orientation: gtk::Orientation::Vertical,
                        set_width_request: 320,
                        add_css_class: "preview-pane",
                        #[watch]
                        set_visible: model.show_preview_pane,

                        gtk::Box {
                            set_orientation: gtk::Orientation::Horizontal,
                            gtk::Label {
                                set_hexpand: true,
                                set_xalign: 0.0,
                                #[watch]
                                set_text: &model.preview_name,
                                add_css_class: "error-dialog-title",
                                set_ellipsize: gtk::pango::EllipsizeMode::End,
                            },
                            gtk::Button {
                                set_label: "✕",
                                add_css_class: "ribbon-btn",
                                connect_clicked[sender] => move |_| {
                                    sender.input(VaultMsg::CloseQuickLook);
                                }
                            }
                        },

                        gtk::Label {
                            set_xalign: 0.0,
                            #[watch]
                            set_text: &model.preview_meta,
                            set_margin_bottom: 8,
                        },

                        gtk::Picture {
                            set_can_shrink: true,
                            set_height_request: 220,
                            #[watch]
                            set_visible: model.preview_has_image,
                            #[watch]
                            set_paintable: model.preview_texture.as_ref(),
                        },

                        gtk::ScrolledWindow {
                            set_vexpand: true,
                            #[watch]
                            set_visible: !model.preview_has_image,

                            gtk::TextView {
                                set_editable: false,
                                set_monospace: true,
                                add_css_class: "preview-text",
                                #[watch]
                                set_buffer: Some(&model.preview_buffer),
                            }
                        }
                    }
                },

                // --- 5. AGGREGATE STATUS & METRICS BAR ---
                gtk::Box {
                    set_orientation: gtk::Orientation::Horizontal,
                    set_spacing: 14,
                    add_css_class: "winzip-status-bar",

                    gtk::Label {
                        #[watch]
                        set_text: &format!(
                            "Files: {} | Raw: {} | Zstd Size: {} ({:.1}% ratio)",
                            model.stats.total_files,
                            format_bytes(model.stats.total_bytes),
                            format_bytes(model.stats.compressed_bytes),
                            if model.stats.total_bytes > 0 {
                                (model.stats.compressed_bytes as f64 / model.stats.total_bytes as f64) * 100.0
                            } else {
                                100.0
                            }
                        ),
                    },
                    gtk::Separator { set_orientation: gtk::Orientation::Vertical },
                    gtk::Label {
                        #[watch]
                        set_text: &format!("Current: {} items", model.entries.len()),
                    },
                    gtk::Separator { set_orientation: gtk::Orientation::Vertical },
                    gtk::Label {
                        set_hexpand: true,
                        set_xalign: 0.0,
                        #[watch]
                        set_text: &model.status,
                    },
                    gtk::ProgressBar {
                        set_width_request: 180,
                        #[watch]
                        set_fraction: model.progress_fraction,
                        #[watch]
                        set_visible: model.is_loading,
                    }
                }
            }
        }
    }

    fn init(
        _init: Self::Init,
        root: Self::Root,
        sender: ComponentSender<Self>,
    ) -> ComponentParts<Self> {
        let provider = CssProvider::new();
        provider.load_from_data(WINZIP_CSS);
        if let Some(display) = Display::default() {
            gtk::style_context_add_provider_for_display(
                &display,
                &provider,
                gtk::STYLE_PROVIDER_PRIORITY_APPLICATION,
            );
        }

        let entries = FactoryVecDeque::builder()
            .launch(gtk::ListBox::default())
            .forward(sender.input_sender(), |msg| match msg {
                EntryRowOutput::Open(idx) => VaultMsg::ActivateEntry(idx),
                EntryRowOutput::Preview(idx) => VaultMsg::ShowQuickLook(idx),
                EntryRowOutput::Extract(idx) => VaultMsg::PromptExtractFile(Some(idx)),
                EntryRowOutput::Rename(idx) => VaultMsg::PromptRenameSelected(Some(idx)),
                EntryRowOutput::Delete(idx) => VaultMsg::DeleteSelectedItem(Some(idx)),
            });

        let model = VaultModel {
            db: None,
            active_vault_path: None,
            current_folder_id: None,
            folder_path_stack: vec![(None, "/root".into())],
            entries,
            selected_index: None,
            stats: VaultStats::default(),
            is_loading: false,
            progress_fraction: 0.0,
            status: "Drag files here to compress & encrypt.".into(),
            search_query: String::new(),
            sort_column: SortColumn::Name,
            sort_direction: SortDirection::Asc,

            preview_name: String::new(),
            preview_meta: String::new(),
            preview_buffer: gtk::TextBuffer::new(None),
            preview_has_image: false,
            preview_texture: None,
            show_preview_pane: false,
            import_queue: VecDeque::new(),
        };

        let file_list_box = model.entries.widget();

        let formats = ContentFormats::for_type(FileList::static_type());
        let formats = formats
            .union(&ContentFormats::for_type(glib::types::Type::STRING))
            .union(&ContentFormats::for_type(gio::File::static_type()));

        let drop_target = DropTarget::builder()
            .formats(&formats)
            .actions(DragAction::COPY)
            .build();

        drop_target.connect_accept(|_, _| true);

        let s_drop = sender.clone();
        drop_target.connect_drop(move |_, value, _, _| {
            if let Ok(file_list) = value.get::<FileList>() {
                let paths: Vec<PathBuf> = file_list
                    .files()
                    .into_iter()
                    .filter_map(|f| f.path())
                    .map(clean_path)
                    .collect();

                if !paths.is_empty() {
                    s_drop.input(VaultMsg::ImportFilesList(paths));
                    return true;
                }
            }

            if let Ok(file) = value.get::<gio::File>() {
                if let Some(path) = file.path() {
                    s_drop.input(VaultMsg::ImportFilesList(vec![clean_path(path)]));
                    return true;
                }
            }

            if let Ok(uri_string) = value.get::<String>() {
                let paths = parse_uri_list(&uri_string);
                if !paths.is_empty() {
                    s_drop.input(VaultMsg::ImportFilesList(paths));
                    return true;
                }
            }

            if let Ok(g_str) = value.get::<glib::GString>() {
                let paths = parse_uri_list(g_str.as_str());
                if !paths.is_empty() {
                    s_drop.input(VaultMsg::ImportFilesList(paths));
                    return true;
                }
            }

            false
        });

        file_list_box.add_controller(drop_target);

        let widgets = view_output!();
        ComponentParts { model, widgets }
    }

    fn update(&mut self, msg: Self::Input, sender: ComponentSender<Self>) {
        match msg {
            VaultMsg::PromptCreateVault => {}
            VaultMsg::PromptOpenVault => {}
            VaultMsg::PromptAddFile => {}
            VaultMsg::PromptChangePassword => {}

            VaultMsg::ExecuteUnlock(path, password, is_new) => {
                self.is_loading = true;
                self.progress_fraction = 0.0;
                self.status = "Verifying SQLCipher & Zstd headers...".into();
                let s = sender.clone();

                tokio::task::spawn_blocking(move || {
                    match EncryptedDb::open(&path, &password) {
                        Ok(database) => {
                            let stats = database.get_vault_stats().unwrap_or_default();
                            let db_arc = Arc::new(Mutex::new(database));
                            s.input(VaultMsg::VaultUnlocked(db_arc, path, stats));
                        }
                        Err(e) => {
                            let msg = if is_new {
                                format!("Creation failed: {}", e)
                            } else {
                                "Incorrect password or corrupt file.".into()
                            };
                            s.input(VaultMsg::SetError(msg));
                        }
                    }
                });
            }

            VaultMsg::VaultUnlocked(db, path, stats) => {
                self.db = Some(db);
                self.active_vault_path = Some(path);
                self.current_folder_id = None;
                self.folder_path_stack = vec![(None, "/root".into())];
                self.stats = stats;
                self.is_loading = false;
                self.status = "Archive opened".into();
                sender.input(VaultMsg::LoadCurrentDirectory);
            }

            VaultMsg::LoadCurrentDirectory => {
                if let Some(db_arc) = self.db.clone() {
                    let folder_id = self.current_folder_id;
                    let search = if self.search_query.trim().is_empty() {
                        None
                    } else {
                        Some(self.search_query.clone())
                    };
                    let sort_c = self.sort_column;
                    let sort_d = self.sort_direction;
                    let s = sender.clone();
                    self.is_loading = true;

                    tokio::task::spawn_blocking(move || {
                        let result = run_on_db(&db_arc, move |db| {
                            let folders = if search.is_none() {
                                db.list_folders(folder_id)?
                            } else {
                                Vec::new()
                            };
                            let files = db.list_files_query(
                                folder_id,
                                search.as_deref(),
                                sort_c,
                                sort_d,
                                PAGE_SIZE,
                            )?;
                            Ok((folders, files))
                        });

                        match result {
                            Ok((folders, files)) => s.input(VaultMsg::DirectoryInitialized(folders, files)),
                            Err(e) => s.input(VaultMsg::SetError(e)),
                        }
                    });
                }
            }

            VaultMsg::DirectoryInitialized(folders, files) => {
                let mut guard = self.entries.guard();
                guard.clear();

                let mut current_idx = 0;
                for f in folders {
                    guard.push_back((ArchiveEntry::Folder(f), current_idx));
                    current_idx += 1;
                }

                for f in files {
                    guard.push_back((ArchiveEntry::File(f), current_idx));
                    current_idx += 1;
                }

                self.selected_index = None;
                self.is_loading = false;
                self.status = "Ready".into();
            }

            VaultMsg::SetSearchQuery(q) => {
                self.search_query = q;
                sender.input(VaultMsg::LoadCurrentDirectory);
            }

            VaultMsg::ToggleSort(col) => {
                if self.sort_column == col {
                    self.sort_direction = match self.sort_direction {
                        SortDirection::Asc => SortDirection::Desc,
                        SortDirection::Desc => SortDirection::Asc,
                    };
                } else {
                    self.sort_column = col;
                    self.sort_direction = SortDirection::Asc;
                }
                sender.input(VaultMsg::LoadCurrentDirectory);
            }

            VaultMsg::ExecuteRekey(new_pwd) => {
                if let Some(db_arc) = self.db.clone() {
                    let s = sender.clone();
                    self.is_loading = true;
                    tokio::task::spawn_blocking(move || {
                        let res = run_on_db(&db_arc, move |db| db.change_key(&new_pwd));
                        match res {
                            Ok(_) => s.input(VaultMsg::SetStatus("Archive password updated successfully!".into())),
                            Err(e) => s.input(VaultMsg::SetError(format!("Rekey failed: {}", e))),
                        }
                    });
                }
            }

            VaultMsg::TriggerCompact => {
                if let Some(db_arc) = self.db.clone() {
                    let s = sender.clone();
                    self.is_loading = true;
                    self.status = "Compacting database pages (VACUUM)...".into();
                    tokio::task::spawn_blocking(move || {
                        let res = run_on_db(&db_arc, |db| db.vacuum_compact());
                        match res {
                            Ok(_) => s.input(VaultMsg::SetStatus("Archive compacted successfully".into())),
                            Err(e) => s.input(VaultMsg::SetError(format!("Compact failed: {}", e))),
                        }
                    });
                }
            }

            VaultMsg::TriggerIntegrityTest => {
                if let Some(db_arc) = self.db.clone() {
                    let s = sender.clone();
                    self.is_loading = true;
                    self.status = "Checking BLAKE3 chunk hashes...".into();

                    tokio::task::spawn_blocking(move || {
                        let s_prog = s.clone();
                        let res = run_on_db(&db_arc, move |db| {
                            db.verify_integrity(|current, total, name| {
                                let pct = current as f64 / total as f64;
                                s_prog.input(VaultMsg::UpdateProgress(
                                    pct,
                                    format!("Verifying [{}/{}]: {}", current, total, name),
                                ));
                            })
                        });

                        match res {
                            Ok(results) => s.input(VaultMsg::IntegrityVerified(results)),
                            Err(e) => s.input(VaultMsg::SetError(format!("Integrity check aborted: {}", e))),
                        }
                    });
                }
            }

            VaultMsg::IntegrityVerified(results) => {
                self.is_loading = false;
                self.progress_fraction = 0.0;

                let corrupt: Vec<_> = results.iter().filter(|(_, ok)| !ok).collect();
                if corrupt.is_empty() {
                    self.status = format!("Integrity check passed! Verified {} files.", results.len());
                    spawn_error_dialog(
                        "Integrity Check: PASSED",
                        &format!("All {} files passed BLAKE3 checksum and Zstandard decompression verification without any errors.", results.len()),
                    );
                } else {
                    let err = format!("Integrity Check FAILED! {} corrupted file(s) found.", corrupt.len());
                    self.status = err.clone();
                    spawn_error_dialog("Integrity Warning", &err);
                }
            }

            VaultMsg::ShowQuickLook(idx) => {
                if let Some(row) = self.entries.get(idx) {
                    if let ArchiveEntry::File(meta) = &row.entry {
                        let id = meta.id;
                        let name = meta.name.clone();
                        let size = meta.size;
                        let comp_size = meta.compressed_size;
                        let hash = meta.checksum.clone();
                        let created_at = meta.created_at;
                        let is_img = is_previewable_image(&name);
                        let s = sender.clone();
                        let db_opt = self.db.clone();

                        self.is_loading = true;
                        tokio::task::spawn_blocking(move || {
                            if let Some(db_arc) = db_opt {
                                let data = run_on_db(&db_arc, move |db| {
                                    db.load_file_preview_bytes(id, 256 * 1024)
                                }).ok();

                                let summary = format!(
                                    "Size: {} (Zstd: {})\nHash: {}\nCreated: {}",
                                    format_bytes(size),
                                    format_bytes(comp_size),
                                    if hash.is_empty() { "None" } else { &hash[..12] },
                                    format_timestamp(created_at)
                                );

                                s.input(VaultMsg::PreviewLoaded(name, summary, data, is_img));
                            }
                        });
                    }
                }
            }

            VaultMsg::PreviewLoaded(name, meta, data, is_img) => {
                self.is_loading = false;
                self.preview_name = name;
                self.preview_meta = meta;
                self.show_preview_pane = true;

                if is_img && data.is_some() {
                    let bytes = glib::Bytes::from(&data.unwrap()[..]);
                    if let Ok(texture) = Texture::from_bytes(&bytes) {
                        self.preview_texture = Some(texture);
                        self.preview_has_image = true;
                    } else {
                        self.preview_has_image = false;
                        self.preview_buffer.set_text("[Image format decoding unsupported]");
                    }
                } else if let Some(d) = data {
                    self.preview_has_image = false;
                    let text = String::from_utf8(d)
                        .unwrap_or_else(|_| "[Binary Content - Text Preview Unavailable]".into());
                    self.preview_buffer.set_text(&text);
                } else {
                    self.preview_has_image = false;
                    self.preview_buffer.set_text("[No Preview Available]");
                }
            }

            VaultMsg::CloseQuickLook => {
                self.show_preview_pane = false;
                self.preview_texture = None;
            }

            VaultMsg::PromptExportVault => {
                if let Some(active_path) = self.active_vault_path.clone() {
                    let chooser = gtk::FileChooserNative::new(
                        Some("Backup Archive"),
                        gtk::Window::NONE,
                        gtk::FileChooserAction::Save,
                        Some("Backup"),
                        Some("Cancel"),
                    );
                    chooser.set_current_name("Backup.ivault");

                    let s = sender.clone();
                    chooser.connect_response(move |dialog, res| {
                        if res == gtk::ResponseType::Accept {
                            if let Some(file) = dialog.file() {
                                if let Some(raw_target) = file.path() {
                                    let target = clean_path(raw_target);
                                    let src = active_path.clone();
                                    let task_s = s.clone();

                                    tokio::task::spawn_blocking(move || {
                                        match std::fs::copy(&src, &target) {
                                            Ok(_) => task_s.input(VaultMsg::SetStatus("Backup complete".into())),
                                            Err(e) => task_s.input(VaultMsg::SetError(format!("Backup failed: {}", e))),
                                        }
                                    });
                                }
                            }
                        }
                    });
                    chooser.show();
                }
            }

            VaultMsg::LockVault => {
                self.db = None;
                self.active_vault_path = None;
                self.current_folder_id = None;
                self.folder_path_stack.clear();
                self.entries.guard().clear();
                self.selected_index = None;
                self.show_preview_pane = false;
                self.stats = VaultStats::default();
                self.import_queue.clear();
                self.status = "Archive locked".into();
            }

            VaultMsg::PromptCreateFolder => {
                let db_opt = self.db.clone();
                let parent_id = self.current_folder_id;
                let s = sender.clone();

                if let Some(db_arc) = db_opt {
                    tokio::task::spawn_blocking(move || {
                        let result = run_on_db(&db_arc, move |db| {
                            db.create_folder("NewFolder", parent_id)
                        });
                        match result {
                            Ok(_) => s.input(VaultMsg::LoadCurrentDirectory),
                            Err(e) => s.input(VaultMsg::SetError(e)),
                        }
                    });
                }
            }

            // --- INGESTION & PARALLEL DEDUPLICATION QUEUE ---
            VaultMsg::ImportFilesList(paths) => {
                if self.db.is_none() {
                    sender.input(VaultMsg::SetError("Unlock or create an archive before dropping items.".into()));
                    return;
                }

                let folder_id = self.current_folder_id;
                fn expand_paths(p: PathBuf, parent_fid: Option<Uuid>, out: &mut VecDeque<(PathBuf, Option<Uuid>)>) {
                    if p.is_dir() {
                        if let Ok(entries) = std::fs::read_dir(&p) {
                            for entry in entries.flatten() {
                                expand_paths(clean_path(entry.path()), parent_fid, out);
                            }
                        }
                    } else if p.is_file() {
                        out.push_back((p, parent_fid));
                    }
                }

                for path in paths {
                    expand_paths(path, folder_id, &mut self.import_queue);
                }

                sender.input(VaultMsg::ProcessNextImportQueue);
            }

            VaultMsg::ProcessNextImportQueue => {
                if let Some((path, folder_id)) = self.import_queue.pop_front() {
                    if let Some(db_arc) = self.db.clone() {
                        self.is_loading = true;
                        let s = sender.clone();

                        tokio::task::spawn_blocking(move || {
                            let file_hash_res = compute_file_hash_binary(&path);
                            match file_hash_res {
                                Ok(hash_bytes) => {
                                    let existing_file_opt = run_on_db(&db_arc, |db| {
                                        db.find_existing_file_by_hash(&hash_bytes)
                                    }).unwrap_or(None);

                                    if let Some(existing_name) = existing_file_opt {
                                        s.input(VaultMsg::PromptDuplicateEncountered {
                                            path,
                                            folder_id,
                                            existing_file_name: existing_name,
                                        });
                                    } else {
                                        s.input(VaultMsg::CommitSingleFileImport(path, folder_id));
                                    }
                                }
                                Err(e) => {
                                    s.input(VaultMsg::SetError(format!("Failed reading file {}: {}", path.display(), e)));
                                    s.input(VaultMsg::ProcessNextImportQueue);
                                }
                            }
                        });
                    }
                } else {
                    self.is_loading = false;
                    self.progress_fraction = 0.0;
                    self.status = "All items processed.".into();
                    if let Some(db_arc) = self.db.clone() {
                        if let Ok(stats) = run_on_db(&db_arc, |db| db.get_vault_stats()) {
                            self.stats = stats;
                        }
                    }
                    sender.input(VaultMsg::LoadCurrentDirectory);
                }
            }

            VaultMsg::PromptDuplicateEncountered { path, folder_id, existing_file_name } => {
                let file_name = path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();

                let s = sender.clone();
                let path_clone = path.clone();
                spawn_duplicate_alert_dialog(
                    &file_name,
                    &existing_file_name,
                    move |keep| {
                        s.input(VaultMsg::ResolveDuplicate {
                            path: path_clone.clone(),
                            folder_id,
                            keep,
                        });
                    },
                );
            }

            VaultMsg::ResolveDuplicate { path, folder_id, keep } => {
                if keep {
                    sender.input(VaultMsg::CommitSingleFileImport(path, folder_id));
                } else {
                    self.status = format!("Skipped duplicate: {}", path.file_name().unwrap_or_default().to_string_lossy());
                    sender.input(VaultMsg::ProcessNextImportQueue);
                }
            }

            VaultMsg::CommitSingleFileImport(path, folder_id) => {
                if let Some(db_arc) = self.db.clone() {
                    let s = sender.clone();
                    let file_name = path
                        .file_name()
                        .unwrap_or_default()
                        .to_string_lossy()
                        .to_string();

                    tokio::task::spawn_blocking(move || {
                        let s_prog = s.clone();
                        let res = run_on_db(&db_arc, move |db| {
                            db.stream_insert_file(&path, folder_id, |done, total| {
                                let pct = if total > 0 { done as f64 / total as f64 } else { 1.0 };
                                let msg = format!(
                                    "Deduplicating & Ingesting: {} ({} / {})",
                                    file_name,
                                    format_bytes(done),
                                    format_bytes(total)
                                );
                                s_prog.input(VaultMsg::UpdateProgress(pct, msg));
                            })
                        });

                        match res {
                            Ok(_) => {
                                s.input(VaultMsg::ProcessNextImportQueue);
                            }
                            Err(e) => {
                                s.input(VaultMsg::SetError(format!("Import error: {}", e)));
                                s.input(VaultMsg::ProcessNextImportQueue);
                            }
                        }
                    });
                }
            }

            VaultMsg::SelectEntry(idx) => {
                if let Some(i) = idx {
                    if i < self.entries.len() {
                        self.selected_index = Some(i);
                    } else {
                        self.selected_index = None;
                    }
                } else {
                    self.selected_index = None;
                }
            }

            VaultMsg::ActivateEntry(idx) => {
                if let Some(row) = self.entries.get(idx) {
                    match &row.entry {
                        ArchiveEntry::Folder(f) => {
                            let fid = f.id;
                            let fname = f.name.clone();
                            self.current_folder_id = Some(fid);
                            self.folder_path_stack.push((Some(fid), fname));
                            sender.input(VaultMsg::LoadCurrentDirectory);
                        }
                        ArchiveEntry::File(_) => {
                            sender.input(VaultMsg::ShowQuickLook(idx));
                        }
                    }
                }
            }

            VaultMsg::NavigateUp => {
                if self.folder_path_stack.len() > 1 {
                    self.folder_path_stack.pop();
                    self.current_folder_id = self.folder_path_stack.last().unwrap().0;
                    sender.input(VaultMsg::LoadCurrentDirectory);
                }
            }

            VaultMsg::PromptRenameSelected(target_idx) => {
                let chosen_idx = target_idx.or(self.selected_index);
                if let Some(idx) = chosen_idx {
                    if let Some(row) = self.entries.get(idx) {
                        let (id, name, is_folder) = match &row.entry {
                            ArchiveEntry::Folder(f) => (f.id, f.name.clone(), true),
                            ArchiveEntry::File(f) => (f.id, f.name.clone(), false),
                        };
                        let db_opt = self.db.clone();
                        let s = sender.clone();

                        spawn_entry_dialog("Rename", "New name:", &name, gtk::Window::NONE, move |new_name| {
                            if let Some(db_arc) = db_opt.clone() {
                                let task_s = s.clone();
                                let name_clone = new_name.clone();
                                tokio::task::spawn_blocking(move || {
                                    let result = run_on_db(&db_arc, move |db| {
                                        db.rename_item(id, &name_clone, is_folder)
                                    });
                                    match result {
                                        Ok(_) => task_s.input(VaultMsg::LoadCurrentDirectory),
                                        Err(e) => task_s.input(VaultMsg::SetError(e)),
                                    }
                                });
                            }
                        });
                    }
                }
            }

            VaultMsg::DeleteSelectedItem(target_idx) => {
                let chosen_idx = target_idx.or(self.selected_index);
                if let Some(idx) = chosen_idx {
                    if let Some(row) = self.entries.get(idx) {
                        let (id, is_folder) = match &row.entry {
                            ArchiveEntry::Folder(f) => (f.id, true),
                            ArchiveEntry::File(f) => (f.id, false),
                        };
                        let db_opt = self.db.clone();
                        let s = sender.clone();

                        if let Some(db_arc) = db_opt {
                            self.is_loading = true;
                            tokio::task::spawn_blocking(move || {
                                let result = run_on_db(&db_arc, move |db| {
                                    db.delete_item(id, is_folder)
                                });
                                match result {
                                    Ok(_) => s.input(VaultMsg::LoadCurrentDirectory),
                                    Err(e) => s.input(VaultMsg::SetError(e)),
                                }
                            });
                        }
                    }
                }
            }

            VaultMsg::PromptExtractFile(target_idx) => {
                let chosen_idx = target_idx.or(self.selected_index);
                if let Some(idx) = chosen_idx {
                    if let Some(row) = self.entries.get(idx) {
                        if let ArchiveEntry::File(meta) = &row.entry {
                            let id = meta.id;
                            let name = meta.name.clone();
                            let total_size = meta.size;
                            let db_opt = self.db.clone();

                            let chooser = gtk::FileChooserNative::new(
                                Some("Extract To"),
                                gtk::Window::NONE,
                                gtk::FileChooserAction::Save,
                                Some("Extract"),
                                Some("Cancel"),
                            );
                            chooser.set_current_name(&name);

                            let s = sender.clone();
                            chooser.connect_response(move |dialog, res| {
                                if res == gtk::ResponseType::Accept {
                                    if let Some(file) = dialog.file() {
                                        if let Some(raw_path) = file.path() {
                                            let path = clean_path(raw_path);
                                            if let Some(db_arc) = db_opt.clone() {
                                                let task_s = s.clone();
                                                task_s.input(VaultMsg::SetStatus(format!("Decompressing '{}'...", name)));

                                                tokio::task::spawn_blocking(move || {
                                                    let task_s_clone = task_s.clone();
                                                    let result = run_on_db(&db_arc, move |db| {
                                                        db.stream_export_file(id, &path, total_size, |done, total| {
                                                            let pct = done as f64 / total as f64;
                                                            let msg = format!("Decompressing: {} / {}", format_bytes(done), format_bytes(total));
                                                            task_s_clone.input(VaultMsg::UpdateProgress(pct, msg));
                                                        })
                                                    });

                                                    match result {
                                                        Ok(_) => task_s.input(VaultMsg::SetStatus("Extracted successfully".into())),
                                                        Err(e) => task_s.input(VaultMsg::SetError(e)),
                                                    }
                                                });
                                            }
                                        }
                                    }
                                }
                            });
                            chooser.show();
                        }
                    }
                }
            }

            VaultMsg::UpdateProgress(pct, msg) => {
                self.is_loading = true;
                self.progress_fraction = pct;
                self.status = msg;
            }

            VaultMsg::SetStatus(msg) => {
                self.status = msg;
                self.is_loading = false;
                self.progress_fraction = 0.0;
            }

            VaultMsg::SetError(err) => {
                self.status = format!("Error: {}", err);
                self.is_loading = false;
                self.progress_fraction = 0.0;
                spawn_error_dialog("Warning / Error", &err);
            }
        }
    }
}

// --- MODAL DIALOGS ---

fn spawn_duplicate_alert_dialog<F>(new_name: &str, existing_name: &str, on_decision: F)
where
    F: Fn(bool) + 'static,
{
    let dialog = gtk::Window::builder()
        .title("Duplicate File Detected")
        .modal(true)
        .default_width(420)
        .resizable(false)
        .build();

    let root_box = gtk::Box::new(gtk::Orientation::Vertical, 16);
    root_box.set_margin_all(20);

    let content_box = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    content_box.set_valign(gtk::Align::Center);

    let icon_label = gtk::Label::new(Some("📑"));
    icon_label.set_css_classes(&["entry-icon"]);
    icon_label.set_valign(gtk::Align::Start);

    let text_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    text_box.set_hexpand(true);

    let header_label = gtk::Label::new(Some("Duplicate File"));
    header_label.set_xalign(0.0);
    header_label.set_css_classes(&["error-dialog-title"]);

    let desc_label = gtk::Label::new(Some(&format!(
        "The file '{}' has the exact same cryptographic contents as '{}' already in this vault.\n\nDue to BLAKE3 deduplication, keeping it will reference the existing chunks without consuming additional storage.",
        new_name, existing_name
    )));
    desc_label.set_xalign(0.0);
    desc_label.set_wrap(true);
    desc_label.set_max_width_chars(44);
    desc_label.set_css_classes(&["error-dialog-msg"]);

    text_box.append(&header_label);
    text_box.append(&desc_label);

    content_box.append(&icon_label);
    content_box.append(&text_box);

    let btn_box = gtk::Box::new(gtk::Orientation::Horizontal, 10);
    btn_box.set_halign(gtk::Align::End);

    let skip_btn = gtk::Button::with_label("Skip File");
    skip_btn.set_css_classes(&["duplicate-btn-skip"]);

    let keep_btn = gtk::Button::with_label("Keep Duplicate");
    keep_btn.set_css_classes(&["duplicate-btn-keep"]);

    let on_dec = Arc::new(on_decision);

    let dlg_clone1 = dialog.clone();
    let dec_clone1 = on_dec.clone();
    skip_btn.connect_clicked(move |_| {
        dec_clone1(false);
        dlg_clone1.close();
    });

    let dlg_clone2 = dialog.clone();
    let dec_clone2 = on_dec.clone();
    keep_btn.connect_clicked(move |_| {
        dec_clone2(true);
        dlg_clone2.close();
    });

    btn_box.append(&skip_btn);
    btn_box.append(&keep_btn);

    root_box.append(&content_box);
    root_box.append(&btn_box);

    dialog.set_child(Some(&root_box));
    dialog.present();
}

fn spawn_error_dialog(title: &str, message: &str) {
    let dialog = gtk::Window::builder()
        .title(title)
        .modal(true)
        .default_width(380)
        .resizable(false)
        .build();

    let root_box = gtk::Box::new(gtk::Orientation::Vertical, 16);
    root_box.set_margin_all(20);

    let content_box = gtk::Box::new(gtk::Orientation::Horizontal, 14);
    content_box.set_valign(gtk::Align::Center);

    let icon_label = gtk::Label::new(Some("⚠️"));
    icon_label.set_css_classes(&["entry-icon"]);
    icon_label.set_valign(gtk::Align::Start);

    let text_box = gtk::Box::new(gtk::Orientation::Vertical, 6);
    text_box.set_hexpand(true);

    let header_label = gtk::Label::new(Some(title));
    header_label.set_xalign(0.0);
    header_label.set_css_classes(&["error-dialog-title"]);

    let desc_label = gtk::Label::new(Some(message));
    desc_label.set_xalign(0.0);
    desc_label.set_wrap(true);
    desc_label.set_max_width_chars(40);
    desc_label.set_css_classes(&["error-dialog-msg"]);

    text_box.append(&header_label);
    text_box.append(&desc_label);

    content_box.append(&icon_label);
    content_box.append(&text_box);

    let btn_box = gtk::Box::new(gtk::Orientation::Horizontal, 0);
    btn_box.set_halign(gtk::Align::End);

    let ok_btn = gtk::Button::with_label("OK");
    ok_btn.set_css_classes(&["error-btn"]);

    let dlg_clone = dialog.clone();
    ok_btn.connect_clicked(move |_| {
        dlg_clone.close();
    });

    btn_box.append(&ok_btn);

    root_box.append(&content_box);
    root_box.append(&btn_box);

    dialog.set_child(Some(&root_box));
    dialog.present();
}

fn spawn_password_dialog<F>(
    title: &str,
    prompt: &str,
    parent: Option<&gtk::Window>,
    sender: ComponentSender<VaultModel>,
    on_submit: F,
) where
    F: Fn(String, ComponentSender<VaultModel>) + 'static,
{
    let dialog = gtk::Window::builder()
        .title(title)
        .modal(true)
        .default_width(360)
        .build();

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    let root_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
    root_box.set_margin_all(16);

    let label = gtk::Label::new(Some(prompt));
    label.set_xalign(0.0);
    let entry = gtk::PasswordEntry::new();
    entry.set_show_peek_icon(true);
    let btn = gtk::Button::with_label("OK");
    btn.add_css_class("ribbon-btn");

    root_box.append(&label);
    root_box.append(&entry);
    root_box.append(&btn);
    dialog.set_child(Some(&root_box));

    let dlg_clone = dialog.clone();
    btn.connect_clicked(move |_| {
        let text = entry.text().to_string();
        if !text.is_empty() {
            on_submit(text, sender.clone());
            dlg_clone.close();
        }
    });
    dialog.present();
}

fn spawn_entry_dialog<F>(
    title: &str,
    prompt: &str,
    initial_val: &str,
    parent: Option<&gtk::Window>,
    on_submit: F,
) where
    F: Fn(String) + 'static,
{
    let dialog = gtk::Window::builder()
        .title(title)
        .modal(true)
        .default_width(360)
        .build();

    if let Some(p) = parent {
        dialog.set_transient_for(Some(p));
    }

    let root_box = gtk::Box::new(gtk::Orientation::Vertical, 10);
    root_box.set_margin_all(16);

    let label = gtk::Label::new(Some(prompt));
    label.set_xalign(0.0);
    let entry = gtk::Entry::new();
    entry.set_text(initial_val);
    let btn = gtk::Button::with_label("OK");
    btn.add_css_class("ribbon-btn");

    root_box.append(&label);
    root_box.append(&entry);
    root_box.append(&btn);
    dialog.set_child(Some(&root_box));

    let dlg_clone = dialog.clone();
    btn.connect_clicked(move |_| {
        let text = entry.text().to_string();
        if !text.trim().is_empty() {
            on_submit(text);
            dlg_clone.close();
        }
    });
    dialog.present();
}

fn main() {
    let app = RelmApp::new("io.ironvault.enterprise.pro");
    app.run::<VaultModel>(());
}