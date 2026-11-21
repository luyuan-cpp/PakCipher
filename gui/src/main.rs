#![cfg_attr(
    all(windows, not(debug_assertions), not(test)),
    windows_subsystem = "windows"
)]

use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        mpsc::{self, Receiver, TryRecvError},
        Arc,
    },
    thread,
    time::Duration,
};

use eframe::egui;
use pakcipher_core::{
    generate_key_pair, load_private_key, load_public_key, pack_folder, pack_folder_volumes,
    unpack_packet, VolumeSize,
};
use zeroize::{Zeroize, Zeroizing};

mod folder_drop;

const PUBLIC_KEY_PATH: &str = "public_key_path";
const PRIVATE_KEY_PATH: &str = "private_key_path";

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Page {
    #[default]
    Encrypt,
    Decrypt,
    Keys,
    About,
}

#[derive(Default)]
struct KeyForm {
    label: String,
    output: String,
    passphrase: Zeroizing<String>,
    confirmation: Zeroizing<String>,
}

#[derive(Default)]
struct Form {
    source: String,
    key: String,
    output: String,
}

#[derive(Default)]
struct Progress {
    done: AtomicU64,
    total: AtomicU64,
}

struct Job {
    page: Page,
    result: Receiver<pakcipher_core::Result<()>>,
    progress: Arc<Progress>,
}

#[derive(Default)]
struct App {
    page: Page,
    encrypt: Form,
    decrypt: Form,
    keys: KeyForm,
    min_volume_size: String,
    max_volume_size: String,
    passphrase: Zeroizing<String>,
    job: Option<Job>,
    close_after_job: bool,
    status: Option<(Page, bool, String)>,
    drop_error: Option<&'static str>,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        self.poll();
        if self.handle_close_request(ctx) {
            return;
        }
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("PakCipher");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.page, Page::Encrypt, "Encrypt");
                ui.selectable_value(&mut self.page, Page::Decrypt, "Decrypt");
                ui.selectable_value(&mut self.page, Page::Keys, "Generate keys");
                ui.selectable_value(&mut self.page, Page::About, "About");
            });
            ui.separator();
            if self.page == Page::About {
                ui.label("Offline folder encryption and restoration.");
                ui.label("Encrypt with the recipient's OpenPGP RSA public key.");
                ui.label("New archives encrypt paths, file sizes, and file contents.");
            } else if self.page == Page::Keys {
                ui.add_enabled_ui(self.job.is_none(), |ui| self.show_keys(ui));
            } else if self.page == Page::Encrypt {
                ui.add_enabled_ui(self.job.is_none(), |ui| {
                    ui.columns_const(|[form, drop_zone]| {
                        let supported = folder_drop::is_available(frame);
                        let area = folder_drop::show_zone(drop_zone, supported);
                        let position = if supported
                            && self.job.is_none()
                            && ctx.input(|input| !input.raw.dropped_files.is_empty())
                        {
                            folder_drop::cursor_position(frame, ctx)
                        } else {
                            None
                        };
                        let dropped = position.and_then(|position| {
                            ctx.input(|input| {
                                self.folder_dropped_at(area, position, &input.raw.dropped_files)
                            })
                        });
                        self.show_form(form, dropped);
                        if let Some(error) = self.drop_error {
                            drop_zone.colored_label(drop_zone.visuals().error_fg_color, error);
                        }
                    });
                });
            } else {
                ui.add_enabled_ui(self.job.is_none(), |ui| self.show_form(ui, None));
            }

            if let Some(job) = &self.job {
                if self.close_after_job {
                    ui.label("Closing after the current operation finishes…");
                }
                if job.page == self.page {
                    let operation = match job.page {
                        Page::Encrypt => "Encrypting…",
                        Page::Decrypt => "Restoring…",
                        Page::Keys => "Generating keys…",
                        Page::About => "",
                    };
                    ui.label(operation);
                    let total = job.progress.total.load(Ordering::Relaxed);
                    let done = job.progress.done.load(Ordering::Relaxed);
                    if total == 0 {
                        ui.spinner();
                    } else {
                        ui.add(
                            egui::ProgressBar::new(done as f32 / total as f32).show_percentage(),
                        );
                    }
                }
                ctx.request_repaint_after(Duration::from_millis(80));
            }
            if let Some((_, success, message)) = self
                .status
                .as_ref()
                .filter(|(page, _, _)| *page == self.page)
            {
                if *success {
                    ui.add(egui::ProgressBar::new(1.0).show_percentage());
                }
                let color = if *success {
                    ui.visuals().text_color()
                } else {
                    ui.visuals().error_fg_color
                };
                ui.colored_label(color, message);
            }
        });
    }

    fn save(&mut self, storage: &mut dyn eframe::Storage) {
        storage.set_string(PUBLIC_KEY_PATH, self.encrypt.key.clone());
        storage.set_string(PRIVATE_KEY_PATH, self.decrypt.key.clone());
    }

    fn persist_egui_memory(&self) -> bool {
        false
    }
}

impl App {
    fn with_storage(storage: Option<&dyn eframe::Storage>) -> Self {
        let mut app = Self::default();
        if let Some(storage) = storage {
            app.encrypt.key = storage.get_string(PUBLIC_KEY_PATH).unwrap_or_default();
            app.decrypt.key = storage.get_string(PRIVATE_KEY_PATH).unwrap_or_default();
        }
        app
    }

    fn folder_dropped_at(
        &mut self,
        area: egui::Rect,
        position: egui::Pos2,
        files: &[egui::DroppedFile],
    ) -> Option<String> {
        if !area.contains(position) {
            return None;
        }
        match folder_drop::folder(files) {
            Ok(path) => {
                self.drop_error = None;
                Some(path.to_owned())
            }
            Err(message) => {
                self.drop_error = Some(message);
                None
            }
        }
    }

    fn handle_close_request(&mut self, ctx: &egui::Context) -> bool {
        let close_requested = ctx.input(|input| input.viewport().close_requested());
        if self.job.is_some() {
            if close_requested {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                self.close_after_job = true;
            }
            return false;
        }
        if std::mem::take(&mut self.close_after_job) {
            if let Some((page, success, _)) = &self.status {
                if *success {
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                    return true;
                }
                self.page = *page;
                if close_requested {
                    ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                }
                return false;
            }
        }
        close_requested
    }

    fn show_keys(&mut self, ui: &mut egui::Ui) {
        let form = &mut self.keys;
        ui.label("Key label (included in the public key)");
        ui.add(egui::TextEdit::singleline(&mut form.label).desired_width(f32::INFINITY));
        path_field(
            ui,
            "New folder for public.key and private.key",
            &mut form.output,
            || {
                rfd::FileDialog::new()
                    .pick_folder()
                    .map(|parent| parent.join("pakcipher-keys"))
            },
        );
        password_field(ui, "Private key passphrase", &mut form.passphrase);
        password_field(ui, "Confirm passphrase", &mut form.confirmation);
        let matches = *form.passphrase == *form.confirmation;
        if !form.confirmation.is_empty() && !matches {
            ui.colored_label(ui.visuals().error_fg_color, "Passphrases do not match.");
        }
        let ready = !form.label.trim().is_empty()
            && !form.output.is_empty()
            && !form.passphrase.trim().is_empty()
            && matches;
        if ui
            .add_enabled(ready, egui::Button::new("Generate key pair"))
            .clicked()
        {
            let output = PathBuf::from(&form.output);
            let label = form.label.clone();
            let passphrase = std::mem::take(&mut form.passphrase);
            form.confirmation.zeroize();
            self.start_job(move |_| generate_key_pair(&output, &label, &passphrase));
        }
    }

    fn show_form(&mut self, ui: &mut egui::Ui, dropped: Option<String>) {
        let encrypting = self.page == Page::Encrypt;
        let form = if encrypting {
            &mut self.encrypt
        } else {
            &mut self.decrypt
        };
        let was_split = encrypting
            && (!self.min_volume_size.trim().is_empty() || !self.max_volume_size.trim().is_empty());
        let prior_default = default_output(Path::new(&form.source), encrypting, was_split);
        let use_default =
            form.output.is_empty() || prior_default.as_deref() == Some(Path::new(&form.output));
        let replaced_by_drop = dropped.is_some();
        if let Some(path) = dropped {
            form.source = path;
        }
        let source_edited = path_field(
            ui,
            if encrypting {
                "Source folder"
            } else {
                "Archive or first volume (part-000001.pak)"
            },
            &mut form.source,
            || {
                if encrypting {
                    rfd::FileDialog::new().pick_folder()
                } else {
                    rfd::FileDialog::new()
                        .add_filter("PakCipher archive", &["pak"])
                        .pick_file()
                }
            },
        );
        if encrypting && source_edited {
            self.drop_error = None;
        }
        path_field(
            ui,
            if encrypting {
                "RSA public key"
            } else {
                "RSA private key"
            },
            &mut form.key,
            || rfd::FileDialog::new().pick_file(),
        );
        if encrypting {
            ui.label("Volume sizes in MiB (leave both blank for one .pak)");
            ui.horizontal(|ui| {
                ui.label("Minimum");
                ui.add(
                    egui::TextEdit::singleline(&mut self.min_volume_size)
                        .desired_width(110.0)
                        .hint_text("Default: 1"),
                );
                ui.label("Maximum");
                ui.add(
                    egui::TextEdit::singleline(&mut self.max_volume_size)
                        .desired_width(110.0)
                        .hint_text("Default: 2 × min"),
                );
            });
        } else {
            password_field(
                ui,
                "Private key passphrase (if protected)",
                &mut self.passphrase,
            );
        }
        let min = self.min_volume_size.trim();
        let max = self.max_volume_size.trim();
        let split = encrypting && (!min.is_empty() || !max.is_empty());
        let sizes = if split {
            let parse = |value: &str| {
                (!value.is_empty())
                    .then(|| value.parse::<u64>())
                    .transpose()
                    .map_err(|_| pakcipher_core::Error::VolumeSize)
            };
            parse(min).and_then(|min| VolumeSize::from_mib_bounds(min, parse(max)?))
        } else {
            Ok(None)
        };
        let valid_sizes = sizes.is_ok();
        if !valid_sizes {
            ui.colored_label(
                ui.visuals().error_fg_color,
                "Enter whole MiB values with 1 ≤ minimum ≤ maximum.",
            );
        }
        let suggested = default_output(Path::new(&form.source), encrypting, split);
        if use_default && (replaced_by_drop || source_edited || was_split != split) {
            form.output = suggested
                .as_ref()
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
        }
        path_field(
            ui,
            if split {
                "New volume folder"
            } else if encrypting {
                "New archive"
            } else {
                "New output folder"
            },
            &mut form.output,
            || {
                if encrypting && !split {
                    rfd::FileDialog::new()
                        .add_filter("PakCipher archive", &["pak"])
                        .save_file()
                } else {
                    let name = suggested
                        .as_ref()
                        .and_then(|path| path.file_name())
                        .unwrap_or_else(|| {
                            std::ffi::OsStr::new(if split { "volumes" } else { "restored" })
                        });
                    rfd::FileDialog::new()
                        .pick_folder()
                        .map(|path| path.join(name))
                }
            },
        );
        let ready = valid_sizes
            && !form.source.is_empty()
            && !form.key.is_empty()
            && !form.output.is_empty();
        let label = if encrypting { "Encrypt" } else { "Restore" };
        if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
            let source = PathBuf::from(&form.source);
            let key_file = PathBuf::from(&form.key);
            let output = PathBuf::from(&form.output);
            let sizes = sizes.ok().flatten();
            let passphrase = if encrypting {
                Zeroizing::default()
            } else {
                std::mem::take(&mut self.passphrase)
            };
            self.start_job(move |worker_progress| {
                let report = |done, total| {
                    worker_progress.total.store(total, Ordering::Relaxed);
                    worker_progress.done.store(done, Ordering::Relaxed);
                };
                if encrypting {
                    load_public_key(&key_file).and_then(|key| {
                        if let Some(sizes) = sizes {
                            pack_folder_volumes(&source, &key, &output, sizes, report)
                        } else {
                            pack_folder(&source, &key, &output, report)
                        }
                    })
                } else {
                    load_private_key(&key_file)
                        .and_then(|key| unpack_packet(&source, &key, &passphrase, &output, report))
                }
            });
        }
    }

    fn start_job(
        &mut self,
        task: impl FnOnce(Arc<Progress>) -> pakcipher_core::Result<()> + Send + 'static,
    ) {
        self.status = None;
        let (send, result) = mpsc::channel();
        let progress = Arc::new(Progress::default());
        let worker_progress = Arc::clone(&progress);
        match thread::Builder::new()
            .name("pakcipher".into())
            .spawn(move || {
                let _ = send.send(task(worker_progress));
            }) {
            Ok(_) => {
                self.job = Some(Job {
                    page: self.page,
                    result,
                    progress,
                })
            }
            Err(error) => self.status = Some((self.page, false, error.to_string())),
        }
    }

    fn poll(&mut self) {
        let Some(job) = &self.job else { return };
        let (success, message) = match job.result.try_recv() {
            Ok(Ok(())) if job.page == Page::Keys => {
                (true, "Saved public.key and private.key.".into())
            }
            Ok(Ok(())) => (true, "Finished successfully.".into()),
            Ok(Err(error)) => (false, error.to_string()),
            Err(TryRecvError::Disconnected) => (false, "The operation ended unexpectedly.".into()),
            Err(TryRecvError::Empty) => return,
        };
        self.status = Some((job.page, success, message));
        self.job = None;
    }
}

fn password_field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    let mut field = egui::TextEdit::singleline(value)
        .password(true)
        .desired_width(f32::INFINITY)
        .show(ui);
    field.state.clear_undoer();
    field.state.store(ui.ctx(), field.response.id);
}

fn default_output(mut source: &Path, encrypting: bool, split: bool) -> Option<PathBuf> {
    if !encrypting
        && source
            .file_name()
            .is_some_and(|name| name == "part-000001.pak")
    {
        if let Some(folder) = source.parent().filter(|path| path.file_name().is_some()) {
            source = folder;
        }
    }
    let mut name = if encrypting {
        source.file_name()?
    } else {
        source.file_stem()?
    }
    .to_os_string();
    name.push(if split {
        "-volumes"
    } else if encrypting {
        ".pak"
    } else {
        "-restored"
    });
    Some(source.with_file_name(name))
}

fn path_field(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut String,
    browse: impl FnOnce() -> Option<PathBuf>,
) -> bool {
    ui.label(label);
    ui.horizontal(|ui| {
        let width = (ui.available_width() - 90.0).max(70.0);
        let changed = ui
            .add(egui::TextEdit::singleline(value).desired_width(width))
            .changed();
        if ui.button("Browse…").clicked() {
            if let Some(path) = browse() {
                *value = path.to_string_lossy().into_owned();
                return true;
            }
        }
        changed
    })
    .inner
}

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([740.0, 360.0])
            .with_min_inner_size([620.0, 360.0]),
        persist_window: false,
        ..Default::default()
    };
    eframe::run_native(
        "PakCipher",
        options,
        Box::new(|context| Ok(Box::new(App::with_storage(context.storage)))),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use eframe::App as _;

    #[derive(Default)]
    struct TestStorage(std::collections::HashMap<String, String>);

    impl eframe::Storage for TestStorage {
        fn get_string(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }

        fn set_string(&mut self, key: &str, value: String) {
            self.0.insert(key.to_owned(), value);
        }

        fn flush(&mut self) {}
    }

    #[test]
    fn restores_only_key_paths_and_preserves_cleared_fields() {
        let mut storage = TestStorage::default();
        let mut app = App::with_storage(Some(&storage));
        assert!(app.encrypt.key.is_empty() && app.decrypt.key.is_empty());
        app.encrypt.key = "keys/收件人 public.key".into();
        app.decrypt.key = "keys/我的 private.key".into();
        app.encrypt.source = "a folder".into();
        app.decrypt.output = "a restored folder".into();
        app.passphrase.push_str("a passphrase");

        app.save(&mut storage);
        assert_eq!(storage.0.len(), 2);
        let mut restored = App::with_storage(Some(&storage));
        assert_eq!(restored.encrypt.key, app.encrypt.key);
        assert_eq!(restored.decrypt.key, app.decrypt.key);
        assert!(restored.encrypt.source.is_empty());
        assert!(restored.decrypt.output.is_empty());
        assert!(restored.passphrase.is_empty());

        restored.encrypt.key.clear();
        restored.save(&mut storage);
        let restored = App::with_storage(Some(&storage));
        assert!(restored.encrypt.key.is_empty());
        assert_eq!(restored.decrypt.key, app.decrypt.key);
    }

    #[test]
    fn folder_drop_replaces_source_and_updates_only_suggested_output() {
        let temp = tempfile::tempdir().unwrap();
        let first = temp.path().join("first");
        let second = temp.path().join("second");
        let ordinary_file = temp.path().join("file.txt");
        std::fs::create_dir(&first).unwrap();
        std::fs::create_dir(&second).unwrap();
        std::fs::write(&ordinary_file, b"not a folder").unwrap();
        let event = |path| egui::DroppedFile {
            path: Some(path),
            ..Default::default()
        };
        let area = egui::Rect::from_min_max(egui::pos2(100.0, 10.0), egui::pos2(200.0, 75.0));
        let mut app = App::default();
        assert!(app
            .folder_dropped_at(area, egui::Pos2::ZERO, &[event(first.clone())])
            .is_none());
        assert!(app.drop_error.is_none());
        assert!(app
            .folder_dropped_at(area, area.center(), &[event(ordinary_file)])
            .is_none());
        assert!(app
            .folder_dropped_at(
                area,
                area.center(),
                &[event(first.clone()), event(second.clone())]
            )
            .is_none());
        assert!(app.drop_error.is_some());

        let ctx = egui::Context::default();
        let drop_folder = |app: &mut App, path| {
            let dropped = app.folder_dropped_at(area, area.center(), &[event(path)]);
            let _ = ctx.run(egui::RawInput::default(), |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.show_form(ui, dropped.clone()));
            });
        };
        drop_folder(&mut app, first.clone());
        assert_eq!(Path::new(&app.encrypt.source), first);
        assert_eq!(Path::new(&app.encrypt.output), first.with_extension("pak"));
        assert!(app.drop_error.is_none());
        drop_folder(&mut app, second.clone());
        assert_eq!(Path::new(&app.encrypt.source), second);
        assert_eq!(Path::new(&app.encrypt.output), second.with_extension("pak"));
        app.encrypt.output = "chosen.pak".into();
        drop_folder(&mut app, first.clone());
        assert_eq!(Path::new(&app.encrypt.source), first);
        assert_eq!(app.encrypt.output, "chosen.pak");
    }

    #[test]
    fn closing_waits_for_success_and_keeps_failures_visible() {
        for outcome in [Ok(()), Err(pakcipher_core::Error::OutputInSource)] {
            let success = outcome.is_ok();
            let (send, result) = mpsc::channel();
            let mut app = App {
                job: Some(Job {
                    page: Page::Encrypt,
                    result,
                    progress: Arc::default(),
                }),
                ..App::default()
            };
            let ctx = egui::Context::default();
            let mut input = egui::RawInput::default();
            let root = egui::ViewportId::ROOT;
            input
                .viewports
                .get_mut(&root)
                .unwrap()
                .events
                .push(egui::ViewportEvent::Close);
            let output = ctx.run(input, |ctx| {
                app.poll();
                assert!(!app.handle_close_request(ctx));
            });
            assert!(output.viewport_output[&root]
                .commands
                .iter()
                .any(|cmd| matches!(cmd, egui::ViewportCommand::CancelClose)));

            let output = ctx.run(egui::RawInput::default(), |ctx| {
                assert!(!app.handle_close_request(ctx));
            });
            assert!(!output.viewport_output[&root]
                .commands
                .iter()
                .any(|cmd| matches!(cmd, egui::ViewportCommand::Close)));

            app.page = Page::About;
            send.send(outcome).unwrap();
            let output = ctx.run(egui::RawInput::default(), |ctx| {
                app.poll();
                assert_eq!(app.handle_close_request(ctx), success);
            });
            assert_eq!(
                output.viewport_output[&root]
                    .commands
                    .iter()
                    .any(|cmd| matches!(cmd, egui::ViewportCommand::Close)),
                success
            );
            assert!(app.job.is_none());
            assert!(!app.close_after_job);
            assert!(success || app.page == Page::Encrypt);
        }
    }
}
