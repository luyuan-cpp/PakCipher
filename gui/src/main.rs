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
use pakcipher_core::{load_private_key, load_public_key, pack_folder, unpack_packet};
use zeroize::Zeroizing;

#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Page {
    #[default]
    Encrypt,
    Decrypt,
    About,
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
    passphrase: Zeroizing<String>,
    job: Option<Job>,
    status: Option<(Page, bool, String)>,
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll();
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("PakCipher");
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.page, Page::Encrypt, "Encrypt");
                ui.selectable_value(&mut self.page, Page::Decrypt, "Decrypt");
                ui.selectable_value(&mut self.page, Page::About, "About");
            });
            ui.separator();
            if self.page == Page::About {
                ui.label("Offline folder encryption and restoration.");
                ui.label("Encrypt with the recipient's OpenPGP RSA public key.");
                ui.label("Archive names and sizes are visible. File contents are encrypted.");
            } else {
                ui.add_enabled_ui(self.job.is_none(), |ui| self.show_form(ui));
            }

            if let Some(job) = &self.job {
                if job.page == self.page {
                    let operation = if job.page == Page::Encrypt {
                        "Encrypting…"
                    } else {
                        "Restoring…"
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
}

impl App {
    fn show_form(&mut self, ui: &mut egui::Ui) {
        let encrypting = self.page == Page::Encrypt;
        let form = if encrypting {
            &mut self.encrypt
        } else {
            &mut self.decrypt
        };
        let prior_default = default_output(Path::new(&form.source), encrypting);
        let use_default =
            form.output.is_empty() || prior_default.as_deref() == Some(Path::new(&form.output));
        let source = path_field(
            ui,
            if encrypting {
                "Source folder"
            } else {
                "Archive"
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
        if source && use_default {
            form.output = default_output(Path::new(&form.source), encrypting)
                .map(|path| path.to_string_lossy().into_owned())
                .unwrap_or_default();
        }
        let restored_name = default_output(Path::new(&form.source), false)
            .and_then(|path| path.file_name().map(|name| name.to_owned()))
            .unwrap_or_else(|| "restored".into());
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
        if !encrypting {
            ui.label("Private key passphrase (if protected)");
            let mut field = egui::TextEdit::singleline(&mut *self.passphrase)
                .password(true)
                .desired_width(f32::INFINITY)
                .show(ui);
            field.state.clear_undoer();
            field.state.store(ui.ctx(), field.response.id);
        }
        path_field(
            ui,
            if encrypting {
                "New archive"
            } else {
                "New output folder"
            },
            &mut form.output,
            || {
                if encrypting {
                    rfd::FileDialog::new()
                        .add_filter("PakCipher archive", &["pak"])
                        .save_file()
                } else {
                    rfd::FileDialog::new()
                        .pick_folder()
                        .map(|path| path.join(restored_name))
                }
            },
        );
        let ready = !form.source.is_empty() && !form.key.is_empty() && !form.output.is_empty();
        let label = if encrypting { "Encrypt" } else { "Restore" };
        if ui.add_enabled(ready, egui::Button::new(label)).clicked() {
            let source = PathBuf::from(&form.source);
            let key_file = PathBuf::from(&form.key);
            let output = PathBuf::from(&form.output);
            let passphrase = if encrypting {
                Zeroizing::default()
            } else {
                std::mem::take(&mut self.passphrase)
            };
            self.status = None;
            let (send, result) = mpsc::channel();
            let progress = Arc::new(Progress::default());
            let worker_progress = Arc::clone(&progress);
            match thread::Builder::new()
                .name("pakcipher".into())
                .spawn(move || {
                    let report = |done, total| {
                        worker_progress.total.store(total, Ordering::Relaxed);
                        worker_progress.done.store(done, Ordering::Relaxed);
                    };
                    let outcome = if encrypting {
                        load_public_key(&key_file)
                            .and_then(|key| pack_folder(&source, &key, &output, report))
                    } else {
                        load_private_key(&key_file).and_then(|key| {
                            unpack_packet(&source, &key, &passphrase, &output, report)
                        })
                    };
                    let _ = send.send(outcome);
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
    }

    fn poll(&mut self) {
        let Some(job) = &self.job else { return };
        let (success, message) = match job.result.try_recv() {
            Ok(Ok(())) => (true, "Finished successfully.".into()),
            Ok(Err(error)) => (false, error.to_string()),
            Err(TryRecvError::Disconnected) => (false, "The operation ended unexpectedly.".into()),
            Err(TryRecvError::Empty) => return,
        };
        self.status = Some((job.page, success, message));
        self.job = None;
    }
}

fn default_output(source: &Path, encrypting: bool) -> Option<PathBuf> {
    let mut name = if encrypting {
        source.file_name()?
    } else {
        source.file_stem()?
    }
    .to_os_string();
    name.push(if encrypting { ".pak" } else { "-restored" });
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
        viewport: egui::ViewportBuilder::default().with_inner_size([640.0, 360.0]),
        ..Default::default()
    };
    eframe::run_native(
        "PakCipher",
        options,
        Box::new(|_| Ok(Box::new(App::default()))),
    )
}
