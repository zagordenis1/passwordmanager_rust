//! `pwm-gui` — desktop GUI front-end for the password manager.
//!
//! Built on egui + eframe. Re-uses the [`passwordmanagerrs`] library
//! crate, so the encryption/DB logic and the CLI binary `pwm` remain
//! the single source of truth — this binary is purely a presentation
//! layer.
//!
//! # Build
//!
//! ```text
//! cargo build --release --features gui --bin pwm-gui
//! ```
//!
//! # CLI flags
//!
//! `pwm-gui [DB_PATH]` — path defaults to `users.db` (same as the CLI).
//!
//! # Auto-lock
//!
//! Honours `PM_AUTO_LOCK_SECONDS` exactly like the CLI:
//! * unset → 300 s
//! * `0`   → disabled
//! * `N`   → lock after N seconds of UI inactivity

#![deny(unsafe_code)]
#![warn(clippy::pedantic)]
// Pragmatic relaxations: the GUI module pushes a lot of `String`s into
// egui widgets and uses straightforward integer arithmetic — pedantic
// lints here would only obscure the code.
#![allow(
    clippy::too_many_lines,
    clippy::module_name_repetitions,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::cast_precision_loss,
    clippy::needless_pass_by_value,
    clippy::needless_continue,
    clippy::struct_excessive_bools,
    clippy::doc_markdown
)]

use std::env;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use eframe::egui;
use passwordmanagerrs::generator::{self, GeneratorError, PasswordPolicy, MAX_LENGTH, MIN_LENGTH};
use passwordmanagerrs::{DuplicateLogin, PasswordManager, UserRecord, DEFAULT_DB_PATH};
use zeroize::Zeroize;

const APP_TITLE: &str = "pwm — Менеджер паролів";
const DEFAULT_AUTO_LOCK_SECONDS: u64 = 300;
const AUTO_LOCK_ENV_VAR: &str = "PM_AUTO_LOCK_SECONDS";
const CLIPBOARD_CLEAR_SECONDS: u64 = 30;
const TOAST_DISPLAY_SECONDS: u64 = 4;

// ---------------------------------------------------------------------
// entry point
// ---------------------------------------------------------------------

fn main() -> eframe::Result<()> {
    // First positional arg is an optional DB path, mirroring the CLI's
    // `--db` flag default. We don't pull clap in just for one arg.
    let db_path = env::args()
        .nth(1)
        .map_or_else(|| PathBuf::from(DEFAULT_DB_PATH), PathBuf::from);

    let auto_lock_secs = read_auto_lock_seconds();

    let pm = match PasswordManager::new(&db_path) {
        Ok(pm) => pm,
        Err(e) => {
            // We can't show a nice egui error before the event loop is
            // up, so fall back to stderr + non-zero exit.
            eprintln!(
                "pwm-gui: failed to open database {}: {e:#}",
                db_path.display()
            );
            std::process::exit(1);
        }
    };

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title(APP_TITLE)
            .with_inner_size([960.0, 640.0])
            .with_min_inner_size([640.0, 420.0]),
        ..Default::default()
    };

    eframe::run_native(
        APP_TITLE,
        native_options,
        Box::new(move |cc| {
            install_ukrainian_fonts(&cc.egui_ctx);
            Box::new(PwmGuiApp::new(pm, db_path, auto_lock_secs))
        }),
    )
}

fn read_auto_lock_seconds() -> u64 {
    match env::var(AUTO_LOCK_ENV_VAR) {
        Ok(v) => match v.trim().parse::<i64>() {
            Ok(n) if n >= 0 => n as u64,
            _ => DEFAULT_AUTO_LOCK_SECONDS,
        },
        Err(_) => DEFAULT_AUTO_LOCK_SECONDS,
    }
}

/// egui's bundled `default_fonts` cover Latin and a useful subset of
/// Cyrillic for our prompts. We don't ship custom font files in this
/// repo (keeping the binary small is a stated goal), but we still
/// nudge the proportional family to a slightly larger default so the
/// Ukrainian diacritics have a touch more vertical room.
fn install_ukrainian_fonts(ctx: &egui::Context) {
    let mut style: egui::Style = (*ctx.style()).clone();
    for font_id in style.text_styles.values_mut() {
        font_id.size = (font_id.size * 1.05).round();
    }
    ctx.set_style(style);
}

// ---------------------------------------------------------------------
// state
// ---------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Screen {
    /// Either "set up master" (first-time) or "unlock".
    Login,
    /// Logged in: account list + details + modals.
    Main,
}

struct PwmGuiApp {
    pm: PasswordManager,
    db_path: PathBuf,

    screen: Screen,

    // Login screen state -------------------------------------------------
    login_pw: String,
    /// Confirmation field; only used during first-time setup.
    login_pw_confirm: String,
    login_err: Option<String>,

    // Main screen state --------------------------------------------------
    accounts: Vec<UserRecord>,
    selected_login: Option<String>,
    search: String,
    reveal_password: bool,

    // Modal: Add ---------------------------------------------------------
    add_open: bool,
    add_login: String,
    add_email: String,
    add_password: String,
    add_reveal: bool,
    add_policy: PasswordPolicy,
    add_err: Option<String>,

    // Modal: Edit (update password) -------------------------------------
    edit_open: bool,
    edit_login: String,
    edit_password: String,
    edit_reveal: bool,
    edit_policy: PasswordPolicy,
    edit_err: Option<String>,

    // Modal: Delete confirm ---------------------------------------------
    delete_open: bool,
    delete_login: String,

    // Modal: Change master ----------------------------------------------
    cm_open: bool,
    cm_old: String,
    cm_new: String,
    cm_confirm: String,
    cm_err: Option<String>,

    // Modal: Generator ---------------------------------------------------
    gen_open: bool,
    gen_policy: PasswordPolicy,
    gen_last: String,
    gen_err: Option<String>,

    // Modal: About -------------------------------------------------------
    about_open: bool,

    // Auto-lock + clipboard ---------------------------------------------
    auto_lock_secs: u64,
    last_activity: Instant,

    clipboard: Option<arboard::Clipboard>,
    /// When set, the clipboard will be wiped on the next update tick
    /// after this instant.
    clipboard_clear_at: Option<Instant>,

    // Status toast (bottom-right) ---------------------------------------
    toast: Option<(String, Instant)>,
}

impl PwmGuiApp {
    fn new(pm: PasswordManager, db_path: PathBuf, auto_lock_secs: u64) -> Self {
        Self {
            pm,
            db_path,
            screen: Screen::Login,
            login_pw: String::new(),
            login_pw_confirm: String::new(),
            login_err: None,
            accounts: Vec::new(),
            selected_login: None,
            search: String::new(),
            reveal_password: false,
            add_open: false,
            add_login: String::new(),
            add_email: String::new(),
            add_password: String::new(),
            add_reveal: false,
            add_policy: PasswordPolicy::default(),
            add_err: None,
            edit_open: false,
            edit_login: String::new(),
            edit_password: String::new(),
            edit_reveal: false,
            edit_policy: PasswordPolicy::default(),
            edit_err: None,
            delete_open: false,
            delete_login: String::new(),
            cm_open: false,
            cm_old: String::new(),
            cm_new: String::new(),
            cm_confirm: String::new(),
            cm_err: None,
            gen_open: false,
            gen_policy: PasswordPolicy::default(),
            gen_last: String::new(),
            gen_err: None,
            about_open: false,
            auto_lock_secs,
            last_activity: Instant::now(),
            clipboard: arboard::Clipboard::new().ok(),
            clipboard_clear_at: None,
            toast: None,
        }
    }

    fn first_time_setup(&self) -> bool {
        // Treat read errors as "needs setup" — the login form will
        // still surface a useful error when the user tries to act.
        !self.pm.has_master_password().unwrap_or(false)
    }

    fn note_activity(&mut self) {
        self.last_activity = Instant::now();
    }

    fn show_toast(&mut self, message: impl Into<String>) {
        self.toast = Some((message.into(), Instant::now()));
    }

    /// Wipe in-memory secret-ish UI strings. Called on lock + after
    /// every successful destructive action that contained a secret.
    fn zeroize_ui_secrets(&mut self) {
        // Rust's String::clear leaves the backing buffer allocated; we
        // overwrite first to make best-effort sure the bytes don't
        // linger. Not a hard guarantee (egui itself may have copies in
        // glyph atlases) — the actual security boundary is `pm.lock()`.
        for s in [
            &mut self.login_pw,
            &mut self.login_pw_confirm,
            &mut self.add_password,
            &mut self.edit_password,
            &mut self.cm_old,
            &mut self.cm_new,
            &mut self.cm_confirm,
            &mut self.gen_last,
        ] {
            // `zeroize::Zeroize` is implemented for `String` and overwrites
            // the backing buffer with zeros before clearing — same
            // best-effort guarantee as the CLI.
            s.zeroize();
        }
    }

    fn lock_now(&mut self) {
        self.pm.lock();
        self.zeroize_ui_secrets();
        self.screen = Screen::Login;
        self.selected_login = None;
        self.reveal_password = false;
        self.add_open = false;
        self.edit_open = false;
        self.delete_open = false;
        self.cm_open = false;
        self.gen_open = false;
        self.accounts.clear();
    }

    fn refresh_accounts(&mut self) {
        match self.pm.list_users() {
            Ok(rows) => self.accounts = rows,
            Err(e) => self.show_toast(format!("Не вдалося прочитати акаунти: {e}")),
        }
    }

    fn copy_to_clipboard(&mut self, text: &str, kind: &str) {
        match &mut self.clipboard {
            Some(cb) => match cb.set_text(text.to_string()) {
                Ok(()) => {
                    self.clipboard_clear_at =
                        Some(Instant::now() + Duration::from_secs(CLIPBOARD_CLEAR_SECONDS));
                    self.toast = Some((
                        format!(
                            "Скопійовано {kind} (буфер очиститься через {CLIPBOARD_CLEAR_SECONDS} с)"
                        ),
                        Instant::now(),
                    ));
                }
                Err(e) => self.show_toast(format!("Помилка копіювання: {e}")),
            },
            None => self.show_toast("Системний буфер обміну недоступний".to_string()),
        }
    }

    fn maybe_clear_clipboard(&mut self) {
        if let Some(deadline) = self.clipboard_clear_at {
            if Instant::now() >= deadline {
                if let Some(cb) = &mut self.clipboard {
                    // Best-effort: overwrite with empty string.
                    let _ = cb.set_text(String::new());
                }
                self.clipboard_clear_at = None;
            }
        }
    }

    fn maybe_auto_lock(&mut self, ctx: &egui::Context) {
        if self.auto_lock_secs == 0 || !self.pm.is_unlocked() {
            return;
        }
        let elapsed = self.last_activity.elapsed();
        let timeout = Duration::from_secs(self.auto_lock_secs);
        if elapsed >= timeout {
            self.lock_now();
            self.show_toast(format!(
                "Сесію заблоковано після {} с неактивності",
                self.auto_lock_secs
            ));
            ctx.request_repaint();
        } else if let Some(remaining) = timeout.checked_sub(elapsed) {
            // Wake up exactly when the deadline expires.
            ctx.request_repaint_after(remaining);
        }
    }
}

// ---------------------------------------------------------------------
// eframe::App
// ---------------------------------------------------------------------

impl eframe::App for PwmGuiApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.maybe_clear_clipboard();
        self.maybe_auto_lock(ctx);

        match self.screen {
            Screen::Login => self.render_login(ctx),
            Screen::Main => self.render_main(ctx),
        }

        self.render_toast(ctx);
    }

    fn on_exit(&mut self, _gl: Option<&eframe::glow::Context>) {
        // Best-effort: wipe clipboard on close if we still own it.
        if let Some(cb) = &mut self.clipboard {
            let _ = cb.set_text(String::new());
        }
        self.lock_now();
    }
}

// ---------------------------------------------------------------------
// login screen
// ---------------------------------------------------------------------

impl PwmGuiApp {
    fn render_login(&mut self, ctx: &egui::Context) {
        let first_time = self.first_time_setup();

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(60.0);
                ui.heading(APP_TITLE);
                ui.add_space(8.0);
                ui.label(format!("База: {}", self.db_path.display()));
                ui.add_space(24.0);

                let group_width = 380.0_f32.min(ui.available_width() - 40.0);
                ui.allocate_ui_with_layout(
                    egui::vec2(group_width, 0.0),
                    egui::Layout::top_down(egui::Align::Center),
                    |ui| {
                        ui.group(|ui| {
                            ui.set_min_width(group_width);
                            if first_time {
                                ui.heading("Створення майстер-пароля");
                                ui.add_space(8.0);
                                ui.label(
                                    "Майстер-пароль шифрує всю базу. Якщо ви його втратите — \
                                     відновити збережені паролі буде неможливо.",
                                );
                            } else {
                                ui.heading("Розблокування");
                                ui.add_space(8.0);
                                ui.label("Введіть майстер-пароль, щоб відкрити сховище.");
                            }
                            ui.add_space(12.0);

                            ui.label("Майстер-пароль:");
                            let pw = ui.add(
                                egui::TextEdit::singleline(&mut self.login_pw)
                                    .password(true)
                                    .desired_width(group_width - 20.0),
                            );
                            if pw.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                                self.try_login(first_time);
                            }
                            if first_time {
                                ui.add_space(6.0);
                                ui.label("Підтвердження:");
                                let cf = ui.add(
                                    egui::TextEdit::singleline(&mut self.login_pw_confirm)
                                        .password(true)
                                        .desired_width(group_width - 20.0),
                                );
                                if cf.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter))
                                {
                                    self.try_login(first_time);
                                }
                            }

                            ui.add_space(12.0);
                            ui.horizontal(|ui| {
                                let primary = if first_time {
                                    "Створити майстер-пароль"
                                } else {
                                    "Розблокувати"
                                };
                                if ui.button(primary).clicked() {
                                    self.try_login(first_time);
                                }
                                if ui.button("Очистити").clicked() {
                                    self.login_pw.clear();
                                    self.login_pw_confirm.clear();
                                    self.login_err = None;
                                }
                            });

                            if let Some(err) = &self.login_err {
                                ui.add_space(8.0);
                                ui.colored_label(egui::Color32::LIGHT_RED, err);
                            }
                        });
                    },
                );

                ui.add_space(16.0);
                ui.label(
                    egui::RichText::new(format!(
                        "Авто-лок: {}",
                        if self.auto_lock_secs == 0 {
                            "вимкнено".to_string()
                        } else {
                            format!("{} с неактивності", self.auto_lock_secs)
                        }
                    ))
                    .small()
                    .weak(),
                );
            });
        });
    }

    fn try_login(&mut self, first_time: bool) {
        self.login_err = None;
        if first_time {
            if self.login_pw.is_empty() {
                self.login_err = Some("Майстер-пароль не може бути порожнім.".to_string());
                return;
            }
            if self.login_pw != self.login_pw_confirm {
                self.login_err = Some("Паролі не співпадають.".to_string());
                return;
            }
            match self.pm.set_master_password(&self.login_pw) {
                Ok(()) => {
                    // After set_master_password the manager is NOT
                    // automatically unlocked — we follow the same
                    // policy as the CLI and call verify next.
                    match self.pm.verify_master_password(&self.login_pw) {
                        Ok(true) => self.enter_main_screen(),
                        Ok(false) => {
                            self.login_err =
                                Some("Внутрішня помилка: щойно встановлений пароль не пройшов перевірку.".to_string());
                        }
                        Err(e) => self.login_err = Some(format!("Помилка: {e}")),
                    }
                }
                Err(e) => self.login_err = Some(format!("Не вдалося створити майстер-пароль: {e}")),
            }
        } else {
            if self.login_pw.is_empty() {
                self.login_err = Some("Введіть майстер-пароль.".to_string());
                return;
            }
            match self.pm.verify_master_password(&self.login_pw) {
                Ok(true) => self.enter_main_screen(),
                Ok(false) => self.login_err = Some("Невірний майстер-пароль.".to_string()),
                Err(e) => self.login_err = Some(format!("Помилка: {e}")),
            }
        }
    }

    fn enter_main_screen(&mut self) {
        self.zeroize_ui_secrets();
        self.note_activity();
        self.refresh_accounts();
        self.screen = Screen::Main;
    }
}

// ---------------------------------------------------------------------
// main screen
// ---------------------------------------------------------------------

impl PwmGuiApp {
    fn render_main(&mut self, ctx: &egui::Context) {
        // Any UI interaction this frame counts as activity.
        if ctx.input(|i| {
            i.events.iter().any(|e| {
                matches!(
                    e,
                    egui::Event::Key { .. }
                        | egui::Event::Text(_)
                        | egui::Event::PointerButton { .. }
                        | egui::Event::PointerMoved(_)
                        | egui::Event::Scroll(_)
                )
            })
        }) {
            self.note_activity();
        }

        self.render_top_bar(ctx);
        self.render_status_bar(ctx);
        self.render_accounts_panel(ctx);
        self.render_details_panel(ctx);

        self.render_add_modal(ctx);
        self.render_edit_modal(ctx);
        self.render_delete_modal(ctx);
        self.render_change_master_modal(ctx);
        self.render_generator_modal(ctx);
        self.render_about_modal(ctx);
    }

    fn render_top_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("top_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.heading("pwm");
                ui.separator();
                if ui.button("Додати акаунт").clicked() {
                    self.add_open = true;
                    self.add_login.clear();
                    self.add_email.clear();
                    self.add_password.clear();
                    self.add_err = None;
                }
                if ui.button("Генератор").clicked() {
                    self.gen_open = true;
                    self.gen_last.clear();
                    self.gen_err = None;
                }
                ui.separator();
                ui.label("Пошук:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.search)
                        .desired_width(220.0)
                        .hint_text("логін або email"),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("🔒 Заблокувати").clicked() {
                        self.lock_now();
                        self.show_toast("Заблоковано");
                        return;
                    }
                    ui.menu_button("Меню", |ui| {
                        if ui.button("Змінити майстер-пароль…").clicked() {
                            self.cm_open = true;
                            self.cm_old.clear();
                            self.cm_new.clear();
                            self.cm_confirm.clear();
                            self.cm_err = None;
                            ui.close_menu();
                        }
                        if ui.button("Експорт у JSON…").clicked() {
                            self.action_export();
                            ui.close_menu();
                        }
                        if ui.button("Імпорт із JSON…").clicked() {
                            self.action_import();
                            ui.close_menu();
                        }
                        ui.separator();
                        if ui.button("Про програму…").clicked() {
                            self.about_open = true;
                            ui.close_menu();
                        }
                    });
                });
            });
        });
    }

    fn render_status_bar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::bottom("status_bar").show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(format!("Акаунтів: {}", self.accounts.len()));
                ui.separator();
                ui.label(format!("База: {}", self.db_path.display()));
                ui.separator();
                let lock_label = if self.auto_lock_secs == 0 {
                    "Авто-лок: вимкнено".to_string()
                } else {
                    let remaining = Duration::from_secs(self.auto_lock_secs)
                        .saturating_sub(self.last_activity.elapsed());
                    format!("Авто-лок через {} с", remaining.as_secs())
                };
                ui.label(lock_label);
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if let Some(deadline) = self.clipboard_clear_at {
                        let remaining = deadline.saturating_duration_since(Instant::now());
                        ui.colored_label(
                            egui::Color32::LIGHT_BLUE,
                            format!("Буфер очиститься через {} с", remaining.as_secs()),
                        );
                    }
                });
            });
        });
    }

    fn filtered_accounts(&self) -> Vec<&UserRecord> {
        if self.search.trim().is_empty() {
            return self.accounts.iter().collect();
        }
        let q = self.search.to_ascii_lowercase();
        self.accounts
            .iter()
            .filter(|u| {
                u.login.to_ascii_lowercase().contains(&q)
                    || u.email
                        .as_deref()
                        .is_some_and(|e| e.to_ascii_lowercase().contains(&q))
            })
            .collect()
    }

    fn render_accounts_panel(&mut self, ctx: &egui::Context) {
        egui::SidePanel::left("accounts")
            .default_width(280.0)
            .resizable(true)
            .show(ctx, |ui| {
                ui.heading("Акаунти");
                ui.separator();
                let filtered = self.filtered_accounts();
                if filtered.is_empty() {
                    ui.label(
                        egui::RichText::new(if self.accounts.is_empty() {
                            "База порожня. Натисніть «Додати акаунт»."
                        } else {
                            "Нічого не знайдено."
                        })
                        .weak(),
                    );
                    return;
                }
                let logins: Vec<String> = filtered.iter().map(|u| u.login.clone()).collect();
                let emails: Vec<Option<String>> =
                    filtered.iter().map(|u| u.email.clone()).collect();
                drop(filtered);
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (login, email) in logins.into_iter().zip(emails) {
                        let is_selected = self.selected_login.as_deref() == Some(login.as_str());
                        let label = match email.as_deref() {
                            Some(e) if !e.is_empty() => format!("{login}\n  {e}"),
                            _ => login.clone(),
                        };
                        if ui.selectable_label(is_selected, label).clicked() {
                            self.selected_login = Some(login.clone());
                            self.reveal_password = false;
                        }
                    }
                });
            });
    }

    fn render_details_panel(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            let selected = self
                .selected_login
                .clone()
                .and_then(|l| self.accounts.iter().find(|u| u.login == l).cloned());
            match selected {
                None => {
                    ui.vertical_centered(|ui| {
                        ui.add_space(40.0);
                        ui.label(egui::RichText::new("Оберіть акаунт зі списку зліва").weak());
                    });
                }
                Some(rec) => self.render_record_details(ui, &rec),
            }
        });
    }

    fn render_record_details(&mut self, ui: &mut egui::Ui, rec: &UserRecord) {
        ui.heading(&rec.login);
        ui.add_space(4.0);
        ui.label(format!("Створено: {}", rec.created_at));
        ui.separator();

        egui::Grid::new("details_grid")
            .num_columns(3)
            .spacing([8.0, 8.0])
            .show(ui, |ui| {
                ui.label("Логін:");
                ui.label(&rec.login);
                if ui.button("Копіювати").clicked() {
                    let login = rec.login.clone();
                    self.copy_to_clipboard(&login, "логін");
                }
                ui.end_row();

                ui.label("Email:");
                ui.label(rec.email.as_deref().unwrap_or("—"));
                if let Some(e) = &rec.email {
                    if !e.is_empty() && ui.button("Копіювати").clicked() {
                        let email = e.clone();
                        self.copy_to_clipboard(&email, "email");
                    }
                } else {
                    ui.label("");
                }
                ui.end_row();

                ui.label("Пароль:");
                let shown = if self.reveal_password {
                    rec.password.clone()
                } else {
                    "•".repeat(rec.password.chars().count().min(32))
                };
                ui.add(
                    egui::TextEdit::singleline(&mut shown.clone())
                        .desired_width(360.0)
                        .interactive(false),
                );
                ui.horizontal(|ui| {
                    let label = if self.reveal_password {
                        "Сховати"
                    } else {
                        "Показати"
                    };
                    if ui.button(label).clicked() {
                        self.reveal_password = !self.reveal_password;
                    }
                    if ui.button("Копіювати").clicked() {
                        let pw = rec.password.clone();
                        self.copy_to_clipboard(&pw, "пароль");
                    }
                });
                ui.end_row();
            });

        ui.add_space(12.0);
        ui.horizontal(|ui| {
            if ui.button("Оновити пароль…").clicked() {
                self.edit_open = true;
                self.edit_login.clone_from(&rec.login);
                self.edit_password.clear();
                self.edit_err = None;
            }
            if ui
                .button(egui::RichText::new("Видалити…").color(egui::Color32::LIGHT_RED))
                .clicked()
            {
                self.delete_open = true;
                self.delete_login.clone_from(&rec.login);
            }
        });
    }
}

// ---------------------------------------------------------------------
// modals
// ---------------------------------------------------------------------

impl PwmGuiApp {
    fn render_add_modal(&mut self, ctx: &egui::Context) {
        if !self.add_open {
            return;
        }
        let mut close = false;
        let mut open = self.add_open;
        egui::Window::new("Додати акаунт")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label("Логін:");
                ui.add(egui::TextEdit::singleline(&mut self.add_login).desired_width(320.0));
                ui.label("Email (необов'язково):");
                ui.add(egui::TextEdit::singleline(&mut self.add_email).desired_width(320.0));
                ui.label("Пароль:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.add_password)
                            .password(!self.add_reveal)
                            .desired_width(280.0),
                    );
                    if ui
                        .button(if self.add_reveal {
                            "Сховати"
                        } else {
                            "Показати"
                        })
                        .clicked()
                    {
                        self.add_reveal = !self.add_reveal;
                    }
                });

                ui.collapsing("Згенерувати пароль", |ui| {
                    policy_editor(ui, &mut self.add_policy);
                    if ui.button("Згенерувати → у поле").clicked() {
                        match generator::generate_password(&self.add_policy) {
                            Ok(p) => self.add_password = p,
                            Err(e) => self.add_err = Some(format_gen_err(&e)),
                        }
                    }
                });

                if let Some(err) = &self.add_err {
                    ui.colored_label(egui::Color32::LIGHT_RED, err);
                }

                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Зберегти").clicked() {
                        match self.pm.create_user(
                            &self.add_login,
                            &self.add_email,
                            &self.add_password,
                        ) {
                            Ok(_) => {
                                self.refresh_accounts();
                                self.show_toast(format!("Додано: {}", self.add_login));
                                self.selected_login = Some(self.add_login.clone());
                                self.add_login.clear();
                                self.add_email.clear();
                                self.add_password.clear();
                                self.add_err = None;
                                close = true;
                            }
                            Err(e) => {
                                if e.downcast_ref::<DuplicateLogin>().is_some() {
                                    self.add_err =
                                        Some(format!("Акаунт «{}» вже існує.", self.add_login));
                                } else {
                                    self.add_err = Some(format!("Помилка: {e}"));
                                }
                            }
                        }
                    }
                    if ui.button("Скасувати").clicked() {
                        close = true;
                    }
                });
            });
        if close || !open {
            self.add_open = false;
        }
    }

    fn render_edit_modal(&mut self, ctx: &egui::Context) {
        if !self.edit_open {
            return;
        }
        let mut close = false;
        let mut open = self.edit_open;
        let title = format!("Оновити пароль для «{}»", self.edit_login);
        egui::Window::new(title)
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label("Новий пароль:");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.edit_password)
                            .password(!self.edit_reveal)
                            .desired_width(280.0),
                    );
                    if ui
                        .button(if self.edit_reveal {
                            "Сховати"
                        } else {
                            "Показати"
                        })
                        .clicked()
                    {
                        self.edit_reveal = !self.edit_reveal;
                    }
                });

                ui.collapsing("Згенерувати пароль", |ui| {
                    policy_editor(ui, &mut self.edit_policy);
                    if ui.button("Згенерувати → у поле").clicked() {
                        match generator::generate_password(&self.edit_policy) {
                            Ok(p) => self.edit_password = p,
                            Err(e) => self.edit_err = Some(format_gen_err(&e)),
                        }
                    }
                });

                if let Some(err) = &self.edit_err {
                    ui.colored_label(egui::Color32::LIGHT_RED, err);
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Зберегти").clicked() {
                        if self.edit_password.is_empty() {
                            self.edit_err = Some("Пароль не може бути порожнім.".to_string());
                            return;
                        }
                        match self
                            .pm
                            .update_password(&self.edit_login, &self.edit_password)
                        {
                            Ok(true) => {
                                self.refresh_accounts();
                                self.show_toast(format!("Оновлено пароль: {}", self.edit_login));
                                self.edit_password.clear();
                                close = true;
                            }
                            Ok(false) => {
                                self.edit_err =
                                    Some(format!("Акаунт «{}» не знайдено.", self.edit_login));
                            }
                            Err(e) => self.edit_err = Some(format!("Помилка: {e}")),
                        }
                    }
                    if ui.button("Скасувати").clicked() {
                        close = true;
                    }
                });
            });
        if close || !open {
            self.edit_open = false;
        }
    }

    fn render_delete_modal(&mut self, ctx: &egui::Context) {
        if !self.delete_open {
            return;
        }
        let mut close = false;
        let mut open = self.delete_open;
        egui::Window::new("Видалити акаунт")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label(format!(
                    "Видалити акаунт «{}»? Цю дію неможливо скасувати.",
                    self.delete_login
                ));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui
                        .button(
                            egui::RichText::new("Так, видалити").color(egui::Color32::LIGHT_RED),
                        )
                        .clicked()
                    {
                        match self.pm.delete_user(&self.delete_login) {
                            Ok(true) => {
                                self.refresh_accounts();
                                if self.selected_login.as_deref()
                                    == Some(self.delete_login.as_str())
                                {
                                    self.selected_login = None;
                                }
                                self.show_toast(format!("Видалено: {}", self.delete_login));
                                close = true;
                            }
                            Ok(false) => {
                                self.show_toast(format!(
                                    "Акаунт «{}» не знайдено",
                                    self.delete_login
                                ));
                                close = true;
                            }
                            Err(e) => self.show_toast(format!("Помилка: {e}")),
                        }
                    }
                    if ui.button("Скасувати").clicked() {
                        close = true;
                    }
                });
            });
        if close || !open {
            self.delete_open = false;
        }
    }

    fn render_change_master_modal(&mut self, ctx: &egui::Context) {
        if !self.cm_open {
            return;
        }
        let mut close = false;
        let mut open = self.cm_open;
        egui::Window::new("Змінити майстер-пароль")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.label("Поточний майстер-пароль:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.cm_old)
                        .password(true)
                        .desired_width(320.0),
                );
                ui.label("Новий майстер-пароль:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.cm_new)
                        .password(true)
                        .desired_width(320.0),
                );
                ui.label("Підтвердіть новий:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.cm_confirm)
                        .password(true)
                        .desired_width(320.0),
                );

                if let Some(err) = &self.cm_err {
                    ui.colored_label(egui::Color32::LIGHT_RED, err);
                }
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Змінити").clicked() {
                        if self.cm_new.is_empty() {
                            self.cm_err = Some("Новий пароль не може бути порожнім.".to_string());
                            return;
                        }
                        if self.cm_new != self.cm_confirm {
                            self.cm_err = Some("Нові паролі не співпадають.".to_string());
                            return;
                        }
                        match self.pm.change_master_password(&self.cm_old, &self.cm_new) {
                            Ok(n) => {
                                self.cm_old.clear();
                                self.cm_new.clear();
                                self.cm_confirm.clear();
                                self.cm_err = None;
                                self.show_toast(format!(
                                    "Майстер-пароль змінено. Перешифровано записів: {n}"
                                ));
                                close = true;
                            }
                            Err(e) => self.cm_err = Some(format!("Помилка: {e}")),
                        }
                    }
                    if ui.button("Скасувати").clicked() {
                        close = true;
                    }
                });
            });
        if close || !open {
            self.cm_open = false;
        }
    }

    fn render_generator_modal(&mut self, ctx: &egui::Context) {
        if !self.gen_open {
            return;
        }
        let mut close = false;
        let mut open = self.gen_open;
        egui::Window::new("Генератор паролів")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                policy_editor(ui, &mut self.gen_policy);
                ui.separator();
                ui.horizontal(|ui| {
                    if ui.button("Згенерувати").clicked() {
                        match generator::generate_password(&self.gen_policy) {
                            Ok(p) => {
                                self.gen_last = p;
                                self.gen_err = None;
                            }
                            Err(e) => self.gen_err = Some(format_gen_err(&e)),
                        }
                    }
                    if ui.button("Закрити").clicked() {
                        close = true;
                    }
                });
                if let Some(err) = &self.gen_err {
                    ui.colored_label(egui::Color32::LIGHT_RED, err);
                }
                ui.separator();
                ui.label("Останній згенерований:");
                ui.add(
                    egui::TextEdit::singleline(&mut self.gen_last.clone())
                        .desired_width(360.0)
                        .interactive(false),
                );
                if !self.gen_last.is_empty() && ui.button("Копіювати").clicked() {
                    let pw = self.gen_last.clone();
                    self.copy_to_clipboard(&pw, "пароль");
                }
            });
        if close || !open {
            self.gen_open = false;
        }
    }

    fn render_about_modal(&mut self, ctx: &egui::Context) {
        if !self.about_open {
            return;
        }
        let mut open = self.about_open;
        egui::Window::new("Про програму")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                ui.heading("pwm-gui");
                ui.label(format!("Версія: {}", env!("CARGO_PKG_VERSION")));
                ui.label("Графічний інтерфейс для pwm CLI.");
                ui.separator();
                ui.label("Шифрування: Argon2id KDF + Fernet (AES-128-CBC + HMAC-SHA256).");
                ui.label("База даних: SQLite (WAL, synchronous=FULL).");
                ui.label("CLI-бінарник `pwm` працює з тією самою базою.");
                ui.separator();
                ui.hyperlink_to(
                    "GitHub",
                    "https://github.com/zagordenis1/passwordmanager_rust",
                );
            });
        self.about_open = open;
    }
}

// ---------------------------------------------------------------------
// export / import (file dialogs)
// ---------------------------------------------------------------------

impl PwmGuiApp {
    fn action_export(&mut self) {
        let path = rfd::FileDialog::new()
            .set_title("Експорт у JSON")
            .set_file_name("passwords.json")
            .add_filter("JSON", &["json"])
            .save_file();
        let Some(path) = path else { return };
        match self.pm.export_to_json(&path) {
            Ok(n) => {
                let mut msg = format!("Експортовано {n} акаунтів у {}", path.display());
                if cfg!(unix) {
                    msg.push_str(" (режим 0600)");
                }
                self.show_toast(msg);
            }
            Err(e) => self.show_toast(format!("Помилка експорту: {e}")),
        }
    }

    fn action_import(&mut self) {
        let path = rfd::FileDialog::new()
            .set_title("Імпорт із JSON")
            .add_filter("JSON", &["json"])
            .pick_file();
        let Some(path) = path else { return };
        // Skip duplicates by default — same as the CLI default.
        match self.pm.import_from_json(&path, true) {
            Ok(n) => {
                self.refresh_accounts();
                self.show_toast(format!(
                    "Імпортовано {n} нових акаунтів (дублікати пропущено)"
                ));
            }
            Err(e) => {
                if let Some(dup) = e.downcast_ref::<DuplicateLogin>() {
                    self.show_toast(format!("Дублікат логіна «{}»: імпорт відкочено", dup.login));
                } else {
                    self.show_toast(format!("Помилка імпорту: {e}"));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------
// shared helpers
// ---------------------------------------------------------------------

fn policy_editor(ui: &mut egui::Ui, policy: &mut PasswordPolicy) {
    ui.horizontal(|ui| {
        ui.label("Довжина:");
        let mut len = policy.length as i64;
        if ui
            .add(
                egui::DragValue::new(&mut len)
                    .clamp_range(MIN_LENGTH as i64..=MAX_LENGTH as i64)
                    .speed(1),
            )
            .changed()
        {
            policy.length = len as usize;
        }
    });
    ui.checkbox(&mut policy.use_lower, "Малі літери (a-z)");
    ui.checkbox(&mut policy.use_upper, "Великі літери (A-Z)");
    ui.checkbox(&mut policy.use_digits, "Цифри (0-9)");
    ui.checkbox(&mut policy.use_symbols, "Символи");
    if policy.use_symbols {
        ui.horizontal(|ui| {
            ui.label("Набір символів:");
            ui.add(
                egui::TextEdit::singleline(&mut policy.symbols)
                    .desired_width(260.0)
                    .hint_text("!@#$%^&*…"),
            );
        });
    }
}

fn format_gen_err(e: &GeneratorError) -> String {
    match e {
        GeneratorError::LengthOutOfRange(n) => {
            format!("Довжина {n} поза діапазоном {MIN_LENGTH}–{MAX_LENGTH}.")
        }
        GeneratorError::NoClassesEnabled => "Жоден клас символів не увімкнено.".to_string(),
        GeneratorError::LengthShorterThanClasses { length, classes } => {
            format!("Довжина {length} менша за кількість обов'язкових класів {classes}.")
        }
    }
}

impl PwmGuiApp {
    fn render_toast(&mut self, ctx: &egui::Context) {
        let Some((msg, started)) = self.toast.clone() else {
            return;
        };
        let elapsed = started.elapsed();
        if elapsed > Duration::from_secs(TOAST_DISPLAY_SECONDS) {
            self.toast = None;
            return;
        }
        // Force a repaint when the toast should fade out.
        ctx.request_repaint_after(
            Duration::from_secs(TOAST_DISPLAY_SECONDS).saturating_sub(elapsed),
        );

        egui::Area::new(egui::Id::new("toast"))
            .anchor(egui::Align2::RIGHT_BOTTOM, egui::vec2(-16.0, -40.0))
            .order(egui::Order::Foreground)
            .show(ctx, |ui| {
                egui::Frame::popup(&ctx.style()).show(ui, |ui| {
                    ui.label(msg);
                });
            });
    }
}
