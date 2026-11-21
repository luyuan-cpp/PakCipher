use eframe::egui;
use raw_window_handle::{HasDisplayHandle, RawDisplayHandle};

pub(crate) fn is_available(frame: &eframe::Frame) -> bool {
    matches!(
        frame.display_handle().map(|handle| handle.as_raw()),
        Ok(RawDisplayHandle::Windows(_) | RawDisplayHandle::AppKit(_) | RawDisplayHandle::Xlib(_))
    )
}

pub(crate) fn show_zone(ui: &mut egui::Ui, supported: bool) -> egui::Rect {
    let (area, _) = ui.allocate_exact_size(
        egui::vec2(ui.available_width(), 148.0),
        egui::Sense::hover(),
    );
    let visuals = ui.visuals();
    ui.painter().rect(
        area,
        6.0,
        visuals.faint_bg_color,
        visuals.widgets.noninteractive.bg_stroke,
        egui::StrokeKind::Inside,
    );
    let message = if !ui.is_enabled() {
        "Wait for the operation to finish"
    } else if supported {
        "Drop a folder here\nto select or replace it"
    } else {
        "Use Browse… to select a folder\nin this desktop session"
    };
    ui.painter().text(
        area.center(),
        egui::Align2::CENTER_CENTER,
        message,
        egui::FontId::proportional(14.0),
        visuals.text_color(),
    );
    area
}

pub(crate) fn folder(files: &[egui::DroppedFile]) -> Result<&str, &'static str> {
    let [file] = files else {
        return Err("Drop one folder at a time.");
    };
    let path = file
        .path
        .as_deref()
        .filter(|path| path.is_dir())
        .ok_or("Drop an existing folder.")?;
    path.to_str()
        .ok_or("This folder path is not valid Unicode.")
}

// winit's desktop file-drop events supply paths but no cursor coordinates.
#[cfg(target_os = "windows")]
pub(crate) fn cursor_position(frame: &eframe::Frame, ctx: &egui::Context) -> Option<egui::Pos2> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    use windows_sys::Win32::{
        Foundation::POINT, Graphics::Gdi::ScreenToClient, UI::WindowsAndMessaging::GetCursorPos,
    };

    let RawWindowHandle::Win32(handle) = frame.window_handle().ok()?.as_raw() else {
        return None;
    };
    let mut point = POINT { x: 0, y: 0 };
    // The HWND remains valid while the borrowed Frame is being updated.
    unsafe {
        if GetCursorPos(&mut point) == 0 || ScreenToClient(handle.hwnd.get() as _, &mut point) == 0
        {
            return None;
        }
    }
    let scale = ctx.pixels_per_point();
    Some(egui::pos2(point.x as f32 / scale, point.y as f32 / scale))
}

#[cfg(target_os = "macos")]
pub(crate) fn cursor_position(frame: &eframe::Frame, ctx: &egui::Context) -> Option<egui::Pos2> {
    use objc2_app_kit::NSView;
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let RawWindowHandle::AppKit(handle) = frame.window_handle().ok()?.as_raw() else {
        return None;
    };
    // eframe updates on AppKit's main thread and owns the NSView for the lifetime of the Frame.
    let (x, y) = unsafe {
        let view = handle.ns_view.cast::<NSView>().as_ref();
        let window = view.window()?;
        let point = view.convertPoint_fromView(window.mouseLocationOutsideOfEventStream(), None);
        let bounds = view.bounds();
        let x = point.x - bounds.origin.x;
        let y = point.y - bounds.origin.y;
        (
            x,
            if view.isFlipped() {
                y
            } else {
                bounds.size.height - y
            },
        )
    };
    let scale = ctx.zoom_factor();
    Some(egui::pos2(x as f32 / scale, y as f32 / scale))
}

#[cfg(target_os = "linux")]
pub(crate) fn cursor_position(frame: &eframe::Frame, ctx: &egui::Context) -> Option<egui::Pos2> {
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let RawDisplayHandle::Xlib(display) = frame.display_handle().ok()?.as_raw() else {
        return None;
    };
    let RawWindowHandle::Xlib(window) = frame.window_handle().ok()?.as_raw() else {
        return None;
    };
    let display = display.display?;
    let xlib = x11_dl::xlib::Xlib::open().ok()?;
    let (mut root, mut child, mut root_x, mut root_y, mut window_x, mut window_y, mut mask) =
        (0, 0, 0, 0, 0, 0, 0);
    // Reuse eframe's live display connection and window while the Frame is borrowed.
    let same_screen = unsafe {
        (xlib.XQueryPointer)(
            display.as_ptr().cast(),
            window.window,
            &mut root,
            &mut child,
            &mut root_x,
            &mut root_y,
            &mut window_x,
            &mut window_y,
            &mut mask,
        )
    };
    let scale = ctx.pixels_per_point();
    (same_screen != 0).then(|| egui::pos2(window_x as f32 / scale, window_y as f32 / scale))
}

#[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
pub(crate) fn cursor_position(_frame: &eframe::Frame, _ctx: &egui::Context) -> Option<egui::Pos2> {
    None
}
