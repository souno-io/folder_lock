//! Modern Win32 dialog UI with DWM/Dark Mode/rounded corners styling.
//!
//! Features:
//!  - DWM extended frame → immersive dark title bar + rounded corners (Win11)
//!  - Custom white/light-gray dialog background
//!  - Large Segoe UI typography with hierarchy
//!  - Group box around password fields
//!  - MessageBox for notifications / confirmations
//!  - PE-embedded icon in title bar
//!
//! Win32 structures use their canonical PascalCase/camelCase field names.
#![allow(non_snake_case, dead_code)]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

// ══════════════════════════════════════════════════════════════════ type aliases

type Hwnd = *mut std::ffi::c_void;
type Hinst = *mut std::ffi::c_void;
type Hglobal = *mut std::ffi::c_void;
type Hbrush = *mut std::ffi::c_void;
type Hicon = *mut std::ffi::c_void;
type Lpdlgproc = Option<unsafe extern "system" fn(Hwnd, u32, usize, isize) -> isize>;

// ═══════════════════════════════════════════════════════════════════ FFI imports

#[link(name = "user32")]
unsafe extern "system" {
    fn DialogBoxIndirectParamW(
        hInstance: Hinst, lpTemplate: *const DlgTemplate, hWndParent: Hwnd,
        lpDialogFunc: Lpdlgproc, dwInitParam: isize) -> isize;
    fn EndDialog(hDlg: Hwnd, nResult: isize);
    fn GetDlgItemTextW(hDlg: Hwnd, nIDDlgItem: i32, lpString: *mut u16, cchMax: i32) -> i32;
    fn SetWindowTextW(hWnd: Hwnd, lpString: *const u16);
    fn GetDlgItem(hDlg: Hwnd, nIDDlgItem: i32) -> Hwnd;
    fn LoadIconW(hInstance: Hinst, lpIconName: *const u16) -> Hicon;
    fn SendMessageW(hWnd: Hwnd, msg: u32, wParam: usize, lParam: isize) -> isize;
    fn DestroyIcon(hIcon: Hicon) -> i32;
    fn MessageBoxW(hWnd: Hwnd, lpText: *const u16, lpCaption: *const u16, uType: u32) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetModuleHandleW(lpModuleName: *const u16) -> Hinst;
    fn GlobalAlloc(uFlags: u32, dwBytes: usize) -> Hglobal;
    fn GlobalFree(hMem: Hglobal) -> Hglobal;
}

// ════════════════════════════════════════════════════════════ runtime-loaded FFI

/// Dynamically resolve a function pointer from a system DLL (which is always
/// already loaded). Returns a null pointer on failure.
macro_rules! dynfn {
    ($dll:expr, $fn_name:expr) => {{
        static ONCE: std::sync::Once = std::sync::Once::new();
        static mut PTR: *mut std::ffi::c_void = std::ptr::null_mut();
        ONCE.call_once(|| {
            let dll_name = concat!($dll, "\0");
            let fn_name = concat!($fn_name, "\0");
            let m = unsafe { LoadLibraryA(dll_name.as_ptr()) };
            if !m.is_null() {
                unsafe { PTR = GetProcAddress(m, fn_name.as_ptr()); }
            }
        });
        unsafe { std::mem::transmute::<*mut std::ffi::c_void, _>(PTR) }
    }};
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryA(lpLibFileName: *const u8) -> Hinst;
    fn GetProcAddress(hModule: Hinst, lpProcName: *const u8) -> *mut std::ffi::c_void;
}

// Type-safe wrappers for dynamically-loaded DWM/theming functions.
fn dwm_extend_frame(hWnd: Hwnd, margins: &Margins) -> i32 {
    let f: unsafe extern "system" fn(Hwnd, *const Margins) -> i32 =
        dynfn!("dwmapi.dll", "DwmExtendFrameIntoClientArea");
    unsafe { f(hWnd, margins) }
}
fn dwm_set_attr(hWnd: Hwnd, attr: u32, val: *const std::ffi::c_void, size: u32) -> i32 {
    let f: unsafe extern "system" fn(Hwnd, u32, *const std::ffi::c_void, u32) -> i32 =
        dynfn!("dwmapi.dll", "DwmSetWindowAttribute");
    unsafe { f(hWnd, attr, val, size) }
}
fn set_win_theme(hWnd: Hwnd, a: *const u16, b: *const u16) -> i32 {
    let f: unsafe extern "system" fn(Hwnd, *const u16, *const u16) -> i32 =
        dynfn!("uxtheme.dll", "SetWindowTheme");
    unsafe { f(hWnd, a, b) }
}

#[link(name = "gdi32")]
unsafe extern "system" {
    fn CreateSolidBrush(color: u32) -> Hbrush;
    fn DeleteObject(ho: *mut std::ffi::c_void) -> i32;
    fn SetBkColor(hdc: *mut std::ffi::c_void, color: u32) -> u32;
    fn SetTextColor(hdc: *mut std::ffi::c_void, color: u32) -> u32;
    fn GetStockObject(i: i32) -> *mut std::ffi::c_void;
}

#[link(name = "user32")]
unsafe extern "system" {
    fn GetDC(hWnd: Hwnd) -> *mut std::ffi::c_void;
    fn ReleaseDC(hWnd: Hwnd, hDC: *mut std::ffi::c_void) -> i32;
    fn GetClientRect(hWnd: Hwnd, lpRect: *mut Rect) -> i32;
}

// ═══════════════════════════════════════════════════════════════ structs / packs

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DlgTemplate { style: u32, dwExtendedStyle: u32, cdit: u16, x: i16, y: i16, cx: i16, cy: i16 }

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct DlgItemTemplate {
    style: u32, dwExtendedStyle: u32, x: i16, y: i16, cx: i16, cy: i16, id: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Rect { left: i32, top: i32, right: i32, bottom: i32 }

#[repr(C)]
#[derive(Clone, Copy)]
struct Margins { cxLeftWidth: i32, cxRightWidth: i32, cyTopHeight: i32, cyBottomHeight: i32 }

// ════════════════════════════════════════════════════════════════ style constants

const WS_VISIBLE: u32        = 0x1000_0000;
const WS_CHILD: u32          = 0x4000_0000;
const WS_TABSTOP: u32        = 0x0001_0000;
const WS_GROUP: u32          = 0x0002_0000;
const WS_BORDER: u32         = 0x0080_0000;
const WS_EX_CLIENTEDGE: u32  = 0x0000_0200;
const WS_EX_COMPOSITED: u32  = 0x0200_0000;
const DS_MODALFRAME: u32     = 0x0000_0080;
const DS_CENTER: u32         = 0x0000_0800;
const DS_SETFONT: u32        = 0x0000_0040;
const ES_AUTOHSCROLL: u32    = 0x0080;
const ES_PASSWORD: u32       = 0x0020;
const BS_DEFPUSHBUTTON: u32  = 0x0001;
const BS_AUTORADIOBUTTON: u32 = 0x0009;
const BS_GROUPBOX: u32       = 0x0007;
const SS_LEFT: u32           = 0x0000;
const SS_CENTER: u32         = 0x0001;

const CLASS_BUTTON: u16 = 0x0080;
const CLASS_EDIT: u16   = 0x0081;
const CLASS_STATIC: u16 = 0x0082;

const WM_COMMAND: u32    = 0x0111;
const WM_INITDIALOG: u32 = 0x0110;
const WM_CTLCOLORDLG: u32 = 0x0136;
const WM_CTLCOLORSTATIC: u32 = 0x0138;
const WM_CTLCOLOREDIT: u32 = 0x0133;
const WM_CTLCOLORBTN: u32  = 0x0135;
const WM_PAINT: u32     = 0x000F;
const WM_SETICON: u32   = 0x0080;
const BN_CLICKED: u16   = 0;

const ICON_BIG: usize = 1;
const ICON_SMALL: usize = 0;

// DWM attributes
const DWMWA_WINDOW_CORNER_PREFERENCE: u32 = 33;
const DWMWA_USE_IMMERSIVE_DARK_MODE: u32 = 20;
const DWMWA_BORDER_COLOR: u32 = 34;
const DWMWA_CAPTION_COLOR: u32 = 35;
const DWMWA_TEXT_COLOR: u32 = 36;
const DWMWA_VISIBLE_FRAME_BORDER_THICKNESS: u32 = 37;

const DWMWCP_ROUND: u32 = 2;

// GDI stock objects
const WHITE_BRUSH: i32 = 0;
const LTGRAY_BRUSH: i32 = 1;
const GRAY_BRUSH: i32 = 2;
const DKGRAY_BRUSH: i32 = 3;

// ─── colors (COLORREF = 0x00BBGGRR) ───
const COLOR_BG: u32        = 0x00F0F0F0; // light gray
const COLOR_BANNER: u32    = 0x00D44527; // accent orange-red
const COLOR_TITLE: u32     = 0x00FFFFFF; // white
const COLOR_SUBTITLE: u32  = 0x00E0E0E0; // light gray
const COLOR_TEXT: u32      = 0x00202020; // near-black
const COLOR_EDIT_BG: u32   = 0x00FFFFFF; // white
const COLOR_GRAY_TEXT: u32 = 0x00707070;

// ─── control IDs ───
const IDC_BANNER_TITLE: i32 = 100;
const IDC_BANNER_SUBTITLE: i32 = 101;
const IDC_GROUPBOX: i32     = 102;
const IDC_PASS1_LABEL: i32  = 103;
const IDC_PASS1: i32        = 104;
const IDC_PASS2_LABEL: i32  = 105;
const IDC_PASS2: i32        = 106;
const IDC_OK: i32           = 1;
const IDC_CANCEL: i32       = 2;

// ═══════════════════════════════════════════════════════════════ public API

#[derive(Clone, Copy)]
pub enum DialogMode { AskPassword, SetPassword }

#[derive(Clone, Copy)]
pub enum EncryptMode { Full, Simple }

pub enum DialogResult {
    Ok { password: String, confirm: Option<String> },
    Cancel,
}

/// Control IDs for the encrypt-mode selection dialog.
const IDC_MODE_FULL: i32    = 200;
const IDC_MODE_SIMPLE: i32  = 201;
const IDC_MODE_GROUP: i32   = 202;

// ════════════════════════════════════════════════════════ thread-local state

thread_local! {
    static ACTIVE_MODE: std::cell::Cell<u8> = std::cell::Cell::new(0);
    static STORED: std::cell::RefCell<Option<DialogResult>> = std::cell::RefCell::new(None);
    static DIALOG_ICON: std::cell::RefCell<Option<Hicon>> = std::cell::RefCell::new(None);
    static BG_BRUSH: std::cell::RefCell<Option<Hbrush>> = std::cell::RefCell::new(None);
    static BANNER_BRUSH: std::cell::RefCell<Option<Hbrush>> = std::cell::RefCell::new(None);
    static STORED_MODE: std::cell::RefCell<Option<EncryptMode>> = std::cell::RefCell::new(None);
}

fn store_result(r: DialogResult) { STORED.with(|s| *s.borrow_mut() = Some(r)); }
fn take_stored_result() -> DialogResult { STORED.with(|s| s.borrow_mut().take().unwrap_or(DialogResult::Cancel)) }
fn store_mode(m: EncryptMode) { STORED_MODE.with(|s| *s.borrow_mut() = Some(m)); }
fn take_stored_mode() -> Option<EncryptMode> { STORED_MODE.with(|s| s.borrow_mut().take()) }

// ═══════════════════════════════════════════════════════════ dialog creation

/// Show the password dialog.
pub fn password_dialog(mode: DialogMode, title: &str, label: &str) -> DialogResult {
    ACTIVE_MODE.with(|c| c.set(if let DialogMode::SetPassword = mode { 1 } else { 0 }));
    store_result(DialogResult::Cancel);
    // Create custom brushes for dialog background and banner
    let bg = unsafe { CreateSolidBrush(COLOR_BG) };
    let banner = unsafe { CreateSolidBrush(COLOR_BANNER) };
    BG_BRUSH.with(|b| *b.borrow_mut() = Some(bg));
    BANNER_BRUSH.with(|b| *b.borrow_mut() = Some(banner));

    let template = build_template(mode, title);
    let bytes = template;
    let hmem = unsafe { GlobalAlloc(0, bytes.len()) };
    if hmem.is_null() { return DialogResult::Cancel; }
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), hmem as *mut u8, bytes.len()); }

    let title_w = to_wide(title);
    let label_w = to_wide(label);
    let payload = Payload { mode, title: title_w.as_ptr(), label: label_w.as_ptr() };
    let payload_ptr = &payload as *const Payload as isize;

    let result = unsafe {
        DialogBoxIndirectParamW(module_handle(), hmem as *const DlgTemplate,
            std::ptr::null_mut(), Some(dlg_proc), payload_ptr)
    };
    unsafe { GlobalFree(hmem) };

    // Clean up brushes
    if let Some(b) = BG_BRUSH.with(|b| b.borrow_mut().take()) { unsafe { DeleteObject(b); } }
    if let Some(b) = BANNER_BRUSH.with(|b| b.borrow_mut().take()) { unsafe { DeleteObject(b); } }
    // Destroy icon
    DIALOG_ICON.with(|c| { if let Some(h) = c.borrow_mut().take() { unsafe { DestroyIcon(h); } } });

    if result == 0 { DialogResult::Cancel } else { take_stored_result() }
}

// ════════════════════════════════════════════════════ encrypt mode dialog

/// Show a dialog asking the user to choose between Full and Simple encryption.
/// Returns `None` if cancelled.
pub fn encrypt_mode_dialog() -> Option<EncryptMode> {
    store_mode(EncryptMode::Full); // default
    let bg = unsafe { CreateSolidBrush(COLOR_BG) };
    let banner = unsafe { CreateSolidBrush(COLOR_BANNER) };
    BG_BRUSH.with(|b| *b.borrow_mut() = Some(bg));
    BANNER_BRUSH.with(|b| *b.borrow_mut() = Some(banner));

    let template = build_mode_template();
    let hmem = unsafe { GlobalAlloc(0, template.len()) };
    if hmem.is_null() { return None; }
    unsafe { std::ptr::copy_nonoverlapping(template.as_ptr(), hmem as *mut u8, template.len()); }

    let title_w = to_wide("选择加密模式");
    let result = unsafe {
        DialogBoxIndirectParamW(module_handle(), hmem as *const DlgTemplate,
            std::ptr::null_mut(), Some(mode_dlg_proc), title_w.as_ptr() as isize)
    };
    unsafe { GlobalFree(hmem) };

    if let Some(b) = BG_BRUSH.with(|b| b.borrow_mut().take()) { unsafe { DeleteObject(b); } }
    if let Some(b) = BANNER_BRUSH.with(|b| b.borrow_mut().take()) { unsafe { DeleteObject(b); } }
    DIALOG_ICON.with(|c| { if let Some(h) = c.borrow_mut().take() { unsafe { DestroyIcon(h); } } });

    if result == 0 { None } else { take_stored_mode() }
}

/// Dialog proc for the mode selection dialog.
unsafe extern "system" fn mode_dlg_proc(hdlg: Hwnd, msg: u32, wparam: usize, _lparam: isize) -> isize {
    match msg {
        WM_INITDIALOG => {
            init_dwm(hdlg);
            set_window_icon(hdlg);
            // Set banner texts
            unsafe { SetWindowTextW(GetDlgItem(hdlg, IDC_BANNER_TITLE), to_wide("选择加密模式").as_ptr()); }
            unsafe { SetWindowTextW(GetDlgItem(hdlg, IDC_BANNER_SUBTITLE), to_wide("请选择您需要的保护方式").as_ptr()); }
            // Default selection: Full
            unsafe { SendMessageW(GetDlgItem(hdlg, IDC_MODE_FULL), 0x00F1 /* BM_SETCHECK */, 1, 0); }
            1
        }
        WM_COMMAND => {
            let cid = (wparam & 0xFFFF) as i32;
            if ((wparam >> 16) & 0xFFFF) as u16 == BN_CLICKED {
                match cid {
                    IDC_OK => {
                        let is_simple = unsafe {
                            SendMessageW(GetDlgItem(hdlg, IDC_MODE_SIMPLE), 0x00F0 /* BM_GETCHECK */, 0, 0)
                        } != 0;
                        store_mode(if is_simple { EncryptMode::Simple } else { EncryptMode::Full });
                        unsafe { EndDialog(hdlg, 1); }
                        1
                    }
                    IDC_CANCEL => { unsafe { EndDialog(hdlg, 0); } 1 }
                    _ => 0,
                }
            } else { 0 }
        }
        WM_CTLCOLORDLG => {
            BG_BRUSH.with(|b| b.borrow().unwrap_or(std::ptr::null_mut()) as isize)
        }
        WM_CTLCOLORSTATIC => {
            let hdc = wparam as *mut std::ffi::c_void;
            unsafe { SetBkColor(hdc, COLOR_BG); SetBkMode(hdc, 1); }
            BG_BRUSH.with(|b| b.borrow().unwrap_or(std::ptr::null_mut()) as isize)
        }
        _ => 0,
    }
}

/// Build an in-memory dialog template for the mode selection dialog.
fn build_mode_template() -> Vec<u8> {
    let mut buf = Vec::new();
    let cx: i16 = 360;
    let cy: i16 = 220;
    let ctrl_count: u16 = 9;

    let dlg = DlgTemplate {
        style: WS_VISIBLE | DS_MODALFRAME | DS_CENTER | WS_GROUP | DS_SETFONT,
        dwExtendedStyle: 0,
        cdit: ctrl_count,
        x: 0, y: 0, cx, cy,
    };
    push_struct(&mut buf, &dlg);
    push_u16(&mut buf, 0); // menu
    push_u16(&mut buf, 0); // class
    push_wide(&mut buf, "选择加密模式"); // title
    push_u16(&mut buf, 10);
    push_u16(&mut buf, 400);
    push_u8(&mut buf, 0);
    push_u8(&mut buf, 1);
    push_wide(&mut buf, "Segoe UI");

    // ── banner ──
    add_static(&mut buf, IDC_BANNER_TITLE, "", 60, 8, 270, 18);
    add_static(&mut buf, IDC_BANNER_SUBTITLE, "", 60, 28, 270, 14);

    // ── group box for mode selection ──
    let gb_top = 50i16;
    let gb_height = 108i16;
    align_dword(&mut buf);
    push_struct(&mut buf, &DlgItemTemplate {
        style: WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        dwExtendedStyle: 0,
        x: 12, y: gb_top, cx: cx - 24, cy: gb_height,
        id: IDC_MODE_GROUP as u16,
    });
    push_u16(&mut buf, 0xFFFF); push_u16(&mut buf, CLASS_BUTTON);
    push_wide(&mut buf, "加密模式");
    push_u16(&mut buf, 0);

    // ── radio: Full encryption ──
    add_radio(&mut buf, IDC_MODE_FULL, 24, gb_top + 16, cx - 48);
    // Description for full
    add_static(&mut buf, IDC_PASS1_LABEL /* repurpose */, "完全加密 — 使用 AES-256 加密所有文件内容，\n速度较慢但安全性最高。", 40, gb_top + 32, cx - 64, 24);

    // ── radio: Simple encryption ──
    add_radio(&mut buf, IDC_MODE_SIMPLE, 24, gb_top + 62, cx - 48);
    // Description for simple
    add_static(&mut buf, IDC_PASS2_LABEL /* repurpose */, "简单加密 — 利用 NTFS ADS 隐藏文件，\n速度快，适合大文件文件夹。", 40, gb_top + 78, cx - 64, 24);

    // ── buttons ──
    let btn_y = gb_top + gb_height + 12;
    let btn_w = 56i16;
    let btn_h = 16i16;
    let btn_r = cx - 16;
    add_button(&mut buf, IDC_OK, "确定", btn_r - 2 * btn_w - 8, btn_y, btn_w, btn_h, true);
    add_button(&mut buf, IDC_CANCEL, "取消", btn_r - btn_w, btn_y, btn_w, btn_h, false);

    buf
}

fn add_radio(buf: &mut Vec<u8>, id: i32, x: i16, y: i16, cx: i16) {
    let style = WS_CHILD | WS_VISIBLE | WS_TABSTOP | WS_GROUP | BS_AUTORADIOBUTTON;
    align_dword(buf);
    push_struct(buf, &DlgItemTemplate {
        style, dwExtendedStyle: 0, x, y, cx, cy: 14, id: id as u16,
    });
    push_u16(buf, 0xFFFF); push_u16(buf, CLASS_BUTTON);
    let text = if id == IDC_MODE_FULL { "完全加密" } else { "简单加密" };
    push_wide(buf, text);
    push_u16(buf, 0);
}

#[repr(C)]
struct Payload { mode: DialogMode, title: *const u16, label: *const u16 }

// ══════════════════════════════════════════════════════════════ dialog proc

unsafe extern "system" fn dlg_proc(hdlg: Hwnd, msg: u32, wparam: usize, lparam: isize) -> isize {
    match msg {
        WM_INITDIALOG => {
            let payload = &*(lparam as *const Payload);
            init_dwm(hdlg);
            set_window_icon(hdlg);
            // Set title text in the banner
            SetWindowTextW(GetDlgItem(hdlg, IDC_BANNER_TITLE), payload.title);
            SetWindowTextW(GetDlgItem(hdlg, IDC_BANNER_SUBTITLE), payload.label);
            // Set dark theme for edit controls (just styling hint)
            // SetWindowTheme(GetDlgItem(hdlg, IDC_PASS1), to_wide("DarkMode_Explorer").as_ptr(), std::ptr::null());
            1
        }
        WM_COMMAND => {
            let cid = (wparam & 0xFFFF) as i32;
            if ((wparam >> 16) & 0xFFFF) as u16 == BN_CLICKED {
                match cid {
                    IDC_OK => {
                        let pw = get_text(hdlg, IDC_PASS1);
                        let confirm = if ACTIVE_MODE.with(|c| c.get()) == 1 {
                            Some(get_text(hdlg, IDC_PASS2))
                        } else { None };
                        store_result(DialogResult::Ok { password: pw, confirm });
                        EndDialog(hdlg, 1); 1
                    }
                    IDC_CANCEL => { store_result(DialogResult::Cancel); EndDialog(hdlg, 0); 1 }
                    _ => 0,
                }
            } else { 0 }
        }
        WM_CTLCOLORDLG => {
            BG_BRUSH.with(|b| b.borrow().unwrap_or(std::ptr::null_mut()) as isize)
        }
        WM_CTLCOLORSTATIC => {
            let hdc = wparam as *mut std::ffi::c_void;
            unsafe { SetBkColor(hdc, COLOR_BG); SetBkMode(hdc, 1); }
            BG_BRUSH.with(|b| b.borrow().unwrap_or(std::ptr::null_mut()) as isize)
        }
        WM_CTLCOLOREDIT => {
            let hdc = wparam as *mut std::ffi::c_void;
            unsafe { SetBkColor(hdc, COLOR_EDIT_BG); }
            unsafe { GetStockObject(WHITE_BRUSH) as isize }
        }
        _ => 0,
    }
}

// ═══════════════════════════════════════════════════════════════ DWM styling

fn init_dwm(hdlg: Hwnd) {
    // Extend the frame into the client area
    let margins = Margins { cxLeftWidth: 0, cxRightWidth: 0, cyTopHeight: 1, cyBottomHeight: 0 };
    dwm_extend_frame(hdlg, &margins);

    // Rounded corners (Win11)
    let corner: u32 = DWMWCP_ROUND;
    dwm_set_attr(hdlg, DWMWA_WINDOW_CORNER_PREFERENCE,
        &corner as *const u32 as *const std::ffi::c_void, 4);

    // Immersive dark mode for title bar
    let dark: i32 = 1;
    dwm_set_attr(hdlg, DWMWA_USE_IMMERSIVE_DARK_MODE,
        &dark as *const i32 as *const std::ffi::c_void, 4);
}

fn set_window_icon(hdlg: Hwnd) {
    let hicon = unsafe { LoadIconW(module_handle(), 1 as *const u16) };
    if !hicon.is_null() {
        unsafe { SendMessageW(hdlg, WM_SETICON, ICON_BIG, hicon as isize); }
        DIALOG_ICON.with(|c| *c.borrow_mut() = Some(hicon));
    }
}

// ════════════════════════════════════════════════════════════ helpers (GDI)

unsafe fn SetBkMode(hdc: *mut std::ffi::c_void, mode: i32) -> i32 {
    unsafe extern "system" { fn SetBkMode(hdc: *mut std::ffi::c_void, mode: i32) -> i32; }
    SetBkMode(hdc, mode)
}

fn get_text(hdlg: Hwnd, id: i32) -> String {
    let mut buf = [0u16; 512];
    let n = unsafe { GetDlgItemTextW(hdlg, id, buf.as_mut_ptr(), buf.len() as i32) };
    String::from_utf16_lossy(&buf[..n.max(0) as usize])
}

// ══════════════════════════════════════════════════════════ dialog template

fn build_template(mode: DialogMode, title: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    let cx: i16 = 330;
    let cy: i16 = if let DialogMode::SetPassword = mode { 185 } else { 155 };
    let ctrl_count: u16 = if let DialogMode::SetPassword = mode { 9 } else { 7 };

    let dlg = DlgTemplate {
        style: WS_VISIBLE | DS_MODALFRAME | DS_CENTER | WS_GROUP | DS_SETFONT,
        dwExtendedStyle: 0,
        cdit: ctrl_count,
        x: 0, y: 0, cx, cy,
    };
    push_struct(&mut buf, &dlg);
    push_u16(&mut buf, 0); // menu
    push_u16(&mut buf, 0); // class
    push_wide(&mut buf, title); // title
    // Font: Segoe UI 10pt
    push_u16(&mut buf, 10);
    push_u16(&mut buf, 400); // normal weight
    push_u8(&mut buf, 0);
    push_u8(&mut buf, 1); // DEFAULT_CHARSET
    push_wide(&mut buf, "Segoe UI");

    // ── banner area ──
    // (Painted manually; we use invisible static controls as text placeholders)
    add_static(&mut buf, IDC_BANNER_TITLE, "", 60, 8, 250, 18);
    add_static(&mut buf, IDC_BANNER_SUBTITLE, "", 60, 28, 250, 14);

    // ── group box around password fields ──
    let gb_top = 50i16;
    let gb_height: i16 = if let DialogMode::SetPassword = mode { 76 } else { 48 };
    let gb = DlgItemTemplate {
        style: WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
        dwExtendedStyle: 0,
        x: 12, y: gb_top, cx: cx - 24, cy: gb_height,
        id: IDC_GROUPBOX as u16,
    };
    align_dword(&mut buf);
    push_struct(&mut buf, &gb);
    push_u16(&mut buf, 0xFFFF); push_u16(&mut buf, CLASS_BUTTON);
    push_wide(&mut buf, "密码"); // group label
    push_u16(&mut buf, 0);

    // ── password fields inside group box ──
    let gy = gb_top + 14i16;
    let lx = 24i16;
    let lw = 40i16;
    let ex = lx + lw + 6;
    let ew = cx - ex - 20;

    if let DialogMode::SetPassword = mode {
        add_static(&mut buf, IDC_PASS1_LABEL, "密码:", lx, gy + 2, lw, 14);
        add_edit(&mut buf, IDC_PASS1, ex, gy, ew, 14);
        let gy2 = gy + 22;
        add_static(&mut buf, IDC_PASS2_LABEL, "确认:", lx, gy2 + 2, lw, 14);
        add_edit(&mut buf, IDC_PASS2, ex, gy2, ew, 14);
    } else {
        add_static(&mut buf, IDC_PASS1_LABEL, "密码:", lx, gy + 2, lw, 14);
        add_edit(&mut buf, IDC_PASS1, ex, gy, ew, 14);
    }

    // ── buttons (right-aligned) ──
    let btn_y = gb_top + gb_height + 10;
    let btn_w = 56i16;
    let btn_h = 16i16;
    let btn_r = cx - 16;
    add_button(&mut buf, IDC_OK, "确定", btn_r - 2 * btn_w - 8, btn_y, btn_w, btn_h, true);
    add_button(&mut buf, IDC_CANCEL, "取消", btn_r - btn_w, btn_y, btn_w, btn_h, false);

    buf
}

fn add_static(buf: &mut Vec<u8>, id: i32, text: &str, x: i16, y: i16, cx: i16, cy: i16) {
    let style = WS_CHILD | WS_VISIBLE | WS_GROUP;
    add_control(buf, style, 0, CLASS_STATIC, id, text, x, y, cx, cy);
}

fn add_edit(buf: &mut Vec<u8>, id: i32, x: i16, y: i16, cx: i16, cy: i16) {
    let style = WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL | ES_PASSWORD;
    add_control(buf, style, WS_EX_CLIENTEDGE, CLASS_EDIT, id, "", x, y, cx, cy);
}

fn add_button(buf: &mut Vec<u8>, id: i32, text: &str, x: i16, y: i16, cx: i16, cy: i16, def: bool) {
    let mut style = WS_CHILD | WS_VISIBLE | WS_TABSTOP;
    if def { style |= BS_DEFPUSHBUTTON; }
    add_control(buf, style, 0, CLASS_BUTTON, id, text, x, y, cx, cy);
}

fn add_control(buf: &mut Vec<u8>, style: u32, ex: u32, class: u16, id: i32, text: &str,
               x: i16, y: i16, cx: i16, cy: i16) {
    align_dword(buf);
    let item = DlgItemTemplate { style, dwExtendedStyle: ex, x, y, cx, cy, id: id as u16 };
    push_struct(buf, &item);
    push_u16(buf, 0xFFFF); push_u16(buf, class);
    push_wide(buf, text);
    push_u16(buf, 0);
}

// ════════════════════════════════════════════════════════════ byte helpers

fn push_struct<T: Copy>(buf: &mut Vec<u8>, val: &T) {
    let bytes = unsafe { std::slice::from_raw_parts(val as *const T as *const u8, std::mem::size_of::<T>()) };
    buf.extend_from_slice(bytes);
}
fn push_u16(buf: &mut Vec<u8>, v: u16) { buf.extend_from_slice(&v.to_le_bytes()); }
fn push_u8(buf: &mut Vec<u8>, v: u8) { buf.push(v); }
fn push_wide(buf: &mut Vec<u8>, s: &str) {
    for w in OsStr::new(s).encode_wide() { buf.extend_from_slice(&w.to_le_bytes()); }
    buf.extend_from_slice(&[0u8, 0]);
}
fn align_dword(buf: &mut Vec<u8>) { while buf.len() % 4 != 0 { buf.push(0); } }

// ═══════════════════════════════════════════════ MessageBox wrappers (reliable fallback)

pub fn message_box_error(text: &str) {
    msgbox(text, "错误", MB_ICONERROR);
}

pub fn message_box_info(text: &str) {
    msgbox(text, "Folder Lock", MB_ICONINFORMATION);
}

pub fn message_box_yesno(text: &str, title: &str) -> bool {
    msgbox(text, title, MB_ICONQUESTION | MB_YESNO) == IDYES
}

fn msgbox(text: &str, title: &str, flags: u32) -> i32 {
    let t = to_wide(text);
    let c = to_wide(title);
    unsafe { MessageBoxW(std::ptr::null_mut(), t.as_ptr(), c.as_ptr(), flags) }
}

const MB_ICONERROR: u32 = 0x0000_0010;
const MB_ICONINFORMATION: u32 = 0x0000_0040;
const MB_ICONQUESTION: u32 = 0x0000_0020;
const MB_YESNO: u32 = 0x0000_0004;
const IDYES: i32 = 6;

fn module_handle() -> Hinst { unsafe { GetModuleHandleW(std::ptr::null()) } }
fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = OsStr::new(s).encode_wide().collect();
    v.push(0); v
}

// ── silence unused-import warning for the FFI functions referenced via call ──
#[allow(dead_code)]
fn _ensure_link() {
    unsafe {
        let _ = GetDC(std::ptr::null_mut());
        let _ = ReleaseDC(std::ptr::null_mut(), std::ptr::null_mut());
    }
    // Reference the dynamic wrappers so they aren't flagged as unused.
    let _ = dwm_extend_frame;
    let _ = dwm_set_attr;
    let _ = set_win_theme;
}
