//! Terminal / UI string sanitization — ANSI CSI and bidi overrides.
//!
//! Checklist §26 / abuse tests: identity spoofing via bidirectional controls
//! or escape sequences in aliases / message previews must be neutralized.
//!
//! Two flavours:
//! * [`sanitize_terminal_text`] — multi-line text (keeps TAB / LF; a CR never
//!   survives as a bare carriage return, so it cannot overwrite a line).
//! * [`sanitize_terminal_line`] — anything rendered on ONE line (identity
//!   labels, message previews next to a direction/id prefix, status rows).
//!   Line breaks become a visible `⏎`, and invisible / zero-width format code
//!   points are dropped so a peer cannot forge or hide prefix text.

/// Visible stand-in for a line break inside single-line output.
pub const LINE_BREAK_MARK: char = '\u{23CE}';

/// Strip ANSI CSI / OSC-ish escape sequences (ESC [ ... final-byte).
pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek().copied() {
                Some('[') => {
                    chars.next();
                    for d in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&d) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    chars.next();
                    for d in chars.by_ref() {
                        if d == '\u{07}' || d == '\\' {
                            break;
                        }
                    }
                }
                // lone ESC — drop
                _ => {}
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Unicode bidi / isolate controls that can spoof order in terminals.
///
/// Kept stable on purpose: persisted chat history is validated as a fixpoint
/// of [`sanitize_terminal_text`], so widening this list would turn existing
/// stored rows "corrupt". Extra single-line controls live in
/// [`is_invisible_format`] and are applied by [`sanitize_terminal_line`].
const BIDI_CONTROLS: &[char] = &[
    '\u{202A}', // LRE
    '\u{202B}', // RLE
    '\u{202C}', // PDF
    '\u{202D}', // LRO
    '\u{202E}', // RLO
    '\u{2066}', // LRI
    '\u{2067}', // RLI
    '\u{2068}', // FSI
    '\u{2069}', // PDI
    '\u{200E}', // LRM
    '\u{200F}', // RLM
];

pub fn strip_bidi(input: &str) -> String {
    input
        .chars()
        .filter(|c| !BIDI_CONTROLS.contains(c))
        .collect()
}

fn is_c0_c1_or_del(c: char) -> bool {
    let u = c as u32;
    u < 0x20 || u == 0x7f || (0x80..=0x9f).contains(&u)
}

/// Invisible / zero-width format code points that can hide or fake text in a
/// single-line label. ZWNJ (U+200C) and ZWJ (U+200D) are deliberately kept:
/// Persian/Arabic words and emoji sequences need them.
fn is_invisible_format(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'                      // soft hyphen
            | '\u{034F}'                // combining grapheme joiner
            | '\u{061C}'                // ARABIC LETTER MARK (bidi)
            | '\u{115F}'
            | '\u{1160}'                // Hangul fillers (render blank)
            | '\u{17B4}'
            | '\u{17B5}'
            | '\u{180E}'                // Mongolian vowel separator
            | '\u{200B}'                // zero width space
            | '\u{2060}'..='\u{2064}'   // word joiner, invisible operators
            | '\u{206A}'..='\u{206F}'   // deprecated format controls
            | '\u{3164}'
            | '\u{FFA0}'                // Hangul fillers
            | '\u{FEFF}'                // BOM / ZWNBSP
            | '\u{FFF9}'..='\u{FFFB}'   // interlinear annotation
            | '\u{1D173}'..='\u{1D17A}' // musical format controls
            | '\u{E0000}'..='\u{E007F}' // tag characters (ASCII smuggling)
    )
}

/// Sanitize for terminal display (multi-line text, doctor output).
///
/// Drops ANSI escapes, bidi overrides, C0 (except TAB/LF), DEL and C1. A CR is
/// never emitted on its own: CRLF becomes LF and a lone CR becomes LF, so text
/// cannot return the cursor and overwrite what was already printed on a line.
pub fn sanitize_terminal_text(input: &str) -> String {
    let stripped = strip_bidi(&strip_ansi(input));
    let mut out = String::with_capacity(stripped.len());
    let mut chars = stripped.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\t' | '\n' => out.push(c),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push('\n');
            }
            c if is_c0_c1_or_del(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// Sanitize peer-controlled text rendered on a single terminal line.
///
/// Everything [`sanitize_terminal_text`] removes, plus: CR / LF / VT / FF /
/// NEL / U+2028 / U+2029 become a visible [`LINE_BREAK_MARK`] (never a real
/// line break), TAB becomes a space, and invisible format code points (see
/// [`is_invisible_format`], including U+061C) are dropped.
pub fn sanitize_terminal_line(input: &str) -> String {
    let stripped = strip_ansi(input);
    let mut out = String::with_capacity(stripped.len());
    let mut chars = stripped.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(LINE_BREAK_MARK);
            }
            '\n' | '\u{0B}' | '\u{0C}' | '\u{85}' | '\u{2028}' | '\u{2029}' => {
                out.push(LINE_BREAK_MARK)
            }
            '\t' => out.push(' '),
            c if BIDI_CONTROLS.contains(&c) || is_invisible_format(c) || is_c0_c1_or_del(c) => {}
            c => out.push(c),
        }
    }
    out
}

/// True if input contained dangerous controls before sanitization.
pub fn had_dangerous_controls(input: &str) -> bool {
    sanitize_terminal_text(input) != input
        || input
            .chars()
            .any(|c| c == '\u{1b}' || BIDI_CONTROLS.contains(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_ansi_color() {
        let s = "\u{1b}[31mRED\u{1b}[0m";
        assert_eq!(sanitize_terminal_text(s), "RED");
        assert_eq!(sanitize_terminal_line(s), "RED");
    }

    #[test]
    fn strip_ansi_keeps_utf8_and_drops_osc() {
        assert_eq!(strip_ansi("سلام\u{1b}]52;c;AAAA\u{07}!"), "سلام!");
        assert_eq!(strip_ansi("a\u{1b}b"), "ab");
    }

    #[test]
    fn strips_bidi_override() {
        // RLO can reverse displayed order: spoof "alice" as something else in some UIs.
        let s = "evila\u{202E}ecila".to_string();
        let clean = sanitize_terminal_text(&s);
        assert!(!clean.contains('\u{202E}'));
        assert_eq!(clean, "evilaecila");
        assert!(had_dangerous_controls(&s));
    }

    #[test]
    fn clean_passthrough() {
        assert_eq!(sanitize_terminal_text("hello bob"), "hello bob");
        assert_eq!(sanitize_terminal_line("hello bob"), "hello bob");
        assert!(!had_dangerous_controls("hello bob"));
    }

    #[test]
    fn strips_nul_and_c0() {
        let s = "ok\u{0000}bad\u{0007}x";
        assert_eq!(sanitize_terminal_text(s), "okbadx");
        assert_eq!(sanitize_terminal_line(s), "okbadx");
        assert!(had_dangerous_controls(s));
    }

    #[test]
    fn text_never_emits_bare_carriage_return() {
        // CR used to survive and could overwrite the "← <mid>" prefix.
        let forged = "ok\r  \u{2192} 1a2b3c4d I agree to pay";
        let clean = sanitize_terminal_text(forged);
        assert!(!clean.contains('\r'), "{clean:?}");
        assert_eq!(clean, "ok\n  \u{2192} 1a2b3c4d I agree to pay");
        assert_eq!(sanitize_terminal_text("a\r\nb\nc"), "a\nb\nc");
        assert_eq!(sanitize_terminal_text("tab\tok"), "tab\tok");
        assert!(had_dangerous_controls(forged));
    }

    #[test]
    fn line_variant_cannot_break_or_rewind_the_line() {
        for forged in [
            "ok\r  \u{2192} 1a2b3c4d I agree to pay",
            "ok\n  \u{2190} 1a2b3c4d blocked alice",
            "ok\r\nfingerprint AAAA-BBBB",
            "ok\u{2028}fake row",
            "ok\u{2029}fake row",
            "ok\u{0b}x\u{0c}y\u{85}z",
        ] {
            let clean = sanitize_terminal_line(forged);
            assert!(
                !clean.chars().any(|c| matches!(
                    c,
                    '\r' | '\n' | '\u{0b}' | '\u{0c}' | '\u{85}' | '\u{2028}' | '\u{2029}'
                )),
                "{clean:?}"
            );
            assert!(clean.contains(LINE_BREAK_MARK), "{clean:?}");
        }
        assert_eq!(sanitize_terminal_line("a\r\nb"), "a\u{23CE}b");
        assert_eq!(sanitize_terminal_line("a\tb"), "a b");
    }

    #[test]
    fn line_variant_drops_invisible_and_extra_bidi() {
        assert_eq!(sanitize_terminal_line("al\u{200B}ice"), "alice");
        assert_eq!(sanitize_terminal_line("\u{FEFF}bob"), "bob");
        assert_eq!(sanitize_terminal_line("x\u{061C}y"), "xy");
        assert_eq!(sanitize_terminal_line("x\u{2066}y\u{2069}"), "xy");
        assert_eq!(sanitize_terminal_line("hi\u{E0041}\u{E0042}"), "hi");
        assert_eq!(sanitize_terminal_line("\u{3164}\u{115F}"), "");
        assert_eq!(sanitize_terminal_line("soft\u{00AD}hyphen"), "softhyphen");
    }

    #[test]
    fn line_variant_keeps_persian_zwnj_and_emoji_zwj() {
        // "می‌خواهم" uses ZWNJ; family emoji uses ZWJ + VS16 stays intact.
        let fa = "\u{0645}\u{06CC}\u{200C}\u{062E}\u{0648}\u{0627}\u{0647}\u{0645}";
        assert_eq!(sanitize_terminal_line(fa), fa);
        let emoji = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467} \u{2764}\u{FE0F}";
        assert_eq!(sanitize_terminal_line(emoji), emoji);
    }

    #[test]
    fn text_variant_output_is_fixpoint_for_line_free_values() {
        // chat_history validates stored rows as fixpoints of the text sanitizer.
        for s in [
            "plain",
            "with\u{200B}zwsp",
            "alm\u{061C}kept",
            "tab\tx",
            "a\nb",
        ] {
            let once = sanitize_terminal_text(s);
            assert_eq!(sanitize_terminal_text(&once), once);
        }
        assert_eq!(sanitize_terminal_text("alm\u{061C}kept"), "alm\u{061C}kept");
    }
}
