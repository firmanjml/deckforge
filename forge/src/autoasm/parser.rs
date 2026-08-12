//! Auto Assembler line parser: turns section source lines into statements.
//!
//! Understands the CE directive subset (`aobscan`, `aobscanmodule`, `alloc`,
//! `dealloc`, `label`, `define`, `registersymbol`, `unregistersymbol`,
//! `assert`), data emissions (`db`/`dw`/`dd`/`dq`), label definitions
//! (`name:`) and plain assembly lines. Unknown `name(...)` constructs are
//! reported as unsupported directives (never silently ignored).
//!
//! `define(NAME,VALUE)` is a textual macro: tokens equal to NAME are replaced
//! by VALUE in all subsequent lines of the same section (CE semantics).

use super::error::{AaResult, ErrorCtx};
use super::source::SrcLine;

/// A parsed statement with provenance for error reporting.
#[derive(Debug, Clone)]
pub struct StmtLine {
    pub stmt: Stmt,
    /// Package-relative file the line came from.
    pub file: String,
    /// 1-based line number in that file.
    pub line: u32,
    /// The trimmed source text (after define substitution).
    pub text: String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Stmt {
    /// aobscan(name, pattern)
    AobScan { name: String, pattern: String },
    /// aobscanmodule(name, module, pattern)
    AobScanModule {
        name: String,
        module: String,
        pattern: String,
    },
    /// aobscanregion(name, startExpr, stopExpr, pattern)
    AobScanRegion {
        name: String,
        start: String,
        stop: String,
        pattern: String,
    },
    /// alloc(name, size[, nearExpr])
    Alloc {
        name: String,
        size: String,
        near: Option<String>,
    },
    /// dealloc(name)
    Dealloc { name: String },
    /// label(name) — declares a local label
    LabelDecl(String),
    /// registersymbol(name)
    RegisterSymbol(String),
    /// unregistersymbol(name)
    UnregisterSymbol(String),
    /// assert(addrExpr, byte string) — bytes may contain ?? wildcards
    Assert { addr: String, bytes: String },
    /// readmem(symbol/addr, size) — reads `size` bytes from the resolved
    /// address at execution time and emits them as raw data. Used in
    /// [DISABLE] sections to restore original bytes: `label: readmem(SYM, N)`.
    ReadMem { addr: String, size: String },
    /// align(N, fill) — align the current code block offset to a multiple
    /// of N, filling with byte `fill` (e.g. `align 10,cc`).
    Align { align: String, fill: String },
    /// `name:` — label definition / block origin
    LabelDef(String),
    /// db/dw/dd/dq values (raw texts, evaluated at assembly time)
    Data {
        width: DataWidth,
        values: Vec<String>,
    },
    /// A plain assembly instruction line
    Asm(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DataWidth {
    Byte,
    Word,
    Dword,
    Qword,
}

impl DataWidth {
    pub fn size(self) -> usize {
        match self {
            DataWidth::Byte => 1,
            DataWidth::Word => 2,
            DataWidth::Dword => 4,
            DataWidth::Qword => 8,
        }
    }
}

/// CE directives we recognize but deliberately do not support yet. Anything
/// in this list produces a clear "unsupported directive" error; anything not
/// in the list and not a supported directive falls through to assembly.
const KNOWN_UNSUPPORTED: &[&str] = &[
    "createthread",
    "loadlibrary",
    "globalalloc",
    "fullaccess",
    "aobscanunique",
    "loadedsymbol",
    "deallocf",
    "allocnx",
    "registerexe",
    "unregisterexe",
    "include",
];

/// Parse one section's lines into statements, applying `define()` macros in
/// order. `ctx` provides error context (trainer/owner/script/section).
pub fn parse_section(lines: &[SrcLine], ctx: &ErrorCtx) -> AaResult<Vec<StmtLine>> {
    let mut out = Vec::new();
    let mut defines: Vec<(String, String)> = Vec::new();
    // Anonymous label tracking: each `@@:` gets a synthetic name
    // `__anon_N`. `@f` resolves to the next one, `@b` to the previous one.
    let mut anon_counter: u32 = 0;
    let mut anon_labels: Vec<String> = Vec::new(); // synthetic names in order

    for src in lines {
        // Strip comments first (quote-aware), then apply defines.
        let stripped = strip_comments(&src.text);
        let text = apply_defines(stripped.trim(), &defines);
        if text.is_empty() {
            continue;
        }

        // define() is consumed at parse time.
        if let Some((name, value)) = as_define(&text) {
            if name.is_empty() || value.is_empty() {
                return Err(ctx.err(src.line, &text, "define() needs a name and a value"));
            }
            defines.push((name, value));
            continue;
        }

        // Handle anonymous labels: `@@:` → synthetic label, `@f`/`@b` →
        // resolve to the appropriate synthetic name. We do this before
        // classify() so the synthetic names flow through normally.
        let text = if text.starts_with("@@:") || text == "@@" {
            // `@@:` — define a new anonymous label.
            let name = format!("__anon_{anon_counter}");
            anon_counter += 1;
            anon_labels.push(name.clone());
            // Replace the leading `@@` with the synthetic name.
            let rest = &text[2..];
            format!("{name}{rest}")
        } else {
            // Replace `@f` and `@b` tokens with the appropriate synthetic name.
            resolve_anon_refs(&text, &anon_labels)
        };

        let stmt = classify(&text).map_err(|cause| ctx.err(src.line, &text, cause))?;

        out.push(StmtLine {
            stmt,
            file: src.file.clone(),
            line: src.line,
            text,
        });
    }
    Ok(out)
}

/// Replace `@f` with the next anonymous label and `@b` with the previous.
/// If the reference can't be resolved yet (forward ref where no next exists),
/// leave it as-is — the assembler will report it as an unknown symbol.
fn resolve_anon_refs(text: &str, anon_labels: &[String]) -> String {
    // We need to find `@f` (forward = next anon, which hasn't been defined
    // yet — we can't know it). And `@b` (backward = last defined anon).
    //
    // For `@b`: replace with the last entry in anon_labels.
    // For `@f`: we can't resolve it at parse time because it refers to a
    // label that hasn't been defined yet. Instead, we replace `@f` with a
    // special placeholder `__anon_fwd_N` where N is the current count. The
    // assembler's label resolution pass will map `__anon_fwd_N` to the
    // actual `__anon_N` label once all labels are known.
    //
    // Actually, simpler approach: since `@f` is always used in branch
    // instructions (je @f, jmp @f, etc.), and the assembler resolves labels
    // in a fixpoint loop, we can just leave `@f` as a symbolic reference
    // that the expression evaluator resolves. But the evaluator doesn't know
    // about anonymous labels.
    //
    // Best approach: replace `@b` with the last anon label, and `@f` with a
    // forward-looking synthetic name `__anon_next` which we'll define as the
    // next `@@:`. But since we process line by line, `@f` on line N refers
    // to the next `@@:` on line M > N. We can't know M at line N.
    //
    // Solution: replace `@b` with the concrete last label, and for `@f`,
    // use a placeholder that encodes "forward ref #N". After all lines are
    // parsed, we do a second pass to resolve forward refs.
    //
    // Actually, the simplest correct approach: just replace `@b` and `@f`
    // as whole-word tokens. `@b` → last anon label. `@f` → a marker that
    // post-processing resolves. But since we return Vec<StmtLine> directly,
    // we need to handle this in one pass or add a post-pass.
    //
    // Let me just do a two-pass approach: first pass collects all anon
    // labels and their positions, second pass resolves @f/@b. But
    // parse_section is already one pass...
    //
    // OK, simplest working approach: `@b` resolves immediately to the last
    // anon label. `@f` is replaced with `__anon_fwd_{current_count}` — a
    // unique placeholder. After parsing all lines, we don't need a second
    // pass because the assembler's fixpoint loop will fail to resolve
    // `__anon_fwd_N` unless we map it. So instead, let's just use the
    // approach where `@f` is left as `@f` and handled specially in the
    // expression evaluator's lookup function.
    //
    // Actually the CLEANEST approach: since the assembler already does a
    // multi-pass label resolution, we can just convert `@f` to a synthetic
    // name based on the *current* anon count (which will be the name of the
    // NEXT `@@:`). This works because anon_counter increments BEFORE the
    // name is used, so the next `@@:` will get `__anon_{current_count}`.
    let forward_name = format!("__anon_{}", anon_labels.len());
    let backward_name = anon_labels.last().cloned();

    let mut result = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if i + 2 <= bytes.len() && &bytes[i..i + 2] == b"@f" {
            let before_ok = i == 0 || !is_ident_char(bytes[i - 1] as char);
            let after_ok = i + 2 >= bytes.len() || !is_ident_char(bytes[i + 2] as char);
            if before_ok && after_ok {
                result.push_str(&forward_name);
                i += 2;
                continue;
            }
        }
        if i + 2 <= bytes.len() && &bytes[i..i + 2] == b"@b" {
            let before_ok = i == 0 || !is_ident_char(bytes[i - 1] as char);
            let after_ok = i + 2 >= bytes.len() || !is_ident_char(bytes[i + 2] as char);
            if before_ok && after_ok {
                if let Some(name) = &backward_name {
                    result.push_str(name);
                    i += 2;
                    continue;
                }
            }
        }
        result.push(bytes[i] as char);
        i += 1;
    }
    result
}

fn is_ident_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '_' || c == '.'
}

/// Is this line a `define(name, value)` directive? (Case-insensitive.)
fn as_define(text: &str) -> Option<(String, String)> {
    let (name, args) = as_call(text)?;
    if !name.eq_ignore_ascii_case("define") {
        return None;
    }
    let parts = split_args(args);
    if parts.len() != 2 {
        return Some((String::new(), String::new())); // signals malformed define
    }
    Some((parts[0].to_string(), parts[1].to_string()))
}

/// Replace whole-word occurrences of each defined macro. Longest names first
/// so `healthAddr` isn't mangled by a `health` define.
fn apply_defines(text: &str, defines: &[(String, String)]) -> String {
    let mut out = text.to_string();
    let mut defs: Vec<&(String, String)> = defines.iter().collect();
    defs.sort_by_key(|(n, _)| std::cmp::Reverse(n.len()));
    for (name, value) in defs {
        out = replace_word(&out, name, value);
    }
    out
}

fn replace_word(text: &str, word: &str, value: &str) -> String {
    let is_ident = |c: char| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '@';
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < text.len() {
        if text[i..].starts_with(word) {
            let before_ok = i == 0 || !is_ident(bytes[i - 1] as char);
            let after = i + word.len();
            let after_ok = after >= text.len() || !is_ident(bytes[after] as char);
            if before_ok && after_ok {
                out.push_str(value);
                i = after;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Strip `//` and `;` comments, respecting single/double quotes.
pub fn strip_comments(text: &str) -> &str {
    let bytes = text.as_bytes();
    let mut i = 0;
    let mut in_squote = false;
    let mut in_dquote = false;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'\'' if !in_dquote => in_squote = !in_squote,
            b'"' if !in_squote => in_dquote = !in_dquote,
            b';' if !in_squote && !in_dquote => return &text[..i],
            b'/' if !in_squote && !in_dquote && i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                return &text[..i]
            }
            _ => {}
        }
        i += 1;
    }
    text
}

/// If `text` is a `name(arg,arg,...)` call, return (name, args-inner).
fn as_call(text: &str) -> Option<(&str, &str)> {
    let open = text.find('(')?;
    let name = text[..open].trim();
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '$')
    {
        return None;
    }
    let inner = text.strip_suffix(')')?[..].split_at(open + 1).1;
    Some((name, inner))
}

/// Split directive arguments on top-level commas (paren/quote aware).
pub fn split_args(inner: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_squote = false;
    let mut in_dquote = false;
    let mut start = 0;
    let bytes = inner.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        match c {
            b'\'' if !in_dquote => in_squote = !in_squote,
            b'"' if !in_squote => in_dquote = !in_dquote,
            b'(' if !in_squote && !in_dquote => depth += 1,
            b')' if !in_squote && !in_dquote => depth -= 1,
            b',' if depth == 0 && !in_squote && !in_dquote => {
                out.push(inner[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    let last = inner[start..].trim();
    if !last.is_empty() || !out.is_empty() {
        out.push(last);
    }
    out
}

fn is_label_name(s: &str) -> bool {
    !s.is_empty()
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '@')
        && s.chars().next().is_some_and(|c| !c.is_ascii_digit())
}

fn classify(text: &str) -> Result<Stmt, String> {
    // Label definition / block origin: `name:` optionally followed by code.
    // (Code on the same line after the colon stays part of the Asm/Data line;
    //  we split it here.)
    if let Some(colon) = text.find(':') {
        let head = text[..colon].trim();
        // Avoid misclassifying `mov ax,[fs:..]` style — labels never contain
        // spaces/brackets.
        if is_label_name(head) {
            return Ok(Stmt::LabelDef(head.to_string()));
        }
    }

    // Data emission.
    for (kw, w) in [
        ("db", DataWidth::Byte),
        ("dw", DataWidth::Word),
        ("dd", DataWidth::Dword),
        ("dq", DataWidth::Qword),
    ] {
        if let Some(rest) = keyword_rest(text, kw) {
            let values = split_data_values(rest);
            if values.is_empty() {
                return Err(format!("{kw} needs at least one value"));
            }
            return Ok(Stmt::Data { width: w, values });
        }
    }

    // align directive: `align N, FILL` or `align N` (fill defaults to 00).
    if let Some(rest) = keyword_rest(text, "align") {
        let parts = split_data_values(rest);
        if parts.is_empty() {
            return Err("align needs at least one argument".to_string());
        }
        let align_val = parts[0].to_string();
        let fill_val = if parts.len() > 1 {
            parts[1].to_string()
        } else {
            "00".to_string()
        };
        return Ok(Stmt::Align {
            align: align_val,
            fill: fill_val,
        });
    }

    // Directive calls.
    if let Some((name, inner)) = as_call(text) {
        let args: Vec<String> = split_args(inner).iter().map(|s| s.to_string()).collect();
        let lower = name.to_ascii_lowercase();
        let need = |n: usize| -> Result<(), String> {
            if args.len() < n {
                Err(format!(
                    "{name}() expects at least {n} argument(s), got {}",
                    args.len()
                ))
            } else {
                Ok(())
            }
        };
        return match lower.as_str() {
            "aobscan" => {
                need(2)?;
                Ok(Stmt::AobScan {
                    name: args[0].clone(),
                    pattern: args[1].clone(),
                })
            }
            "aobscanmodule" => {
                need(3)?;
                Ok(Stmt::AobScanModule {
                    name: args[0].clone(),
                    module: args[1].clone(),
                    pattern: args[2].clone(),
                })
            }
            "aobscanregion" => {
                need(4)?;
                Ok(Stmt::AobScanRegion {
                    name: args[0].clone(),
                    start: args[1].clone(),
                    stop: args[2].clone(),
                    pattern: args[3].clone(),
                })
            }
            "alloc" => {
                need(2)?;
                Ok(Stmt::Alloc {
                    name: args[0].clone(),
                    size: args[1].clone(),
                    near: args.get(2).cloned(),
                })
            }
            "dealloc" => {
                need(1)?;
                Ok(Stmt::Dealloc {
                    name: args[0].clone(),
                })
            }
            "label" => {
                need(1)?;
                Ok(Stmt::LabelDecl(args[0].clone()))
            }
            "registersymbol" => {
                need(1)?;
                Ok(Stmt::RegisterSymbol(args[0].clone()))
            }
            "unregistersymbol" => {
                need(1)?;
                Ok(Stmt::UnregisterSymbol(args[0].clone()))
            }
            "assert" => {
                need(2)?;
                Ok(Stmt::Assert {
                    addr: args[0].clone(),
                    bytes: args[1].clone(),
                })
            }
            "readmem" => {
                need(2)?;
                Ok(Stmt::ReadMem {
                    addr: args[0].clone(),
                    size: args[1].clone(),
                })
            }
            "define" => Err("define() is handled by the parser; internal error".into()),
            other => Err(format!("Unsupported Auto Assembler directive: {other}")),
        };
    }

    // A bare identifier that is a known CE directive without parens, e.g.
    // someone writing `createthread foo` — still report unsupported.
    let first_word = text.split_whitespace().next().unwrap_or("");
    if KNOWN_UNSUPPORTED.contains(&first_word.to_ascii_lowercase().as_str()) {
        return Err(format!(
            "Unsupported Auto Assembler directive: {first_word}"
        ));
    }

    Ok(Stmt::Asm(text.to_string()))
}

/// If `text` starts with keyword `kw` followed by whitespace, return the rest.
fn keyword_rest<'a>(text: &'a str, kw: &str) -> Option<&'a str> {
    let lower = text.to_ascii_lowercase();
    if lower.starts_with(kw) {
        let rest = &text[kw.len()..];
        if rest.starts_with(char::is_whitespace) {
            return Some(rest.trim());
        }
    }
    None
}

/// Split db/dw/dd/dq values: CE accepts both comma-separated and
/// space-separated lists (`db 90 90 90`, `dd (float)100`). Quotes and parens
/// are respected (`db "a b"`, `dd (float)100`).
fn split_data_values(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut in_squote = false;
    let mut in_dquote = false;
    let mut start: Option<usize> = None;
    let bytes = text.as_bytes();
    for (i, &c) in bytes.iter().enumerate() {
        // Quotes/parens both count as content and affect separator tracking.
        if start.is_none() {
            start = Some(i);
        }
        match c {
            b'\'' if !in_dquote => in_squote = !in_squote,
            b'"' if !in_squote => in_dquote = !in_dquote,
            b'(' if !in_squote && !in_dquote => depth += 1,
            b')' if !in_squote && !in_dquote => depth -= 1,
            b',' | b' ' | b'\t' if depth == 0 && !in_squote && !in_dquote => {
                if let Some(s) = start.take() {
                    let v = text[s..i].trim();
                    if !v.is_empty() {
                        out.push(v.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(s) = start {
        let v = text[s..].trim();
        if !v.is_empty() {
            out.push(v.to_string());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::autoasm::error::Section;

    fn ctx() -> ErrorCtx {
        ErrorCtx {
            trainer: "123456".into(),
            owner: "cheat".into(),
            script: "scripts/x.asm".into(),
            section: Section::Enable,
        }
    }

    fn lines(src: &str) -> Vec<SrcLine> {
        src.lines()
            .enumerate()
            .map(|(i, l)| SrcLine {
                text: l.to_string(),
                file: "scripts/x.asm".into(),
                line: (i + 1) as u32,
            })
            .collect()
    }

    fn parse(src: &str) -> AaResult<Vec<StmtLine>> {
        parse_section(&lines(src), &ctx())
    }

    #[test]
    fn parses_directives() {
        let stmts = parse(
            "aobscanmodule(INJECT,game.exe,F3 0F 11 83 ?? ?? ?? ??)\n\
             alloc(newmem,1024,INJECT)\n\
             label(return)\n\
             registersymbol(INJECT)\n",
        )
        .unwrap();
        assert!(matches!(
            &stmts[0].stmt,
            Stmt::AobScanModule { name, module, .. } if name == "INJECT" && module == "game.exe"
        ));
        assert!(matches!(
            &stmts[1].stmt,
            Stmt::Alloc { name, size, near }
                if name == "newmem" && size == "1024" && near.as_deref() == Some("INJECT")
        ));
        assert!(matches!(&stmts[2].stmt, Stmt::LabelDecl(l) if l == "return"));
        assert!(matches!(&stmts[3].stmt, Stmt::RegisterSymbol(s) if s == "INJECT"));
    }

    #[test]
    fn parses_labels_and_asm_and_data() {
        let stmts = parse("newmem:\n  movss [rbx+20],xmm0\n  jmp return\nreturn:\n  db F3 0F 11\n")
            .unwrap();
        assert!(matches!(&stmts[0].stmt, Stmt::LabelDef(l) if l == "newmem"));
        assert!(matches!(&stmts[1].stmt, Stmt::Asm(_)));
        assert!(matches!(&stmts[3].stmt, Stmt::LabelDef(l) if l == "return"));
        assert!(matches!(
            &stmts[4].stmt,
            Stmt::Data { width: DataWidth::Byte, values } if values == &["F3", "0F", "11"]
        ));
    }

    #[test]
    fn strips_comments_quote_aware() {
        let stmts = parse("db \"a;b\" // comment\ndb 'c;d' ; comment\nnop // done").unwrap();
        assert!(matches!(&stmts[0].stmt, Stmt::Data { values, .. } if values == &["\"a;b\""]));
        assert!(matches!(&stmts[1].stmt, Stmt::Data { values, .. } if values == &["'c;d'"]));
        assert!(matches!(&stmts[2].stmt, Stmt::Asm(a) if a == "nop"));
    }

    #[test]
    fn define_substitutes_subsequent_lines() {
        let stmts =
            parse("define(ADDR,game.exe+123456)\nassert(ADDR,90 90)\nalloc(ADDR,128)\n").unwrap();
        assert!(matches!(&stmts[0].stmt, Stmt::Assert { addr, .. } if addr == "game.exe+123456"));
        assert!(matches!(&stmts[1].stmt, Stmt::Alloc { name, .. } if name == "game.exe+123456"));
    }

    #[test]
    fn define_does_not_mangle_longer_names() {
        let stmts = parse("define(health,100)\nalloc(healthAddr,64)\n").unwrap();
        assert!(matches!(&stmts[0].stmt, Stmt::Alloc { name, .. } if name == "healthAddr"));
    }

    #[test]
    fn unknown_directive_is_explicit_error() {
        let err = parse("createthread(mythread)\n").unwrap_err();
        assert!(err
            .cause
            .contains("Unsupported Auto Assembler directive: createthread"));
        assert_eq!(err.section, Section::Enable);
    }

    #[test]
    fn aobscan_variants() {
        let stmts =
            parse("aobscan(HEALTH,48 8B ?? ??)\ndealloc(newmem)\nunregistersymbol(X)\n").unwrap();
        assert!(matches!(&stmts[0].stmt, Stmt::AobScan { name, .. } if name == "HEALTH"));
        assert!(matches!(&stmts[1].stmt, Stmt::Dealloc { name } if name == "newmem"));
        assert!(matches!(&stmts[2].stmt, Stmt::UnregisterSymbol(s) if s == "X"));
    }

    #[test]
    fn parses_aobscanregion() {
        let stmts = parse("aobscanregion(HOOK,game.exe+100,game.exe+200,48 8B ??)\n").unwrap();
        assert!(matches!(
            &stmts[0].stmt,
            Stmt::AobScanRegion { name, start, stop, pattern }
                if name == "HOOK"
                    && start == "game.exe+100"
                    && stop == "game.exe+200"
                    && pattern == "48 8B ??"
        ));
    }

    #[test]
    fn dq_with_symbol_value() {
        let stmts = parse("dq playerInstance\ndd (float)100\n").unwrap();
        assert!(
            matches!(&stmts[0].stmt, Stmt::Data { width: DataWidth::Qword, values } if values == &["playerInstance"])
        );
        assert!(
            matches!(&stmts[1].stmt, Stmt::Data { width: DataWidth::Dword, values } if values == &["(float)100"])
        );
    }

    #[test]
    fn keeps_line_numbers() {
        let stmts = parse("nop\n\nnop\n").unwrap();
        assert_eq!(stmts[1].line, 3);
    }
}
