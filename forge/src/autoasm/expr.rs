//! Address/size expression evaluation for Auto Assembler scripts.
//!
//! Supported (CE-compatible subset):
//!
//! ```text
//! game.exe+123456        module base + offset (module names may contain dots)
//! newmem                 symbol (scan result / allocation / label)
//! newmem+10 / newmem-4   symbol arithmetic
//! 0x1234 / $1234         hex
//! #1234                  decimal
//! 1234                   hex in address context, decimal in size context
//! ```
//!
//! Addition and subtraction chains are supported (`a+b-c`); nothing else —
//! trainer scripts don't need a full expression language, and a small grammar
//! keeps errors comprehensible.

/// Number radix convention for bare literals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BareNumbers {
    /// Address context (CE parity): `123456` = 0x123456.
    Hex,
    /// Size/count context (alloc sizes, nop counts): `1024` = one thousand.
    Decimal,
}

/// Evaluate `expr` to a signed value. `lookup` resolves identifiers
/// (symbols, allocations, labels, module names) to addresses.
pub fn eval_i128(
    expr: &str,
    bare: BareNumbers,
    lookup: &dyn Fn(&str) -> Option<u64>,
) -> Result<i128, String> {
    let expr = expr.trim();
    if expr.is_empty() {
        return Err("empty expression".into());
    }

    // Strip one layer of wrapping parentheses: (game.exe+10)
    let expr = if expr.starts_with('(') && expr.ends_with(')') && balanced(&expr[1..expr.len() - 1])
    {
        expr[1..expr.len() - 1].trim()
    } else {
        expr
    };

    // Split into additive terms. A leading '-' negates the first term.
    let mut terms: Vec<(bool, &str)> = Vec::new(); // (is_negative, text)
    let mut depth = 0i32;
    let mut start = 0;
    let bytes = expr.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            b'(' => depth += 1,
            b')' => depth -= 1,
            b'+' | b'-' if depth == 0 => {
                let leading = expr[..i].trim().is_empty();
                if leading {
                    // unary sign
                    if c == b'-' {
                        terms.push((true, ""));
                    }
                } else {
                    let t = expr[start..i].trim();
                    if !t.is_empty() {
                        terms.push((false, t));
                    }
                    if c == b'-' {
                        terms.push((true, ""));
                    }
                }
                start = i + 1;
            }
            _ => {}
        }
        i += 1;
    }
    let last = expr[start..].trim();
    terms.push((false, last));

    // Normalize: the marker entries ("", sign) attach to the next real term.
    let mut result: i128 = 0;
    let mut pending_sign: Option<bool> = None;
    let mut any = false;
    for (neg, text) in terms {
        if text.is_empty() {
            pending_sign = Some(neg);
            continue;
        }
        let v = term(text, bare, lookup)?;
        let neg = pending_sign.take().unwrap_or(false) || neg;
        result += if neg { -(v as i128) } else { v as i128 };
        any = true;
    }
    if !any {
        return Err(format!("invalid expression '{expr}'"));
    }
    Ok(result)
}

/// Evaluate `expr`, requiring a non-negative result (addresses).
pub fn eval(
    expr: &str,
    bare: BareNumbers,
    lookup: &dyn Fn(&str) -> Option<u64>,
) -> Result<u64, String> {
    let result = eval_i128(expr, bare, lookup)?;
    if result < 0 {
        return Err(format!("expression '{expr}' evaluated negative ({result})"));
    }
    Ok(result as u64)
}

fn balanced(s: &str) -> bool {
    let mut d = 0i32;
    for c in s.chars() {
        match c {
            '(' => d += 1,
            ')' => {
                d -= 1;
                if d < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    d == 0
}

/// One term: number literal or identifier.
fn term(
    text: &str,
    bare: BareNumbers,
    lookup: &dyn Fn(&str) -> Option<u64>,
) -> Result<u64, String> {
    let t = text.trim();
    if t.is_empty() {
        return Err("empty term in expression".into());
    }
    if let Some(rest) = t.strip_prefix('#') {
        return rest
            .parse::<u64>()
            .map_err(|_| format!("invalid decimal literal '{t}'"));
    }
    if let Some(rest) = t.strip_prefix('$') {
        return u64::from_str_radix(rest, 16).map_err(|_| format!("invalid hex literal '{t}'"));
    }
    if let Some(rest) = t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
        return u64::from_str_radix(rest, 16).map_err(|_| format!("invalid hex literal '{t}'"));
    }
    if t.chars().next().is_some_and(|c| c.is_ascii_digit()) {
        // Bare literal. Hex context: digits and a-f/A-F only, otherwise it's
        // an identifier like a register name would be (rejected below).
        let radix = match bare {
            BareNumbers::Hex => 16,
            BareNumbers::Decimal => 10,
        };
        return u64::from_str_radix(t, radix)
            .map_err(|_| format!("invalid numeric literal '{t}'"));
    }
    // Identifier-like token: symbols win, but an all-hex token in hex context
    // (e.g. `F3` in `db F3 0F`) is a literal — CE parity.
    if let Some(v) = lookup(t) {
        return Ok(v);
    }
    if bare == BareNumbers::Hex
        && !t.is_empty()
        && t.chars().all(|c| c.is_ascii_hexdigit())
        && t.len() <= 16
    {
        return Ok(u64::from_str_radix(t, 16).expect("all hex digits"));
    }
    Err(format!("unknown symbol '{t}'"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(name: &str) -> Option<u64> {
        match name {
            "game.exe" => Some(0x400000),
            "newmem" => Some(0x700000),
            "playerInstance" => Some(0x12345678),
            _ => None,
        }
    }

    #[test]
    fn module_relative() {
        assert_eq!(
            eval("game.exe+123456", BareNumbers::Hex, &lookup).unwrap(),
            0x400000 + 0x123456
        );
    }

    #[test]
    fn symbol_arithmetic() {
        assert_eq!(eval("newmem", BareNumbers::Hex, &lookup).unwrap(), 0x700000);
        assert_eq!(eval("newmem+10", BareNumbers::Hex, &lookup).unwrap(), 0x700010);
        assert_eq!(eval("newmem-4", BareNumbers::Hex, &lookup).unwrap(), 0x6FFFFC);
    }

    #[test]
    fn number_bases() {
        assert_eq!(eval("0x100", BareNumbers::Hex, &lookup).unwrap(), 0x100);
        assert_eq!(eval("$100", BareNumbers::Hex, &lookup).unwrap(), 0x100);
        assert_eq!(eval("#100", BareNumbers::Hex, &lookup).unwrap(), 100);
        // Bare numbers: hex in address context, decimal in size context.
        assert_eq!(eval("1024", BareNumbers::Hex, &lookup).unwrap(), 0x1024);
        assert_eq!(eval("1024", BareNumbers::Decimal, &lookup).unwrap(), 1024);
    }

    #[test]
    fn negative_result_is_error() {
        assert!(eval("newmem-FFFFFF", BareNumbers::Hex, &lookup).is_err());
    }

    #[test]
    fn unknown_symbol_is_error() {
        let err = eval("doesnotexist+4", BareNumbers::Hex, &lookup).unwrap_err();
        assert!(err.contains("unknown symbol 'doesnotexist'"));
    }

    #[test]
    fn parenthesized() {
        assert_eq!(
            eval("(game.exe+10)", BareNumbers::Hex, &lookup).unwrap(),
            0x400010
        );
    }
}
