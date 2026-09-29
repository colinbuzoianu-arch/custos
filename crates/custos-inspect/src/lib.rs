//! Content inspection for tool-call arguments — pure functions, no I/O.
//!
//! Scans a JSON value for patterns that look like personal or sensitive
//! data (IBANs, payment cards, national ID numbers, email addresses, API
//! keys) and reports only what *kind* was found, how many times, and
//! *where* in the JSON structure — never the matched text itself. Findings
//! are meant to flow into the audit log and, later, into Cedar policy
//! context (see `docs/PLAN.md`, session 7); logging the very data this
//! exists to protect would defeat the point.
//!
//! Detection here is heuristic on purpose: checksummed formats (IBAN, card,
//! CNP, Steuer-ID) are only counted when their checksum actually validates,
//! so a random 13-digit number isn't reported as a Romanian CNP. Email and
//! API-key detection has no checksum to lean on, so expect some false
//! positives there — for a tool meant to flag *possible* exposure, an
//! over-eager match is the safer failure mode than a missed one.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// What kind of sensitive-looking content a [`Finding`] reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// IBAN, mod-97 checksum valid.
    Iban,
    /// Payment card number, Luhn checksum valid.
    Card,
    /// Romanian CNP, checksum digit valid.
    Cnp,
    /// German Steuer-ID, ISO 7064 MOD 11,10 checksum valid.
    SteuerId,
    Email,
    ApiKey,
}

/// One kind of match at one location. Never carries the matched text —
/// only its kind, where it was, and how many times it occurred there.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub kind: Kind,
    /// e.g. `$.customer.iban` or `$.rows[3].email`.
    pub path: String,
    pub count: usize,
}

/// Caps that keep inspection cheap and bounded no matter what an agent
/// sends. `max_bytes` is checked before any content scanning starts, so a
/// huge payload never reaches the more expensive per-character work at all.
#[derive(Debug, Clone, Copy)]
pub struct InspectConfig {
    /// Recursion limit for nested objects/arrays.
    pub max_depth: usize,
    /// Above this many serialized bytes, inspection doesn't run at all.
    pub max_bytes: usize,
}

impl Default for InspectConfig {
    fn default() -> Self {
        Self {
            max_depth: 32,
            max_bytes: 1_000_000,
        }
    }
}

/// Result of [`inspect`]. `truncated` is true if a cap was hit —
/// inspection stopped rather than silently pretending it saw everything,
/// so a caller can (and should) treat an incomplete scan as itself
/// suspicious rather than trusting a clean-looking but partial result.
///
/// `args_bytes` and `array_max_len` are always computed (not gated by a
/// threshold): a policy decides what counts as "too big," this just reports
/// the numbers so it can.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Findings {
    pub items: Vec<Finding>,
    pub args_bytes: usize,
    /// The longest array found anywhere in the value, or 0 if there are none.
    pub array_max_len: usize,
    pub truncated: bool,
}

/// Scans `value` for sensitive-looking content, using `config`'s caps.
/// Never panics and never fails: worst case is `truncated: true` and an
/// incomplete (never wrong) `items` list.
pub fn inspect(value: &Value, config: &InspectConfig) -> Findings {
    let args_bytes = serde_json::to_vec(value)
        .map(|b| b.len())
        .unwrap_or(usize::MAX);

    let mut findings = Findings {
        items: Vec::new(),
        args_bytes,
        array_max_len: 0,
        truncated: false,
    };

    if args_bytes > config.max_bytes {
        findings.truncated = true;
        return findings;
    }

    walk(value, "$", 0, config, &mut findings);
    findings
}

fn walk(value: &Value, path: &str, depth: usize, config: &InspectConfig, out: &mut Findings) {
    if depth > config.max_depth {
        out.truncated = true;
        return;
    }
    match value {
        Value::String(s) => scan_string(s, path, out),
        Value::Array(items) => {
            out.array_max_len = out.array_max_len.max(items.len());
            for (i, v) in items.iter().enumerate() {
                walk(v, &format!("{path}[{i}]"), depth + 1, config, out);
            }
        }
        Value::Object(map) => {
            for (k, v) in map {
                walk(v, &format!("{path}.{k}"), depth + 1, config, out);
            }
        }
        _ => {}
    }
}

fn scan_string(s: &str, path: &str, out: &mut Findings) {
    push_if(out, path, Kind::Iban, count_iban(s));
    push_if(out, path, Kind::Card, count_card(s));
    push_if(out, path, Kind::Cnp, count_cnp(s));
    push_if(out, path, Kind::SteuerId, count_steuer_id(s));
    push_if(out, path, Kind::Email, count_email(s));
    push_if(out, path, Kind::ApiKey, count_api_key(s));
}

fn push_if(out: &mut Findings, path: &str, kind: Kind, count: usize) {
    if count > 0 {
        out.items.push(Finding {
            kind,
            path: path.to_string(),
            count,
        });
    }
}

/// Splits `s` into maximal runs of characters `keep` accepts — the
/// tokenizer every detector below uses to pull candidate substrings out of
/// free text, without a regex dependency.
fn tokens_of(s: &str, keep: impl Fn(char) -> bool) -> Vec<String> {
    s.split(|c: char| !keep(c))
        .filter(|t| !t.is_empty())
        .map(str::to_string)
        .collect()
}

/// Digits, spaces and dashes — for card numbers and national IDs, which
/// real-world text sometimes groups with separators (`4242 4242 4242
/// 4242`).
fn digit_group_tokens(s: &str) -> Vec<String> {
    tokens_of(s, |c| c.is_ascii_digit() || c == ' ' || c == '-')
}

/// Letters, digits and spaces — for IBANs, which are sometimes written in
/// 4-character groups.
fn alnum_space_tokens(s: &str) -> Vec<String> {
    tokens_of(s, |c| c.is_ascii_alphanumeric() || c == ' ')
}

/// Letters, digits, dashes and underscores — API key formats commonly use
/// both (`sk-...`, `ghp_...`).
fn secret_tokens(s: &str) -> Vec<String> {
    tokens_of(s, |c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// A superset of characters a plausible email address can contain.
fn email_like_tokens(s: &str) -> Vec<String> {
    tokens_of(s, |c| {
        c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '%' | '+' | '-' | '@')
    })
}

fn digits_only(t: &str) -> String {
    t.chars().filter(char::is_ascii_digit).collect()
}

// --- IBAN: ISO 13616 mod-97 -------------------------------------------

fn count_iban(s: &str) -> usize {
    alnum_space_tokens(s)
        .iter()
        .map(|t| t.replace(' ', ""))
        .filter(|compact| is_valid_iban(compact))
        .count()
}

fn is_valid_iban(compact: &str) -> bool {
    let len = compact.chars().count();
    if !(15..=34).contains(&len) {
        return false;
    }
    let mut chars = compact.chars();
    if !chars.by_ref().take(2).all(|c| c.is_ascii_alphabetic()) {
        return false;
    }
    if !chars.by_ref().take(2).all(|c| c.is_ascii_digit()) {
        return false;
    }
    // Move the first 4 characters (country + check digits) to the end,
    // then map letters to numbers (A=10..Z=35) and reduce mod 97 as we go
    // so the running remainder never needs more than a few digits.
    let rearranged = compact
        .chars()
        .skip(4)
        .chain(compact.chars().take(4))
        .collect::<String>();
    let mut rem: u32 = 0;
    for c in rearranged.chars() {
        let Some(v) = c.to_digit(36) else {
            return false;
        };
        rem = if v < 10 {
            (rem * 10 + v) % 97
        } else {
            (rem * 100 + v) % 97
        };
    }
    rem == 1
}

// --- Payment cards: Luhn ------------------------------------------------

fn count_card(s: &str) -> usize {
    digit_group_tokens(s)
        .iter()
        .map(|t| digits_only(t))
        .filter(|compact| is_valid_card(compact))
        .count()
}

fn is_valid_card(digits: &str) -> bool {
    let len = digits.chars().count();
    if !(12..=19).contains(&len) {
        return false;
    }
    let Some(nums) = digits
        .chars()
        .map(|c| c.to_digit(10))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    let sum: u32 = nums
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 { doubled - 9 } else { doubled }
            } else {
                d
            }
        })
        .sum();
    sum.is_multiple_of(10)
}

// --- Romanian CNP ---------------------------------------------------------

const CNP_WEIGHTS: [u32; 12] = [2, 7, 9, 1, 4, 6, 3, 5, 8, 2, 7, 9];

fn count_cnp(s: &str) -> usize {
    digit_group_tokens(s)
        .iter()
        .map(|t| digits_only(t))
        .filter(|compact| compact.chars().count() == 13 && is_valid_cnp(compact))
        .count()
}

fn is_valid_cnp(digits: &str) -> bool {
    let Some(nums) = digits
        .chars()
        .map(|c| c.to_digit(10))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if nums.len() != 13 {
        return false;
    }
    let sum: u32 = nums[..12]
        .iter()
        .zip(CNP_WEIGHTS.iter())
        .map(|(d, w)| d * w)
        .sum();
    let rem = sum % 11;
    let check = if rem == 10 { 1 } else { rem };
    check == nums[12]
}

// --- German Steuer-ID: ISO/IEC 7064 MOD 11,10 -----------------------------

fn count_steuer_id(s: &str) -> usize {
    digit_group_tokens(s)
        .iter()
        .map(|t| digits_only(t))
        .filter(|compact| compact.chars().count() == 11 && is_valid_steuer_id(compact))
        .count()
}

fn is_valid_steuer_id(digits: &str) -> bool {
    let Some(nums) = digits
        .chars()
        .map(|c| c.to_digit(10))
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    if nums.len() != 11 {
        return false;
    }
    let mut product: u32 = 10;
    for &d in &nums[..10] {
        let mut sum = (d + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let check = (11 - product) % 10;
    check == nums[10]
}

// --- Email addresses -------------------------------------------------------

fn count_email(s: &str) -> usize {
    email_like_tokens(s)
        .iter()
        .filter(|t| is_valid_email(t))
        .count()
}

fn is_valid_email(t: &str) -> bool {
    let mut parts = t.split('@');
    let Some(local) = parts.next().filter(|l| !l.is_empty()) else {
        return false;
    };
    let Some(domain) = parts.next().filter(|d| !d.is_empty()) else {
        return false;
    };
    if parts.next().is_some() {
        return false; // more than one '@'
    }
    if local.starts_with('.') || local.ends_with('.') {
        return false;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || labels.iter().any(|l| l.is_empty()) {
        return false;
    }
    let Some(tld) = labels.last() else {
        return false;
    };
    tld.chars().count() >= 2 && tld.chars().all(|c| c.is_ascii_alphabetic())
}

// --- API keys / secrets -----------------------------------------------------

const API_KEY_PREFIXES: &[&str] = &["sk-", "ghp_", "AKIA"];

fn count_api_key(s: &str) -> usize {
    secret_tokens(s)
        .iter()
        .filter(|t| looks_like_secret(t))
        .count()
}

fn looks_like_secret(t: &str) -> bool {
    let len = t.chars().count();
    if len < 16 {
        return false;
    }
    if API_KEY_PREFIXES.iter().any(|p| t.starts_with(p)) {
        return true;
    }
    len >= 20 && shannon_entropy(t) >= 3.5
}

/// Shannon entropy in bits per character — a long, high-entropy token
/// looks more like a generated secret than natural text or a short word.
fn shannon_entropy(s: &str) -> f64 {
    let len = s.chars().count() as f64;
    if len == 0.0 {
        return 0.0;
    }
    let mut counts = std::collections::HashMap::new();
    for c in s.chars() {
        *counts.entry(c).or_insert(0u32) += 1;
    }
    counts
        .values()
        .map(|&c| {
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Well-known, publicly published test values — not real personal data:
    // the canonical example IBAN from the IBAN Wikipedia article, and
    // Stripe's standard Luhn-valid test Visa number.
    const VALID_IBAN: &str = "DE89370400440532013000";
    const VALID_CARD: &str = "4242424242424242";
    // Derived by hand from the CNP checksum algorithm below, for a
    // syntactically plausible (not a real person's) birth-date/county/seq.
    const VALID_CNP: &str = "1800101221232";
    // Derived by hand from the ISO 7064 MOD 11,10 algorithm below.
    const VALID_STEUER_ID: &str = "12345678903";

    fn inspect_default(value: &Value) -> Findings {
        inspect(value, &InspectConfig::default())
    }

    fn kinds(findings: &Findings) -> Vec<Kind> {
        findings.items.iter().map(|f| f.kind).collect()
    }

    #[test]
    fn valid_iban_is_detected() {
        let f = inspect_default(&json!({"iban": VALID_IBAN}));
        assert!(kinds(&f).contains(&Kind::Iban), "{f:?}");
    }

    #[test]
    fn iban_with_flipped_digit_is_not_detected() {
        let mut bad = VALID_IBAN.to_string();
        bad.replace_range(20..21, "9");
        assert_ne!(bad, VALID_IBAN);
        let f = inspect_default(&json!({"iban": bad}));
        assert!(!kinds(&f).contains(&Kind::Iban), "{f:?}");
    }

    #[test]
    fn valid_card_is_detected() {
        let f = inspect_default(&json!({"card": VALID_CARD}));
        assert!(kinds(&f).contains(&Kind::Card), "{f:?}");
    }

    #[test]
    fn card_with_flipped_digit_is_not_detected() {
        let bad = "4242424242424241"; // last digit changed, breaks Luhn
        let f = inspect_default(&json!({"card": bad}));
        assert!(!kinds(&f).contains(&Kind::Card), "{f:?}");
    }

    #[test]
    fn valid_cnp_is_detected() {
        let f = inspect_default(&json!({"cnp": VALID_CNP}));
        assert!(kinds(&f).contains(&Kind::Cnp), "{f:?}");
    }

    #[test]
    fn cnp_with_flipped_check_digit_is_not_detected() {
        let bad = "1800101221231"; // wrong check digit
        let f = inspect_default(&json!({"cnp": bad}));
        assert!(!kinds(&f).contains(&Kind::Cnp), "{f:?}");
    }

    #[test]
    fn valid_steuer_id_is_detected() {
        let f = inspect_default(&json!({"steuer_id": VALID_STEUER_ID}));
        assert!(kinds(&f).contains(&Kind::SteuerId), "{f:?}");
    }

    #[test]
    fn steuer_id_with_flipped_check_digit_is_not_detected() {
        let bad = "12345678904"; // wrong check digit
        let f = inspect_default(&json!({"steuer_id": bad}));
        assert!(!kinds(&f).contains(&Kind::SteuerId), "{f:?}");
    }

    #[test]
    fn email_is_detected() {
        let f = inspect_default(&json!({"note": "contact jane@example.com please"}));
        assert!(kinds(&f).contains(&Kind::Email), "{f:?}");
    }

    #[test]
    fn plain_text_is_not_detected_as_email() {
        let f = inspect_default(&json!({"note": "no address here at all"}));
        assert!(!kinds(&f).contains(&Kind::Email), "{f:?}");
    }

    #[test]
    fn known_api_key_prefix_is_detected() {
        let f = inspect_default(&json!({"key": "sk-abcdefghijklmnopqrstuvwxyz"}));
        assert!(kinds(&f).contains(&Kind::ApiKey), "{f:?}");
    }

    #[test]
    fn high_entropy_token_is_detected() {
        let f = inspect_default(&json!({"blob": "xK9pL2mQ8vN4wR7tY1zA3bC6dE0fG5hJ"}));
        assert!(kinds(&f).contains(&Kind::ApiKey), "{f:?}");
    }

    #[test]
    fn low_entropy_long_string_is_not_detected_as_api_key() {
        let f = inspect_default(&json!({"blob": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}));
        assert!(!kinds(&f).contains(&Kind::ApiKey), "{f:?}");
    }

    #[test]
    fn nested_objects_and_arrays_get_correct_paths() {
        let f = inspect_default(&json!({
            "customer": {"iban": VALID_IBAN},
            "rows": [{"note": "x"}, {"email": "a@b.example"}]
        }));
        let iban = f.items.iter().find(|i| i.kind == Kind::Iban);
        assert_eq!(iban.map(|i| i.path.as_str()), Some("$.customer.iban"));
        let email = f.items.iter().find(|i| i.kind == Kind::Email);
        assert_eq!(email.map(|i| i.path.as_str()), Some("$.rows[1].email"));
    }

    #[test]
    fn oversized_input_is_truncated_with_no_content_findings() {
        let big = "a".repeat(2_000_000);
        let f = inspect_default(&json!({"blob": big}));
        assert!(f.truncated);
        assert!(f.items.is_empty(), "{f:?}");
    }

    #[test]
    fn deeply_nested_input_is_truncated() {
        let mut value = json!("leaf");
        for _ in 0..(InspectConfig::default().max_depth + 10) {
            value = json!({"child": value});
        }
        let f = inspect_default(&value);
        assert!(f.truncated);
    }

    #[test]
    fn array_max_len_is_the_longest_array_anywhere() {
        let arr: Vec<Value> = (0..1000).map(|i| json!(i)).collect();
        let f = inspect_default(&json!({"rows": arr, "other": [1, 2]}));
        assert_eq!(f.array_max_len, 1000);
    }

    #[test]
    fn args_bytes_reflects_payload_size() {
        let big = "a".repeat(200_000);
        let f = inspect_default(&json!({"blob": big}));
        assert!(!f.truncated);
        assert!(f.args_bytes > 200_000, "{f:?}");
    }

    #[test]
    fn matched_values_never_appear_in_findings() {
        let f = inspect_default(&json!({
            "iban": VALID_IBAN,
            "card": VALID_CARD,
            "cnp": VALID_CNP,
            "steuer_id": VALID_STEUER_ID,
            "note": "jane@example.com",
            "key": "sk-abcdefghijklmnopqrstuvwxyz",
        }));
        let serialized = match serde_json::to_string(&f) {
            Ok(s) => s,
            Err(e) => panic!("{e}"),
        };
        for secret in [
            VALID_IBAN,
            VALID_CARD,
            VALID_CNP,
            VALID_STEUER_ID,
            "jane@example.com",
            "sk-abcdefghijklmnopqrstuvwxyz",
        ] {
            assert!(
                !serialized.contains(secret),
                "matched value {secret:?} leaked into findings: {serialized}"
            );
        }
    }
}
