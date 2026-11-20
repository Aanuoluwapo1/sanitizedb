use once_cell::sync::Lazy;
use regex::Regex;

use crate::masker::SemanticType;

static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$").unwrap());
static PHONE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^\+?[0-9][0-9\-\s().]{7,18}[0-9]$").unwrap());
static CC_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"^(?:\d[ -]*?){13,19}$").unwrap());
static NATIONAL_ID_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^(?:NIN-\d{11}|\d{3}-\d{2}-\d{4}|[A-Z]{2}-\d{8,12})$").unwrap());
static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$").unwrap()
});

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PiiRiskLevel {
    High,
    Medium,
    Low,
}

impl PiiRiskLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            PiiRiskLevel::High => "HIGH",
            PiiRiskLevel::Medium => "MEDIUM",
            PiiRiskLevel::Low => "LOW",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PiiDetection {
    pub risk_level: PiiRiskLevel,
    pub category: Option<SemanticType>,
    pub confidence: f32,
    pub matched_pattern: String,
    pub reason: String,
}

/// Classifies a column name into HIGH, MEDIUM, or LOW PII risk using token and pattern heuristics:
/// - HIGH:   email, phone, mobile, ssn, nin, bvn, passport, card, cvv, iban, account, address, ip, dob, birth, token, secret
/// - MEDIUM: name, user, city, country, zip, postal
/// - LOW:    all other columns
pub fn classify_column_heuristic(column_name: &str) -> PiiDetection {
    let col = column_name.trim().to_ascii_lowercase();
    let tokens: Vec<&str> = col.split('_').filter(|t| !t.is_empty()).collect();

    let has_token = |target: &str| tokens.iter().any(|&t| t == target);
    let has_substr = |target: &str| col.contains(target);

    // 1. HIGH RISK PATTERNS
    if has_substr("email") || has_token("mail") {
        return PiiDetection {
            risk_level: PiiRiskLevel::High,
            category: Some(SemanticType::Email),
            confidence: 0.98,
            matched_pattern: "email".into(),
            reason: "HIGH:Matches email PII pattern".into(),
        };
    }
    if has_substr("phone") || has_substr("mobile") || has_token("tel") || has_token("msisdn") {
        let pat = if has_substr("mobile") { "mobile" } else { "phone" };
        return PiiDetection {
            risk_level: PiiRiskLevel::High,
            category: Some(SemanticType::Phone),
            confidence: 0.96,
            matched_pattern: pat.into(),
            reason: format!("HIGH:Matches {pat} PII pattern"),
        };
    }
    for &id_pat in &["ssn", "nin", "bvn", "passport"] {
        if has_token(id_pat) || (id_pat.len() >= 4 && has_substr(id_pat)) {
            return PiiDetection {
                risk_level: PiiRiskLevel::High,
                category: Some(SemanticType::NationalId),
                confidence: 0.97,
                matched_pattern: id_pat.into(),
                reason: format!("HIGH:Matches regulated national identifier pattern '{id_pat}'"),
            };
        }
    }
    if col == "national_id" || has_substr("national_id") {
        return PiiDetection {
            risk_level: PiiRiskLevel::High,
            category: Some(SemanticType::NationalId),
            confidence: 0.97,
            matched_pattern: "nin".into(),
            reason: "HIGH:Matches national_id PII pattern".into(),
        };
    }
    for &fin_pat in &["card", "cvv", "iban", "account"] {
        if has_token(fin_pat) || has_substr("card") || has_substr("iban") || has_substr("account") {
            let matched = if has_token("cvv") {
                "cvv"
            } else if has_substr("iban") {
                "iban"
            } else if has_substr("account") {
                "account"
            } else {
                "card"
            };
            return PiiDetection {
                risk_level: PiiRiskLevel::High,
                category: Some(SemanticType::CreditCard),
                confidence: 0.96,
                matched_pattern: matched.into(),
                reason: format!("HIGH:Matches PCI/financial pattern '{matched}'"),
            };
        }
    }
    if has_substr("address") {
        return PiiDetection {
            risk_level: PiiRiskLevel::High,
            category: Some(SemanticType::StreetAddress),
            confidence: 0.93,
            matched_pattern: "address".into(),
            reason: "HIGH:Matches physical address PII pattern".into(),
        };
    }
    if has_token("ip") || has_token("ipv4") || has_token("ipv6") {
        return PiiDetection {
            risk_level: PiiRiskLevel::High,
            category: Some(SemanticType::IpAddress),
            confidence: 0.94,
            matched_pattern: "ip".into(),
            reason: "HIGH:Matches network IP address pattern".into(),
        };
    }
    if has_token("dob") || has_substr("birth") {
        let pat = if has_token("dob") { "dob" } else { "birth" };
        return PiiDetection {
            risk_level: PiiRiskLevel::High,
            category: Some(SemanticType::DateOfBirth),
            confidence: 0.95,
            matched_pattern: pat.into(),
            reason: format!("HIGH:Matches date of birth pattern '{pat}'"),
        };
    }
    if has_substr("token") || has_substr("secret") {
        let pat = if has_substr("secret") { "secret" } else { "token" };
        return PiiDetection {
            risk_level: PiiRiskLevel::High,
            category: Some(SemanticType::GenericString),
            confidence: 0.95,
            matched_pattern: pat.into(),
            reason: format!("HIGH:Matches credential/secret pattern '{pat}'"),
        };
    }

    // 2. MEDIUM RISK PATTERNS (skip relational foreign key user_id / user_agent when classifying 'user')
    if has_substr("name") {
        return PiiDetection {
            risk_level: PiiRiskLevel::Medium,
            category: Some(SemanticType::FullName),
            confidence: 0.85,
            matched_pattern: "name".into(),
            reason: "MEDIUM:Matches personal name pattern".into(),
        };
    }
    if (has_token("user") || has_substr("username")) && col != "user_id" && col != "user_agent" {
        return PiiDetection {
            risk_level: PiiRiskLevel::Medium,
            category: Some(SemanticType::FullName),
            confidence: 0.78,
            matched_pattern: "user".into(),
            reason: "MEDIUM:Matches user identifier pattern".into(),
        };
    }
    for &loc_pat in &["city", "country", "zip", "postal"] {
        if has_token(loc_pat) || has_substr(loc_pat) {
            return PiiDetection {
                risk_level: PiiRiskLevel::Medium,
                category: Some(SemanticType::StreetAddress),
                confidence: 0.76,
                matched_pattern: loc_pat.into(),
                reason: format!("MEDIUM:Matches geographic location pattern '{loc_pat}'"),
            };
        }
    }

    // 3. LOW RISK
    PiiDetection {
        risk_level: PiiRiskLevel::Low,
        category: None,
        confidence: 0.10,
        matched_pattern: "none".into(),
        reason: "LOW:No PII heuristic pattern matched".into(),
    }
}

/// Inspects a column name and an optional in-memory slice of sample values to flag PII.
#[allow(dead_code)]
pub fn detect_column_pii(column_name: &str, samples: &[&str]) -> PiiDetection {
    let non_empty: Vec<&str> = samples
        .iter()
        .copied()
        .map(str::trim)
        .filter(|v| !v.is_empty())
        .collect();

    if !non_empty.is_empty() {
        let total = non_empty.len() as f32;

        let email_hits = non_empty.iter().filter(|v| EMAIL_RE.is_match(v)).count() as f32 / total;
        if email_hits >= 0.6 {
            return PiiDetection {
                risk_level: PiiRiskLevel::High,
                category: Some(SemanticType::Email),
                confidence: (0.75 + 0.24 * email_hits).min(0.99),
                matched_pattern: "email".into(),
                reason: format!(
                    "HIGH:{:.0}% of sampled values match RFC email pattern",
                    email_hits * 100.0
                ),
            };
        }

        let cc_hits = non_empty
            .iter()
            .filter(|v| CC_RE.is_match(v) && passes_luhn(v))
            .count() as f32
            / total;
        if cc_hits >= 0.5 {
            return PiiDetection {
                risk_level: PiiRiskLevel::High,
                category: Some(SemanticType::CreditCard),
                confidence: (0.85 + 0.14 * cc_hits).min(0.99),
                matched_pattern: "card".into(),
                reason: format!(
                    "HIGH:{:.0}% of sampled values pass Luhn PAN check",
                    cc_hits * 100.0
                ),
            };
        }

        let nid_hits = non_empty
            .iter()
            .filter(|v| NATIONAL_ID_RE.is_match(v))
            .count() as f32
            / total;
        if nid_hits >= 0.5 {
            return PiiDetection {
                risk_level: PiiRiskLevel::High,
                category: Some(SemanticType::NationalId),
                confidence: (0.80 + 0.18 * nid_hits).min(0.98),
                matched_pattern: "nin".into(),
                reason: "HIGH:Values match SSN/NIN national identifier format".into(),
            };
        }

        let ip_hits = non_empty.iter().filter(|v| IPV4_RE.is_match(v)).count() as f32 / total;
        if ip_hits >= 0.6 {
            return PiiDetection {
                risk_level: PiiRiskLevel::High,
                category: Some(SemanticType::IpAddress),
                confidence: (0.75 + 0.22 * ip_hits).min(0.97),
                matched_pattern: "ip".into(),
                reason: "HIGH:Values match IPv4 address format".into(),
            };
        }

        let phone_hits = non_empty.iter().filter(|v| PHONE_RE.is_match(v)).count() as f32 / total;
        if phone_hits >= 0.6 {
            return PiiDetection {
                risk_level: PiiRiskLevel::High,
                category: Some(SemanticType::Phone),
                confidence: 0.94,
                matched_pattern: "phone".into(),
                reason: "HIGH:Values match E.164/local phone regex".into(),
            };
        }
    }

    classify_column_heuristic(column_name)
}

fn passes_luhn(input: &str) -> bool {
    let digits: Vec<u32> = input.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let sum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(idx, &d)| {
            if idx % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();
    sum % 10 == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_high_medium_low_heuristics_accurately() {
        let phone = classify_column_heuristic("backup_phone");
        assert_eq!(phone.risk_level, PiiRiskLevel::High);
        assert_eq!(phone.category, Some(SemanticType::Phone));

        let nin = classify_column_heuristic("secondary_nin");
        assert_eq!(nin.risk_level, PiiRiskLevel::High);
        assert_eq!(nin.category, Some(SemanticType::NationalId));

        let zip = classify_column_heuristic("billing_zip");
        assert_eq!(zip.risk_level, PiiRiskLevel::Medium);

        let amount = classify_column_heuristic("amount_cents");
        assert_eq!(amount.risk_level, PiiRiskLevel::Low);
        assert_eq!(amount.category, None);
    }

    #[test]
    fn sample_value_detector_identifies_emails_and_pans() {
        let email_det = detect_column_pii("contact_field", &["alice@example.com", "bob@corp.org"]);
        assert_eq!(email_det.risk_level, PiiRiskLevel::High);
        assert_eq!(email_det.category, Some(SemanticType::Email));
    }
}
