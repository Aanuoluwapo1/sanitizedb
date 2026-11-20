use fake::faker::address::en::StreetName;
use fake::faker::internet::en::{IPv4, SafeEmail};
use fake::faker::name::en::Name;
use fake::faker::phone_number::en::PhoneNumber;
use fake::Fake;
use hmac::{Hmac, Mac};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroizing;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MaskingStrategy {
    DeterministicFake,
    Nullify,
    PartialMask,
    Shuffle,
    PassThrough,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticType {
    GenericString,
    Email,
    Phone,
    CreditCard,
    NationalId,
    IpAddress,
    FullName,
    StreetAddress,
    DateOfBirth,
}

#[derive(Debug, Clone)]
pub struct ColumnRule {
    pub column_name: String,
    pub strategy: MaskingStrategy,
    pub semantic_type: SemanticType,
    /// Shared domain tag (e.g., "user_email") so `users.email`, `orders.customer_email`,
    /// and `audit_logs.actor_email` produce identical synthetic values across tables.
    pub deterministic_domain: String,
    pub preserve_prefix_chars: usize,
    pub preserve_suffix_chars: usize,
    pub preserve_nulls: bool,
}

#[derive(Debug, Error)]
pub enum MaskError {
    #[error("invalid HMAC key length")]
    InvalidKey,
}

/// Core trait for zero-disk-leak in-memory value anonymization.
/// Implementations must be Send + Sync to run across Tokio worker pools.
pub trait DeterministicMasker: Send + Sync {
    fn mask_value(&self, raw: Option<&str>, rule: &ColumnRule) -> Result<Option<String>, MaskError>;
}

/// HMAC-SHA256 keyed deterministic anonymizer backed by `fake-rs`.
///
/// Security Properties:
/// - `job_salt` is wrapped in `Zeroizing<Vec<u8>>` so the per-job cryptographic key is
///   explicitly scrubbed from RAM when the job finishes or is cancelled.
/// - Same `(job_salt, deterministic_domain, raw_value)` ALWAYS yields the same synthetic
///   output, preserving foreign-key and denormalized join integrity across tables.
pub struct HmacDeterministicMasker {
    job_salt: Zeroizing<Vec<u8>>,
}

impl HmacDeterministicMasker {
    pub fn new(job_salt: Vec<u8>) -> Result<Self, MaskError> {
        if job_salt.len() < 16 {
            return Err(MaskError::InvalidKey);
        }
        Ok(Self {
            job_salt: Zeroizing::new(job_salt),
        })
    }

    /// Derive a 256-bit deterministic PRNG seed using HMAC-SHA256(job_salt, domain || 0x00 || raw).
    fn derive_seed(&self, domain: &str, raw: &str) -> Result<[u8; 32], MaskError> {
        let mut mac =
            HmacSha256::new_from_slice(&self.job_salt).map_err(|_| MaskError::InvalidKey)?;
        mac.update(domain.as_bytes());
        mac.update(&[0x00]); // Domain separator prevents prefix collisions
        mac.update(raw.as_bytes());
        let bytes = mac.finalize().into_bytes();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        Ok(seed)
    }

    fn generate_deterministic_fake(
        &self,
        raw: &str,
        rule: &ColumnRule,
    ) -> Result<String, MaskError> {
        let domain = if rule.deterministic_domain.is_empty() {
            &rule.column_name
        } else {
            &rule.deterministic_domain
        };
        let seed = self.derive_seed(domain, raw)?;
        let mut rng = StdRng::from_seed(seed);

        let synthetic = match rule.semantic_type {
            SemanticType::Email => {
                // Append deterministic short hash suffix to guarantee uniqueness on UNIQUE columns
                let base: String = SafeEmail().fake_with_rng(&mut rng);
                let tag = hex::encode(&seed[..3]);
                match base.split_once('@') {
                    Some((local, host)) => format!("{local}.{tag}@{host}"),
                    None => format!("user.{tag}@example.test"),
                }
            }
            SemanticType::FullName => Name().fake_with_rng(&mut rng),
            SemanticType::Phone => PhoneNumber().fake_with_rng(&mut rng),
            SemanticType::IpAddress => IPv4().fake_with_rng(&mut rng),
            SemanticType::StreetAddress => {
                let num: u16 = rng.gen_range(10..9999);
                let street: String = StreetName().fake_with_rng(&mut rng);
                format!("{num} {street}, Staging City")
            }
            SemanticType::CreditCard => generate_luhn_safe_test_pan(&mut rng),
            SemanticType::NationalId => {
                format!(
                    "SYN-{:03}-{:02}-{:04}",
                    rng.gen_range(100..999),
                    rng.gen_range(10..99),
                    rng.gen_range(1000..9999)
                )
            }
            SemanticType::DateOfBirth => {
                let year: u16 = rng.gen_range(1955..2003);
                let month: u8 = rng.gen_range(1..=12);
                let day: u8 = rng.gen_range(1..=28);
                format!("{year:04}-{month:02}-{day:02}")
            }
            SemanticType::GenericString => format!("syn_{}", hex::encode(&seed[..8])),
        };

        Ok(synthetic)
    }

    fn apply_partial_mask(raw: &str, prefix: usize, suffix: usize) -> String {
        let chars: Vec<char> = raw.chars().collect();
        let len = chars.len();
        if len <= prefix + suffix {
            return "*".repeat(len.max(4));
        }
        let mut out = String::with_capacity(len);
        for (idx, ch) in chars.iter().enumerate() {
            if idx < prefix || idx >= len - suffix || *ch == '@' || *ch == '-' {
                out.push(*ch);
            } else {
                out.push('*');
            }
        }
        out
    }
}

impl DeterministicMasker for HmacDeterministicMasker {
    fn mask_value(&self, raw: Option<&str>, rule: &ColumnRule) -> Result<Option<String>, MaskError> {
        let Some(value) = raw else {
            return Ok(None);
        };

        match rule.strategy {
            MaskingStrategy::PassThrough => Ok(Some(value.to_owned())),
            MaskingStrategy::Nullify => {
                if rule.preserve_nulls {
                    Ok(None)
                } else {
                    Ok(Some(String::new()))
                }
            }
            MaskingStrategy::PartialMask => Ok(Some(Self::apply_partial_mask(
                value,
                rule.preserve_prefix_chars,
                rule.preserve_suffix_chars,
            ))),
            MaskingStrategy::DeterministicFake => {
                self.generate_deterministic_fake(value, rule).map(Some)
            }
            MaskingStrategy::Shuffle => {
                // Window-level shuffle is performed in the streaming batch operator;
                // fallback to deterministic token if invoked per-scalar.
                self.generate_deterministic_fake(value, rule).map(Some)
            }
        }
    }
}

/// Generates a deterministic, Luhn-valid synthetic test card number in the 4242 test range.
fn generate_luhn_safe_test_pan(rng: &mut StdRng) -> String {
    let mut digits = [0u8; 16];
    digits[0] = 4;
    digits[1] = 2;
    digits[2] = 4;
    digits[3] = 2;
    for d in &mut digits[4..15] {
        *d = rng.gen_range(0..=9);
    }
    // Compute Luhn check digit
    let mut sum = 0u32;
    for (i, &d) in digits[..15].iter().rev().enumerate() {
        let mut val = d as u32;
        if i % 2 == 0 {
            val *= 2;
            if val > 9 {
                val -= 9;
            }
        }
        sum += val;
    }
    digits[15] = ((10 - (sum % 10)) % 10) as u8;
    format!(
        "{}{}{}{}-{}{}{}{}-{}{}{}{}-{}{}{}{}",
        digits[0], digits[1], digits[2], digits[3],
        digits[4], digits[5], digits[6], digits[7],
        digits[8], digits[9], digits[10], digits[11],
        digits[12], digits[13], digits[14], digits[15],
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_cross_table_email_integrity() {
        let masker = HmacDeterministicMasker::new(vec![0x42; 32]).unwrap();

        let users_email_rule = ColumnRule {
            column_name: "email".into(),
            strategy: MaskingStrategy::DeterministicFake,
            semantic_type: SemanticType::Email,
            deterministic_domain: "identity.email".into(),
            preserve_prefix_chars: 0,
            preserve_suffix_chars: 0,
            preserve_nulls: true,
        };
        let orders_email_rule = ColumnRule {
            column_name: "customer_email".into(),
            deterministic_domain: "identity.email".into(),
            ..users_email_rule.clone()
        };

        let raw = Some("adaeze.okafor@finbank-corp.ng");
        let masked_user = masker.mask_value(raw, &users_email_rule).unwrap().unwrap();
        let masked_order = masker.mask_value(raw, &orders_email_rule).unwrap().unwrap();

        assert_eq!(masked_user, masked_order);
        assert_ne!(masked_user, "adaeze.okafor@finbank-corp.ng");
        assert!(masked_user.contains('@'));
    }

    #[test]
    fn different_job_salts_produce_distinct_outputs() {
        let masker_a = HmacDeterministicMasker::new(vec![0x11; 32]).unwrap();
        let masker_b = HmacDeterministicMasker::new(vec![0x22; 32]).unwrap();
        let rule = ColumnRule {
            column_name: "email".into(),
            strategy: MaskingStrategy::DeterministicFake,
            semantic_type: SemanticType::Email,
            deterministic_domain: "identity.email".into(),
            preserve_prefix_chars: 0,
            preserve_suffix_chars: 0,
            preserve_nulls: true,
        };

        let a = masker_a.mask_value(Some("m.vance@healthtech.io"), &rule).unwrap();
        let b = masker_b.mask_value(Some("m.vance@healthtech.io"), &rule).unwrap();
        assert_ne!(a, b);
    }
}
