use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::ops::Range;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::{ExtractedString, Finding, FindingCategory};

// Delimiters such as quotes, brackets, braces, commas, semicolons, and pipes are
// deliberately excluded so adjacent printable binary noise is not swallowed.
static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\bhttps?://[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?(?:[/?#][a-z0-9._~:/?#@!$&*+=%-]*)?",
    )
    .expect("the URL regex must be valid")
});
static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("the IPv4 regex must be valid")
});
static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9-]{1,63}\.)+[a-z]{2,24}\b")
        .expect("the domain regex must be valid")
});
static PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s\"'=:(])(/(?:[A-Za-z0-9._+@%~-]+/?)+)"#)
        .expect("the Linux path regex must be valid")
});

// A deliberately small and readable set. It covers common generic and country
// TLDs while avoiding the binary-noise explosion caused by accepting any suffix.
const COMMON_TLDS: &[&str] = &[
    "ae", "ai", "app", "au", "biz", "br", "ca", "ch", "cloud", "cn", "co", "com", "de", "dev",
    "edu", "es", "eu", "fi", "fr", "gov", "in", "info", "io", "it", "jp", "me", "mil", "net", "nl",
    "no", "online", "org", "pl", "ru", "se", "site", "tech", "test", "tr", "tv", "uk", "us", "xyz",
];

const FILE_EXTENSIONS: &[&str] = &[
    "a", "c", "cc", "cpp", "cxx", "go", "h", "hpp", "java", "js", "o", "py", "rs", "sh", "so", "ts",
];

const SUSPICIOUS_RULES: [(&str, &str); 10] = [
    ("shell-bin-sh", "/bin/sh"),
    ("shell-bash", "bash"),
    ("download-curl", "curl"),
    ("download-wget", "wget"),
    ("permission-chmod", "chmod"),
    ("scheduler-crontab", "crontab"),
    ("service-systemctl", "systemctl"),
    ("temporary-tmp", "/tmp"),
    ("memory-dev-shm", "/dev/shm"),
    ("shell-bin-dash", "/bin/dash"),
];

const PERSISTENCE_RULES: [(&str, &str); 16] = [
    ("persistence-crontab", "/etc/crontab"),
    ("persistence-cron-d", "/etc/cron.d"),
    ("persistence-cron-spool", "/var/spool/cron"),
    ("persistence-systemd-etc", "/etc/systemd/system"),
    ("persistence-systemd-usr", "/usr/lib/systemd/system"),
    ("persistence-init-d", "/etc/init.d"),
    ("persistence-rc-local", "/etc/rc.local"),
    ("persistence-profile", "/etc/profile"),
    ("persistence-profile-d", "/etc/profile.d"),
    ("persistence-bashrc", ".bashrc"),
    ("persistence-bash-profile", ".bash_profile"),
    ("persistence-authorized-keys", ".ssh/authorized_keys"),
    ("persistence-user-autostart", ".config/autostart"),
    ("persistence-system-autostart", "/etc/xdg/autostart"),
    ("persistence-ld-preload", "/etc/ld.so.preload"),
    ("persistence-sudoers-d", "/etc/sudoers.d"),
];

pub fn detect_findings(strings: &[ExtractedString]) -> Vec<Finding> {
    let mut findings = Vec::new();

    for extracted in strings {
        let url_ranges = detect_urls(extracted, &mut findings);
        detect_ipv4_addresses(extracted, &mut findings);
        detect_domains(extracted, &url_ranges, &mut findings);
        detect_linux_paths(extracted, &mut findings);
        detect_literal_rules(
            extracted,
            &SUSPICIOUS_RULES,
            FindingCategory::SuspiciousIndicator,
            &mut findings,
        );
        detect_literal_rules(
            extracted,
            &PERSISTENCE_RULES,
            FindingCategory::PersistenceLocation,
            &mut findings,
        );
    }

    // Extraction order already follows file offsets. Sorting makes that promise
    // explicit, then retain keeps only the first identical value per category.
    findings.sort_by_key(|finding| finding.offset);
    let mut seen = HashSet::new();
    findings.retain(|finding| seen.insert((finding.category, finding.value.clone())));
    findings
}

fn detect_urls(extracted: &ExtractedString, output: &mut Vec<Finding>) -> Vec<Range<usize>> {
    let mut ranges = Vec::new();
    for found in URL_RE.find_iter(&extracted.value) {
        let value = trim_url_punctuation(found.as_str());
        if value.is_empty() || !has_valid_url_host(value) {
            continue;
        }

        let end = found.start() + value.len();
        ranges.push(found.start()..end);
        push_finding(
            extracted,
            found.start(),
            value,
            FindingCategory::Url,
            "url",
            output,
        );
    }
    ranges
}

fn has_valid_url_host(value: &str) -> bool {
    let Some((_, remainder)) = value.split_once("://") else {
        return false;
    };
    let authority = remainder.split(['/', '?', '#']).next().unwrap_or_default();
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if port.parse::<u16>().is_ok() => host,
        Some(_) => return false,
        None => authority,
    };

    if host.eq_ignore_ascii_case("localhost") || host.parse::<Ipv4Addr>().is_ok() {
        return true;
    }
    valid_labels(host)
}

fn detect_ipv4_addresses(extracted: &ExtractedString, output: &mut Vec<Finding>) {
    for found in IPV4_RE.find_iter(&extracted.value) {
        if found.as_str().parse::<Ipv4Addr>().is_ok() {
            push_finding(
                extracted,
                found.start(),
                found.as_str(),
                FindingCategory::Ipv4Address,
                "ipv4",
                output,
            );
        }
    }
}

fn detect_domains(
    extracted: &ExtractedString,
    url_ranges: &[Range<usize>],
    output: &mut Vec<Finding>,
) {
    for found in DOMAIN_RE.find_iter(&extracted.value) {
        let belongs_to_url = url_ranges
            .iter()
            .any(|range| range.start <= found.start() && found.end() <= range.end);
        if !belongs_to_url && is_realistic_domain(found.as_str()) {
            push_finding(
                extracted,
                found.start(),
                found.as_str(),
                FindingCategory::Domain,
                "domain",
                output,
            );
        }
    }
}

fn is_realistic_domain(value: &str) -> bool {
    if value.len() > 253 || !valid_labels(value) {
        return false;
    }

    let lowercase = value.to_ascii_lowercase();
    let Some((labels, tld)) = lowercase.rsplit_once('.') else {
        return false;
    };
    if FILE_EXTENSIONS.contains(&tld) || !COMMON_TLDS.contains(&tld) {
        return false;
    }

    // Requiring a letter before the TLD rejects noise such as "5.aE" while
    // preserving legitimate short names such as "x.test".
    labels.bytes().any(|byte| byte.is_ascii_alphabetic())
}

fn valid_labels(value: &str) -> bool {
    value.contains('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn detect_linux_paths(extracted: &ExtractedString, output: &mut Vec<Finding>) {
    for captures in PATH_RE.captures_iter(&extracted.value) {
        let Some(found) = captures.get(1) else {
            continue;
        };
        push_finding(
            extracted,
            found.start(),
            found.as_str(),
            FindingCategory::LinuxPath,
            "linux-path",
            output,
        );
    }
}

fn detect_literal_rules(
    extracted: &ExtractedString,
    rules: &[(&'static str, &str)],
    category: FindingCategory,
    output: &mut Vec<Finding>,
) {
    let lowercase = extracted.value.to_ascii_lowercase();
    for &(rule, needle) in rules {
        for (start, _) in lowercase.match_indices(needle) {
            if has_token_boundaries(&lowercase, start, needle.len()) {
                push_finding(
                    extracted,
                    start,
                    &extracted.value[start..start + needle.len()],
                    category,
                    rule,
                    output,
                );
            }
        }
    }
}

fn has_token_boundaries(text: &str, start: usize, length: usize) -> bool {
    let is_word = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'_';
    let bytes = text.as_bytes();
    let first_is_word = is_word(bytes[start]);
    let last_is_word = is_word(bytes[start + length - 1]);
    let left_ok = !first_is_word || start == 0 || !is_word(bytes[start - 1]);
    let right = start + length;
    let right_ok = !last_is_word || right == bytes.len() || !is_word(bytes[right]);
    left_ok && right_ok
}

fn trim_url_punctuation(value: &str) -> &str {
    value.trim_end_matches(['.', ':', '!', '?', '#', '@', '$', '&', '*', '+', '=', '%'])
}

fn push_finding(
    extracted: &ExtractedString,
    relative_offset: usize,
    value: &str,
    category: FindingCategory,
    rule: &'static str,
    output: &mut Vec<Finding>,
) {
    if !value.is_empty() {
        output.push(Finding {
            category,
            value: value.to_string(),
            offset: extracted.offset + relative_offset,
            rule,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn extracted(value: &str, offset: usize) -> ExtractedString {
        ExtractedString {
            offset,
            value: value.into(),
        }
    }

    fn values(findings: &[Finding], category: FindingCategory) -> Vec<&str> {
        findings
            .iter()
            .filter(|finding| finding.category == category)
            .map(|finding| finding.value.as_str())
            .collect()
    }

    #[test]
    fn detects_each_requested_category_and_rejects_invalid_ipv4() {
        let strings = vec![extracted(
            "curl http://evil.example/p x.test 10.1.2.3 999.1.2.3 /bin/sh /etc/cron.d/job",
            100,
        )];
        let findings = detect_findings(&strings);

        assert!(findings.iter().any(|f| f.category == FindingCategory::Url));
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::Domain && f.value == "x.test")
        );
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::Ipv4Address && f.value == "10.1.2.3")
        );
        assert!(!findings.iter().any(|f| f.value == "999.1.2.3"));
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::LinuxPath)
        );
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::SuspiciousIndicator)
        );
        assert!(
            findings
                .iter()
                .any(|f| f.category == FindingCategory::PersistenceLocation)
        );
    }

    #[test]
    fn detects_valid_urls_and_stops_at_delimiters() {
        let findings = detect_findings(&[extracted(
            "https://example.com/a?q=1|unrelated https://rust-lang.org/learn);noise",
            20,
        )]);
        assert_eq!(
            values(&findings, FindingCategory::Url),
            vec!["https://example.com/a?q=1", "https://rust-lang.org/learn"]
        );
        assert_eq!(
            findings
                .iter()
                .find(|finding| finding.value.starts_with("https://example"))
                .map(|finding| finding.offset),
            Some(20)
        );
    }

    #[test]
    fn accepts_realistic_domains_and_rejects_binary_noise() {
        let findings =
            detect_findings(&[extracted("example.com sub.rust-lang.org t.UH j.ZH 5.aE", 0)]);
        assert_eq!(
            values(&findings, FindingCategory::Domain),
            vec!["example.com", "sub.rust-lang.org"]
        );
    }

    #[test]
    fn rejects_source_and_shared_library_filenames() {
        let findings = detect_findings(&[extracted(
            "line.rs mod.rs lib.rs libc.so libm.so useful.dev",
            0,
        )]);
        assert_eq!(
            values(&findings, FindingCategory::Domain),
            vec!["useful.dev"]
        );
    }

    #[test]
    fn deduplicates_each_category_and_keeps_first_offset() {
        let findings = detect_findings(&[
            extracted("example.com 10.0.0.1 https://example.com/a", 10),
            extracted("example.com 10.0.0.1 https://example.com/a", 100),
        ]);
        let domains: Vec<_> = findings
            .iter()
            .filter(|finding| finding.category == FindingCategory::Domain)
            .collect();
        let addresses: Vec<_> = findings
            .iter()
            .filter(|finding| finding.category == FindingCategory::Ipv4Address)
            .collect();
        let urls: Vec<_> = findings
            .iter()
            .filter(|finding| finding.category == FindingCategory::Url)
            .collect();

        assert_eq!(domains.len(), 1);
        assert_eq!(domains[0].offset, 10);
        assert_eq!(addresses.len(), 1);
        assert_eq!(addresses[0].offset, 22);
        assert_eq!(urls.len(), 1);
        assert_eq!(urls[0].offset, 31);
    }
}
