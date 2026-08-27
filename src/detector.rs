use std::net::Ipv4Addr;
use std::sync::LazyLock;

use regex::Regex;

use crate::model::{ExtractedString, Finding, FindingCategory};

static URL_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?i)\bhttps?://[^\s<>\"']+"#).expect("the URL regex must be valid")
});
static IPV4_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b").expect("the IPv4 regex must be valid")
});
static DOMAIN_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
        .expect("the domain regex must be valid")
});
static PATH_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?:^|[\s\"'=:(])(/(?:[A-Za-z0-9._+@%~-]+/?)+)"#)
        .expect("the Linux path regex must be valid")
});

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
        detect_urls(extracted, &mut findings);
        detect_ipv4_addresses(extracted, &mut findings);
        detect_domains(extracted, &mut findings);
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

    findings.sort_by_key(|finding| {
        (
            finding.offset,
            finding.category.heading(),
            finding.value.clone(),
        )
    });
    findings.dedup_by(|left, right| {
        left.category == right.category && left.offset == right.offset && left.value == right.value
    });
    findings
}

fn detect_urls(extracted: &ExtractedString, output: &mut Vec<Finding>) {
    for found in URL_RE.find_iter(&extracted.value) {
        let value = trim_url_punctuation(found.as_str());
        push_finding(
            extracted,
            found.start(),
            value,
            FindingCategory::Url,
            "url",
            output,
        );
    }
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

fn detect_domains(extracted: &ExtractedString, output: &mut Vec<Finding>) {
    let url_ranges: Vec<_> = URL_RE
        .find_iter(&extracted.value)
        .map(|found| found.start()..found.end())
        .collect();

    for found in DOMAIN_RE.find_iter(&extracted.value) {
        let belongs_to_url = url_ranges
            .iter()
            .any(|range| range.start <= found.start() && found.end() <= range.end);
        if !belongs_to_url {
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
    value.trim_end_matches(['.', ',', ';', ':', ')', ']', '}'])
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

    #[test]
    fn detects_each_requested_category_and_rejects_invalid_ipv4() {
        let strings = vec![ExtractedString {
            offset: 100,
            value: "curl http://evil.example/p x.test 10.1.2.3 999.1.2.3 /bin/sh /etc/cron.d/job"
                .into(),
        }];
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
}
