use std::collections::HashSet;

use crate::model::{Finding, FindingCategory, RiskScore, ScoreContribution};

const SUSPICIOUS_WEIGHTS: [(&str, u8); 10] = [
    ("shell-bin-sh", 12),
    ("shell-bash", 6),
    ("download-curl", 5),
    ("download-wget", 5),
    ("permission-chmod", 5),
    ("scheduler-crontab", 10),
    ("service-systemctl", 8),
    ("temporary-tmp", 4),
    ("memory-dev-shm", 10),
    ("shell-bin-dash", 8),
];

const HIGH_ENTROPY_THRESHOLD: f64 = 7.2;

pub fn calculate_risk(findings: &[Finding]) -> RiskScore {
    calculate_risk_with_entropy(findings, 0.0)
}

pub fn calculate_risk_with_entropy(findings: &[Finding], entropy: f64) -> RiskScore {
    let mut contributions = Vec::new();
    let unique_rules: HashSet<_> = findings.iter().map(|finding| finding.rule).collect();

    for (rule, points) in SUSPICIOUS_WEIGHTS {
        if unique_rules.contains(rule) {
            contributions.push(ScoreContribution {
                description: format!("Suspicious indicator matched: {rule}"),
                points,
            });
        }
    }

    add_capped_category_score(
        findings,
        FindingCategory::PersistenceLocation,
        12,
        36,
        "Unique persistence-location rules",
        &mut contributions,
    );

    // High entropy is common in compressed and encrypted benign files, so it is
    // intentionally a small contribution and never a verdict by itself.
    if entropy >= HIGH_ENTROPY_THRESHOLD {
        contributions.push(ScoreContribution {
            description: format!(
                "High overall entropy ({entropy:.2}/8.00); weak packing/encryption heuristic"
            ),
            points: 5,
        });
    }
    add_capped_category_score(
        findings,
        FindingCategory::Url,
        2,
        6,
        "URLs",
        &mut contributions,
    );
    add_capped_category_score(
        findings,
        FindingCategory::Ipv4Address,
        3,
        9,
        "IPv4 addresses",
        &mut contributions,
    );
    add_capped_category_score(
        findings,
        FindingCategory::Domain,
        1,
        5,
        "Domains",
        &mut contributions,
    );

    let uncapped_total: u16 = contributions
        .iter()
        .map(|item| u16::from(item.points))
        .sum();
    RiskScore {
        total: uncapped_total.min(100) as u8,
        contributions,
    }
}

fn add_capped_category_score(
    findings: &[Finding],
    category: FindingCategory,
    points_each: u8,
    maximum: u8,
    label: &str,
    output: &mut Vec<ScoreContribution>,
) {
    let unique_rules: HashSet<_> = findings
        .iter()
        .filter(|finding| finding.category == category)
        .map(|finding| (finding.rule, finding.value.to_ascii_lowercase()))
        .collect();
    let points = (unique_rules.len() as u16 * u16::from(points_each)).min(u16::from(maximum)) as u8;

    if points > 0 {
        output.push(ScoreContribution {
            description: format!(
                "{label}: {} unique match(es), capped at {maximum}",
                unique_rules.len()
            ),
            points,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_indicator_does_not_inflate_indicator_weight() {
        let finding = Finding {
            category: FindingCategory::SuspiciousIndicator,
            value: "curl".into(),
            offset: 0,
            rule: "download-curl",
        };
        let score = calculate_risk(&[finding.clone(), finding]);
        assert_eq!(score.total, 5);
    }

    #[test]
    fn score_never_exceeds_one_hundred() {
        let mut findings = Vec::new();
        for (index, (rule, _)) in SUSPICIOUS_WEIGHTS.iter().enumerate() {
            findings.push(Finding {
                category: FindingCategory::SuspiciousIndicator,
                value: (*rule).into(),
                offset: index,
                rule,
            });
        }
        for index in 0..10 {
            findings.push(Finding {
                category: FindingCategory::PersistenceLocation,
                value: format!("/p/{index}"),
                offset: index,
                rule: "persistence-test",
            });
        }
        assert_eq!(calculate_risk(&findings).total, 100);
    }

    #[test]
    fn high_entropy_adds_only_a_small_explained_contribution() {
        let score = calculate_risk_with_entropy(&[], 7.8);
        assert_eq!(score.total, 5);
        assert_eq!(score.contributions.len(), 1);
        assert!(score.contributions[0].description.contains("weak"));
    }
}
