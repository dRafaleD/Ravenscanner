use std::fmt::Write;
use std::path::Path;

use serde::Serialize;

use crate::elf::ElfInspection;
use crate::model::{Finding, FindingCategory, ScanResult};

pub fn print_report(path: &Path, result: &ScanResult, max_results: usize) {
    print!("{}", render_text_report(path, result, max_results));
}

pub fn terminal_literal(value: &str) -> String {
    value
        .chars()
        .flat_map(|character| {
            if character.is_control()
                || matches!(character, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
            {
                character.escape_unicode().collect::<Vec<_>>()
            } else {
                vec![character]
            }
        })
        .collect()
}

pub fn render_text_report(path: &Path, result: &ScanResult, max_results: usize) -> String {
    let mut output = String::new();
    writeln!(output, "RavenScanner static triage report").unwrap();
    writeln!(
        output,
        "File: {}",
        terminal_literal(&path.display().to_string())
    )
    .unwrap();
    writeln!(output, "Size: {} bytes", result.byte_count).unwrap();
    writeln!(output, "SHA-256: {}", result.sha256).unwrap();
    writeln!(output, "Entropy: {:.2} / 8.00", result.entropy).unwrap();
    writeln!(
        output,
        "Printable ASCII strings: {}\n",
        result.strings.len()
    )
    .unwrap();

    write_elf_information(&mut output, &result.elf, max_results);

    for category in FindingCategory::ALL {
        write_category(&mut output, result, category, max_results);
    }

    writeln!(output, "Risk score: {}/100", result.risk.total).unwrap();
    if result.risk.contributions.is_empty() {
        writeln!(output, "Reasons: none").unwrap();
    } else {
        writeln!(output, "Reasons:").unwrap();
        for contribution in &result.risk.contributions {
            writeln!(
                output,
                "  +{:>2}  {}",
                contribution.points, contribution.description
            )
            .unwrap();
        }
        let uncapped_total: u16 = result
            .risk
            .contributions
            .iter()
            .map(|item| u16::from(item.points))
            .sum();
        if uncapped_total > 100 {
            writeln!(output, "  Total capped at 100.").unwrap();
        }
    }
    writeln!(output).unwrap();
    writeln!(
        output,
        "This heuristic score is a triage aid, not a malware verdict."
    )
    .unwrap();
    output
}

fn write_elf_information(output: &mut String, inspection: &ElfInspection, max_results: usize) {
    writeln!(output, "ELF information:").unwrap();
    match inspection {
        ElfInspection::NotElf => writeln!(output, "  Format: Not ELF").unwrap(),
        ElfInspection::Valid(header) => {
            writeln!(output, "  Format: ELF").unwrap();
            writeln!(output, "  Class: {}", header.class).unwrap();
            writeln!(output, "  Endianness: {}", header.endianness).unwrap();
            writeln!(output, "  Architecture: {}", header.architecture).unwrap();
            writeln!(output, "  Entry point: 0x{:x}", header.entry_point).unwrap();
            if let Some(error) = &header.section_error {
                writeln!(output, "  Sections: unavailable ({error})").unwrap();
            } else if header.sections.is_empty() {
                writeln!(output, "  Sections: none").unwrap();
            } else {
                write_counted_heading(output, "  Sections", header.sections.len(), max_results);
                for name in header.sections.iter().take(max_results) {
                    writeln!(output, "    {}", terminal_literal(name)).unwrap();
                }
            }
        }
        ElfInspection::Malformed { reason } => {
            writeln!(output, "  Format: ELF").unwrap();
            writeln!(output, "  Status: Malformed ({reason})").unwrap();
        }
    }
    writeln!(output).unwrap();
}

fn write_category(
    output: &mut String,
    result: &ScanResult,
    category: FindingCategory,
    max_results: usize,
) {
    let matches: Vec<_> = result
        .findings
        .iter()
        .filter(|finding| finding.category == category)
        .collect();
    write_counted_heading(output, category.heading(), matches.len(), max_results);
    if matches.is_empty() {
        writeln!(output, "  none").unwrap();
    } else {
        for finding in matches.into_iter().take(max_results) {
            writeln!(
                output,
                "  - 0x{:08x}  {}",
                finding.offset,
                terminal_literal(&finding.value)
            )
            .unwrap();
        }
    }
    writeln!(output).unwrap();
}

fn write_counted_heading(output: &mut String, heading: &str, total: usize, maximum: usize) {
    if total > maximum {
        writeln!(
            output,
            "{heading} ({total} total, showing first {maximum}):"
        )
        .unwrap();
    } else {
        writeln!(output, "{heading} ({total}):").unwrap();
    }
}

#[derive(Serialize)]
struct JsonReport<'a> {
    file_path: String,
    file_size: usize,
    sha256: &'a str,
    entropy: f64,
    elf: Option<JsonElf<'a>>,
    urls: JsonCategory<'a>,
    ipv4_addresses: JsonCategory<'a>,
    domains: JsonCategory<'a>,
    linux_paths: JsonCategory<'a>,
    suspicious_indicators: JsonCategory<'a>,
    persistence_indicators: JsonCategory<'a>,
    risk: JsonRisk<'a>,
}

#[derive(Serialize)]
struct JsonElf<'a> {
    status: &'static str,
    class: Option<String>,
    endianness: Option<String>,
    architecture: Option<String>,
    entry_point: Option<String>,
    section_total: usize,
    sections: Vec<&'a str>,
    section_error: Option<&'a str>,
    error: Option<&'a str>,
}

#[derive(Serialize)]
struct JsonCategory<'a> {
    total: usize,
    results: Vec<JsonFinding<'a>>,
}

#[derive(Serialize)]
struct JsonFinding<'a> {
    value: &'a str,
    offset: usize,
}

#[derive(Serialize)]
struct JsonRisk<'a> {
    score: u8,
    maximum: u8,
    heuristic: bool,
    reasons: Vec<JsonReason<'a>>,
}

#[derive(Serialize)]
struct JsonReason<'a> {
    points: u8,
    description: &'a str,
}

pub fn render_json_report(
    path: &Path,
    result: &ScanResult,
    max_results: usize,
) -> Result<String, serde_json::Error> {
    let report = JsonReport {
        file_path: path.display().to_string(),
        file_size: result.byte_count,
        sha256: &result.sha256,
        entropy: result.entropy,
        elf: json_elf(&result.elf, max_results),
        urls: json_category(result, FindingCategory::Url, max_results),
        ipv4_addresses: json_category(result, FindingCategory::Ipv4Address, max_results),
        domains: json_category(result, FindingCategory::Domain, max_results),
        linux_paths: json_category(result, FindingCategory::LinuxPath, max_results),
        suspicious_indicators: json_category(
            result,
            FindingCategory::SuspiciousIndicator,
            max_results,
        ),
        persistence_indicators: json_category(
            result,
            FindingCategory::PersistenceLocation,
            max_results,
        ),
        risk: JsonRisk {
            score: result.risk.total,
            maximum: 100,
            heuristic: true,
            reasons: result
                .risk
                .contributions
                .iter()
                .map(|contribution| JsonReason {
                    points: contribution.points,
                    description: &contribution.description,
                })
                .collect(),
        },
    };
    serde_json::to_string_pretty(&report)
}

fn json_category(
    result: &ScanResult,
    category: FindingCategory,
    max_results: usize,
) -> JsonCategory<'_> {
    let matches: Vec<&Finding> = result
        .findings
        .iter()
        .filter(|finding| finding.category == category)
        .collect();
    JsonCategory {
        total: matches.len(),
        results: matches
            .into_iter()
            .take(max_results)
            .map(|finding| JsonFinding {
                value: &finding.value,
                offset: finding.offset,
            })
            .collect(),
    }
}

fn json_elf(inspection: &ElfInspection, max_results: usize) -> Option<JsonElf<'_>> {
    match inspection {
        ElfInspection::NotElf => None,
        ElfInspection::Valid(header) => Some(JsonElf {
            status: "valid",
            class: Some(header.class.to_string()),
            endianness: Some(header.endianness.to_string()),
            architecture: Some(header.architecture.to_string()),
            entry_point: Some(format!("0x{:x}", header.entry_point)),
            section_total: header.sections.len(),
            sections: header
                .sections
                .iter()
                .take(max_results)
                .map(String::as_str)
                .collect(),
            section_error: header.section_error.as_deref(),
            error: None,
        }),
        ElfInspection::Malformed { reason } => Some(JsonElf {
            status: "malformed",
            class: None,
            endianness: None,
            architecture: None,
            entry_point: None,
            section_total: 0,
            sections: Vec::new(),
            section_error: None,
            error: Some(reason),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn untrusted_names_are_literal_but_json_retains_original_data() {
        let mut result = crate::scan_bytes(b"hello", 4);
        let name = "\u{1b}]8;;https://example.test\u{7}name\r\n\u{202e}";
        result.elf = crate::elf::ElfInspection::Valid(crate::elf::ElfHeader {
            class: crate::elf::ElfClass::Elf64,
            endianness: crate::elf::Endianness::Little,
            architecture: crate::elf::MachineArchitecture::X86_64,
            entry_point: 0,
            sections: vec![name.into()],
            section_error: None,
        });
        let report = render_text_report(Path::new(name), &result, 10);
        assert!(!report.contains('\u{1b}'));
        assert!(!report.contains('\r'));
        assert!(!report.contains('\u{202e}'));
        assert!(report.contains("name"));
        let json: serde_json::Value =
            serde_json::from_str(&render_json_report(Path::new("sample"), &result, 10).unwrap())
                .unwrap();
        assert_eq!(json["elf"]["sections"][0], name);
    }

    #[test]
    fn serializes_stable_json_fields() {
        let result = crate::scan_bytes(b"example.com\0/bin/sh", 4);
        let json = render_json_report(Path::new("sample.bin"), &result, 50).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["file_path"], "sample.bin");
        assert_eq!(value["file_size"], 19);
        assert_eq!(value["sha256"].as_str().map(str::len), Some(64));
        assert_eq!(value["domains"]["total"], 1);
        assert_eq!(value["risk"]["maximum"], 100);
        assert_eq!(value["risk"]["heuristic"], true);
    }

    #[test]
    fn result_limit_keeps_total_visible_in_text_and_json() {
        let result = crate::scan_bytes(b"one.com two.org three.net", 4);
        let text = render_text_report(Path::new("sample"), &result, 2);
        assert!(text.contains("Domains (3 total, showing first 2):"));

        let json = render_json_report(Path::new("sample"), &result, 2).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["domains"]["total"], 3);
        assert_eq!(
            value["domains"]["results"].as_array().map(Vec::len),
            Some(2)
        );
    }
}
