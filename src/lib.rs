pub mod detector;
pub mod elf;
pub mod extractor;
pub mod model;
pub mod report;
pub mod scoring;

use model::ScanResult;

/// Analyze bytes without opening files, starting processes, or using the network.
pub fn scan_bytes(bytes: &[u8], minimum_string_length: usize) -> ScanResult {
    let elf = elf::inspect(bytes);
    let strings = extractor::extract_ascii_strings(bytes, minimum_string_length);
    let findings = detector::detect_findings(&strings);
    let risk = scoring::calculate_risk(&findings);

    ScanResult {
        byte_count: bytes.len(),
        elf,
        strings,
        findings,
        risk,
    }
}
