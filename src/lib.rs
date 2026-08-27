pub mod detector;
pub mod elf;
pub mod entropy;
pub mod extractor;
pub mod hashing;
pub mod model;
pub mod report;
pub mod scoring;

use model::ScanResult;

/// Analyze bytes without opening files, starting processes, or using the network.
pub fn scan_bytes(bytes: &[u8], minimum_string_length: usize) -> ScanResult {
    let sha256 = hashing::sha256_hex(bytes);
    let entropy = entropy::shannon_entropy(bytes);
    let elf = elf::inspect(bytes);
    let strings = extractor::extract_ascii_strings(bytes, minimum_string_length);
    let findings = detector::detect_findings(&strings);
    let risk = scoring::calculate_risk_with_entropy(&findings, entropy);

    ScanResult {
        byte_count: bytes.len(),
        sha256,
        entropy,
        elf,
        strings,
        findings,
        risk,
    }
}
