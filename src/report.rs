use crate::elf::ElfInspection;
use crate::model::{FindingCategory, ScanResult};

pub fn print_report(path: &std::path::Path, result: &ScanResult) {
    println!("RavenScanner static triage report");
    println!("File: {}", path.display());
    println!("Size: {} bytes", result.byte_count);
    println!("Printable ASCII strings: {}", result.strings.len());
    println!();

    print_elf_information(&result.elf);

    for category in FindingCategory::ALL {
        let matches: Vec<_> = result
            .findings
            .iter()
            .filter(|finding| finding.category == category)
            .collect();
        println!("{} ({}):", category.heading(), matches.len());
        if matches.is_empty() {
            println!("  none");
        } else {
            for finding in matches {
                println!("  - 0x{:08x}  {}", finding.offset, finding.value);
            }
        }
        println!();
    }

    println!("Risk score: {}/100", result.risk.total);
    if result.risk.contributions.is_empty() {
        println!("  No scoring rules matched.");
    } else {
        println!("Score explanation:");
        for contribution in &result.risk.contributions {
            println!(
                "  +{:>2}  {}",
                contribution.points, contribution.description
            );
        }
        if result
            .risk
            .contributions
            .iter()
            .map(|item| u16::from(item.points))
            .sum::<u16>()
            > 100
        {
            println!("  Total capped at 100.");
        }
    }
    println!();
    println!("This score is a triage aid, not a malware verdict.");
}

fn print_elf_information(inspection: &ElfInspection) {
    println!("ELF information:");
    match inspection {
        ElfInspection::NotElf => println!("  Format: Not ELF"),
        ElfInspection::Valid(header) => {
            println!("  Format: ELF");
            println!("  Class: {}", header.class);
            println!("  Endianness: {}", header.endianness);
            println!("  Architecture: {}", header.architecture);
            println!("  Entry point: 0x{:x}", header.entry_point);
        }
        ElfInspection::Malformed { reason } => {
            println!("  Format: ELF");
            println!("  Status: Malformed ({reason})");
        }
    }
    println!();
}
