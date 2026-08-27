use std::fmt;

const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];
const ELF32_HEADER_SIZE: usize = 52;
const ELF64_HEADER_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfClass {
    Elf32,
    Elf64,
}

impl fmt::Display for ElfClass {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Elf32 => write!(formatter, "32-bit"),
            Self::Elf64 => write!(formatter, "64-bit"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Endianness {
    Little,
    Big,
}

impl fmt::Display for Endianness {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Little => write!(formatter, "Little Endian"),
            Self::Big => write!(formatter, "Big Endian"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MachineArchitecture {
    X86,
    X86_64,
    Arm,
    AArch64,
    Unknown(u16),
}

impl fmt::Display for MachineArchitecture {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X86 => write!(formatter, "x86"),
            Self::X86_64 => write!(formatter, "x86_64"),
            Self::Arm => write!(formatter, "ARM"),
            Self::AArch64 => write!(formatter, "AArch64"),
            Self::Unknown(value) => {
                write!(formatter, "Unknown (e_machine: {value}, 0x{value:04x})")
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ElfHeader {
    pub class: ElfClass,
    pub endianness: Endianness,
    pub architecture: MachineArchitecture,
    pub entry_point: u64,
    pub sections: Vec<String>,
    pub section_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ElfInspection {
    NotElf,
    Valid(ElfHeader),
    Malformed { reason: String },
}

/// Inspect only the small set of ELF header fields RavenScanner reports.
/// Every byte access is preceded by a length check so malformed input is safe.
pub fn inspect(bytes: &[u8]) -> ElfInspection {
    if !bytes.starts_with(&ELF_MAGIC) {
        return ElfInspection::NotElf;
    }

    let Some(&class_value) = bytes.get(4) else {
        return truncated("ELF identification");
    };
    let class = match class_value {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        other => return malformed(format!("unknown ELF class value {other}")),
    };

    let Some(&endianness_value) = bytes.get(5) else {
        return truncated("ELF identification");
    };
    let endianness = match endianness_value {
        1 => Endianness::Little,
        2 => Endianness::Big,
        other => return malformed(format!("unknown ELF data encoding value {other}")),
    };

    let required_size = match class {
        ElfClass::Elf32 => ELF32_HEADER_SIZE,
        ElfClass::Elf64 => ELF64_HEADER_SIZE,
    };
    if bytes.len() < required_size {
        return malformed(format!(
            "truncated {} header: expected at least {required_size} bytes, found {}",
            class,
            bytes.len()
        ));
    }

    // e_machine is a 16-bit value at offset 18 in both ELF classes.
    let machine = read_u16(&bytes[18..20], endianness);
    let architecture = decode_architecture(machine);

    // e_entry starts at offset 24. Its width follows the ELF class.
    let entry_point = match class {
        ElfClass::Elf32 => u64::from(read_u32(&bytes[24..28], endianness)),
        ElfClass::Elf64 => read_u64(&bytes[24..32], endianness),
    };

    let (sections, section_error) = match parse_section_names(bytes, class, endianness) {
        Ok(sections) => (sections, None),
        Err(error) => (Vec::new(), Some(error)),
    };

    ElfInspection::Valid(ElfHeader {
        class,
        endianness,
        architecture,
        entry_point,
        sections,
        section_error,
    })
}

/// Parse only the section table fields needed to resolve section names.
fn parse_section_names(
    bytes: &[u8],
    class: ElfClass,
    endianness: Endianness,
) -> Result<Vec<String>, String> {
    let (table_offset, entry_size, section_count, names_index) = match class {
        ElfClass::Elf32 => (
            u64::from(read_u32(&bytes[32..36], endianness)),
            read_u16(&bytes[46..48], endianness),
            read_u16(&bytes[48..50], endianness),
            read_u16(&bytes[50..52], endianness),
        ),
        ElfClass::Elf64 => (
            read_u64(&bytes[40..48], endianness),
            read_u16(&bytes[58..60], endianness),
            read_u16(&bytes[60..62], endianness),
            read_u16(&bytes[62..64], endianness),
        ),
    };

    if table_offset == 0 && section_count == 0 {
        return Ok(Vec::new());
    }
    if table_offset == 0 {
        return Err("section table has a zero file offset".into());
    }
    if section_count == 0 || names_index == 0xffff {
        return Err("extended ELF section numbering is not supported".into());
    }
    if names_index == 0 {
        return Ok(Vec::new());
    }
    if names_index >= section_count {
        return Err(format!(
            "section-name table index {names_index} is outside {section_count} sections"
        ));
    }

    let minimum_entry_size = match class {
        ElfClass::Elf32 => 40_u16,
        ElfClass::Elf64 => 64_u16,
    };
    if entry_size < minimum_entry_size {
        return Err(format!(
            "section-header entry size {entry_size} is smaller than {minimum_entry_size}"
        ));
    }

    let table_start = usize::try_from(table_offset)
        .map_err(|_| "section table offset does not fit this platform".to_string())?;
    let table_size = usize::from(entry_size)
        .checked_mul(usize::from(section_count))
        .ok_or_else(|| "section table size overflowed".to_string())?;
    checked_range(bytes, table_start, table_size, "section table")?;

    let names_header_start = table_start
        .checked_add(usize::from(names_index) * usize::from(entry_size))
        .ok_or_else(|| "section-name header offset overflowed".to_string())?;
    let names_header = checked_range(
        bytes,
        names_header_start,
        usize::from(entry_size),
        "section-name header",
    )?;

    let (names_offset, names_size) = match class {
        ElfClass::Elf32 => (
            u64::from(read_u32(&names_header[16..20], endianness)),
            u64::from(read_u32(&names_header[20..24], endianness)),
        ),
        ElfClass::Elf64 => (
            read_u64(&names_header[24..32], endianness),
            read_u64(&names_header[32..40], endianness),
        ),
    };
    let names_start = usize::try_from(names_offset)
        .map_err(|_| "section-name string-table offset does not fit this platform".to_string())?;
    let names_length = usize::try_from(names_size)
        .map_err(|_| "section-name string-table size does not fit this platform".to_string())?;
    let names_table = checked_range(
        bytes,
        names_start,
        names_length,
        "section-name string table",
    )?;

    let mut sections = Vec::new();
    for index in 0..usize::from(section_count) {
        let header_start = table_start + index * usize::from(entry_size);
        let header = checked_range(
            bytes,
            header_start,
            usize::from(entry_size),
            "section header",
        )?;
        let name_offset = read_u32(&header[0..4], endianness) as usize;
        if name_offset == 0 {
            continue;
        }
        let name_bytes = names_table
            .get(name_offset..)
            .ok_or_else(|| format!("section {index} name offset is outside the string table"))?;
        let name_end = name_bytes
            .iter()
            .position(|&byte| byte == 0)
            .ok_or_else(|| format!("section {index} name is not null terminated"))?;
        let name = String::from_utf8_lossy(&name_bytes[..name_end]).into_owned();
        if !name.is_empty() {
            sections.push(name);
        }
    }
    Ok(sections)
}

fn checked_range<'a>(
    bytes: &'a [u8],
    start: usize,
    length: usize,
    description: &str,
) -> Result<&'a [u8], String> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| format!("{description} range overflowed"))?;
    bytes
        .get(start..end)
        .ok_or_else(|| format!("truncated {description}"))
}

fn decode_architecture(value: u16) -> MachineArchitecture {
    match value {
        3 => MachineArchitecture::X86,
        40 => MachineArchitecture::Arm,
        62 => MachineArchitecture::X86_64,
        183 => MachineArchitecture::AArch64,
        other => MachineArchitecture::Unknown(other),
    }
}

fn read_u16(bytes: &[u8], endianness: Endianness) -> u16 {
    let value = [bytes[0], bytes[1]];
    match endianness {
        Endianness::Little => u16::from_le_bytes(value),
        Endianness::Big => u16::from_be_bytes(value),
    }
}

fn read_u32(bytes: &[u8], endianness: Endianness) -> u32 {
    let value = [bytes[0], bytes[1], bytes[2], bytes[3]];
    match endianness {
        Endianness::Little => u32::from_le_bytes(value),
        Endianness::Big => u32::from_be_bytes(value),
    }
}

fn read_u64(bytes: &[u8], endianness: Endianness) -> u64 {
    let value = [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ];
    match endianness {
        Endianness::Little => u64::from_le_bytes(value),
        Endianness::Big => u64::from_be_bytes(value),
    }
}

fn truncated(part: &str) -> ElfInspection {
    malformed(format!("truncated {part}"))
}

fn malformed(reason: String) -> ElfInspection {
    ElfInspection::Malformed { reason }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn elf_header(class: u8, endianness: u8, machine: u16, entry_point: u64) -> Vec<u8> {
        let size = if class == 1 {
            ELF32_HEADER_SIZE
        } else {
            ELF64_HEADER_SIZE
        };
        let mut bytes = vec![0; size];
        bytes[0..4].copy_from_slice(&ELF_MAGIC);
        bytes[4] = class;
        bytes[5] = endianness;

        let machine_bytes = if endianness == 2 {
            machine.to_be_bytes()
        } else {
            machine.to_le_bytes()
        };
        bytes[18..20].copy_from_slice(&machine_bytes);

        if class == 1 {
            let entry_bytes = if endianness == 2 {
                (entry_point as u32).to_be_bytes()
            } else {
                (entry_point as u32).to_le_bytes()
            };
            bytes[24..28].copy_from_slice(&entry_bytes);
        } else {
            let entry_bytes = if endianness == 2 {
                entry_point.to_be_bytes()
            } else {
                entry_point.to_le_bytes()
            };
            bytes[24..32].copy_from_slice(&entry_bytes);
        }
        bytes
    }

    #[test]
    fn parses_valid_64_bit_little_endian_header() {
        let bytes = elf_header(2, 1, 62, 0x401050);
        let ElfInspection::Valid(header) = inspect(&bytes) else {
            panic!("expected a valid ELF header");
        };

        assert_eq!(header.class, ElfClass::Elf64);
        assert_eq!(header.endianness, Endianness::Little);
        assert_eq!(header.architecture, MachineArchitecture::X86_64);
        assert_eq!(header.entry_point, 0x401050);
        assert!(header.sections.is_empty());
        assert!(header.section_error.is_none());
    }

    #[test]
    fn parses_valid_32_bit_big_endian_header() {
        let bytes = elf_header(1, 2, 40, 0x1020_3040);
        let ElfInspection::Valid(header) = inspect(&bytes) else {
            panic!("expected a valid ELF header");
        };

        assert_eq!(header.class, ElfClass::Elf32);
        assert_eq!(header.endianness, Endianness::Big);
        assert_eq!(header.architecture, MachineArchitecture::Arm);
        assert_eq!(header.entry_point, 0x1020_3040);
    }

    #[test]
    fn identifies_non_elf_input() {
        assert_eq!(inspect(b"ordinary text"), ElfInspection::NotElf);
    }

    #[test]
    fn reports_truncated_elf_without_panicking() {
        let result = inspect(&ELF_MAGIC);
        assert!(matches!(result, ElfInspection::Malformed { .. }));
    }

    #[test]
    fn decodes_supported_and_unknown_architectures() {
        assert_eq!(decode_architecture(3), MachineArchitecture::X86);
        assert_eq!(decode_architecture(62), MachineArchitecture::X86_64);
        assert_eq!(decode_architecture(40), MachineArchitecture::Arm);
        assert_eq!(decode_architecture(183), MachineArchitecture::AArch64);
        assert_eq!(decode_architecture(999), MachineArchitecture::Unknown(999));
    }

    #[test]
    fn parses_valid_elf_section_names() {
        let mut bytes = vec![0_u8; 0x200];
        bytes[..ELF64_HEADER_SIZE].copy_from_slice(&elf_header(2, 1, 62, 0x401050));

        let section_table_offset = 0x80_u64;
        let names_offset = 0x180_u64;
        let names = b"\0.shstrtab\0.text\0.rodata\0";
        bytes[40..48].copy_from_slice(&section_table_offset.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&4_u16.to_le_bytes());
        bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());

        // Section 1 is the section-name string table itself.
        let section_one = 0x80 + 64;
        bytes[section_one..section_one + 4].copy_from_slice(&1_u32.to_le_bytes());
        bytes[section_one + 24..section_one + 32].copy_from_slice(&names_offset.to_le_bytes());
        bytes[section_one + 32..section_one + 40]
            .copy_from_slice(&(names.len() as u64).to_le_bytes());

        let section_two = 0x80 + 128;
        bytes[section_two..section_two + 4].copy_from_slice(&11_u32.to_le_bytes());
        let section_three = 0x80 + 192;
        bytes[section_three..section_three + 4].copy_from_slice(&17_u32.to_le_bytes());
        bytes[names_offset as usize..names_offset as usize + names.len()].copy_from_slice(names);

        let ElfInspection::Valid(header) = inspect(&bytes) else {
            panic!("expected a valid ELF header");
        };
        assert_eq!(header.sections, [".shstrtab", ".text", ".rodata"]);
        assert!(header.section_error.is_none());
    }

    #[test]
    fn reports_truncated_section_table_without_panicking() {
        let mut bytes = elf_header(2, 1, 62, 0x401050);
        bytes[40..48].copy_from_slice(&0x1000_u64.to_le_bytes());
        bytes[58..60].copy_from_slice(&64_u16.to_le_bytes());
        bytes[60..62].copy_from_slice(&2_u16.to_le_bytes());
        bytes[62..64].copy_from_slice(&1_u16.to_le_bytes());

        let ElfInspection::Valid(header) = inspect(&bytes) else {
            panic!("base ELF header should remain valid");
        };
        assert!(header.sections.is_empty());
        assert!(
            header
                .section_error
                .as_deref()
                .is_some_and(|error| error.contains("truncated section table"))
        );
    }
}
