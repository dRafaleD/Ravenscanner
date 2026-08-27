#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedString {
    pub offset: usize,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FindingCategory {
    Url,
    Ipv4Address,
    Domain,
    LinuxPath,
    SuspiciousIndicator,
    PersistenceLocation,
}

impl FindingCategory {
    pub const ALL: [Self; 6] = [
        Self::Url,
        Self::Ipv4Address,
        Self::Domain,
        Self::LinuxPath,
        Self::SuspiciousIndicator,
        Self::PersistenceLocation,
    ];

    pub fn heading(self) -> &'static str {
        match self {
            Self::Url => "URLs",
            Self::Ipv4Address => "IPv4 addresses",
            Self::Domain => "Domains",
            Self::LinuxPath => "Linux paths",
            Self::SuspiciousIndicator => "Suspicious Linux indicators",
            Self::PersistenceLocation => "Persistence-related locations",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub category: FindingCategory,
    pub value: String,
    pub offset: usize,
    /// Stable rule name used by the explainable scoring logic.
    pub rule: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScoreContribution {
    pub description: String,
    pub points: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskScore {
    pub total: u8,
    pub contributions: Vec<ScoreContribution>,
}

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub byte_count: usize,
    pub sha256: String,
    pub entropy: f64,
    pub elf: crate::elf::ElfInspection,
    pub strings: Vec<ExtractedString>,
    pub findings: Vec<Finding>,
    pub risk: RiskScore,
}
