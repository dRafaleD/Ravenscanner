# RavenScanner

[![Rust](https://img.shields.io/badge/Rust-2024_edition-000000?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)](#requirements--gereksinimler)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**Defensive static file triage for Linux, written in Rust.**

**Linux için Rust ile geliştirilmiş savunma odaklı statik dosya triyaj aracı.**

[English](#english) · [Türkçe](#türkçe)

> [!IMPORTANT]
> RavenScanner is a triage aid, not a malware verdict. It performs static
> analysis only and never executes or modifies the scanned file.

---

## English

### Overview

RavenScanner is a small, explainable, Linux-only command-line tool for the
first-pass inspection of unknown or suspicious files. It reads the target as raw
bytes, extracts printable ASCII strings, recognizes useful indicators, and
summarizes the results with a transparent risk score from 0 to 100.

Its intentionally focused implementation makes it useful both for defensive
triage and for learning Rust or the fundamentals of malware analysis without
hiding behavior behind a large parsing framework.

### What can it be used for?

- Initial triage of files collected during incident response
- Reviewing unknown Linux binaries before deeper analysis
- Finding network indicators such as URLs, domains, and IPv4 addresses
- Spotting shell commands, temporary locations, and persistence-related paths
- Reading basic ELF identity information without executing the binary
- Teaching static-analysis concepts with beginner-readable Rust modules

RavenScanner does not determine whether a file is malicious. Its output helps an
analyst decide what deserves closer inspection with tools such as a disassembler,
sandbox, or reverse-engineering suite.

### Features

- Raw-byte, read-only file inspection
- Printable ASCII string extraction with byte offsets
- URL, IPv4 address, domain, and Linux filesystem path detection
- Suspicious Linux indicators including `/bin/sh`, `bash`, `curl`, `wget`,
  `chmod`, `crontab`, `systemctl`, `/tmp`, and `/dev/shm`
- Common cron, systemd, shell-profile, SSH, autostart, and loader persistence paths
- Basic ELF header inspection:
  - 32-bit and 64-bit class
  - Little-endian and big-endian encoding
  - x86, x86_64, ARM, AArch64, and clearly labeled unknown architectures
  - Entry-point address
- Graceful handling of non-ELF, malformed, and truncated input
- Explainable risk score from 0 to 100 with itemized contributions
- No networking, execution, dynamic analysis, or file modification

### Why RavenScanner?

Many security tools provide a result without making the reasoning easy to
follow. RavenScanner favors a compact codebase, explicit matching rules, visible
byte offsets, and an itemized score. This makes findings easy to verify and the
implementation approachable for someone learning how static triage works.

### Build and run

#### Requirements / Gereksinimler

- Linux
- A current stable Rust toolchain with Cargo

RavenScanner deliberately refuses normal builds on non-Linux targets.

```bash
git clone https://github.com/dRafaleD/Ravenscanner.git
cd Ravenscanner
cargo build --release
```

Scan a file:

```bash
./target/release/ravenscanner /path/to/file
```

Change the minimum printable-string length (default: `4`):

```bash
./target/release/ravenscanner --min-string-length 6 /path/to/file
```

### Example output

```text
RavenScanner static triage report
File: ./sample
Size: 14568 bytes
Printable ASCII strings: 217

ELF information:
  Format: ELF
  Class: 64-bit
  Endianness: Little Endian
  Architecture: x86_64
  Entry point: 0x401050

URLs (1):
  - 0x000012a0  https://updates.example.test/payload

IPv4 addresses (1):
  - 0x000012d2  192.0.2.10

Suspicious Linux indicators (2):
  - 0x00001310  curl
  - 0x00001320  /bin/sh

Risk score: 22/100
Score explanation:
  +12  Suspicious indicator matched: shell-bin-sh
  + 5  Suspicious indicator matched: download-curl
  + 2  URLs: 1 unique match(es), capped at 6
  + 3  IPv4 addresses: 1 unique match(es), capped at 9

This score is a triage aid, not a malware verdict.
```

The complete report also includes domains, Linux paths, persistence locations,
and empty categories.

### Risk score

The score is deliberately simple and auditable:

- Each distinct suspicious indicator has a fixed weight.
- Each unique persistence-location match adds 12 points, capped at 36.
- Unique URLs add 2 points each (cap 6), IPv4 addresses add 3 each (cap 9),
  and domains add 1 each (cap 5).
- Generic Linux paths and ELF metadata are reported but do not add risk alone.
- Repeated indicators do not repeatedly inflate their fixed indicator weight.
- The final score is capped at 100.

### Safety and scope

RavenScanner performs **static analysis only**. It reads the selected target as
raw bytes and never:

- Executes or loads it as a program
- Modifies the target
- Makes network requests
- Performs dynamic analysis or sandboxing

Handle untrusted samples with appropriate permissions and isolated lab
practices. Pattern matching can produce false positives and can miss encoded,
encrypted, UTF-16, or obfuscated content. ELF support is intentionally limited
to the required header fields; sections and program headers are not parsed.

---

## Türkçe

### Genel bakış

RavenScanner; bilinmeyen veya şüpheli dosyaların ilk incelemesi için geliştirilmiş,
açıklanabilir ve yalnızca Linux üzerinde çalışan küçük bir komut satırı aracıdır.
Hedef dosyayı ham baytlar olarak okur, yazdırılabilir ASCII dizelerini çıkarır,
yararlı göstergeleri sınıflandırır ve sonuçları 0–100 arasında şeffaf bir risk
skoruyla özetler.

Odaklı ve modüler yapısı sayesinde hem savunma amaçlı dosya triyajında hem de Rust
ve temel zararlı yazılım analizi kavramlarını öğrenirken kullanılabilir.

### Ne için kullanılabilir?

- Olay müdahalesi sırasında toplanan dosyaların ilk triyajı
- Bilinmeyen Linux binary dosyalarının ileri analiz öncesinde incelenmesi
- URL, domain ve IPv4 adresi gibi ağ göstergelerinin bulunması
- Shell komutları, geçici dizinler ve kalıcılıkla ilişkili yolların fark edilmesi
- Bir ELF dosyasını çalıştırmadan temel başlık bilgilerinin okunması
- Okunabilir Rust modülleri üzerinden statik analiz mantığının öğrenilmesi

RavenScanner bir dosyanın zararlı olup olmadığına tek başına karar vermez. Çıktı,
hangi dosya veya göstergelerin daha ayrıntılı tersine mühendislik, disassembly ya
da kontrollü sandbox analizini hak ettiğini belirlemeye yardımcı olur.

### Özellikler

- Salt-okunur ham bayt incelemesi
- Bayt ofsetleriyle yazdırılabilir ASCII dize çıkarımı
- URL, IPv4, domain ve Linux dosya yolu tespiti
- `/bin/sh`, `bash`, `curl`, `wget`, `chmod`, `crontab`, `systemctl`, `/tmp` ve
  `/dev/shm` gibi şüpheli Linux göstergeleri
- Cron, systemd, shell profili, SSH, autostart ve loader kalıcılık konumları
- Temel ELF başlık incelemesi:
  - 32-bit ve 64-bit sınıf
  - Little-endian ve big-endian bayt sıralaması
  - x86, x86_64, ARM, AArch64 ve güvenli bilinmeyen mimari gösterimi
  - Giriş noktası adresi
- ELF olmayan, bozuk veya kesik dosyaların panik olmadan işlenmesi
- Katkıları tek tek gösterilen açıklanabilir 0–100 risk skoru
- Ağ bağlantısı, çalıştırma, dinamik analiz veya dosya değişikliği yoktur

### Neden RavenScanner?

Birçok güvenlik aracı sonucu gösterirken sonuca nasıl ulaştığını takip etmeyi
zorlaştırabilir. RavenScanner küçük bir kod tabanını, açık eşleşme kurallarını,
görünür bayt ofsetlerini ve kalem kalem açıklanan bir skoru tercih eder. Böylece
hem bulgular kolayca doğrulanabilir hem de statik triyajın çalışma biçimi kod
üzerinden rahatça öğrenilebilir.

### Derleme ve kullanım

Linux üzerinde güncel bir Rust ve Cargo kurulumu gereklidir:

```bash
git clone https://github.com/dRafaleD/Ravenscanner.git
cd Ravenscanner
cargo build --release
```

Bir dosyayı tara:

```bash
./target/release/ravenscanner /dosya/yolu
```

Minimum yazdırılabilir dize uzunluğunu değiştir (varsayılan: `4`):

```bash
./target/release/ravenscanner --min-string-length 6 /dosya/yolu
```

### Risk skoru

Skor özellikle basit ve denetlenebilir tutulmuştur:

- Her benzersiz şüpheli göstergenin sabit bir ağırlığı vardır.
- Her benzersiz kalıcılık konumu 12 puan ekler; bu kategori en fazla 36 puandır.
- Benzersiz URL'ler 2 (en fazla 6), IPv4 adresleri 3 (en fazla 9), domain'ler ise
  1 puan (en fazla 5) ekler.
- Genel Linux yolları ve ELF bilgileri tek başına skoru yükseltmez.
- Tekrarlanan aynı göstergeler sabit gösterge ağırlığını tekrar tekrar artırmaz.
- Sonuç en fazla 100 olabilir.

### Güvenlik ve kapsam

RavenScanner **yalnızca statik analiz** yapar. Seçilen hedefi ham baytlar olarak
okur ve hiçbir zaman:

- Dosyayı çalıştırmaz veya program olarak yüklemez
- Hedef dosyayı değiştirmez
- Ağ isteği yapmaz
- Dinamik analiz veya sandbox işlemi gerçekleştirmez

Güvenilmeyen örnekleri uygun yetkilerle ve izole laboratuvar uygulamalarıyla ele
alın. Örüntü eşleştirme yanlış pozitif üretebilir; kodlanmış, şifrelenmiş, UTF-16
veya gizlenmiş içerikleri kaçırabilir. ELF desteği gerekli temel başlık alanlarıyla
sınırlıdır; section ve program header ayrıştırması yapılmaz.

## Development / Geliştirme

```bash
cargo fmt --check
cargo test
cargo clippy -- -D warnings
```

The project keeps extraction, detection, ELF inspection, scoring, reporting, and
CLI responsibilities in separate modules under [`src/`](src/).

## License / Lisans

Distributed under the [MIT License](LICENSE). / [MIT Lisansı](LICENSE) ile
dağıtılmaktadır.
