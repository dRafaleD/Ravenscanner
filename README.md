# RavenScanner

[![Rust](https://img.shields.io/badge/Rust-2024_edition-000000?logo=rust)](https://www.rust-lang.org/)
[![Platform](https://img.shields.io/badge/platform-Linux-FCC624?logo=linux&logoColor=black)](#requirements)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> Lightweight static file triage and basic ELF inspection CLI for Linux, written in Rust.

RavenScanner performs read-only static inspection of files and extracts useful triage information such as SHA-256 hashes, Shannon entropy, printable strings, network IOCs, Linux paths, persistence-related indicators, and basic ELF metadata.

It is designed for fast, explainable first-pass analysis before deeper inspection with reverse-engineering, sandboxing, or incident-response tools.

[English](#english) · [Türkçe](#türkçe)

> [!WARNING]
> RavenScanner is a static triage tool, not an antivirus, EDR, sandbox, malware detector, or forensic framework. Its heuristic triage score is not a malware verdict. Scanned files are never executed or modified.

---

# English

## Overview

RavenScanner is a Linux-focused command-line tool for inspecting unknown or suspicious files without executing them.

The scanner reads the target as raw bytes, extracts a limited set of useful indicators, performs basic ELF inspection when applicable, and produces either a human-readable terminal report or machine-readable JSON output.

The project intentionally favors conservative detection, explicit byte offsets, bounded parsing, and explainable scoring over aggressive classification.

## Quick start

Build the project:

```bash
cargo build --release
```

Scan a file:

```bash
./target/release/ravenscanner /path/to/file
```

Limit displayed results:

```bash
./target/release/ravenscanner --max-results 25 /path/to/file
```

Generate JSON output:

```bash
./target/release/ravenscanner --json /path/to/file
```

Combine both options:

```bash
./target/release/ravenscanner --json --max-results 100 /path/to/file
```

## Features

* Read-only static file inspection
* SHA-256 hashing
* Shannon entropy calculation
* Printable ASCII string extraction
* URL detection
* IPv4 address detection
* Domain detection
* Linux path detection
* Suspicious Linux indicator detection
* Persistence-related location detection
* Per-category IOC deduplication
* Preservation of the first observed byte offset
* Conservative URL and domain validation
* Filtering for common binary-noise and filename-like false positives
* Basic ELF inspection
* Safe ELF section-name parsing
* Graceful handling of malformed or truncated ELF structures
* Explainable heuristic triage score
* Configurable result limiting with `--max-results`
* Machine-readable JSON output
* No file execution
* No file modification
* No network communication

## IOC detection behavior

IOC detection is intentionally conservative rather than exhaustive.

RavenScanner attempts to reduce common false positives caused by binary noise, source-file names, shared-library suffixes, and malformed textual fragments.

Detected values are deduplicated per category while preserving the first observed byte offset.

A recorded IOC test used the following input:

```text
main.rs
libexample.so
example.com
https://openai.com/test
192.168.1.10
```

Observed behavior:

* `main.rs` was not reported as a domain
* `libexample.so` was not reported as a domain
* `example.com` was reported as a domain
* `https://openai.com/test` was reported as a URL
* `192.168.1.10` was reported as an IPv4 address
* detected IOC byte offsets were preserved

These filters reduce false positives but do not make string-based IOC detection complete or authoritative.

## ELF inspection

When a file begins with ELF magic bytes, RavenScanner performs basic ELF structure inspection.

Current ELF support includes:

* ELF identification
* basic class and encoding information
* architecture metadata
* entry-point information
* section-name parsing

Malformed or truncated input is handled conservatively.

For example, a deliberately malformed ELF-like file was reported as:

```text
ELF information:
  Format: ELF
  Status: Malformed (unknown ELF class value 103)
```

The scanner continued normally instead of panicking.

RavenScanner does not currently provide full ELF analysis such as symbol resolution, import reconstruction, relocations, program-header analysis, or disassembly.

## Heuristic triage score

RavenScanner produces an explainable heuristic triage score from `0` to `100`.

The score is intended only to help prioritize findings. It is not a malware classification or confidence score.

Individual findings contribute bounded values, and every contribution is shown in the report.

High overall entropy is treated only as a weak signal because benign compressed or encrypted files may also have high entropy.

A recorded random-input test produced:

```text
Entropy: 7.96 / 8.00

Risk score: 5/100
Reasons:
  + 5  High overall entropy (7.96/8.00); weak packing/encryption heuristic
```

A normal low-entropy text file with no detected indicators scored:

```text
Risk score: 0/100
Reasons: none
```

## Result limiting

The `--max-results <N>` option limits the number of displayed results per category.

The default limit is:

```text
50
```

Result limiting affects presentation only.

It does not change the total number of detected indicators or the heuristic triage score.

In a recorded test containing 20 unique domains:

```bash
ravenscanner --max-results 5 many-iocs.txt
```

the text report displayed:

```text
Domains (20 total, showing first 5):
```

while preserving the full detection total.

## JSON output

Use:

```bash
ravenscanner --json /path/to/file
```

to generate machine-readable output.

Example:

```json
{
  "file_path": "test.txt",
  "file_size": 12,
  "sha256": "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447",
  "entropy": 3.0220552088742005,
  "elf": null,
  "urls": {
    "total": 0,
    "results": []
  },
  "ipv4_addresses": {
    "total": 0,
    "results": []
  },
  "domains": {
    "total": 0,
    "results": []
  },
  "risk": {
    "score": 0,
    "maximum": 100,
    "heuristic": true,
    "reasons": []
  }
}
```

When combined with `--max-results`, JSON retains the full category total while limiting the number of entries inside `results`.

## CLI options

```text
ravenscanner [OPTIONS] <FILE>
```

Common usage:

```bash
ravenscanner /path/to/file
ravenscanner --max-results 25 /path/to/file
ravenscanner --json /path/to/file
ravenscanner --json --max-results 100 /path/to/file
```

### `--max-results <N>`

Limits displayed results per category.

Default:

```text
50
```

### `--json`

Outputs the report as JSON instead of the normal terminal format.

## Requirements

* Linux
* Current stable Rust toolchain
* Cargo

## Development

Run formatting checks:

```bash
cargo fmt --check
```

Run tests:

```bash
cargo test
```

Run Clippy:

```bash
cargo clippy --all-targets -- -D warnings
```

Current verified development state:

```text
cargo fmt --check                         PASS
cargo test                               PASS — 21/21 tests
cargo clippy --all-targets -- -D warnings PASS on Linux
```

## Design principles

RavenScanner is built around a few simple principles:

* **Static only** — scanned files are not executed
* **Read only** — scanned files are not modified
* **Local first** — scanned content is not uploaded
* **Explainable** — score contributions are visible
* **Conservative** — detection favors fewer false positives over aggressive matching
* **Bounded parsing** — malformed binary structures should fail safely
* **Composable output** — JSON can be consumed by scripts and other tools
* **Small scope** — RavenScanner focuses on first-pass triage rather than full malware analysis

## Known limitations

RavenScanner is intentionally limited.

Current limitations include:

* Linux-focused operation
* no dynamic analysis
* no sandbox execution
* no memory analysis
* no network capture
* no PE parsing
* no disassembly
* no symbol or import reconstruction
* limited ELF parsing
* string-based IOC detection can miss valid indicators
* conservative domain validation may ignore legitimate domains
* heuristic scoring can produce false positives and false negatives
* high entropy alone does not indicate malicious behavior

RavenScanner is not production-ready and should not replace specialized incident-response, malware-analysis, or reverse-engineering tools.

## Responsible use

RavenScanner is intended for defensive security research, malware-analysis education, incident-response triage, and inspection of files you own or are explicitly authorized to analyze.

Always validate findings independently before making security decisions.

## License

RavenScanner is distributed under the [MIT License](LICENSE).

---

# Türkçe

## Genel bakış

RavenScanner, bilinmeyen veya şüpheli dosyaları çalıştırmadan incelemek için geliştirilmiş Linux odaklı bir komut satırı aracıdır.

Dosyayı ham baytlar olarak okur, sınırlı fakat faydalı statik göstergeleri çıkarır, uygun dosyalarda temel ELF incelemesi yapar ve sonuçları terminal raporu veya JSON olarak sunar.

Proje agresif sınıflandırma yapmak yerine temkinli tespit, açık bayt ofsetleri, güvenli ayrıştırma ve açıklanabilir skorlamayı tercih eder.

## Hızlı başlangıç

Projeyi derleyin:

```bash
cargo build --release
```

Dosya tarayın:

```bash
./target/release/ravenscanner /path/to/file
```

Gösterilen sonuçları sınırlayın:

```bash
./target/release/ravenscanner --max-results 25 /path/to/file
```

JSON çıktısı alın:

```bash
./target/release/ravenscanner --json /path/to/file
```

Seçenekleri birlikte kullanın:

```bash
./target/release/ravenscanner --json --max-results 100 /path/to/file
```

## Özellikler

* Salt okunur statik dosya incelemesi
* SHA-256 hesaplama
* Shannon entropy analizi
* Yazdırılabilir ASCII dize çıkarımı
* URL tespiti
* IPv4 adresi tespiti
* Domain tespiti
* Linux dosya yolu tespiti
* Şüpheli Linux göstergelerinin tespiti
* Kalıcılıkla ilişkili konumların tespiti
* Kategori bazında IOC tekilleştirme
* İlk gözlenen bayt ofsetinin korunması
* Daha sıkı URL ve domain doğrulaması
* Binary gürültüsü ve dosya adına benzeyen false-positive değerler için filtreleme
* Temel ELF incelemesi
* Güvenli ELF section-name ayrıştırması
* Bozuk veya kesik ELF yapılarında panik olmadan raporlama
* Açıklanabilir sezgisel triyaj skoru
* `--max-results` ile sonuç sınırlama
* Makine tarafından okunabilir JSON çıktısı
* Dosya çalıştırma yok
* Dosya değiştirme yok
* Ağ iletişimi yok

## IOC tespit davranışı

IOC tespiti kapsamlı olmaktan ziyade temkinli olacak şekilde tasarlanmıştır.

RavenScanner binary gürültüsü, kaynak dosyası adları, shared-library uzantıları ve bozuk metin parçaları nedeniyle oluşabilecek bazı yaygın false-positive sonuçları azaltmaya çalışır.

Bulunan değerler kategori bazında tekilleştirilir ve ilk tespit edilen bayt ofseti korunur.

Kaydedilmiş bir IOC testinde şu girdiler kullanıldı:

```text
main.rs
libexample.so
example.com
https://openai.com/test
192.168.1.10
```

Gözlenen davranış:

* `main.rs` domain olarak raporlanmadı
* `libexample.so` domain olarak raporlanmadı
* `example.com` domain olarak raporlandı
* `https://openai.com/test` URL olarak raporlandı
* `192.168.1.10` IPv4 adresi olarak raporlandı
* tespit edilen IOC değerlerinin bayt ofsetleri korundu

Bu filtreler false-positive sayısını azaltır ancak string tabanlı IOC tespitini eksiksiz veya kesin hale getirmez.

## ELF incelemesi

Bir dosya ELF magic byte'larıyla başlıyorsa RavenScanner temel ELF yapısını inceler.

Mevcut ELF desteği:

* ELF tanımlama
* temel class ve encoding bilgileri
* mimari bilgisi
* entry-point bilgisi
* section-name ayrıştırması

Bozuk veya kesik girdiler temkinli biçimde ele alınır.

Örneğin kasıtlı olarak bozulmuş bir ELF benzeri dosya şu şekilde raporlandı:

```text
ELF information:
  Format: ELF
  Status: Malformed (unknown ELF class value 103)
```

Araç paniklemek yerine normal biçimde çalışmaya devam etti.

RavenScanner şu anda symbol çözümleme, import reconstruction, relocation analizi, program-header analizi veya disassembly gibi tam ELF analizi özellikleri sunmaz.

## Sezgisel triyaj skoru

RavenScanner `0` ile `100` arasında açıklanabilir bir sezgisel triyaj skoru üretir.

Bu skor yalnızca bulguları önceliklendirmeye yardımcı olmak amacıyla tasarlanmıştır. Malware sınıflandırması veya güven skoru değildir.

Her katkı sınırlandırılmıştır ve raporda ayrı ayrı gösterilir.

Yüksek entropy yalnızca zayıf bir sinyal olarak değerlendirilir çünkü zararsız sıkıştırılmış veya şifrelenmiş dosyalar da yüksek entropy değerine sahip olabilir.

Kaydedilmiş rastgele girdi testinde:

```text
Entropy: 7.96 / 8.00

Risk score: 5/100
Reasons:
  + 5  High overall entropy (7.96/8.00); weak packing/encryption heuristic
```

gözlendi.

IOC içermeyen normal düşük-entropy dosyasında ise:

```text
Risk score: 0/100
Reasons: none
```

elde edildi.

## Sonuç sınırlama

`--max-results <N>` seçeneği her kategori için gösterilen sonuç sayısını sınırlar.

Varsayılan değer:

```text
50
```

Bu seçenek yalnızca çıktıyı sınırlar.

Toplam tespit sayısını veya sezgisel triyaj skorunu değiştirmez.

20 benzersiz domain içeren kaydedilmiş bir testte:

```bash
ravenscanner --max-results 5 many-iocs.txt
```

çıktısı:

```text
Domains (20 total, showing first 5):
```

şeklindeydi.

## JSON çıktısı

Makine tarafından okunabilir çıktı için:

```bash
ravenscanner --json /path/to/file
```

kullanılabilir.

`--max-results` ile birlikte kullanıldığında JSON çıktısı tam kategori toplamını korurken `results` içindeki gösterilen değerleri sınırlar.

## CLI seçenekleri

Temel kullanım:

```text
ravenscanner [OPTIONS] <FILE>
```

Örnekler:

```bash
ravenscanner /path/to/file
ravenscanner --max-results 25 /path/to/file
ravenscanner --json /path/to/file
ravenscanner --json --max-results 100 /path/to/file
```

### `--max-results <N>`

Her kategori için gösterilen sonuçları sınırlar.

Varsayılan:

```text
50
```

### `--json`

Normal terminal raporu yerine JSON çıktısı üretir.

## Gereksinimler

* Linux
* Güncel kararlı Rust toolchain
* Cargo

## Geliştirme ve test

Format kontrolü:

```bash
cargo fmt --check
```

Testler:

```bash
cargo test
```

Clippy:

```bash
cargo clippy --all-targets -- -D warnings
```

Doğrulanmış mevcut durum:

```text
cargo fmt --check                          BAŞARILI
cargo test                                BAŞARILI — 21/21 test
cargo clippy --all-targets -- -D warnings BAŞARILI — Linux
```

## Tasarım ilkeleri

* **Yalnızca statik analiz** — dosyalar çalıştırılmaz
* **Salt okunur** — dosyalar değiştirilmez
* **Yerel çalışma** — taranan içerik yüklenmez
* **Açıklanabilirlik** — skor katkıları görülebilir
* **Temkinli tespit** — agresif eşleştirme yerine false-positive azaltma tercih edilir
* **Güvenli ayrıştırma** — bozuk binary yapılarının güvenli biçimde başarısız olması hedeflenir
* **Makine-okunabilir çıktı** — JSON başka araçlarla kullanılabilir
* **Sınırlı kapsam** — amaç tam malware analizi değil, ilk statik triyajdır

## Bilinen sınırlamalar

Mevcut sınırlamalar:

* Linux odaklı çalışma
* dynamic analysis yok
* sandbox execution yok
* memory analysis yok
* network capture yok
* PE parsing yok
* disassembly yok
* symbol veya import reconstruction yok
* ELF ayrıştırması sınırlı
* string tabanlı IOC tespiti bazı geçerli göstergeleri kaçırabilir
* temkinli domain doğrulaması bazı gerçek domainleri görmezden gelebilir
* sezgisel skor false-positive ve false-negative sonuçlar üretebilir
* yüksek entropy tek başına zararlı davranış göstergesi değildir

RavenScanner production-ready değildir ve özel incident-response, malware-analysis veya reverse-engineering araçlarının yerine geçmez.

## Sorumlu kullanım

RavenScanner; savunma amaçlı güvenlik araştırmaları, malware-analysis eğitimi, incident-response triyajı ve size ait veya analiz etme izniniz bulunan dosyaların incelenmesi için tasarlanmıştır.

Güvenlik kararı vermeden önce tüm bulguları bağımsız olarak doğrulayın.

## Lisans

RavenScanner [MIT License](LICENSE) altında dağıtılmaktadır.
