use crate::model::ExtractedString;

/// Extract contiguous printable ASCII sequences (space through `~`).
pub fn extract_ascii_strings(bytes: &[u8], minimum_length: usize) -> Vec<ExtractedString> {
    let minimum_length = minimum_length.max(1);
    let mut strings = Vec::new();
    let mut start = None;

    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte.is_ascii_graphic() || byte == b' ' {
            start.get_or_insert(index);
        } else if let Some(sequence_start) = start.take() {
            push_if_long_enough(bytes, sequence_start, index, minimum_length, &mut strings);
        }
    }

    if let Some(sequence_start) = start {
        push_if_long_enough(
            bytes,
            sequence_start,
            bytes.len(),
            minimum_length,
            &mut strings,
        );
    }

    strings
}

fn push_if_long_enough(
    bytes: &[u8],
    start: usize,
    end: usize,
    minimum_length: usize,
    output: &mut Vec<ExtractedString>,
) {
    if end - start >= minimum_length {
        // Every byte in this range was checked as printable ASCII, so conversion cannot fail.
        let value = String::from_utf8(bytes[start..end].to_vec())
            .expect("printable ASCII is always valid UTF-8");
        output.push(ExtractedString {
            offset: start,
            value,
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_strings_and_offsets_from_binary_data() {
        let bytes = b"\x00hello\xffab\x00/bin/sh\x00";
        let strings = extract_ascii_strings(bytes, 4);

        assert_eq!(strings.len(), 2);
        assert_eq!(strings[0].offset, 1);
        assert_eq!(strings[0].value, "hello");
        assert_eq!(strings[1].value, "/bin/sh");
    }

    #[test]
    fn includes_a_string_at_end_of_file() {
        let strings = extract_ascii_strings(b"\x00trailing", 4);
        assert_eq!(strings[0].value, "trailing");
    }
}
