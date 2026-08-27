/// Calculate Shannon entropy in bits per byte, from 0.0 to 8.0.
///
/// Entropy is only a weak heuristic: compressed, encrypted, and ordinary packed
/// data can all have high entropy without being malicious.
pub fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut counts = [0_usize; 256];
    for &byte in bytes {
        counts[usize::from(byte)] += 1;
    }

    let length = bytes.len() as f64;
    counts
        .iter()
        .filter(|&&count| count > 0)
        .map(|&count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn calculates_entropy_for_simple_inputs() {
        assert_eq!(shannon_entropy(&[]), 0.0);
        assert_eq!(shannon_entropy(&[7, 7, 7, 7]), 0.0);
        assert!((shannon_entropy(&[0, 1, 0, 1]) - 1.0).abs() < f64::EPSILON);
    }
}
