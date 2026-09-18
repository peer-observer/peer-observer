/// Returns the `q`-th percentile of an already sorted slice, where `q` is in [0, 1].
/// Interpolates linearly between the two closest ranks.
pub fn percentile_of_sorted_f64(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }

    let rank = (sorted.len() - 1) as f64 * q.clamp(0.0, 1.0);
    let lower = rank.floor() as usize;
    let upper = rank.ceil() as usize;

    if lower == upper {
        sorted[lower]
    } else {
        sorted[lower] + (sorted[upper] - sorted[lower]) * (rank - lower as f64)
    }
}

/// Returns the `q`-th percentile of `l`, where `q` is in [0, 1]. NaNs are filtered out.
pub fn percentile_f64(l: &[f64], q: f64) -> f64 {
    // Filter out NaNs
    let mut a: Vec<f64> = l.iter().cloned().filter(|x| !x.is_nan()).collect();

    a.sort_by(|a, b| a.partial_cmp(b).unwrap());

    percentile_of_sorted_f64(&a, q)
}

pub fn median_f64(l: &[f64]) -> f64 {
    percentile_f64(l, 0.5)
}

pub fn mean_f64(l: &[f64]) -> f64 {
    let filtered: Vec<f64> = l.iter().cloned().filter(|x| !x.is_nan()).collect();

    if filtered.is_empty() {
        return 0.0;
    }

    filtered.iter().sum::<f64>() / filtered.len() as f64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_median_empty() {
        let v: &[f64] = &[];
        assert_eq!(median_f64(v), 0.0);
    }

    #[test]
    fn test_median_single() {
        let v = &[42.0];
        assert_eq!(median_f64(v), 42.0);
    }

    #[test]
    fn test_median_odd() {
        let v = &[3.0, 1.0, 2.0];
        // Sorted: [1.0, 2.0, 3.0], median = 2.0
        assert_eq!(median_f64(v), 2.0);
    }

    #[test]
    fn test_median_even() {
        let v = &[3.0, 1.0, 4.0, 2.0];
        // Sorted: [1.0, 2.0, 3.0, 4.0], median = (2.0 + 3.0) / 2 = 2.5
        assert_eq!(median_f64(v), 2.5);
    }

    #[test]
    fn test_median_nan_multi() {
        let v = &[1.0, f64::NAN, 2.0];
        // Sorted: [1.0, 2.0], median = (1.0 + 2.0) / 2 = 1.5
        assert_eq!(median_f64(v), 1.5);
    }

    #[test]
    fn test_median_nan_single() {
        let v = &[f64::NAN];
        assert_eq!(median_f64(v), 0.0);
    }

    #[test]
    fn test_mean_empty() {
        let v: &[f64] = &[];
        assert_eq!(mean_f64(v), 0.0);
    }

    #[test]
    fn test_mean_single() {
        let v = &[42.0];
        assert_eq!(mean_f64(v), 42.0);
    }

    #[test]
    fn test_mean_multiple() {
        let v = &[1.0, 2.0, 3.0, 4.0];
        assert_eq!(mean_f64(v), 2.5);
    }

    #[test]
    fn test_mean_negative() {
        let v = &[-1.0, 1.0];
        assert_eq!(mean_f64(v), 0.0);
    }

    #[test]
    fn test_percentile_empty() {
        let v: &[f64] = &[];
        assert_eq!(percentile_f64(v, 0.5), 0.0);
        assert_eq!(percentile_of_sorted_f64(v, 0.9), 0.0);
    }

    #[test]
    fn test_percentile_single() {
        let v = &[42.0];
        assert_eq!(percentile_f64(v, 0.1), 42.0);
        assert_eq!(percentile_f64(v, 0.9), 42.0);
    }

    #[test]
    fn test_percentile_min_and_max() {
        let v = &[4.0, 1.0, 3.0, 2.0];
        assert_eq!(percentile_f64(v, 0.0), 1.0);
        assert_eq!(percentile_f64(v, 1.0), 4.0);
    }

    #[test]
    fn test_percentile_interpolates() {
        let v = &[0.0, 10.0, 20.0, 30.0, 40.0];
        // rank = 4 * 0.25 = 1.0 -> exactly the second value
        assert_eq!(percentile_f64(v, 0.25), 10.0);
        // rank = 4 * 0.9 = 3.6 -> between the fourth and fifth value
        assert_eq!(percentile_f64(v, 0.9), 36.0);
    }

    #[test]
    fn test_percentile_unsorted_input() {
        let v = &[30.0, 0.0, 40.0, 10.0, 20.0];
        assert_eq!(percentile_f64(v, 0.5), 20.0);
    }

    #[test]
    fn test_percentile_nan() {
        let v = &[1.0, f64::NAN, 3.0];
        assert_eq!(percentile_f64(v, 0.5), 2.0);
    }

    #[test]
    fn test_percentile_out_of_range_is_clamped() {
        let v = &[1.0, 2.0, 3.0];
        assert_eq!(percentile_f64(v, -1.0), 1.0);
        assert_eq!(percentile_f64(v, 2.0), 3.0);
    }

    #[test]
    fn test_percentile_matches_median() {
        let odd = &[3.0, 1.0, 2.0];
        let even = &[3.0, 1.0, 4.0, 2.0];
        assert_eq!(percentile_f64(odd, 0.5), median_f64(odd));
        assert_eq!(percentile_f64(even, 0.5), median_f64(even));
    }
}
