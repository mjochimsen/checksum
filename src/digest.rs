/// The `Digest` trait describes a common interface to a digest algorithm,
/// such as the 256-bit digest from the SHA-2 family of digests. The
/// generic parameter `N` describes the size of the computed digest in
/// bytes.
pub trait Digest<const N: usize> {
    /// The number of bytes required to hold the digest.
    fn length(&self) -> usize {
        N
    }

    /// Update the `Digest` with additional `data`.
    fn update(&mut self, data: &[u8]);

    /// Finish computing the digest and return the computed value. The
    /// `Digest` implementor should return itself to its initial state
    /// after calling this method, so that the next call to `update()`
    /// will work as though no data had been received.
    fn finish(&mut self) -> [u8; N];
}

#[cfg(test)]
pub mod count {
    use crate::Digest;

    /// A trivial digest algorithm which just computes a count of the passed
    /// bytes (mod 256). This is intended to be used for testing purposes.
    pub struct Count {
        c: u8,
    }

    impl Count {
        /// Create a new `Count` digest.
        pub fn new() -> Self {
            Self { c: 0 }
        }
    }

    impl Digest<1> for Count {
        /// Update the count of bytes with the length of `data` (mod 256).
        fn update(&mut self, data: &[u8]) {
            self.c =
                ((self.c as usize + data.len()) % 0x100).try_into().unwrap();
        }

        /// Return the count of digested bytes (mod 256).
        fn finish(&mut self) -> [u8; 1] {
            let c = self.c;
            self.c = 0;
            [c]
        }
    }

    /// `Count` digest value for `EMPTY`.
    pub const EMPTY: [u8; 1] = [0x00];

    /// `Count` digest value for `ZERO_400D`.
    pub const ZERO_400D: [u8; 1] = [0x0d];

    /// `Count` digest value for `RANDOM_11171`.
    pub const RANDOM_11171: [u8; 1] = [0x71];
}

#[cfg(test)]
pub mod xor {
    use crate::Digest;

    /// A trivial digest algorithm which just computes a running XOR of the
    /// bytes. This is intended to be used for testing purposes.
    #[allow(clippy::upper_case_acronyms)]
    pub struct XOR {
        d: u8,
    }

    #[cfg(test)]
    impl XOR {
        /// Create a new `XOR` digest.
        pub fn new() -> Self {
            Self { d: 0 }
        }
    }

    #[cfg(test)]
    impl Digest<1> for XOR {
        /// Update the digest with a running XOR of the `data`.
        fn update(&mut self, data: &[u8]) {
            for b in data {
                self.d ^= b;
            }
        }

        /// Return the running XOR of digested bytes.
        fn finish(&mut self) -> [u8; 1] {
            let d = self.d;
            self.d = 0;
            [d]
        }
    }

    /// `XOR` digest value for `EMPTY`.
    pub const EMPTY: [u8; 1] = [0x00];

    /// `XOR` digest value for `ZERO_400D`.
    pub const ZERO_400D: [u8; 1] = [0x00];

    /// `XOR` digest value for `RANDOM_11171`.
    pub const RANDOM_11171: [u8; 1] = [0xac];
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn count_empty() {
        let mut count = count::Count::new();
        assert_eq!(count.finish(), count::EMPTY);
    }

    #[test]
    fn count_zero() {
        let mut count = count::Count::new();
        count.update(&[0; 0x4000]);
        count.update(&[0; 0x0d]);
        assert_eq!(count.finish(), count::ZERO_400D);
    }

    #[test]
    fn count_random() {
        let mut count = count::Count::new();
        count.update(&fixtures::RANDOM_11171);
        assert_eq!(count.finish(), count::RANDOM_11171);
    }

    #[test]
    fn count_multiple() {
        let mut count = count::Count::new();
        assert_eq!(count.finish(), count::EMPTY);
        count.update(&fixtures::ZERO_400D);
        assert_eq!(count.finish(), count::ZERO_400D);
        count.update(&fixtures::RANDOM_11171);
        assert_eq!(count.finish(), count::RANDOM_11171);
    }

    #[test]
    fn xor_empty() {
        let mut xor = xor::XOR::new();
        assert_eq!(xor.finish(), xor::EMPTY);
    }

    #[test]
    fn xor_zero() {
        let mut xor = xor::XOR::new();
        xor.update(&[0; 0x4000]);
        xor.update(&[0; 0x0d]);
        assert_eq!(xor.finish(), xor::ZERO_400D);
    }

    #[test]
    fn xor_random() {
        let mut xor = xor::XOR::new();
        xor.update(&fixtures::RANDOM_11171);
        assert_eq!(xor.finish(), xor::RANDOM_11171);
    }

    #[test]
    fn xor_multiple() {
        let mut xor = xor::XOR::new();
        assert_eq!(xor.finish(), xor::EMPTY);
        xor.update(&fixtures::ZERO_400D);
        assert_eq!(xor.finish(), xor::ZERO_400D);
        xor.update(&fixtures::RANDOM_11171);
        assert_eq!(xor.finish(), xor::RANDOM_11171);
    }
}
