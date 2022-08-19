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

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::fixtures;

        #[test]
        fn empty() {
            let mut count = Count::new();
            assert_eq!(count.finish(), fixtures::count::EMPTY);
        }

        #[test]
        fn zero() {
            let mut count = Count::new();
            count.update(&[0; 0x4000]);
            count.update(&[0; 0x0d]);
            assert_eq!(count.finish(), fixtures::count::ZERO_400D);
        }

        #[test]
        fn random() {
            let mut count = Count::new();
            count.update(&fixtures::RANDOM_11171);
            assert_eq!(count.finish(), fixtures::count::RANDOM_11171);
        }

        #[test]
        fn multiple() {
            let mut count = Count::new();
            assert_eq!(count.finish(), fixtures::count::EMPTY);
            count.update(&fixtures::ZERO_400D);
            assert_eq!(count.finish(), fixtures::count::ZERO_400D);
            count.update(&fixtures::RANDOM_11171);
            assert_eq!(count.finish(), fixtures::count::RANDOM_11171);
        }
    }
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

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::fixtures;

        #[test]
        fn empty() {
            let mut xor = XOR::new();
            assert_eq!(xor.finish(), fixtures::xor::EMPTY);
        }

        #[test]
        fn zero() {
            let mut xor = XOR::new();
            xor.update(&[0; 0x4000]);
            xor.update(&[0; 0x0d]);
            assert_eq!(xor.finish(), fixtures::xor::ZERO_400D);
        }

        #[test]
        fn random() {
            let mut xor = XOR::new();
            xor.update(&fixtures::RANDOM_11171);
            assert_eq!(xor.finish(), fixtures::xor::RANDOM_11171);
        }

        #[test]
        fn multiple() {
            let mut xor = XOR::new();
            assert_eq!(xor.finish(), fixtures::xor::EMPTY);
            xor.update(&fixtures::ZERO_400D);
            assert_eq!(xor.finish(), fixtures::xor::ZERO_400D);
            xor.update(&fixtures::RANDOM_11171);
            assert_eq!(xor.finish(), fixtures::xor::RANDOM_11171);
        }
    }
}
