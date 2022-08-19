use std::sync::Arc;

use libz_sys::crc32;

use crate::{Background, Digest, DigestData, Generator};

/// A structure used to generated a CRC32 checksum.
pub struct CRC32 {
    /// The current CRC32 checksum.
    crc: u32,
}

impl CRC32 {
    /// The length of the CRC32 checksum, in bytes.
    pub const LENGTH: usize = 4;

    /// Create a new CRC32 structure generate a checksum.
    #[must_use]
    pub fn new() -> Self {
        Self { crc: 0 }
    }

    /// Re-initialize the CRC32 structure.
    fn reset(&mut self) {
        self.crc = 0;
    }
}

impl Digest<{ Self::LENGTH }> for CRC32 {
    /// Update the CRC32 checksum using the given `data`.
    ///
    /// ## Panics
    ///
    /// Passing a data block with more than `u32::MAX` bytes will cause a
    /// panic.
    fn update(&mut self, data: &[u8]) {
        let len = data
            .len()
            .try_into()
            .expect("data block is too large for CRC32 processing");
        let crc = unsafe { crc32(self.crc.into(), data.as_ptr(), len) };
        self.crc = crc.try_into().expect("unexpected CRC32 value > u32::MAX");
    }

    /// Return the CRC32 checksum. The CRC32 checksum is reset so that it
    /// can be reused.
    fn finish(&mut self) -> [u8; Self::LENGTH] {
        let crc = self.crc.to_be_bytes();
        self.reset();
        crc
    }
}

impl Default for CRC32 {
    /// Create a default CRC32 structure to generate a checksum.
    fn default() -> Self {
        Self::new()
    }
}

/// Structure used to compute an CRC32 checksum in a separate thread.
pub struct BackgroundCRC32 {
    worker: Background<{ CRC32::LENGTH }>,
}

impl BackgroundCRC32 {
    /// Create a new `BackgroundCRC32` structure.
    pub fn new() -> Self {
        Self {
            worker: Background::new(CRC32::new),
        }
    }
}

impl Generator for BackgroundCRC32 {
    /// Add the given `data` to the CRC32 checksum.
    fn append(&self, data: Arc<[u8]>) {
        self.worker.update(data);
    }

    /// Retrieve the CRC32 checksum, and reset the checksum computation.
    fn result(&self) -> DigestData {
        DigestData::CRC32(self.worker.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fixtures;

    #[test]
    fn empty() {
        let mut crc32 = CRC32::new();
        assert_eq!(crc32.finish(), fixtures::crc32::EMPTY);
    }

    #[test]
    fn zero() {
        let mut crc32 = CRC32::new();
        crc32.update(&[0; 0x4000]);
        crc32.update(&[0; 0x0d]);
        assert_eq!(crc32.finish(), fixtures::crc32::ZERO_400D);
    }

    #[test]
    fn random() {
        let mut crc32 = CRC32::new();
        crc32.update(&fixtures::RANDOM_11171);
        assert_eq!(crc32.finish(), fixtures::crc32::RANDOM_11171);
    }

    #[test]
    fn multiple() {
        let mut crc32 = CRC32::new();
        assert_eq!(crc32.finish(), fixtures::crc32::EMPTY);
        crc32.update(&fixtures::ZERO_400D);
        assert_eq!(crc32.finish(), fixtures::crc32::ZERO_400D);
        crc32.update(&fixtures::RANDOM_11171);
        assert_eq!(crc32.finish(), fixtures::crc32::RANDOM_11171);
    }

    #[test]
    fn background() {
        let crc32 = BackgroundCRC32::new();
        assert_eq!(crc32.result(), DigestData::CRC32(fixtures::crc32::EMPTY));
        crc32.append(Arc::from(fixtures::ZERO_400D));
        assert_eq!(
            crc32.result(),
            DigestData::CRC32(fixtures::crc32::ZERO_400D)
        );
        crc32.append(Arc::from(fixtures::RANDOM_11171));
        assert_eq!(
            crc32.result(),
            DigestData::CRC32(fixtures::crc32::RANDOM_11171)
        );
    }
}
