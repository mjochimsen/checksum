use std::sync::mpsc;
use std::sync::Arc;

use crate::Digest;

/// An interface to compute a digest in a background thread.
///
/// The `Background` struct is used to move a `Digest` implementor into a
/// background thread and let it run there. A constructor function for the
/// `Digest` needs to be passed into the `new()` method when the
/// `Background` object is created, so that the `Digest` can be created in
/// the background thread. The interface is quite similar to the `Digest`
/// trait, but the `data` passed to `update()` needs to be an `Arc<[u8]>`
/// in order to safely share it across thread boundaries.
pub struct Background<const N: usize> {
    tx_input: mpsc::SyncSender<Message>,
    rx_result: mpsc::Receiver<[u8; N]>,
}

/// The `DigestConstructor` type describes a function which can be used to
/// create an object which implements the `Digest` trait.
///
/// Note that the type constraint `Digest<L>` will not actually be applied
/// at compilation time due to current compiler limitations.
#[allow(type_alias_bounds)]
type DigestConstructor<D: Digest<N>, const N: usize> = fn() -> D;

impl<const N: usize> Background<N> {
    /// The length of the digest, in bytes.
    #[must_use]
    pub fn length() -> usize {
        N
    }

    /// Create a new `Background` object. The `digest` function will be
    /// used to create a new `Digest` implementor in a separate thread.
    pub fn new<D: Digest<N> + 'static>(
        digest: DigestConstructor<D, N>,
    ) -> Self {
        let (tx_input, rx_input) = mpsc::sync_channel(4);
        let (tx_result, rx_result) = mpsc::channel();

        std::thread::spawn(move || {
            Self::background(digest, &rx_input, &tx_result);
        });

        Self {
            tx_input,
            rx_result,
        }
    }

    /// Update the encapsulated `Digest` object with the given `data`.
    ///
    /// Note that the the threads use `std::mpsc` channels to communicate.
    /// The channel used to communicate with the digest thread is limited
    /// to 4 entries, so it is possible that this method will block if
    /// that queue becomes saturated.
    pub fn update(&self, data: Arc<[u8]>) {
        self.tx_input
            .send(Message::Append(data))
            .expect("unexpected error appending to digest");
    }

    /// Get digest data back from the encapsulated `Digest` object.
    ///
    /// Note that the the threads use `std::mpsc` channels to communicate.
    /// Consequently, it is possible that this method will block if work
    /// remains to be perfomed in the thread computing the digest.
    pub fn finish(&self) -> [u8; N] {
        use std::time::Duration;

        self.tx_input
            .send(Message::Finish)
            .expect("unexpected error finishing digest");

        let timeout = Duration::new(5, 0);
        self.rx_result
            .recv_timeout(timeout)
            .expect("unable to retrieve digest value")
    }

    /// The function to run in a separate thread. It will use the passed
    /// `DigestConstructor` to create a `Digest` implementor which is then
    /// used to compute a digest with data passed to it using the
    /// `Background::update()` method. The computed data is then sent back
    /// to the calling thread when `Background::finish()` is called.
    fn background<D: Digest<N>>(
        constructor: DigestConstructor<D, N>,
        rx_input: &mpsc::Receiver<Message>,
        tx_result: &mpsc::Sender<[u8; N]>,
    ) {
        let mut worker = constructor();
        loop {
            let msg = rx_input.recv();

            match msg {
                Ok(Message::Append(data)) => worker.update(&data),
                Ok(Message::Finish) => {
                    tx_result.send(worker.finish()).unwrap();
                }
                Err(_) => break,
            }
        }
    }
}

/// An internal `enum` used to communicate between the caller's thread and
/// the thread the `Digest` implementor is running in.
enum Message {
    Append(Arc<[u8]>),
    Finish,
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::digest::{count::Count, xor::XOR};
    use crate::fixtures;

    #[test]
    fn background_count_empty() {
        let bg = Background::new(Count::new);
        assert_eq!(bg.finish(), fixtures::count::EMPTY);
    }

    #[test]
    fn background_count_zero() {
        let bg = Background::new(Count::new);
        bg.update(Arc::from([0; 0x4000]));
        bg.update(Arc::from([0; 0x0d]));
        assert_eq!(bg.finish(), fixtures::count::ZERO_400D);
    }

    #[test]
    fn background_xor_random() {
        let bg = Background::new(XOR::new);
        bg.update(Arc::from(fixtures::RANDOM_11171));
        assert_eq!(bg.finish(), fixtures::xor::RANDOM_11171);
    }

    #[test]
    fn background_count_multiple() {
        let bg = Background::new(Count::new);
        assert_eq!(bg.finish(), fixtures::count::EMPTY);
        bg.update(Arc::from(fixtures::ZERO_400D));
        assert_eq!(bg.finish(), fixtures::count::ZERO_400D);
        bg.update(Arc::from(fixtures::RANDOM_11171));
        assert_eq!(bg.finish(), fixtures::count::RANDOM_11171);
    }
}
