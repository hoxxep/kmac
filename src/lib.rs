mod kmac;
mod traits;
mod encoding;

use crate::kmac::KmacCore;
use digest::block_api::{Block, BlockSizeUser, Buffer, ExtendableOutputCore, XofReaderCore};
use digest::block_buffer::ReadBuffer;
use digest::consts::{U136, U168, U32, U64};
pub use digest::{self, ExtendableOutput, KeyInit, Mac, XofReader};
use digest::{InvalidLength, Output, OutputSizeUser};
use sha3::block_api::Sha3ReaderCore;
use sha3::{CShake128, CShake256};

/// Manually implement the extra KMAC methods and XOF traits.
macro_rules! impl_kmac {
    ($kmac:ident, $cshake:ident, $reader:ident, $block_size:ident, $output_size:ident) => {
        digest::buffer_fixed!(
            pub struct $kmac(KmacCore<$cshake>);
            impl: MacTraits KeyInit;
        );

        impl OutputSizeUser for KmacCore<$cshake> {
            type OutputSize = $output_size;
        }

        impl $kmac {
            /// Create a new KMAC with the given key and customisation.
            #[inline]
            pub fn new_customization(key: &[u8], customisation: &[u8]) -> Result<Self, InvalidLength> {
                // FUTURE: support key+customisation initialisation via traits.
                let core = KmacCore::<$cshake>::new_customization(key, customisation)?;
                let buffer = Buffer::<KmacCore<$cshake>>::default();
                Ok(Self { core, buffer })
            }

            /// Finalize this KMAC to a fixed output size. The output size is generic and determined
            /// by the `out` variable's `ArraySize`.
            #[inline]
            pub fn finalize_fixed(&mut self, out: &mut Output<Self>) {
                // FUTURE: support custom output sizes via traits.
                let buffer = &mut self.buffer;
                self.core.finalize_core(buffer, out);
            }
        }

        /// Reader for KMAC that implements the XOF interface.
        pub struct $reader {
            core: Sha3ReaderCore<$block_size>,
            buffer: ReadBuffer<<Sha3ReaderCore<$block_size> as BlockSizeUser>::BlockSize>,
        }

        impl BlockSizeUser for $reader {
            type BlockSize = <Sha3ReaderCore<$block_size> as BlockSizeUser>::BlockSize;
        }

        impl XofReaderCore for $reader {
            #[inline(always)]
            fn read_block(&mut self) -> Block<Self> {
                self.core.read_block()
            }
        }

        impl XofReader for $reader {
            #[inline(always)]
            fn read(&mut self, buf: &mut [u8]) -> () {
                let Self { core, buffer } = self;
                buffer.read(buf, |block| {
                    *block = XofReaderCore::read_block(core);
                });
            }
        }

        impl ExtendableOutput for $kmac {
            type Reader = $reader;

            #[inline(always)]
            fn finalize_xof(mut self) -> Self::Reader {
                // FUTURE: support extendable output via a MAC trait?
                let Self { core, buffer } = &mut self;
                let core = <KmacCore<$cshake> as ExtendableOutputCore>::finalize_xof_core(core, buffer);
                let buffer = Default::default();
                Self::Reader { core, buffer }
            }
        }
    };
}

impl_kmac!(Kmac128, CShake128, Kmac128Reader, U168, U32);
impl_kmac!(Kmac256, CShake256, Kmac251Reader, U136, U64);
