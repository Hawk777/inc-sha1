#![forbid(unsafe_code)]
#![warn(
	future_incompatible,
	nonstandard_style,
	rust_2018_idioms,
	rustdoc,
	unused
)]
#![warn(
	deprecated_in_future,
	missing_crate_level_docs,
	missing_docs,
	missing_doc_code_examples,
	single_use_lifetimes,
	trivial_casts,
	trivial_numeric_casts,
	unused_crate_dependencies,
	unused_import_braces,
	unused_lifetimes,
	unused_qualifications,
	unused_results
)]
#![warn(clippy::pedantic, clippy::cargo, clippy::cast_possible_truncation)]
// This is actually useful to make a bunch of empty branches with different comments in them.
#![allow(clippy::if_same_then_else)]
// This just makes things look much worse.
#![allow(clippy::non_ascii_literal)]

//! Incremental SHA1 Calculator
//!
//! Inc-SHA1 is a library for incrementally calculating an SHA-1 hash value. It uses the `sha`
//! crate but encapsulates handling of partial blocks and final padding so that the application can
//! simply write any number of blocks of bytes of any length and ask for a final hash value.
//!
//! # Example
//! ```
//! let mut hasher = inc_sha1::Hasher::new();
//! hasher.write(b"Hello ");
//! hasher.write(b"World!");
//! let hash = hasher.finish();
//! let hex_hash = hex::encode(hash);
//! assert_eq!(hex_hash, "2ef7bde608ce5404e97d5f042f95f89f1c232871");
//! ```

/// The length of an SHA-1 hash value, in bits.
pub const LENGTH_BITS: usize = 160;

/// The length of an SHA-1 hash value, in bytes.
pub const LENGTH_BYTES: usize = LENGTH_BITS / 8;

/// The length of an input block, in bits.
const BLOCK_BITS: usize = 512;

/// The length of an input block, in bytes.
const BLOCK_BYTES: usize = BLOCK_BITS / 8;

/// An SHA-1 hash value.
pub type Hash = [u8; LENGTH_BYTES];

/// An in-progress SHA-1 hash operation.
///
/// This struct’s API is intentionally similar to [`std::hash::Hasher`](std::hash::Hasher) in an
/// attempt at familiarity; however, it does not actually implement that trait because that trait
/// only permits 64-bit hash outputs, while SHA-1 has a 160-bit output.
///
/// A `Hasher` can be cloned and copied. Doing so yields a second `Hasher` which acts as if it has
/// had exactly the same sequence of bytes written to it as the original, but can freely diverge
/// from that point forward.
#[derive(Clone, Copy)]
pub struct Hasher {
	state: [u32; LENGTH_BYTES / 4],
	partial_block: [u8; BLOCK_BYTES],
	bytes_in_partial_block: usize,
	data_length: u64,
}

impl Hasher {
	/// Constructs a new `Hasher`.
	///
	/// The new `Hasher` does not yet contain any data.
	#[must_use]
	pub fn new() -> Self {
		Self {
			state: sha::sha1::consts::H,
			partial_block: [0_u8; BLOCK_BYTES],
			bytes_in_partial_block: 0_usize,
			data_length: 0_u64,
		}
	}

	/// Adds data to a `Hasher`.
	pub fn write(&mut self, bytes: &[u8]) {
		use sha::sha1::ops::digest_block;

		// Update the record of total bytes added.
		self.data_length += bytes.len() as u64;

		let bytes: &[u8] = if self.bytes_in_partial_block == 0 {
			// The partial block is empty. Skip this step.
			&bytes
		} else {
			// The partial block is already partly full. Add more data to it.
			let to_copy: usize =
				std::cmp::min(bytes.len(), BLOCK_BYTES - self.bytes_in_partial_block);
			self.partial_block[self.bytes_in_partial_block..self.bytes_in_partial_block + to_copy]
				.copy_from_slice(&bytes[0..to_copy]);
			self.bytes_in_partial_block += to_copy;

			// See if the partial block is now full.
			if self.bytes_in_partial_block == BLOCK_BYTES {
				// Consume it.
				digest_block(&mut self.state, &self.partial_block);
				self.bytes_in_partial_block = 0;
			}

			// Proceed with the rest of the bytes after the ones we consumed.
			&bytes[to_copy..]
		};

		// One of the following must be true now:
		// 1. The partial block started out empty (and still is).
		// 2. The partial block started out nonempty, there were enough bytes to finish it, and it
		//    has been digested and is therefore now empty.
		// 3. The partial block started out nonempty, there were not enough bytes to finish it, and
		//    there are no more bytes of input left.
		debug_assert!(self.bytes_in_partial_block == 0 || bytes.is_empty());

		// Consume as many whole-block chunks as there are available.
		let bytes = bytes.chunks_exact(BLOCK_BYTES);
		for block in bytes.clone() {
			digest_block(&mut self.state, &block);
		}
		let bytes: &[u8] = bytes.remainder();

		if bytes.is_empty() {
			// Leave the partial block alone. This covers the case where less than a block is
			// passed in and the partial block is residue from before the call.
		} else {
			// Stash the remaining less-than-whole-block for later. Since bytes was nonempty after
			// potentially consuming the partial block above, we know that bytes_in_partial_block
			// is zero.
			self.partial_block[0..bytes.len()].copy_from_slice(bytes);
			self.bytes_in_partial_block = bytes.len();
		}
	}

	/// Returns the hash of the data written so far.
	///
	/// The `Hasher` is still usable after this, and more data can be added if desired.
	#[must_use]
	pub fn finish(&self) -> Hash {
		// Make a copy of self where padding can be added without affecting self.
		self.finish_by_value()
	}

	/// Returns the hash of the data written.
	#[must_use]
	fn finish_by_value(mut self) -> Hash {
		const ZEROES: [u8; BLOCK_BYTES] = [0_u8; BLOCK_BYTES];

		// Capture the data length before we start adding any padding.
		let data_length_bits: u64 = self.data_length * 8;

		// The padding comprises a 0x80 byte, 0x00 bytes until the length is congruent to 56 mod
		// 64, and the length of the data excluding padding, in bits, as a big-endian 64-bit
		// integer.

		// First append the 0x80.
		self.write(&[0x80_u8]);

		if BLOCK_BYTES - self.bytes_in_partial_block < 8 {
			// There is not enough space in the current block to put the data length there. Fill
			// with 0x00 and go on to the next block.
			self.write(&ZEROES[0..BLOCK_BYTES - self.bytes_in_partial_block]);
		}

		// Fill the partial block up to the point 8 bytes before the end.
		self.write(&ZEROES[0..BLOCK_BYTES - 8 - self.bytes_in_partial_block]);

		// Add the data length integer, in bits.
		self.write(&data_length_bits.to_be_bytes());

		// The resulting state is the hash value. Convert it from words to bytes.
		let mut result = [0_u8; LENGTH_BYTES];
		let mut result_slice: &mut [u8] = &mut result;
		for word in &self.state {
			use std::io::Write;
			result_slice.write_all(&word.to_be_bytes()).unwrap();
		}

		result
	}
}

impl Default for Hasher {
	fn default() -> Hasher {
		Hasher::new()
	}
}

#[cfg(test)]
mod vectors;

#[cfg(test)]
mod test {
	/// Performs a test using a particular scheme of writing input bytes to the hasher.
	fn test_vectors(writer: fn(&mut super::Hasher, &[u8]) -> ()) {
		for &vectors in &[super::vectors::SHORT_VECTORS, super::vectors::LONG_VECTORS] {
			let vectors = super::vectors::Vectors::new(vectors);
			for vector in vectors {
				let mut h = super::Hasher::default();
				writer(&mut h, &vector.input);
				let h = h.finish();
				println!(
					"Input:    {:?}\nExpected: {:?}\nActual:   {:?}",
					hex::encode(&vector.input),
					vector.output,
					h
				);
				assert_eq!(h, vector.output);
			}
		}
	}

	/// Tests hashing the test vectors a whole input message at a time.
	#[test]
	fn test_vectors_whole() {
		test_vectors(|h, d| h.write(d))
	}

	/// Tests hashing the test vectors a byte at a time.
	#[test]
	fn test_vectors_bytewise() {
		test_vectors(|h, d| {
			for &b in d {
				h.write(&[b])
			}
		})
	}

	/// Tests hashing the test vectors five bytes at a time.
	#[test]
	fn test_vectors_fivebytewise() {
		test_vectors(|h, d| {
			for chunk in d.chunks(5) {
				h.write(chunk)
			}
		})
	}
}
