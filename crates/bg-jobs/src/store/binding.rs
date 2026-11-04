//! Canonical replay binding shared by persistence adapters.

use sha2::{Digest, Sha256};

use super::{Check, Mutation, StoreTransaction, constants::TRANSACTION_BINDING_VERSION};

impl StoreTransaction {
    /// SHA-256 of the versioned, ordered checks and mutations.
    ///
    /// Each collection starts with its unsigned 32-bit big-endian count.
    /// Each entry starts with its tag: absent check 0, value check 1, put 2,
    /// or delete 3. Each key and value starts with its unsigned 32-bit
    /// big-endian byte length. Version 2 preserves the remote adapter's
    /// persisted binding. Construction validates these encoding bounds.
    ///
    /// Operation IDs and caller limits are excluded: neither changes the
    /// transaction's effects. The digest permits compact reuse detection
    /// under SHA-256 collision resistance; it is not recovery material or
    /// evidence that the operation can be retired. Hashing allocates nothing.
    pub fn binding(&self) -> [u8; 32] {
        let mut digest = Sha256::new();
        self.visit_encoding(|bytes| digest.update(bytes));
        digest.finalize().into()
    }

    pub(super) fn visit_encoding(&self, mut write: impl FnMut(&[u8])) {
        write(&[TRANSACTION_BINDING_VERSION]);
        write(&(self.checks().len() as u32).to_be_bytes());
        for check in self.checks() {
            match check {
                Check::Absent(key) => {
                    write(&[0]);
                    write_bytes(&mut write, key.as_bytes());
                }
                Check::Value(key, value) => {
                    write(&[1]);
                    write_bytes(&mut write, key.as_bytes());
                    write_bytes(&mut write, value);
                }
            }
        }
        write(&(self.mutations().len() as u32).to_be_bytes());
        write_mutations(&mut write, self.mutations());
    }
}

fn write_mutations(write: &mut impl FnMut(&[u8]), mutations: &[Mutation]) {
    for mutation in mutations {
        match mutation {
            Mutation::Put(key, value) => {
                write(&[2]);
                write_bytes(write, key.as_bytes());
                write_bytes(write, value);
            }
            Mutation::Delete(key) => {
                write(&[3]);
                write_bytes(write, key.as_bytes());
            }
        }
    }
}

fn write_bytes(write: &mut impl FnMut(&[u8]), bytes: &[u8]) {
    write(&(bytes.len() as u32).to_be_bytes());
    write(bytes);
}
