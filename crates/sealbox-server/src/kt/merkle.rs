//! RFC 6962 Merkle tree hashing and proof generation (SHA-256, `0x00` leaf / `0x01` node
//! prefixes), plus the RFC 9162 §2.1 verifiers used by the unit tests. The client carries its
//! own, independent verifier (`sealbox_core::identity::kt`).

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 node.
pub type Hash = [u8; 32];

fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// `SHA-256(0x00 || data)`.
pub fn leaf_hash(data: &[u8]) -> Hash {
    sha256(&[&[0u8], data])
}

/// `SHA-256(0x01 || left || right)`.
pub fn node_hash(left: &Hash, right: &Hash) -> Hash {
    sha256(&[&[1u8], left, right])
}

/// Root of the empty tree, `SHA-256("")`.
pub fn empty_root() -> Hash {
    sha256(&[])
}

/// Largest power of two strictly smaller than `n` (`n >= 2`).
fn split(n: usize) -> usize {
    let mut k = 1;
    while k * 2 < n {
        k *= 2;
    }
    k
}

/// MTH(D[n]) over leaf hashes.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => empty_root(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node_hash(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// PATH(m, D[n]): the audit path of leaf `m` (`m < n`), bottom-up.
pub fn inclusion_path(m: usize, leaves: &[Hash]) -> Vec<Hash> {
    let n = leaves.len();
    if n <= 1 || m >= n {
        return Vec::new();
    }
    let k = split(n);
    let mut p = if m < k {
        let mut p = inclusion_path(m, &leaves[..k]);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = inclusion_path(m - k, &leaves[k..]);
        p.push(root(&leaves[..k]));
        p
    };
    p.shrink_to_fit();
    p
}

/// PROOF(m, D[n]): consistency proof between the first `m` leaves and all `n` (`0 < m <= n`).
pub fn consistency_proof(m: usize, leaves: &[Hash]) -> Vec<Hash> {
    if m == 0 || m > leaves.len() {
        return Vec::new();
    }
    subproof(m, leaves, true)
}

fn subproof(m: usize, leaves: &[Hash], complete: bool) -> Vec<Hash> {
    let n = leaves.len();
    if m == n {
        return if complete {
            Vec::new()
        } else {
            vec![root(leaves)]
        };
    }
    let k = split(n);
    if m <= k {
        let mut p = subproof(m, &leaves[..k], complete);
        p.push(root(&leaves[k..]));
        p
    } else {
        let mut p = subproof(m - k, &leaves[k..], false);
        p.push(root(&leaves[..k]));
        p
    }
}

/// RFC 9162 §2.1.3.2.
pub fn verify_inclusion(index: u64, size: u64, leaf: &Hash, path: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut f, mut s) = (index, size - 1);
    let mut r = *leaf;
    for p in path {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node_hash(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && &r == root
}

/// RFC 9162 §2.1.4.2.
pub fn verify_consistency(m: u64, n: u64, old: &Hash, new: &Hash, proof: &[Hash]) -> bool {
    if m > n {
        return false;
    }
    if m == n {
        return proof.is_empty() && old == new;
    }
    if m == 0 {
        return proof.is_empty() && old == &empty_root();
    }
    if proof.is_empty() {
        return false;
    }
    let mut path = proof.to_vec();
    if m.is_power_of_two() {
        path.insert(0, *old);
    }
    let (mut f, mut s) = (m - 1, n - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (path[0], path[0]);
    for c in &path[1..] {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    &fr == old && &sr == new && s == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ct_leaves() -> Vec<Hash> {
        let raw: Vec<Vec<u8>> = vec![
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            (0x60..=0x6f).collect(),
        ];
        raw.iter().map(|l| leaf_hash(l)).collect()
    }

    #[test]
    fn known_roots_rfc6962_vectors() {
        let l = ct_leaves();
        let want = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        for (i, w) in want.iter().enumerate() {
            assert_eq!(hex::encode(root(&l[..=i])), *w, "size {}", i + 1);
        }
        assert_eq!(
            hex::encode(root(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn known_paths_rfc6962_vectors() {
        // Audit paths from the certificate-transparency reference tests (8-leaf tree).
        let l = ct_leaves();
        let p = inclusion_path(0, &l);
        let want = [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ];
        assert_eq!(p.iter().map(hex::encode).collect::<Vec<_>>(), want);
        let p = inclusion_path(5, &l);
        let want = [
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ];
        assert_eq!(p.iter().map(hex::encode).collect::<Vec<_>>(), want);
        // Consistency 1 -> 8, 6 -> 8, 2 -> 5.
        let want = [
            "96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7",
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "6b47aaf29ee3c2af9af889bc1fb9254dabd31177f16232dd6aab035ca39bf6e4",
        ];
        let c = consistency_proof(1, &l);
        assert_eq!(c.iter().map(hex::encode).collect::<Vec<_>>(), want);
        let c = consistency_proof(6, &l);
        let want = [
            "0ebc5d3437fbe2db158b9f126a1d118e308181031d0a949f8dededebc558ef6a",
            "ca854ea128ed050b41b35ffc1b87b8eb2bde461e9e3b5596ece6b9d5975a0ae0",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        ];
        assert_eq!(c.iter().map(hex::encode).collect::<Vec<_>>(), want);
        let c = consistency_proof(2, &l[..5]);
        let want = [
            "5f083f0a1a33ca076a95279832580db3e0ef4584bdff1f54c8a360f50de3031e",
            "bc1a0643b12e4d2d7c77918f44e0f4f79a838b6cf9ec5b5c283e1f4d88599e6b",
        ];
        assert_eq!(c.iter().map(hex::encode).collect::<Vec<_>>(), want);
    }

    #[test]
    fn proofs_verify_for_every_size_including_odd() {
        let l: Vec<Hash> = (0..40u32).map(|i| leaf_hash(&i.to_le_bytes())).collect();
        for n in 1..=l.len() {
            let r = root(&l[..n]);
            for m in 0..n {
                let p = inclusion_path(m, &l[..n]);
                assert!(
                    verify_inclusion(m as u64, n as u64, &l[m], &p, &r),
                    "{m}/{n}"
                );
                let mut bad = p.clone();
                if let Some(x) = bad.first_mut() {
                    x[0] ^= 1;
                    assert!(!verify_inclusion(m as u64, n as u64, &l[m], &bad, &r));
                }
            }
            for m in 1..=n {
                let p = consistency_proof(m, &l[..n]);
                let old = root(&l[..m]);
                assert!(
                    verify_consistency(m as u64, n as u64, &old, &r, &p),
                    "{m}->{n}"
                );
                if m < n {
                    let mut forged = l[..n].to_vec();
                    forged[m - 1][0] ^= 1; // rewrite history inside the old tree
                    let fr = root(&forged);
                    let fp = consistency_proof(m, &forged);
                    assert!(!verify_consistency(m as u64, n as u64, &old, &fr, &fp));
                }
            }
        }
    }
}
