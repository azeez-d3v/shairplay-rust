//! Legacy /pair-setup-pin SRP and authenticated Ed25519 key exchange.

use crate::error::CryptoError;
use aes_gcm::{
    AesGcm,
    aead::{AeadInPlace, KeyInit, consts::U16},
};
use ed25519_dalek::VerifyingKey;
use num_bigint::BigUint;
use rand::RngCore;
use sha1::{Digest, Sha1};
use sha2::Sha512;
use subtle::ConstantTimeEq;

type Cipher = AesGcm<aes_gcm::aes::Aes128, U16>;
const N_HEX: &str = concat!(
    "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4",
    "A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF60",
    "95179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF",
    "747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B907",
    "8717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB37861",
    "60279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DB",
    "FBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73"
);

pub(crate) struct PinSetup {
    user: String,
    server_public_key: [u8; 32],
    salt: [u8; 16],
    public: Vec<u8>,
    state: Stage,
}
enum Stage {
    Proof { verifier: BigUint, secret: BigUint },
    Key([u8; 40]),
    Terminal,
}
pub(crate) struct PinConfirmation {
    pub(crate) user: String,
    pub(crate) peer_public_key: [u8; 32],
    pub(crate) encrypted_public_key: [u8; 32],
    pub(crate) auth_tag: [u8; 16],
}
impl PinSetup {
    pub(crate) fn new(
        user: &str,
        pin: &str,
        server_public_key: [u8; 32],
    ) -> Result<Self, CryptoError> {
        let mut salt = [0; 16];
        let mut secret = [0; 32];
        rand::rngs::OsRng
            .try_fill_bytes(&mut salt)
            .map_err(|_| failed())?;
        rand::rngs::OsRng
            .try_fill_bytes(&mut secret)
            .map_err(|_| failed())?;
        Self::from_material(user, pin, server_public_key, salt, secret)
    }
    fn from_material(
        user: &str,
        pin: &str,
        server_public_key: [u8; 32],
        salt: [u8; 16],
        secret: [u8; 32],
    ) -> Result<Self, CryptoError> {
        if user.is_empty()
            || user.len() > 24
            || user.chars().any(char::is_control)
            || pin.len() != 4
            || !pin.bytes().all(|b| b.is_ascii_digit())
            || secret.iter().all(|b| *b == 0)
        {
            return Err(failed());
        }
        let n = modulus();
        let g = BigUint::from(2u8);
        // Apple proofs hash minimal integers; only k/u use RFC5054 padded integers.
        let salted = BigUint::from_bytes_be(&salt);
        let inner = hash(&[user.as_bytes(), b":", pin.as_bytes()]);
        let x = BigUint::from_bytes_be(&hash(&[&minimal(&salted), &inner]));
        let verifier = g.modpow(&x, &n);
        let k = BigUint::from_bytes_be(&hash(&[&padded(&n), &padded(&g)]));
        let secret = BigUint::from_bytes_be(&secret);
        let public = (&k * &verifier + g.modpow(&secret, &n)) % &n;
        if public == BigUint::ZERO {
            return Err(failed());
        }
        Ok(Self {
            user: user.into(),
            server_public_key,
            salt,
            public: minimal(&public),
            state: Stage::Proof { verifier, secret },
        })
    }
    #[cfg(test)]
    pub(crate) fn from_test_material(
        user: &str,
        pin: &str,
        server_public_key: [u8; 32],
        salt: [u8; 16],
        secret: [u8; 32],
    ) -> Result<Self, CryptoError> {
        Self::from_material(user, pin, server_public_key, salt, secret)
    }
    pub(crate) fn challenge(&self) -> ([u8; 16], Vec<u8>) {
        (self.salt, self.public.clone())
    }
    pub(crate) fn verify(
        &mut self,
        client_pk: &[u8],
        proof: &[u8],
    ) -> Result<[u8; 20], CryptoError> {
        // Consume first: malformed, replayed, or failed proofs cannot reuse this attempt.
        let Stage::Proof { verifier, secret } = std::mem::replace(&mut self.state, Stage::Terminal)
        else {
            return Err(failed());
        };
        if client_pk.is_empty() || client_pk.len() > 256 || proof.len() != 20 {
            return Err(failed());
        }
        let n = modulus();
        let a = BigUint::from_bytes_be(client_pk);
        let b = BigUint::from_bytes_be(&self.public);
        if a == BigUint::ZERO || a >= n {
            return Err(failed());
        }
        let u = BigUint::from_bytes_be(&hash(&[&padded(&a), &padded(&b)]));
        if u == BigUint::ZERO {
            return Err(failed());
        }
        let shared = (a.clone() * verifier.modpow(&u, &n)).modpow(&secret, &n);
        let shared = minimal(&shared);
        // Apple expands K with two counter-suffixed SHA1 hashes, not standard SRP H(S).
        let mut key = [0; 40];
        key[..20].copy_from_slice(&hash(&[&shared, &[0, 0, 0, 0]]));
        key[20..].copy_from_slice(&hash(&[&shared, &[0, 0, 0, 1]]));
        let mut group = hash(&[&minimal(&n)]);
        for (out, other) in group.iter_mut().zip(hash(&[&[2]])) {
            *out ^= other;
        }
        let user = hash(&[self.user.as_bytes()]);
        let salt = minimal(&BigUint::from_bytes_be(&self.salt));
        let a = minimal(&a);
        let expected = hash(&[&group, &user, &salt, &a, &self.public, &key]);
        if !bool::from(expected.as_slice().ct_eq(proof)) {
            return Err(failed());
        }
        let response = hash(&[&a, &expected, &key]);
        self.state = Stage::Key(key);
        Ok(response)
    }
    pub(crate) fn finish(
        &mut self,
        epk: &[u8],
        tag: &[u8],
    ) -> Result<PinConfirmation, CryptoError> {
        let Stage::Key(key) = std::mem::replace(&mut self.state, Stage::Terminal) else {
            return Err(failed());
        };
        if epk.len() != 32 || tag.len() != 16 {
            return Err(failed());
        }
        let aes_key = derive(b"Pair-Setup-AES-Key", &key);
        let mut nonce = derive(b"Pair-Setup-AES-IV", &key);
        let cipher = Cipher::new_from_slice(&aes_key).map_err(|_| failed())?;
        // The wire protocol increments only the last nonce octet, not the 128-bit integer.
        nonce[15] = nonce[15].wrapping_add(1);
        let mut peer_public_key = [0; 32];
        peer_public_key.copy_from_slice(epk);
        cipher
            .decrypt_in_place_detached((&nonce).into(), b"", &mut peer_public_key, tag.into())
            .map_err(|_| failed())?;
        let peer = VerifyingKey::from_bytes(&peer_public_key).map_err(|_| failed())?;
        if peer.is_weak() {
            return Err(failed());
        }
        nonce[15] = nonce[15].wrapping_add(1);
        let mut encrypted_public_key = self.server_public_key;
        let auth_tag = cipher
            .encrypt_in_place_detached((&nonce).into(), b"", &mut encrypted_public_key)
            .map_err(|_| failed())?;
        Ok(PinConfirmation {
            user: self.user.clone(),
            peer_public_key,
            encrypted_public_key,
            auth_tag: auth_tag.into(),
        })
    }
}
fn modulus() -> BigUint {
    BigUint::parse_bytes(N_HEX.as_bytes(), 16).expect("fixed RFC5054 2048-bit modulus")
}
fn minimal(value: &BigUint) -> Vec<u8> {
    if *value == BigUint::ZERO {
        Vec::new()
    } else {
        value.to_bytes_be()
    }
}
fn padded(value: &BigUint) -> [u8; 256] {
    let bytes = minimal(value);
    let mut out = [0; 256];
    out[256 - bytes.len()..].copy_from_slice(&bytes);
    out
}
fn hash(parts: &[&[u8]]) -> [u8; 20] {
    let mut hash = Sha1::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}
fn derive(label: &[u8], key: &[u8; 40]) -> [u8; 16] {
    let mut hash = Sha512::new();
    hash.update(label);
    hash.update(key);
    let digest = hash.finalize();
    let mut out = [0; 16];
    out.copy_from_slice(&digest[..16]);
    out
}
fn failed() -> CryptoError {
    CryptoError::PairingHandshake("legacy PIN authentication failed".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    const USER: &str = "A1B2C3D4E5F6";
    const CLIENT: &str = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
    const SERVER: &str = "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c";
    fn fixtures() -> Vec<BTreeMap<&'static str, Vec<u8>>> {
        include_str!("../../tests/support/pin_reference.txt")
            .split("CASE=")
            .skip(1)
            .map(|part| {
                part.lines()
                    .skip(1)
                    .filter_map(|line| line.split_once('='))
                    .map(|(key, value)| (key, hex::decode(value).unwrap()))
                    .collect()
            })
            .collect()
    }
    fn setup(f: &BTreeMap<&str, Vec<u8>>) -> PinSetup {
        PinSetup::from_test_material(
            USER,
            "1234",
            hex::decode(SERVER).unwrap().try_into().unwrap(),
            f["salt"].clone().try_into().unwrap(),
            f["b"].clone().try_into().unwrap(),
        )
        .unwrap()
    }
    #[test]
    fn legacy_pin_matches_working_c_reference_including_leading_zero_salt() {
        let all = fixtures();
        assert_eq!(all.len(), 3);
        for f in all {
            let mut setup = setup(&f);
            let (salt, pk) = setup.challenge();
            assert_eq!(salt.as_slice(), f["salt"]);
            assert_eq!(pk, f["B"]);
            assert_eq!(setup.verify(&f["A"], &f["M1"]).unwrap().as_slice(), f["M2"]);
            let result = setup.finish(&f["client_epk"], &f["client_tag"]).unwrap();
            assert_eq!(result.user, USER);
            assert_eq!(
                result.peer_public_key.as_slice(),
                hex::decode(CLIENT).unwrap()
            );
            assert_eq!(result.encrypted_public_key.as_slice(), f["server_epk"]);
            assert_eq!(result.auth_tag.as_slice(), f["server_tag"]);
            assert!(setup.finish(&f["client_epk"], &f["client_tag"]).is_err());
            assert!(setup.verify(&f["A"], &f["M1"]).is_err());
        }
    }
    #[test]
    fn invalid_user_and_pin_are_rejected_before_challenge() {
        let server = hex::decode(SERVER).unwrap().try_into().unwrap();
        for user in [
            "",
            "abcdefghijklmnopqrstuvwxy",
            "contains\0nul",
            "line\nbreak",
            "tab\t",
        ] {
            assert!(PinSetup::new(user, "1234", server).is_err());
        }
        for pin in ["", "123", "12345", "12a4", "１２３４", "123\n"] {
            assert!(PinSetup::new(USER, pin, server).is_err());
        }
        let first = PinSetup::new(USER, "0000", server).unwrap().challenge();
        let second = PinSetup::new(USER, "0000", server).unwrap().challenge();
        assert_ne!(first, second);
        assert!(!first.1.is_empty() && first.1.len() <= 256);
    }
    #[test]
    fn malformed_public_keys_and_proofs_poison_attempts() {
        let f = fixtures().remove(0);
        for public in [vec![], vec![0], modulus().to_bytes_be(), vec![255; 257]] {
            let mut s = setup(&f);
            assert!(s.verify(&public, &f["M1"]).is_err());
            assert!(s.verify(&f["A"], &f["M1"]).is_err());
        }
        for proof in [vec![], vec![0; 19], vec![0; 20], vec![0; 21]] {
            let mut s = setup(&f);
            assert!(s.verify(&f["A"], &proof).is_err());
            assert!(s.verify(&f["A"], &f["M1"]).is_err());
        }
        let server = hex::decode(SERVER).unwrap().try_into().unwrap();
        let mut wrong_pin = PinSetup::from_test_material(
            USER,
            "9999",
            server,
            f["salt"].clone().try_into().unwrap(),
            f["b"].clone().try_into().unwrap(),
        )
        .unwrap();
        assert!(wrong_pin.verify(&f["A"], &f["M1"]).is_err());
    }
    #[test]
    fn tampered_gcm_keys_tags_lengths_and_replays_fail_closed() {
        let f = fixtures().remove(0);
        let mut bad_epk = f["client_epk"].clone();
        bad_epk[0] ^= 1;
        let mut bad_tag = f["client_tag"].clone();
        bad_tag[15] ^= 1;
        for (epk, tag) in [
            (bad_epk, f["client_tag"].clone()),
            (f["client_epk"].clone(), bad_tag),
            (vec![0; 31], f["client_tag"].clone()),
            (f["client_epk"].clone(), vec![0; 15]),
            (vec![0; 33], vec![0; 17]),
        ] {
            let mut s = setup(&f);
            s.verify(&f["A"], &f["M1"]).unwrap();
            assert!(s.finish(&epk, &tag).is_err());
            assert!(s.finish(&f["client_epk"], &f["client_tag"]).is_err());
        }
        let mut out_of_order = setup(&f);
        assert!(
            out_of_order
                .finish(&f["client_epk"], &f["client_tag"])
                .is_err()
        );
        assert!(out_of_order.verify(&f["A"], &f["M1"]).is_err());
        let mut replay = setup(&f);
        replay.verify(&f["A"], &f["M1"]).unwrap();
        assert!(replay.verify(&f["A"], &f["M1"]).is_err());
        assert!(replay.finish(&f["client_epk"], &f["client_tag"]).is_err());
    }
    #[test]
    fn authenticated_weak_ed25519_key_is_not_persistable() {
        let f = fixtures().remove(0);
        let mut s = setup(&f);
        s.verify(&f["A"], &f["M1"]).unwrap();
        let key: [u8; 40] = f["K"].clone().try_into().unwrap();
        let aes_key = derive(b"Pair-Setup-AES-Key", &key);
        let mut nonce = derive(b"Pair-Setup-AES-IV", &key);
        nonce[15] = nonce[15].wrapping_add(1);
        let mut epk = [0; 32];
        let cipher = Cipher::new_from_slice(&aes_key).unwrap();
        let tag = cipher
            .encrypt_in_place_detached((&nonce).into(), b"", &mut epk)
            .unwrap();
        assert!(s.finish(&epk, &tag).is_err());
    }
}
