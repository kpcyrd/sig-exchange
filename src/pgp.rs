use crate::{errors::*, sig};
use chrono::{DateTime, Utc};
use sequoia_openpgp::{
    Packet, PacketPile, armor,
    packet::{Signature, signature::subpacket::SubpacketValue},
    parse::Parse,
    serialize::{
        Serialize as _,
        stream::{Armorer, Message},
    },
    types::{HashAlgorithm, PublicKeyAlgorithm},
};
use serde::Serialize;
use std::{
    io::{Cursor, Write},
    time::UNIX_EPOCH,
};

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct PgpSig {
    pub chksum: String,
    pub family: String,
    pub issuer: String,
    pub sig_type: i16,
    pub sig_version: i16,
    pub hash_algo: String,
    pub sig_algo: String,
    pub creation_time: Option<DateTime<Utc>>,
    pub digest_prefix: String,
    pub bytes: Vec<u8>,
}

impl PgpSig {
    pub fn to_ascii_armored(&self) -> Result<String> {
        let mut sink = Vec::new();

        {
            let message = Message::new(&mut sink);
            let mut message = Armorer::new(message).kind(armor::Kind::Signature).build()?;
            message.write_all(&self.bytes)?;
            message.finalize()?;
        }

        let armored = String::from_utf8(sink)?;
        Ok(armored)
    }
}

fn split(content: &str) -> Vec<&str> {
    let mut blocks: Vec<&str> = Vec::new();
    let mut current_block_start = 0;

    // Find each "-----BEGIN PGP SIGNATURE-----" and split there
    for (idx, _) in content.match_indices("-----BEGIN PGP ") {
        if idx > 0 && current_block_start < idx {
            blocks.push(&content[current_block_start..idx]);
        }
        current_block_start = idx;
    }

    // Add the last block
    if current_block_start < content.len() {
        blocks.push(&content[current_block_start..]);
    }

    blocks
}

fn format_hash_algo(algo: &HashAlgorithm) -> String {
    format!("{:?}", algo)
}

fn format_sig_algo(algo: &PublicKeyAlgorithm) -> String {
    format!("{:?}", algo)
}

fn encode(sig: Signature) -> Result<Vec<u8>> {
    let p = Packet::from(sig);
    let mut buf = Vec::new();
    p.serialize(&mut buf)?;
    Ok(buf)
}

pub fn parse_sigs(content: &str) -> Result<Vec<PgpSig>> {
    let blocks = split(content);

    let mut sigs = Vec::new();
    for (block_num, block) in blocks.iter().enumerate() {
        if block.trim().is_empty() {
            continue;
        }

        let block_bytes = block.as_bytes();
        let cursor = Cursor::new(block_bytes);

        let pile = match PacketPile::from_reader(cursor) {
            Ok(pile) => pile,
            Err(err) => {
                warn!("Failed to parse block #{}: {err:#}", block_num + 1);
                continue;
            }
        };
        for packet in pile.descendants() {
            if let Packet::Signature(sig) = packet {
                let sig = sig.normalize();

                if sig.level() != 0 {
                    warn!(
                        "This is a level {} signature (not a direct data signature)",
                        sig.level()
                    );
                    continue;
                }

                let sig_type = u8::from(sig.typ());
                let sig_version = sig.version();
                let hash_algo = format_hash_algo(&sig.hash_algo());
                let sig_algo = format_sig_algo(&sig.pk_algo());

                let digest_prefix = format!(
                    "{:02X}{:02X}",
                    sig.digest_prefix()[0],
                    sig.digest_prefix()[1]
                );

                let mut issuer = None;
                for subpacket in sig.hashed_area().iter().chain(sig.unhashed_area().iter()) {
                    /*
                    SubpacketValue::Issuer(keyid) => {
                        println!("Issuer Key ID: {}", keyid);
                    }
                    */
                    /*
                    SubpacketValue::SignersUserID(uid) => {
                        if let Ok(s) = std::str::from_utf8(uid) {
                            println!("Signer User ID: {}", s);
                        }
                    }
                    */
                    if let SubpacketValue::IssuerFingerprint(fp) = subpacket.value() {
                        issuer = Some(format!("{:x}", fp));
                    }
                }

                // Get creation time
                let creation_time = sig
                    .signature_creation_time()
                    .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
                    .and_then(|duration| DateTime::from_timestamp_secs(duration.as_secs() as i64));

                let Some(issuer) = issuer else {
                    warn!("No issuer fingerprint found in signature, skipping");
                    continue;
                };

                let sig = encode(sig)?;

                let sig = PgpSig {
                    chksum: sig::db_id(&sig),
                    family: "pgp".to_string(),
                    issuer,
                    sig_type: i16::from(sig_type),
                    sig_version: i16::from(sig_version),
                    hash_algo,
                    sig_algo,
                    creation_time,
                    digest_prefix,
                    bytes: sig,
                };
                // info!("Parsed PGP Signature: {sig:?}");
                sigs.push(sig);
            }
        }
    }

    Ok(sigs)
}

#[derive(Debug, Serialize, PartialEq)]
pub struct PgpKey {
    pub fingerprint: String,
    pub mpis: String,
}

pub fn parse_keys(content: &str) -> Result<Vec<PgpKey>> {
    let blocks = split(content);

    let mut keys = Vec::new();
    for (block_num, block) in blocks.iter().enumerate() {
        if block.trim().is_empty() {
            continue;
        }

        let block_bytes = block.as_bytes();
        let cursor = Cursor::new(block_bytes);

        let pile = match PacketPile::from_reader(cursor) {
            Ok(pile) => pile,
            Err(err) => {
                warn!("Failed to parse block #{}: {err:#}", block_num + 1);
                continue;
            }
        };

        for packet in pile.descendants() {
            let (fingerprint, mpis) = match packet {
                Packet::PublicKey(key) => (key.fingerprint(), key.mpis()),
                Packet::PublicSubkey(key) => (key.fingerprint(), key.mpis()),
                _ => continue,
            };

            keys.push(PgpKey {
                fingerprint: format!("{fingerprint:x}"),
                mpis: format!("{mpis:#?}"),
            });
        }
    }

    Ok(keys)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split() {
        let content = include_str!("../test_data/SHA256SUMS.asc");
        let blocks = split(content);
        assert_eq!(blocks.len(), 13);
        assert_eq!(
            &blocks[..5],
            &[
                "-----BEGIN PGP SIGNATURE-----

iQEzBAABCAAdFiEEEBWY3II8G1+aZiSrpeCQegOA5sMFAmd/tDwACgkQpeCQegOA
5sPpnAgApjo0MWURz51sZZye3hQ+Ek0xINYdDaeVXURnmdM3lI6feTIVlLIvPN2k
Cyx7rCKqeWcGTcFVr6RSjiZDL4NMmztfiTVXWnAU9uJtkPED10YO0ZNPg9OSfWT+
w7yYJzAZHxUXFaeSDDZtj5MPChIFk54hDIGgStR3q01ukWhNTziL+qRXZ9hK/1uM
Eq54zw+PlaWdewruTt0seDvwVdwtZnVd8dnGPFpluTU3YMwpxRlWqvMHJhITNY11
xkNO9QtN6fOGHs3u409v6ESlM0AXI0ceqLA8bzf9w/iv34xYf2h3DpHMTGy+fpt6
zkGbF/zokANci4YFpbY776TSifwZbQ==
=OJ8B
-----END PGP SIGNATURE-----
",
                "-----BEGIN PGP SIGNATURE-----

iQJEBAABCAAuFiEEFSgSMAeFyWRE0zNNF1ZXMuCOXkEFAmd9x2UQHG1lQGFjaG93
MTAxLmNvbQAKCRAXVlcy4I5eQTpkD/9gAH88aIa69Omvfsg//8UNOTCZj4zVGRMe
qaSeK9TvATlL/NOnVPIADzMSyf/BUJDI2taMUIOL+ZECPQNSMMfhxHx2ECMVgeV9
P2CJztda0tiVFHECRGut93nrqEEqx38Q/fch2rJuthk/MUemdx9UIDnLQHWs149i
pf0Rz5qvxMg4BbLQowpdHMnAL2Vrt0gnNt6pzt6NaMfbaYPwXTg/zYPImHVPJJ2c
e01o0peYw/gCQmeaDYton6JCLiAJnOChk5pm40ze6I5UJH3tAO82k49TfJonRFOY
kP82cnGfvw1os26Xnt4Mn8xWhwky7vk+ayEee0xNBiGSaC2FSqJG+88XXEn6UcG5
kotqYdpZssY+i/8G2L2geflWPrjGkZINg+/8IJV0uAyp3a/Dfzuhg7ORyPnxajgt
ZMxGh8ZVt2o1o7yYaSVPcw7ELWuVdRuXAx2Jr0pYaT5ml9GPOq011O6LNmw57meB
P4Wdr5ce57EU9gTR9PYR5TNH4ESZ/X0WCxqkOGT/ZKKuScX0QpBlsGKeeH1sKTbA
QXWHfNIG7ZFTLgw0aBJUJH6dZKVpGgtK4gTHoUdF7uYo9TqCaExuN2834mNrNFaj
fuVfN2UJ1CXDOlAdHrt/6T1kLfkLCz3JKfVj7rZXXtsgPqyV9i4k04Oe1aYa4BhQ
QrIzb9irBQ==
=76yC
-----END PGP SIGNATURE-----
",
                "-----BEGIN PGP SIGNATURE-----

iQJIBAABCAAyFiEE5hdzzW4BBA4vG9eM5+KYS2KJyToFAmd+p94UHHBpbmhlYWRt
ekBnbWFpbC5jb20ACgkQ5+KYS2KJyTonXBAAwNNqtNDMi4rXjTJSpr9CKVM0hN9j
1eigLkt4Vb6c7noQkbLSn0mwBLU4fEInZ6QQ2czIm1mWqybXwK6vpY4R89Kcm3sF
jKM16fn+LwPlAs5N3L05b/YZ1SzeLSv85g7zA74QVZ29KyXVZ/Dp1cj7b7lqQhpa
aR67leNwvvkS9YIVCnx9zMQvqa2Sr4lDJTuk2Ss6QNS7EVmBR1PlIN5AgoXVC8yg
a4uhOtcaiMXhIW/TbuRlizuo5iMdESkCjKqphm1GPXYT6WPj7ywbjw44JmzDHLCy
HrAR1zH/irN5gKqm7TIW6eTnMYcrd0YKpteaCO6au5lhGchTnnoYGSRnSw+C03HW
PvJl0JxX2sKCJxRWRk97mONDcl8TcbUKCCHexFfcQGUaaxBb7bo45E99F8cyuip3
bY+8L4zqdBiGsaMwY9pBlOIxAJ3XzfkWn9anRyoeJuXtwKm9hqTKjEck8XB7wLpw
R+T2VgDS1g4m7JZ4QpG2Aj/NeGuVn6G/p1OUNNwXiZfLvWW/Hh+MUeFv4d92oyCK
WURcrqsEMGLDZ3ZiezeqvxuJQ4s/src/mz7Dgr5sUWAKyqX6pp9QyoOlP96pWodl
4lSeV4v3HdAcP7XAiVLbkCGEGRO2iRfcDelia5DeA2m1CgmNRgK9SgjYqCyE6IJe
pHoirSmYjn1H/34=
=Vv1t
-----END PGP SIGNATURE-----
",
                "-----BEGIN PGP SIGNATURE-----

iQEzBAABCgAdFiEEnerg3HBjJJ+wVHRoHkrtYphs0l0FAmd+L/8ACgkQHkrtYphs
0l2Hegf+MmNcsoox2IrOE0AYxYOp4CcncfLOmI+JiKd28cV07XCd+9T0UFJtproL
AxgMA00eWswC+bAvsBGZIWe8uXhiYSgV32vtc+jjWQxUMSw/saOul9kQBxJtuBrV
onvym88T2uK+lIqW/HyUiXrumVwtYl9eI28RxarFaouESXg4vLDAJDCVTMbgf3I2
vfu45zrN/Rb+z/ozlDcE8z2BnQwMEjbkPh9gmrsDnTGOBFtRqRY0lU7mZp/Ri9AS
iZQXQ0u57IYkTWdrzJBNek+GG9YGI/HOmetzgQ9hu8kMqQRjR6KJ6TCAwHvVVw3m
r/2flkhltNHTl6oLUM3mwxwgnon/LA==
=/x/l
-----END PGP SIGNATURE-----
",
                "-----BEGIN PGP SIGNATURE-----

iI4EABMIADYWIQTDiPaWH7lyqVZ44yf2JxHb3KiuVgUCZ33JPBgca3ZhY2lyYWxA
cHJvdG9ubWFpbC5jb20ACgkQ9icR29yorlZc8AEA1msV0ubjjhDSBx5ZpOEXchL/
D8HuQ5y6wuF2v9ikiJIA/1JRjc1j0jNr7+JihZln8qXiahqCBChUHxXWvm5CjWIy
=TmdE
-----END PGP SIGNATURE-----
"
            ]
        );
    }

    #[test]
    fn test_parse_sigs() {
        let content = include_str!("../test_data/SHA256SUMS.asc");
        let mut sigs = parse_sigs(content).unwrap();
        for sig in &mut sigs {
            // Clear bytes for comparison
            sig.bytes.clear();
        }
        assert_eq!(
            sigs,
            &[
                PgpSig {
                    chksum: "0b3644f7a642645362dece8785414812".to_string(),
                    family: "pgp".to_string(),
                    issuer: "101598dc823c1b5f9a6624aba5e0907a0380e6c3".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-09T11:34:20Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "E99C".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "7946862be16e765a6b20e680b8d1c6f1".to_string(),
                    family: "pgp".to_string(),
                    issuer: "152812300785c96444d3334d17565732e08e5e41".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T00:31:33Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "3A64".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "e05207afe12041471146eb6a0f228a87".to_string(),
                    family: "pgp".to_string(),
                    issuer: "e61773cd6e01040e2f1bd78ce7e2984b6289c93a".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T16:29:18Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "275C".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "34f5fe1bee3fd6ab298bc23dfb1778e1".to_string(),
                    family: "pgp".to_string(),
                    issuer: "9deae0dc7063249fb05474681e4aed62986cd25d".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA512".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T07:57:51Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "877A".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "c29d7b936b21dc75eb13cc26e270cdc1".to_string(),
                    family: "pgp".to_string(),
                    issuer: "c388f6961fb972a95678e327f62711dbdca8ae56".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "ECDSA".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T00:39:24Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "5CF0".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "2672891ee5b2a4185d72cc63324edc28".to_string(),
                    family: "pgp".to_string(),
                    issuer: "9d3cc86a72f8494342ea5fd10a41bdc3f4faff1c".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T08:19:28Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "EDC2".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "a638dc2c6d22847e68cf53ad9ea37807".to_string(),
                    family: "pgp".to_string(),
                    issuer: "637db1e23370f84aff88cce03152347d07da627c".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T15:42:36Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "2158".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "05c8a485f150e13745dbee16a41602a5".to_string(),
                    family: "pgp".to_string(),
                    issuer: "f2cfc4abd0b99d837eebb7d09b79b45691db4173".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T08:25:10Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "34ED".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "c6253e159288f6b756f4d3789d05f7c3".to_string(),
                    family: "pgp".to_string(),
                    issuer: "e86ae73439625bbee306aae6b66d427f873cb1a3".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "EdDSA".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T12:14:52Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "CF91".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "c1d6a62f4890a3d48391b8e83ab59152".to_string(),
                    family: "pgp".to_string(),
                    issuer: "f19f5ff2b0589ec341220045ba03f4dbe0c63fb4".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T16:01:38Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "DD94".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "dc1d68802daf2955e900b0e5438f08e3".to_string(),
                    family: "pgp".to_string(),
                    issuer: "f4fc70f07310028424efc20a8e4256593f177720".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T11:19:23Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "1FFA".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "90a908f1b6dbfab27c9b26be26c6f6f7".to_string(),
                    family: "pgp".to_string(),
                    issuer: "a0083660f235a27000cd3c81ce6ec49945c17ea6".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T10:20:41Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "3E08".to_string(),
                    bytes: vec![]
                },
                PgpSig {
                    chksum: "2dd7b21df3ed9764975d38fc68ff8388".to_string(),
                    family: "pgp".to_string(),
                    issuer: "0ccbaafd76a2ece2ccd3141de2ffd5b1d88ca97d".to_string(),
                    sig_type: 0,
                    sig_version: 4,
                    hash_algo: "SHA256".to_string(),
                    sig_algo: "RSAEncryptSign".to_string(),
                    creation_time: Some(
                        DateTime::parse_from_rfc3339("2025-01-08T14:17:43Z")
                            .unwrap()
                            .with_timezone(&Utc)
                    ),
                    digest_prefix: "FD17".to_string(),
                    bytes: vec![]
                }
            ]
        );
    }

    #[test]
    fn test_parse_keys() {
        let content = include_bytes!("../test_data/debian-apache-signing-keys.asc");
        let content = String::from_utf8_lossy(content);
        let keys = parse_keys(&content).unwrap();

        assert_eq!(
            &keys[..3],
            &[
                PgpKey {
                    fingerprint: "de29fb3971e71543fd2dc049508eaec5302da568".to_string(),
                    mpis: "DSA {\n    p: 1024 bits: E687 911F A050 3C54 2FDC EFE0 651B 9978 F910 4871 8964 BD81 5970 B6D2 D9F3 E090 70E7 76BA E9E7 121E 6021 6F9E 7452 5469 106C 07E5 E068 FAD9 F19C C9A2 3D40 86CB 001C 867A A4A8 33E0 DB88 4CC8 C91F 9040 DA41 ABE6 E857 5256 6978 AE23 C778 B1D7 F967 24C7 DA74 F511 4595 3E20 6079 71D8 B5D9 E3A2 1EC8 A46E 444C 7DA6 881B 3BB3,\n    q: 160 bits: BDC2 6BCB 72F0 6BC1 5F81 5B42 5C57 88E4 4F30 026D,\n    g: 1024 bits: B3AD C61E 87C0 96D3 5860 0524 503D 456C 36A1 284B 9A8B D81A D767 C5C6 3EC0 75F5 DA80 A46A 729D DBA3 6BD3 D3BE A278 7FC6 2434 992A A5DE FE92 50F9 C27F 20BF A822 DEB8 EDB0 E2FB 290E 514C 6C13 F423 E5C5 52DD 7A3B 095D C6F9 B2E5 F1EF 8428 6CED 8499 AA45 4233 1E62 F8D4 EFC9 DE75 3FD6 842C 51BA 03FE F1DF 3FED A66C A705 EF30,\n    y: 1024 bits: BC97 6F6A 8F12 5234 3B08 30C7 F473 0F12 4D4B 4D28 DF52 9272 95A5 07A4 B476 FEC7 EDF0 ADE5 0448 F072 AE07 E571 39BB CB5B A583 CAD5 6B3C A7B1 2563 3024 6D99 921F 6E85 769A 1B20 3AED 3C69 9DDB 5CFA 5688 7489 E4D4 7DEE 3747 F2CD C8C6 E8B2 43CE 0F1C 7563 C8B0 0887 6F27 0242 2F6C F46D 82DE CCE7 CD5D 3E92 A49C 7BEA CF5B 16E8,\n}".to_string(),
                },
                PgpKey {
                    fingerprint: "c41f1f5c64850100b21beb14a14e77b604e15f28".to_string(),
                    mpis: "ElGamal {\n    p: 1024 bits: F6FD 5C2C 54B4 85E1 D762 E6C1 8364 D0F0 3D4D 6349 3353 20A3 6D2B C14B 1951 D2C7 3993 6E5C 251F 6088 C78F 0F79 D4AD 4AAA 95C6 0AFE 0E9F FD12 5576 A05D 9B3D C88F B2E0 49A4 CFAA 8F86 BF67 0331 DEC4 7FB2 927F 9139 A3F4 CCD2 AD3C F829 E424 1C1F 3F45 5F2C FDD1 766E 538F 1397 2DB4 6BDA A8D2 FDB5 7615 61D0 3E2D BA59 12DE 9007,\n    g: 3 bits: 05,\n    y: 1024 bits: D480 D63C ED3B 33DE 7768 A271 E825 415F CF09 66E6 03A4 9EFC 44D1 293C 7606 3360 FADC 2D7F 5911 3A52 A135 9EA5 B8DF 49ED 85D6 FA13 B1C3 2457 65A1 28C4 AB76 DCC5 ADDF 0F8E F3A8 F2D5 CB90 F2FB DAFC 9483 0EC1 0C59 DF2E F21A 2ED1 C042 ED01 A9F1 DA39 1847 E6E7 C564 B5EB 397B C719 A61F C7F9 126C 53A9 8CAF CA0A B620 2F31 77AF,\n}".to_string(),
                },
                PgpKey {
                    fingerprint: "13155b0e9e634f42bf6c163fddba64ba2c312d2f".to_string(),
                    mpis: "DSA {\n    p: 1024 bits: E41F 81FC 62A1 5A04 713B 9536 FE0E 4675 D822 D7AB B1E4 E350 C0FC 753E 28CD 82AC 6384 C4AE 2B0C EF73 55AE F38C C6E3 86C9 1830 AF40 5533 C2F9 FF8B AC39 383E D4C9 AD1A E1E8 3299 7FC9 6812 1802 86B5 2948 306F 941C B0B1 6880 C56A 8858 074D CB43 CE5E E64D C96F 973D CEAE FDB2 A09F AD69 7BD5 0044 A23E AAAC 48A2 E471 7CF2 6E39,\n    q: 160 bits: FFBA B4B3 262C 9D61 6251 338C 17BF E4BB A3C7 7611,\n    g: 1024 bits: 9569 9773 DAA9 6E41 1316 0AAD D0CB 29F4 341F B8CB 5D73 8006 E978 6C3C E6A6 3531 E569 A4AB 6CE1 87BE 6FE1 B190 4417 4209 301D DC40 28C1 5B24 D956 E151 8FE8 43F6 DFBF B94A DF63 CD4E B86D 03D0 1F69 DB9E 794E A10D 0707 D985 7453 B027 6981 E545 B898 C5CE 8048 665D 48D8 8F2F C098 2EE3 F729 0EDE 4968 D1A8 6FA2 11AD 53E6 71E4,\n    y: 1024 bits: D631 D249 D74A D478 B4A8 A942 869C 3855 0EDE D3EC 7EC4 B847 203E B111 92CC EDCC 173F 6E43 8566 0F9A 4651 6867 CA27 F0B5 110C 38ED 4241 E0CB 55F7 6593 0D8B B465 28E7 C455 5050 0306 B1A9 4CF1 BFC8 0628 186E E354 D97E 4B09 E9EE A3AB 87B0 E75C 012A 5D1D 2DF9 EC58 6771 AF36 C5BD 0AF8 D8A2 226B 9D55 5BCD 5FB8 4596 6DE3 C680,\n}".to_string(),
                },
            ]
        );

        let keys = keys.into_iter().map(|k| k.fingerprint).collect::<Vec<_>>();
        assert_eq!(
            keys,
            &[
                "de29fb3971e71543fd2dc049508eaec5302da568",
                "c41f1f5c64850100b21beb14a14e77b604e15f28",
                "13155b0e9e634f42bf6c163fddba64ba2c312d2f",
                "f05e8a42a30692f17b32e3de2b884a28c9d00816",
                "8b39757b1d8a994df2433ed58b3a601f08c975e5",
                "a06837456088a3cb411569b232c0d8454ccdb430",
                "31ee1a81b8d066548156d37b7d6dbfd1f08e012a",
                "6733bedb681cbcb317374cce000d407cd8f8125a",
                "b1b96f45dfbdccf974019235193f180ab55d9977",
                "674656c738972d5bd2a4815d815467b6cb9b9ec5",
                "a894bd6035ef6782b31c70593317284fff1392f5",
                "699280cb8aae80502ae2d61baac870a9c10fe28b",
                "49620827e32bc882dc6bef54a348b9847f7214a7",
                "f42d1ccca32b586a9866e57563a24fd57715d89c",
                "e2fa6d8c64d0d4c824b8b17b098aa297fcdc8c20",
                "627be9d7d7c69d30a2f5b0085593bca960c5442d",
                "7cd699467617b930b22d5d80c538977217886d66",
                "dd24a793e3bbdba981eb0ba7fec3240be25ac108",
                "91849c3de0860aca7a90d3e28efb19629088f565",
                "3f1b0775fbdc80a7c6b70ef0cfdcbd6bde8fc860",
                "519a22d2ddff910157bc6ff4f19c1b6de1758474",
                "a10208fec3152dd7c0c9b59b361522d782ab7bd1",
                "82a6e2eeb84f250c8711065b86a4074c1fcf5d88",
                "3de024afda7a4b15cb6c14410f81aa8ab0d5f771",
                "eb138c6af0fc691001b16d93344a844d751d7f27",
                "98a198245e22e93399c061ef15d78a2318f4ad9e",
                "fa51765d3ce4eb83bfe1bdb7605e165a6d791a41",
                "3af4f09f1fe77eb9ca84444f188b14bc3cb6c399",
                "cba5a7c21ec143314c41393e5b968010e04f9a89",
                "dd30dbfecf2fa315b0ff2c3a7bc8482c69724023",
                "3c016f2b764621bb549c66b516a96495e2226795",
                "f5de928982ae17cfcb4d05cfbee905f98b626683",
                "67d4d4c479edd9ec88e1734cab7a60bc2cf86427",
                "cd524d348c823ceb8121e9bc8e93f748efc786ba",
                "67d4d4c479edd9ec88e1734cab7a60bc2cf86427",
                "cd524d348c823ceb8121e9bc8e93f748efc786ba",
                "937fb3994a242ba9bf49e93021454af0cc8b0f7e",
                "1dd61dfac3ffd895620a0a40aab84d1687db90e0",
                "ead1359a4c0f2d37472aaf28f55df0293a4e7ac9",
                "9682f491913187ca16b1fea5808f05a83829dea8",
                "4c1eadadb4ef5007579c919c6635b6c0de885dd3",
                "0ebc9a4e4d83e1b8b3f07c6cccc2ccb1532d14ca",
                "01e475360fccf1d0f24b9d145d414ae1e005c9cb",
                "92ccef0aa7dd46ac3a0f498bca6939748103a37e",
                "75d83d25e4be70364d497f20eef85c0fe71fd3a6",
                "bf1cafd976c25159760e42fdea17091c3ec3a5bb",
                "d395c7573a68b9796d38c258153fa0cd75a67692",
                "f2a124003799b66c753019e8d8d182e4a680673f",
                "fa39b617b61493fd283503e7eed1ea392261d073",
                "6de398205bed23a09e8cf1329684c60ba676b84d",
                "984fb3350c1d5c7a3282255bb31b213d208f5064",
                "cf6e126ca693094beafc7a2bb9ff93f8ed4260b6",
                "8bd888d646a57acced82e32e366d6916f8b0462f",
                "f8c2405f8893395e4da868baa01dbc9ea879fcf5",
                "3bda2b9c333c02dd0f509310bc34d4900596f229",
                "fe7a49daa875e890b4167f76ccb2eb46e76cf6d0",
                "45e9fededcb5991c283d85abd2142c6901611fbe",
                "39f6691a0ecf0c50e8bb849cf78875f642721f00",
                "9bb536ace6eac9803636627b0484004c7a2be310",
                "29a2ba848177b73878277fa475caa2a3f39b3750",
                "def21980b4caa25c7e91e0bd0b771de32c7157d3",
                "120a8667241aedd4a78b46104c042818311a3de5",
                "4223c678e4ff93d195ed3b4af8fe6c96a21cd598",
                "63235f3c5381f207008eb558e6d5bed15185ba1c",
                "06871bcffb04fe99c0de3737a06f07113b3bab8f",
                "d694dab98f4e68a84c17f011ecab0e7b83e6ae0d",
                "92d3c5c28cfc220bbbbf5c846472c8e5ea644ee9",
                "453510bda6c5855624e009236d0bc73a40581837",
                "d4a9867eed65a1e40345c9582fa4ffd16a4af32a",
                "fc5a6fc62e252dfd8007ee239bb863b0f51bb88a",
                "a5af82cacb88ed35ab569f5e8d5a18d148bcacc6",
                "8bb3501068d75afd573b9547e2c2f45d632f5abd",
                "0de5c55c6bf3b2352dabb89e13249b4fec88a0bf",
                "ce3ce36cbd834d6f4b6e1b7d81f808ee315b27a0",
                "7cdbed100806552182f98844e8e7e00b4daa1988",
                "5d23b66b5aef5b1723a1f0dc71adc85e9e49284a",
                "3516bea5ba31a99820847ab5712fad58caa19524",
                "a8ba9617ef3bccac3b29b869edb105896f9522d8",
                "1a64e8fe3941d74c0582e7474f61cae56741a3f9",
                "3e6ac004854f3a7f03566b592ff06894e55b0d0e",
                "4ef90eb057cf76fe45b03bc37e63715acb11fc40",
                "62885c50d6ea278ae3bf203fcbff55d231d9665f",
                "5b5181c2c0ab13e59da3f7a3ec582eb639ff092c",
                "2ffe2c48e20d62826cec595cd598d780e4799d69",
                "a93d62ecc3c8ea12db220ec934ea76e6791485a8",
                "abf34d08cbb9234184b28bce1979f6759b6d9bf7",
                "65b2d44fe74bd5e3de3ac3f082781de46d5954fa",
                "a0c0f28271f5cb69eaa05c3d2da7b2ac2b4c4b38",
                "8935926745e1ce7e3ed748f6ec99ee267eb5f61a",
                "87b9c89aa099b1f9ab74a245c944af904b40144a",
                "b9e8213aefb861af35a41f2c995e35221ad84dff",
                "916200f459f84ea46686f0053a202e4dd407183d",
                "e3480043595621fe56105f112ab12a7adc55c003",
                "a0bec00cd94e658e7ee00d16ac2c013d14ff4720",
                "93525cfcf6fdffb3fd9700dd5a4b10ae43b56a27",
                "befca5560e0050718493d88fb4196feba6476d7d",
                "c55ab7b9139eb2263cd1aabc19b033d1760c227b",
                "60a8f59bd4adcacb94d4b4542ce9183901174cd9",
                "26f51ef9a82f4acb43f1903ed377c9e7d1944c66",
                "c6784000c96c1ce455a585b848f6fe7ba7ad2a40",
            ]
        )
    }
}
