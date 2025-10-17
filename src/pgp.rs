use crate::errors::*;
use chrono::{DateTime, Utc};
use sequoia_openpgp::{
    Packet, PacketPile,
    packet::{Signature, signature::subpacket::SubpacketValue},
    parse::Parse,
    serialize::Serialize as _,
    types::{HashAlgorithm, PublicKeyAlgorithm},
};
use serde::Serialize;
use std::{io::Cursor, time::UNIX_EPOCH};

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

fn split(content: &str) -> Vec<&str> {
    let mut blocks: Vec<&str> = Vec::new();
    let mut current_block_start = 0;

    // Find each "-----BEGIN PGP SIGNATURE-----" and split there
    for (idx, _) in content.match_indices("-----BEGIN PGP SIGNATURE-----") {
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

fn chksum(sig: &[u8]) -> String {
    let chksum = blake3::hash(sig);
    format!("blake3:{chksum}")
}

pub fn parse(content: &str) -> Result<Vec<PgpSig>> {
    let blocks = split(content);

    let mut sigs = Vec::new();
    for (block_num, block) in blocks.iter().enumerate() {
        if block.trim().is_empty() {
            continue;
        }

        let block_bytes = block.as_bytes();
        let cursor = Cursor::new(block_bytes);

        match PacketPile::from_reader(cursor) {
            Ok(pile) => {
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
                        for subpacket in sig.hashed_area().iter().chain(sig.unhashed_area().iter())
                        {
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
                            .and_then(|duration| {
                                DateTime::from_timestamp_secs(duration.as_secs() as i64)
                            });

                        let Some(issuer) = issuer else {
                            warn!("No issuer fingerprint found in signature, skipping");
                            continue;
                        };

                        let sig = encode(sig)?;

                        let sig = PgpSig {
                            chksum: chksum(&sig),
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
            Err(err) => {
                warn!("Failed to parse block #{}: {err:#}", block_num + 1);
            }
        }
    }

    Ok(sigs)
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
    fn test_parse() {
        let content = include_str!("../test_data/SHA256SUMS.asc");
        let mut sigs = parse(content).unwrap();
        for sig in &mut sigs {
            // Clear bytes for comparison
            sig.bytes.clear();
        }
        assert_eq!(
            sigs,
            &[
                PgpSig {
                    chksum:
                        "blake3:0b3644f7a642645362dece878541481275be9e32e14e6e668bb427f09983a0c4"
                            .to_string(),
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
                    chksum:
                        "blake3:7946862be16e765a6b20e680b8d1c6f1813df871eec349e9fd6592be84cbdae4"
                            .to_string(),
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
                    chksum:
                        "blake3:e05207afe12041471146eb6a0f228a87db1fdeeaba5ca4845b7ccc33009473c7"
                            .to_string(),
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
                    chksum:
                        "blake3:34f5fe1bee3fd6ab298bc23dfb1778e1cf1c72d4780f34a68963fc5035b6ed5a"
                            .to_string(),
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
                    chksum:
                        "blake3:c29d7b936b21dc75eb13cc26e270cdc165168477ba1b4707ea3ce5f09023040d"
                            .to_string(),
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
                    chksum:
                        "blake3:2672891ee5b2a4185d72cc63324edc2843bba45e920a6b2336c5b24245b4e94c"
                            .to_string(),
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
                    chksum:
                        "blake3:a638dc2c6d22847e68cf53ad9ea378071e6d4a9683a8a0a2355186faf2f5d7c9"
                            .to_string(),
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
                    chksum:
                        "blake3:05c8a485f150e13745dbee16a41602a526a010b87848513588e01f96661ae65f"
                            .to_string(),
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
                    chksum:
                        "blake3:c6253e159288f6b756f4d3789d05f7c3f9b43e3b71abde9192684f7586dfb36a"
                            .to_string(),
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
                    chksum:
                        "blake3:c1d6a62f4890a3d48391b8e83ab5915214b7585d92c06d165fca23cac114db92"
                            .to_string(),
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
                    chksum:
                        "blake3:dc1d68802daf2955e900b0e5438f08e3b59da6e3a62c0e5b3fa267e6ba74c3c6"
                            .to_string(),
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
                    chksum:
                        "blake3:90a908f1b6dbfab27c9b26be26c6f6f73223cdbcccf2a5fe0850964416e99e32"
                            .to_string(),
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
                    chksum:
                        "blake3:2dd7b21df3ed9764975d38fc68ff8388dccf54fbaa7e73f842bc28523b7b6fae"
                            .to_string(),
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
}
