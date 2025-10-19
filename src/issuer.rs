use crate::errors::*;
use sequoia_openpgp::{
    armor,
    serialize::stream::{Armorer, Message},
};
use serde::Serialize;
use std::io::Write;

#[derive(sqlx::FromRow, Debug, Serialize, PartialEq)]
pub struct Issuer {
    pub fingerprint: String,
    pub family: String,
    pub key: Option<Vec<u8>>,
}

impl Issuer {
    // XXX: this only makes sense for PGP keys
    pub fn to_ascii_armored(&self) -> Result<String> {
        let mut sink = Vec::new();

        let bytes = self.key.as_ref().context("Issuer has no key data")?;
        {
            let message = Message::new(&mut sink);
            let mut message = Armorer::new(message).kind(armor::Kind::PublicKey).build()?;
            message.write_all(bytes)?;
            message.finalize()?;
        }

        let armored = String::from_utf8(sink)?;
        Ok(armored)
    }
}
