use boring::asn1::Asn1Time;
use boring::bn::BigNum;
use boring::bn::MsbOption;
use boring::ec::EcGroup;
use boring::ec::EcKey;
use boring::hash::MessageDigest;
use boring::pkey::PKey;
use boring::x509::extension::BasicConstraints;
use chrono::DateTime;
use chrono::Duration;
use chrono::Utc;
use eyre::Result;
use std::fs;
use std::path::PathBuf;

pub const EPHEMERAL_VALID_DAYS: i64 = 10;

#[derive(Clone)]
pub struct WebTransportEphemeralKey {
    pub private_key: PathBuf,
    pub cert: PathBuf,
    pub takes_effect_at: DateTime<Utc>,
}

impl WebTransportEphemeralKey {
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.takes_effect_at + Duration::days(EPHEMERAL_VALID_DAYS)
    }

    /// Leave a 1 day buffer before the old cert expires to switch to it's successor
    pub fn replace_at(&self) -> DateTime<Utc> {
        self.expires_at() - Duration::days(1)
    }

    pub fn should_be_replaced(&self) -> bool {
        self.replace_at() < Utc::now()
    }

    pub fn sha256_fingerprint(&self) -> String {
        let pem_serialized = fs::read_to_string(&self.cert).unwrap();
        let der_serialized = pem::parse(&pem_serialized).unwrap().contents;
        let hash = ring::digest::digest(&ring::digest::SHA256, &der_serialized);

        hash.as_ref()
            .into_iter()
            .into_iter()
            .map(|b| format!("{:02X}", b))
            .collect::<Vec<_>>()
            .join(":")
    }

    pub fn generate(
        cert_pem_path: PathBuf,
        priv_key_pem_path: PathBuf,
        takes_effect_at: DateTime<Utc>,
    ) -> Result<Self> {
        // WebTransport certs are required to be rotated such that their expiration date does not exceed 10 days into the future.
        //
        // This is equivalent to:
        // openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -x509 -sha256 -nodes -out webtransport_example.crt -keyout webtransport_example.key -days 10
        let curve = &EcGroup::from_curve_name(boring::nid::Nid::X9_62_PRIME256V1).unwrap();
        let key_pair = EcKey::generate(curve).unwrap();
        let key_pair = PKey::from_ec_key(key_pair).unwrap();

        let mut builder = boring::x509::X509Builder::new().unwrap();
        builder.set_version(0x2).unwrap();
        let serial_number = {
            let mut serial = BigNum::new().unwrap();
            serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
            serial.to_asn1_integer().unwrap()
        };
        builder.set_serial_number(&serial_number).unwrap();

        let expires_at = takes_effect_at + Duration::days(EPHEMERAL_VALID_DAYS);
        builder
            .set_not_before(&Asn1Time::from_unix(takes_effect_at.timestamp()).unwrap())
            .unwrap();
        builder
            .set_not_after(&Asn1Time::from_unix(expires_at.timestamp()).unwrap())
            .unwrap();

        // Build the x509 issuer and subject names. These are arbitrary.
        let mut x509_name = boring::x509::X509NameBuilder::new().unwrap();
        x509_name.append_entry_by_text("C", "US").unwrap();
        x509_name.append_entry_by_text("ST", "CA").unwrap();
        x509_name
            .append_entry_by_text("O", "Some organization")
            .unwrap();

        let x509_name = x509_name.build();
        builder.set_issuer_name(&x509_name).unwrap();
        builder.set_subject_name(&x509_name).unwrap();

        builder.set_pubkey(&key_pair).unwrap();

        builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();

        builder.sign(&key_pair, MessageDigest::sha256()).unwrap();

        // Write the new cert and private key to disk
        let cert_pem = builder.build().to_pem().unwrap();
        fs::write(&cert_pem_path, cert_pem).unwrap();
        let priv_pem = key_pair.private_key_to_pem_pkcs8().unwrap();
        fs::write(&priv_key_pem_path, priv_pem).unwrap();

        Ok(Self {
            private_key: priv_key_pem_path,
            cert: cert_pem_path,
            takes_effect_at,
        })
    }
}
