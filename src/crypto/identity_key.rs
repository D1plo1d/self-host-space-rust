use boring::{
    ec::{EcGroup, EcKey},
    nid::Nid,
};
use eyre::eyre;
use eyre::{
    Context as _,
    // eyre,
    Result,
};
use jwt_simple::{
    prelude::{Claims, ECDSAP256KeyPairLike, ES256KeyPair},
    reexports::coarsetime,
};
use std::path::PathBuf;
use tokio::{fs, io::AsyncWriteExt};

#[derive(Clone)]
pub struct IdentityKey {
    pub identity_private_key: EcKey<boring::pkey::Private>,
    pub identity_public_key: String,
    pub b58_fingerprint: String,
}

impl IdentityKey {
    pub async fn load_or_create(id_public_key_path: PathBuf) -> Result<Self> {
        let mut id_private_key_path = id_public_key_path.clone();
        id_private_key_path.set_file_name(
            id_public_key_path
                .file_stem()
                .ok_or_else(|| eyre!("Public key path must end in .pub extension"))?,
        );

        // Identity key setup
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut ctx = boring::bn::BigNumContext::new().unwrap();

        if !id_private_key_path.exists() {
            let key = EcKey::generate(&group)?;

            // write the private key
            let private_key = key.private_key_to_pem()?;
            let mut file = fs::File::create(&id_private_key_path).await?;
            file.write_all(&private_key[..]).await?;

            // write the public key
            let public_key = key.public_key_to_pem()?;
            let mut file = fs::File::create(&id_public_key_path).await?;
            file.write_all(&public_key[..]).await?;
        }

        let identity_private_key = fs::read(&id_private_key_path)
            .await
            .wrap_err_with(|| format!("Missing identity private key"))?;

        let identity_public_key = fs::read_to_string(&id_public_key_path)
            .await
            .wrap_err_with(|| format!("Missing identity public key"))?;

        let public_key_bytes: Vec<u8> = identity_public_key.bytes().collect();
        let key = EcKey::public_key_from_pem(&public_key_bytes[..])?;
        let compressed_public_key = key.public_key().to_bytes(
            &group,
            boring::ec::PointConversionForm::COMPRESSED,
            &mut ctx,
        )?;
        let b58_fingerprint = bs58::encode(compressed_public_key).into_string();

        Ok(Self {
            identity_private_key: EcKey::private_key_from_pem(&identity_private_key)?,
            identity_public_key,
            b58_fingerprint,
        })
    }

    pub fn sign_jwt(
        &self,
        claims: serde_json::Value,
        valid_for: coarsetime::Duration,
    ) -> Result<String> {
        let key_pair =
            ES256KeyPair::from_bytes(&self.identity_private_key.private_key().to_vec()[..])
                .map_err(|err| eyre!("Invalid identity private key. Original Error: {:?}", err))?;

        let claims = Claims::with_custom_claims(claims, valid_for);

        let jwt = key_pair
            .sign(claims)
            .map_err(|err| eyre!("Failed to sign JWT. Original Error: {:?}", err))?;

        Ok(jwt)
    }
}
