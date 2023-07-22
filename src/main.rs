use directories::ProjectDirs;
use color_eyre::eyre::Result;
use color_eyre;
use std::env;
use std::fs::File;
use std::io::Write;
use pgp::composed::{KeyType, key::SecretKeyParamsBuilder};
use pgp::types::SecretKeyTrait;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use smallvec::*;

static USAGE: &'static str = "
 generate-key [PASSWORD] generate a key. WARNING: only run once or you'll lose all your passwords
 save [PASSWORD] [NAME]  add password to database
 load [NAME]             get password from database
 generate-pass [NAME]    generate password and add to database
";

fn generate_key(args: Vec<String>) -> (String, String) {
    if args.len() != 3 {
        print_usage();
        return (String::new(), String::new());
    }

    let password = &args[2];

    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Rsa(2048))
        .passphrase(Some(password.clone()))
        .can_sign(true)
        .can_create_certificates(false)
        .primary_user_id("User <vanten-s@vanten-s.com>".into())
        .preferred_symmetric_algorithms(smallvec![SymmetricKeyAlgorithm::AES256]);
        // .passphrase(Some(password.to_owned()));
    let secret_key_params = key_params.build().expect("Failed to generate key params");

    let secret_key = secret_key_params.generate().expect("Failed to generate secret key");
    let passwd_fn = || password.clone();
    let signed_secret_key = secret_key.sign(passwd_fn).expect("Secret key couldn't sign itself");

    let public_key = signed_secret_key.public_key();
    let signed_public_key = public_key.sign(&signed_secret_key, passwd_fn).expect("Public key couldn't sign itself");

    return (signed_secret_key.to_armored_string(None).unwrap(), signed_public_key.to_armored_string(None).unwrap());
}

fn save(args: Vec<String>) -> Result<String, u32> {
    if args.len() != 4 {
        print_usage();
        return Err(1);
    }
    return Ok(String::from("Not Implemented Yet"));
}

fn load(args: Vec<String>) -> Result<String, u32> {
    if args.len() != 3 {
        print_usage();
        return Err(1);
    }
    return Ok(String::from("Not Implemented Yet"));
}

fn generate_pass(args: Vec<String>) -> Result<String, u32> {
    if args.len() != 3 {
        print_usage();
        return Err(1);
    }
    return Ok(String::from("Not Implemented Yet"));
}

fn save_key(keys: (String, String)) -> Result<String, u32> {
    let proj_dirs = ProjectDirs::from("com", "vanten-s", "password-database").unwrap();
    let data_directory: std::path::PathBuf = proj_dirs.data_local_dir().try_into().unwrap();

    std::fs::create_dir_all(data_directory.clone()).expect("Failed to create project directory");
    
    let mut public_key_path = data_directory.clone();
    public_key_path.push("publickey.asc");
    let mut secret_key_path = data_directory.clone();
    secret_key_path.push("secretkey.asc");

    let mut public_key_file = File::create(public_key_path).expect("Couldn't open public key file");
    let mut secret_key_file = File::create(secret_key_path).expect("Couldn't open secret key file");

    secret_key_file.write(keys.0.as_bytes()).unwrap();
    public_key_file.write(keys.1.as_bytes()).unwrap();

    return Ok(String::from("Saved key"));
}

fn print_usage() -> String {
    println!("{USAGE}");
    return String::new();
}

fn main() -> Result<()> {
    color_eyre::install()?;
    let args: Vec<String> = env::args().collect();
    if args.len() <= 1 {
        print_usage();
        return Ok(());
    }
    let mode: &str = &args[1];
    let ret_val = match mode {
        "generate-key" => save_key(generate_key(args)),
        "save" => save(args),
        "load" => load(args),
        "generate-pass" => generate_pass(args),
        _ => Ok(print_usage()),
    }.unwrap();
    println!("{}", ret_val);
    return Ok(())
}
