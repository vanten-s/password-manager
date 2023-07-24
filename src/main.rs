use directories::ProjectDirs;
use color_eyre::eyre::Result;
use color_eyre;
use std::env;
use std::fs::File;
use std::io::{Write, Cursor};
use pgp::composed::{KeyType, key::SecretKeyParamsBuilder, signed_key::*, message::Message};
use pgp::types::SecretKeyTrait;
use pgp::Deserializable;
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use smallvec::*;
use rand::prelude::*;

static USAGE: &'static str = "
 generate-key [PASSWORD]          Generate a key. WARNING: only run once or you'll lose all your passwords
 save [SERVICE] [NAME] [PASSWORD] Add password to database
 load [SERVICE] [NAME] [PASSWORD] Get password from database
 generate-pass [SERVICE] [NAME]   Generate password and add to database
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
    if args.len() != 5 {
        print_usage();
        return Err(1);
    }

    let proj_dirs = ProjectDirs::from("com", "vanten-s", "password-database").unwrap();
    let data_dir: std::path::PathBuf = proj_dirs.data_local_dir().try_into().unwrap();
    
    let mut public_key_path = data_dir.clone();
    public_key_path.push("publickey.asc");

    let public_key = std::fs::read_to_string(public_key_path).expect("Couldn't load public key file!");
    let (public_key, _) = SignedPublicKey::from_string(public_key.as_str()).expect("Couldn't load public key!");

    let mut save_file_path = data_dir.clone();

    save_file_path.push(&args[2]); 
    std::fs::create_dir_all(save_file_path.clone()).expect("Couldn't create directory!");

    save_file_path.push(&args[3]); 
    let mut save_file = File::create(save_file_path).expect("Couldn't open file");

    let msg = Message::new_literal("none", &args[4]);
    
    let armored = generate_armored_string(msg, public_key).expect("Couldn't encrypt password!");
    
    save_file.write(armored.as_bytes()).expect("Could't save!!");
    return Ok(String::from("Ez"))
}

fn load(args: Vec<String>) -> Result<String, u32> {
    if args.len() != 5 {
        print_usage();
        return Err(1);
    }

    let proj_dirs = ProjectDirs::from("com", "vanten-s", "password-database").unwrap();
    let data_dir: std::path::PathBuf = proj_dirs.data_local_dir().try_into().unwrap();
    
    let mut secret_key_path = data_dir.clone();
    secret_key_path.push("secretkey.asc");

    let secret_key = std::fs::read_to_string(secret_key_path).expect("Couldn't load secret key file!");
    let (secret_key, _) = SignedSecretKey::from_string(secret_key.as_str()).expect("Couldn't load secret key!");

    let mut load_file_path = data_dir.clone();

    load_file_path.push(&args[2]);
    load_file_path.push(&args[3]);
    let armored = std::fs::read_to_string(load_file_path).expect("Couldn't load password file");
    let (msg, _) = Message::from_armor_single(Cursor::new(armored)).expect("Couldn't load password into message");
    let (decryptor, _) = msg
        .decrypt(|| String::from(&args[4]), &[&secret_key])
        .expect("Couldn't decrypt msg");

    for msg in decryptor {
        let bytes = msg.unwrap().get_content().unwrap().unwrap();
        let clear = String::from_utf8(bytes).unwrap();
        if String::len(&clear) > 0 {
            return Ok(clear);
        }
    }
    
    Err(1)
}

fn generate_pass(args: Vec<String>) -> Result<String, u32> {
    if args.len() != 4 {
        print_usage();
        return Err(1);
    }

    let password: Vec<u8> =  rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(15)
        .collect();

    let password = String::from_utf8(password).expect("Could not convert Vec<u8> to string :(");

    println!("Password: {password}");

    let mut save_args = args.clone();
    save_args.push(password);

    return save(save_args);
}

fn generate_armored_string(msg: Message, pk: SignedPublicKey) -> Result<String> {
    let mut rng = StdRng::from_entropy();
    let new_msg = msg.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[&pk])?;
    Ok(new_msg.to_armored_string(None)?)
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
