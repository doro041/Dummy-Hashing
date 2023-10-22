use std::collections::{HashMap};
use std::env;
use std::path::PathBuf;
use sha2::{Sha512, Digest};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::{Path};
extern crate itertools;
use itertools::Itertools;

// // This function computes the SHA-512 hash of a given password.
fn sha512_hash(password: &str) -> String {

    // compute the hash of the password using the SHA-512 algorithm.
    let mut hasher = Sha512::new();

    hasher.update(password);
    // finalize the hash and store it in the result variable.
    let result = hasher.finalize();

//it returns the hash as a hexadecimal string.
    format!("{:x}", result)
}

// This function aims to decode a list of hashes using a brute force approach up to a specified password length.
pub fn brute_force_decode(hashes: &[&str], max_length: usize) -> HashMap<String, String> {
    let characters = "abcdefghijklmnopqrstuvwxyz0123456789";
    // Initialize an empty HashMap to store the found passwords, because empty HashMaps are 
    let mut found_passwords: HashMap<String, String> = HashMap::new();

    // Outer loop iterates over the specified maximum password length.
   'outer: for length in 1..=max_length {
        // For each length, generate all possible combinations of passwords.
        for password_chars in (0..length).map(|_| characters.chars()).multi_cartesian_product() {
            // Convert the character combination into a String.
            let password: String = password_chars.into_iter().collect();
            // Compute the SHA-512 hash of the generated password.
            let hash = sha512_hash(&password);
            // Check if the computed hash exists in the provided list of hashes.
            if hashes.contains(&hash.as_str()) {
                // If a match is found, store the password in the HashMap.
                found_passwords.insert(hash, password);
                // If all hashes have been found, break out of the loops.
                if found_passwords.len() == hashes.len() {
                    break 'outer;
                }
            }
        }
    }
    // Return the HashMap containing the decoded passwords.
    found_passwords
}

// This function reads a file line by line and returns an iterator over the lines.
pub fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

// This function reads a file containing a list of passwords and returns a HashMap containing the SHA-512 hashes of the passwords.
pub fn dictionary_attack(dictionary_file: &PathBuf, hashes: &[&str]) -> HashMap<String, String> {
    // Initialize an empty HashMap to store the found passwords.
    let mut hash_dict = HashMap::new();
    if let Ok(lines) = read_lines(dictionary_file) {
        for line in lines {
            // For each line in the file, compute the SHA-512 hash of the password.
            if let Ok(password) = line {
                // Store the hash and password in the HashMap.
                let hash = sha512_hash(&password);
                hash_dict.insert(hash, password);
            }
        }
    }
    // Filter the provided list of hashes to only include the hashes that are found in the dictionary.

    hashes.iter()
        .filter_map(|&hash| hash_dict.get(hash).map(|password| (hash.to_string(), password.to_string())))
        .collect()
}

// This function computes the SHA-512 hash of a given password and salt.
pub fn sha512_hash_with_salt(password: &str, salt: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(password);
    hasher.update(salt);
    format!("{:x}", hasher.finalize())
}

// This function attempts to crack a list of salted hashes using a provided dictionary.
pub fn crack_salted_passwords(dictionary: &[String], salted_hashes: &[(String, String)]) -> HashMap<String, String> {
    let mut cracked_passwords: HashMap<String, String> = HashMap::new();
// Iterate over the provided list of salted hashes.
    for (hash, salt) in salted_hashes.iter() {
        // Iterate over the provided dictionary.
        for word in dictionary {
            // Compute the SHA-512 hash of the current dictionary word and salt.
            if sha512_hash_with_salt(word, salt) == *hash {
                cracked_passwords.insert(hash.clone(), word.clone());
                // Print the cracked password and break out of the loop.
                println!("Hash: {}\nSalt: {}\nPassword: {}\n{}", hash, salt, word, "-".repeat(60));
                break;
            }
        }
    }

    cracked_passwords
}

// This function runs the dictionary, brute force, and salted hash attacks.
pub fn run_attacks () {
    let dict_attack_hashes = vec![
        "31a3423d8f8d93b92baffd753608697ebb695e4fca4610ad7e08d3d0eb7f69d75cb16d61caf7cead0546b9be4e4346c56758e94fc5efe8b437c44ad460628c70",
        "9381163828feb9072d232e02a1ee684a141fa9cddcf81c619e16f1dbbf6818c2edcc7ce2dc053eec3918f05d0946dd5386cbd50f790876449ae589c5b5f82762",
        "a02f6423e725206b0ece283a6d59c85e71c4c5a9788351a24b1ebb18dcd8021ab854409130a3ac941fa35d1334672e36ed312a43462f4c91ca2822dd5762bd2b",
        "834bd9315cb4711f052a5cc25641e947fc2b3ee94c89d90ed37da2d92b0ae0a33f8f7479c2a57a32feabdde1853e10c2573b673552d25b26943aefc3a0d05699",
        "0ae72941b22a8733ca300161619ba9f8314ccf85f4bad1df0dc488fdd15d220b2dba3154dc8c78c577979abd514bf7949ddfece61d37614fbae7819710cae7ab",
        "6768082bcb1ad00f831b4f0653c7e70d9cbc0f60df9f7d16a5f2da0886b3ce92b4cc458fbf03fea094e663cb397a76622de41305debbbb203dbcedff23a10d8a",
        "0f17b11e84964b8df96c36e8aaa68bfa5655d3adf3bf7b4dc162a6aa0f7514f32903b3ceb53d223e74946052c233c466fc0f2cc18c8bf08aa5d0139f58157350",
        "cf4f5338c0f2ccd3b7728d205bc52f0e2f607388ba361839bd6894c6fb8e267beb5b5bfe13b6e8cc5ab04c58b5619968615265141cc6a8a9cd5fd8cc48d837ec",
        "1830a3dfe79e29d30441f8d736e2be7dbc3aa912f11abbffb91810efeef1f60426c31b6d666eadd83bbba2cc650d8f9a6393310b84e2ef02efa9fe161bf8f41d",
        "3b46175f10fdb54c7941eca89cc813ddd8feb611ed3b331093a3948e3ab0c3b141ff6a7920f9a068ab0bf02d7ddaf2a52ef62d8fb3a6719cf25ec6f0061da791"
    ];
    
    let salted_hashes = vec![
            ("63328352350c9bd9611497d97fef965bda1d94ca15cc47d5053e164f4066f546828eee451cb5edd6f2bba1ea0a82278d0aa76c7003c79082d3a31b8c9bc1f58b".to_string(), "dbc3ab99".to_string()),
            ("86ed9024514f1e475378f395556d4d1c2bdb681617157e1d4c7d18fb1b992d0921684263d03dc4506783649ea49bc3c9c7acf020939f1b0daf44adbea6072be6".to_string(), "fa46510a".to_string()),
            ("16ac21a470fb5164b69fc9e4c5482e447f04f67227102107ff778ed76577b560f62a586a159ce826780e7749eadd083876b89de3506a95f51521774fff91497e".to_string(), "9e8dc114".to_string()),
            ("13ef55f6fdfc540bdedcfafb41d9fe5038a6c52736e5b421ea6caf47ba03025e8d4f83573147bc06f769f8aeba0abd0053ca2348ee2924ffa769e393afb7f8b5".to_string(), "c202aebb".to_string()),
            ("9602a9e9531bfb9e386c1565ee733a312bda7fd52b8acd0e51e2a0a13cce0f43551dfb3fe2fc5464d436491a832a23136c48f80b3ea00b7bfb29fedad86fc37a".to_string(), "d831c568".to_string()),
            ("799ed233b218c9073e8aa57f3dad50fbf2156b77436f9dd341615e128bb2cb31f2d4c0f7f8367d7cdeacc7f6e46bd53be9f7773204127e14020854d2a63c6c18".to_string(), "86d01e25".to_string()),
            ("7586ee7271f8ac620af8c00b60f2f4175529ce355d8f51b270128e8ad868b78af852a50174218a03135b5fc319c20fcdc38aa96cd10c6e974f909433c3e559aa".to_string(), "a3582e40".to_string()),
            ("8522d4954fae2a9ad9155025ebc6f2ccd97e540942379fd8f291f1a022e5fa683acd19cb8cde9bd891763a2837a4ceffc5e89d1a99b5c45ea458a60cb7510a73".to_string(), "6f966981".to_string()),
            ("6f5ad32136a430850add25317336847005e72a7cfe4e90ce9d86b89d87196ff6566322d11c13675906883c8072a66ebe87226e2bc834ea523adbbc88d2463ab3".to_string(), "894c88a4".to_string()),
            ("21a60bdd58abc97b1c3084ea8c89aeaef97d682c543ff6edd540040af20b5db228fbce66fac962bdb2b2492f40dd977a944f1c25bc8243a4061dfeeb02ab721e".to_string(), "4c8f1a45".to_string())
        ];
        

    let brute_force_hashes = vec![
        "f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a",
        "e85e639da67767984cebd6347092df661ed79e1ad21e402f8e7de01fdedb5b0f165cbb30a20948f1ba3f94fe33de5d5377e7f6c7bb47d017e6dab6a217d6cc24",
        "4e2589ee5a155a86ac912a5d34755f0e3a7d1f595914373da638c20fecd7256ea1647069a2bb48ac421111a875d7f4294c7236292590302497f84f19e7227d80",
        "afd66cdf7114eae7bd91da3ae49b73b866299ae545a44677d72e09692cdee3b79a022d8dcec99948359e5f8b01b161cd6cfc7bd966c5becf1dff6abd21634f4b"
    ];

    //let dict_file_path = "./static/PasswordDictionary.txt";
    let dict_file_path = std::env::current_dir().unwrap().join("static/PasswordDictionary.txt");
    println!("{:?}", dict_file_path);
    println!("Starting dictionary attack...");

  let dict_attack_passwords = dictionary_attack( &dict_file_path, &dict_attack_hashes);
    display_found_passwords(&dict_attack_passwords, "Dictionary Attack");

    println!("Starting brute force attack...");
    let brute_force_passwords = brute_force_decode(&brute_force_hashes, 4);
    display_found_passwords(&brute_force_passwords, "Brute Force Attack");

    let password_dictionary = read_lines(dict_file_path).unwrap().map(Result::unwrap).collect::<Vec<_>>();
    println!("\nStarting salted hash attack...");
    let cracked_salted_passwords = crack_salted_passwords(&password_dictionary, &salted_hashes);
    display_found_passwords(&cracked_salted_passwords, "Salted Hash Attack");
}


fn main() {
    run_attacks();
}
// This function displays the found passwords.
fn display_found_passwords(found_passwords: &HashMap<String, String>, method: &str) {
    println!("\nResults from {}:", method);
    if found_passwords.is_empty() {
        println!("No passwords were found.");
    } else {
        for (hashed_password, password) in found_passwords.iter() {
            println!("Hash: {} | Password: {}", hashed_password, password);
            println!("{}", "-".repeat(60));
        }
    }
}


