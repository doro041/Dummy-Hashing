use criterion::{criterion_group, criterion_main, Criterion};
use rand::seq::SliceRandom; 
use runattacks::{dictionary_attack, brute_force_decode, crack_salted_passwords};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use sha2::{Sha512, Digest};
use csv::Writer;
use std::time::Instant;
use itertools::Itertools;
use std::path::PathBuf;

// this function specifies that criterion should have a sample size of 10

fn custom_criterion() -> Criterion {
    Criterion::default().sample_size(10)
}

fn get_random_hashes_from_file(file_path: &PathBuf, count: usize) -> Vec<String> {
    let lines = std::fs::read_to_string(file_path)
        .expect("Unable to read the file")
        .lines()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();

    let mut rng = rand::thread_rng();
    lines.choose_multiple(&mut rng, count).cloned().collect()
}
fn read_lines<P>(filename: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    Ok(reader.lines().filter_map(Result::ok).collect())
}

fn generate_random_password(length: usize) -> String {
    let charset: Vec<char> = "abcdefghijklmnopqrstuvwxyz0123456789".chars().collect();
    let password: String = (0..length).map(|_| charset.choose(&mut rand::thread_rng()).unwrap()).collect();
    password
}


fn  brute_force_decode_for_length(hash_val: &str, target_length: usize) -> Option<String> {
    let characters = "abcdefghijklmnopqrstuvwxyz0123456789";
    for password_chars in (0..target_length).map(|_| characters.chars()).multi_cartesian_product() {
        let password: String = password_chars.into_iter().collect();
        let hash = sha512_hash(&password);
        if hash == hash_val {
            return Some(password);
        }
    }
    None
}

fn sha512_hash(password: &str) -> String {
    let mut hasher = sha2::Sha512::new();
    hasher.update(password);
    format!("{:x}", hasher.finalize())
}
pub fn time_brute_force_for_length(hash_val: &str, target_length: usize, runs: usize) -> (f64, f64) {
    let mut times = Vec::new();

    for _ in 0..runs {
        let start_time = Instant::now();
        let _ = brute_force_decode_for_length(hash_val, target_length);
        let elapsed_time = start_time.elapsed().as_secs_f64();
        times.push(elapsed_time);
    }

    let avg_time = mean(&times);

    let std_deviation = if times.len() > 0 {
        let variance = times.iter().map(|&time| {
            let diff = avg_time - time;
            diff * diff
        }).sum::<f64>() / times.len() as f64;

        variance.sqrt()
    } else {
        0.0
    };

    (avg_time, std_deviation)
}

fn mean(data: &[f64]) -> f64 {
    let sum = data.iter().sum::<f64>();
    sum / data.len() as f64

}




pub fn benchmark_dictionary_attack(c: &mut Criterion) {

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
    let dict_file_path = PathBuf::from("./static/PasswordDictionary.txt");
    c.bench_function("dictionary_attack", |b| {
        b.iter(|| dictionary_attack(&dict_file_path, &dict_attack_hashes))
    });
}

pub fn benchmark_brute_force_decode(c: &mut Criterion) {

    let brute_force_hashes = vec![
        "f14aae6a0e050b74e4b7b9a5b2ef1a60ceccbbca39b132ae3e8bf88d3a946c6d8687f3266fd2b626419d8b67dcf1d8d7c0fe72d4919d9bd05efbd37070cfb41a",
        "e85e639da67767984cebd6347092df661ed79e1ad21e402f8e7de01fdedb5b0f165cbb30a20948f1ba3f94fe33de5d5377e7f6c7bb47d017e6dab6a217d6cc24",
        "4e2589ee5a155a86ac912a5d34755f0e3a7d1f595914373da638c20fecd7256ea1647069a2bb48ac421111a875d7f4294c7236292590302497f84f19e7227d80",
        "afd66cdf7114eae7bd91da3ae49b73b866299ae545a44677d72e09692cdee3b79a022d8dcec99948359e5f8b01b161cd6cfc7bd966c5becf1dff6abd21634f4b"
        
    ];
    c.bench_function("brute_force_decode", |b| {
        b.iter(|| brute_force_decode(&brute_force_hashes, 4))
    });
}


pub fn time_brute_force_for_length_benchmark(c: &mut Criterion) {
    c.bench_function("time_brute_force_for_length_benchmark", |b| {
        let runs = 10;
        let max_target_length = 5; 
        let mut wtr = csv::Writer::from_path("bruteforce.csv").expect("Unable to open file");
        wtr.write_record(&["Length", "Password", "Hash", "Average Time"]).unwrap();

        for length in 1..=max_target_length {
            for _ in 0..3 {  
                let random_password = generate_random_password(length);
                let hash_val = sha512_hash(&random_password);
                let (avg_time, _) = time_brute_force_for_length(&hash_val, length, runs);
                wtr.write_record(&[length.to_string(), random_password, hash_val, avg_time.to_string()]).unwrap();
            }
        }
    });
}

pub fn benchmark_crack_salted_passwords(c: &mut Criterion) {
  
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
    let dict_file_path = PathBuf::from("./static/PasswordDictionary.txt");
    let password_dictionary = match read_lines(dict_file_path) {
        Ok(lines) => lines,
        Err(_) => Vec::new(),
    };

    c.bench_function("crack_salted_passwords", |b| {
        b.iter(|| crack_salted_passwords(&password_dictionary, &salted_hashes))
    });
}


criterion_group!{
    name = benches; 
    config = custom_criterion(); 
    targets = benchmark_dictionary_attack, benchmark_brute_force_decode, benchmark_crack_salted_passwords, time_brute_force_for_length_benchmark
}

criterion_main!(benches);

