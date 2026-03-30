use risc0_groth16::verifying_key;

fn main() {
    let vk = verifying_key();
    let json = serde_json::to_string_pretty(&vk).unwrap();
    println!("{}", json);
}
