use methods::SCORER_ID;

fn main() {
    println!("SIGIL_V1_IMAGE_ID: {:?}", SCORER_ID);
    let hex: String = SCORER_ID.iter()
        .map(|b| format!("{:08x}", b))
        .collect();
    println!("Image ID (hex): {}", hex);
}
