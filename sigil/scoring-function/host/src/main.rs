use anyhow::Result;
use methods::{SCORER_ELF, SCORER_ID};
use risc0_zkvm::{
    default_prover, ExecutorEnv, Groth16ReceiptVerifierParameters, Groth16Seal, ProverOpts,
};
use risc0_zkvm::sha::{Digest, Digestible};
use serde::{Deserialize, Serialize};

// Types duplicated from guest (needed for host-side serialization).
// Must stay in sync with methods/guest/src/main.rs.

#[derive(Debug, Deserialize, Serialize)]
pub enum ProposalType {
    TreasurySpend,
    TokenIssuance,
    ParameterChange,
    LaunchpadGovernance,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ScoringInput {
    pub agent_pubkey: [u8; 32],
    pub proposal_id: [u8; 32],
    pub proposal_type: ProposalType,
    pub treasury_usdc: u64,
    pub treasury_token: u64,
    pub token_price_usd: u64,
    pub proposed_usdc_spend: u64,
    pub proposed_token_issuance: u64,
    pub circulating_supply: u64,
    pub pass_twap: u64,
    pub fail_twap: u64,
    pub market_liquidity_usd: u64,
    pub days_elapsed: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ScoringOutput {
    pub agent_pubkey: [u8; 32],
    pub proposal_id: [u8; 32],
    pub position: u8,
    pub score: u32,
}

/// Split a risc0 Digest into two 32-byte big-endian public input values.
///
/// Mirrors the `split_digest` logic in risc0-groth16's verifier:
///   digest (LE) -> reverse to BE -> split at midpoint ->
///   low half = pi[0], high half = pi[1], each zero-padded to 32 bytes.
fn split_digest_to_public_inputs(d: &Digest) -> ([u8; 32], [u8; 32]) {
    let be: Vec<u8> = d.as_bytes().iter().rev().cloned().collect();
    let mut pi0 = [0u8; 32];
    let mut pi1 = [0u8; 32];
    pi0[16..].copy_from_slice(&be[16..32]); // lower 128 bits
    pi1[16..].copy_from_slice(&be[0..16]); // upper 128 bits
    (pi0, pi1)
}

/// Convert a risc0 Digest to a 32-byte big-endian value (simple byte reversal).
fn digest_to_be(d: &Digest) -> [u8; 32] {
    let bytes = d.as_bytes();
    let mut out = [0u8; 32];
    for (i, b) in bytes.iter().rev().enumerate() {
        out[i] = *b;
    }
    out
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // Realistic TreasurySpend proposal
    //
    // Scenario: DAO with $5M USDC + 10M tokens @ $0.50 each ($10M total treasury).
    // Proposal requests $50K USDC spend (100 bps of treasury) — conservative.
    // Market signals: pass TWAP $0.52, fail TWAP $0.48 (~8.3% spread, bullish).
    // Liquidity: $150K. Voting period: day 1 (optimal timing).
    //
    // Expected: high score, PASS position.
    let input = ScoringInput {
        agent_pubkey: [0x01; 32],
        proposal_id: [0x01; 32],
        proposal_type: ProposalType::TreasurySpend,
        treasury_usdc: 5_000_000_000_000,       // $5M (6 decimals)
        treasury_token: 10_000_000_000_000,     // 10M tokens
        token_price_usd: 500_000,               // $0.50 (6 decimals)
        proposed_usdc_spend: 50_000_000_000,    // $50K
        proposed_token_issuance: 0,
        circulating_supply: 100_000_000_000_000, // 100M tokens
        pass_twap: 520_000,                      // $0.52
        fail_twap: 480_000,                      // $0.48
        market_liquidity_usd: 150_000_000_000_000, // $150K (microdollars)
        days_elapsed: 1,
    };

    println!("=== SIGIL v1 Groth16 Proof Generator ===\n");
    println!("Image ID (u32x8): {:?}", SCORER_ID);
    let image_hex: String = SCORER_ID
        .iter()
        .flat_map(|w| w.to_le_bytes())
        .map(|b| format!("{:02x}", b))
        .collect();
    println!("Image ID (hex):   {}\n", image_hex);

    // Build executor environment
    let env = ExecutorEnv::builder().write(&input)?.build()?;

    // Generate Groth16 proof.
    // Requires either:
    //   - BONSAI_API_KEY + BONSAI_API_URL env vars (Bonsai remote proving)
    //   - Local Docker with risc0 Groth16 prover image installed
    println!("Proving with Groth16 (this may take several minutes)...");
    let prove_info = default_prover().prove_with_opts(env, SCORER_ELF, &ProverOpts::groth16())?;
    let receipt = prove_info.receipt;

    // Verify the receipt locally
    receipt.verify(SCORER_ID)?;
    println!("Receipt verified successfully!\n");

    // Decode journal output
    let output: ScoringOutput = receipt.journal.decode()?;
    println!("=== Scoring Output ===");
    println!(
        "Position: {} ({})",
        output.position,
        if output.position == 0 { "PASS" } else { "FAIL" }
    );
    println!("Score:    {}", output.score);
    println!(
        "Journal:  {} bytes\n",
        receipt.journal.bytes.len()
    );

    // Extract Groth16 proof components from seal
    let g16 = receipt
        .inner
        .groth16()
        .expect("Expected Groth16 inner receipt");

    let seal = Groth16Seal::decode(&g16.seal)?;
    let seal_bytes = seal.to_vec();
    assert_eq!(seal_bytes.len(), 256, "Groth16 seal must be 256 bytes");

    let proof_a = &seal_bytes[0..64];
    let proof_b = &seal_bytes[64..192];
    let proof_c = &seal_bytes[192..256];

    println!("=== Groth16 Proof (256 bytes, big-endian) ===\n");
    println!("proof_a (64 bytes):");
    println!("{}\n", hex::encode(proof_a));
    println!("proof_b (128 bytes):");
    println!("{}\n", hex::encode(proof_b));
    println!("proof_c (64 bytes):");
    println!("{}\n", hex::encode(proof_c));

    // Compute the 5 public inputs for on-chain Groth16 verification.
    //
    // risc0 Groth16 public input layout (5 × BN254 field elements, 32 bytes each):
    //   [0] = low  128 bits of control_root
    //   [1] = high 128 bits of control_root
    //   [2] = low  128 bits of claim_digest
    //   [3] = high 128 bits of claim_digest
    //   [4] = BN254 identity control ID
    //
    // These are NOT the same as journal fields — they are circuit-level commitments.
    let params = Groth16ReceiptVerifierParameters::default();
    let claim_digest: Digest = g16.claim.digest();
    let control_root = params.control_root;
    let bn254_control_id = params.bn254_control_id;

    let (pi0, pi1) = split_digest_to_public_inputs(&control_root);
    let (pi2, pi3) = split_digest_to_public_inputs(&claim_digest);
    let pi4 = digest_to_be(&bn254_control_id);

    println!("=== Public Inputs (5 × 32 bytes, big-endian) ===\n");
    println!("  [0] control_root low:   {}", hex::encode(pi0));
    println!("  [1] control_root high:  {}", hex::encode(pi1));
    println!("  [2] claim_digest low:   {}", hex::encode(pi2));
    println!("  [3] claim_digest high:  {}", hex::encode(pi3));
    println!("  [4] bn254_control_id:   {}\n", hex::encode(pi4));

    // Print raw digests for debugging
    println!("=== Raw Digests ===\n");
    println!("control_root:     {}", hex::encode(control_root.as_bytes()));
    println!("claim_digest:     {}", hex::encode(claim_digest.as_bytes()));
    println!("bn254_control_id: {}", hex::encode(bn254_control_id.as_bytes()));

    // Print journal bytes for Anchor program integration
    println!("\n=== Journal Bytes ===\n");
    println!("journal_hex: {}", hex::encode(&receipt.journal.bytes));

    println!("\n=== Done ===");
    Ok(())
}
