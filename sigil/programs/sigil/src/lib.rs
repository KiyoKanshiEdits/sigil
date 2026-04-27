use anchor_lang::prelude::*;
use solana_sha256_hasher::hashv;

use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

pub mod constants;
use constants::*;

declare_id!("9Jnn4EvBvxfhixwVwbjxaZ3pacHtaKEoAzyRitiseBAV");

// ── ACCOUNT DEFINITIONS ───────────────────────────────────────────────────────

#[account]
#[derive(Default)]
pub struct VerifiedComputeReceipt {
    pub agent: Pubkey,            // 32
    pub image_id: [u8; 32],       // 32
    pub journal_digest: [u8; 32], // 32 — SHA-256 of raw journal bytes
    pub claim_digest: [u8; 32],   // 32 — reconstructed from public_inputs[2..3]
    pub proposal_id: [u8; 32],    // 32
    pub position: u8,             // 1  — 0=PASS 1=FAIL
    pub slot: u64,                // 8
    pub is_settled: bool,         // 1
    pub proof_type: u8,           // 1  — 0=ZK_ARITHMETIC (v1 only writes 0)
    pub receipt_hash: [u8; 32],   // 32
}

impl VerifiedComputeReceipt {
    // 8 discriminator + fields
    pub const LEN: usize = 8 + 32 + 32 + 32 + 32 + 32 + 1 + 8 + 1 + 1 + 32;
}

// ── ERRORS ────────────────────────────────────────────────────────────────────

#[error_code]
pub enum SigilError {
    #[msg("Image ID does not match SIGIL_V1_IMAGE_ID")]
    InvalidImageId,
    #[msg("Position must be 0 (PASS) or 1 (FAIL)")]
    InvalidPosition,
    #[msg("Groth16 proof verification failed")]
    ProofVerificationFailed,
    #[msg("Journal contents do not match expected values")]
    JournalMismatch,
    #[msg("Failed to decode journal bytes")]
    JournalDecodeFailed,
    #[msg("Only the original agent can perform this action")]
    UnauthorizedAgent,
    #[msg("Receipt has already been settled")]
    AlreadySettled,
    #[msg("Receipt has not yet been settled")]
    NotYetSettled,
}

// ── INSTRUCTION CONTEXTS ──────────────────────────────────────────────────────

#[derive(Accounts)]
#[instruction(
    proposal_id: [u8; 32],
)]
pub struct IssueVerifiedReceipt<'info> {
    #[account(mut)]
    pub agent: Signer<'info>,

    #[account(
        init,
        payer = agent,
        space = VerifiedComputeReceipt::LEN,
        seeds = [
            b"sigil",
            b"v1" as &[u8],
            b"receipt",
            agent.key().as_ref(),
            proposal_id.as_ref(),
        ],
        bump,
    )]
    pub receipt: Account<'info, VerifiedComputeReceipt>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct MarkSettled<'info> {
    pub agent: Signer<'info>,

    #[account(
        mut,
        constraint = receipt.agent == agent.key() @ SigilError::UnauthorizedAgent,
        constraint = !receipt.is_settled @ SigilError::AlreadySettled,
    )]
    pub receipt: Account<'info, VerifiedComputeReceipt>,
}

#[derive(Accounts)]
pub struct CloseReceipt<'info> {
    #[account(mut)]
    pub agent: Signer<'info>,

    #[account(
        mut,
        close = agent,
        constraint = receipt.agent == agent.key() @ SigilError::UnauthorizedAgent,
        constraint = receipt.is_settled @ SigilError::NotYetSettled,
    )]
    pub receipt: Account<'info, VerifiedComputeReceipt>,
}

// ── PROGRAM ───────────────────────────────────────────────────────────────────

#[program]
pub mod sigil {
    use super::*;

    // ── issue_verified_receipt ────────────────────────────────────────────────
    //
    // RISC Zero Groth16 public input layout (5 × BN254 field elements):
    //   public_inputs[0] — low  128 bits of control_root
    //   public_inputs[1] — high 128 bits of control_root
    //   public_inputs[2] — low  128 bits of claim_digest
    //   public_inputs[3] — high 128 bits of claim_digest
    //   public_inputs[4] — BN254 identity control ID
    //
    // The claim_digest commits to the image ID and journal contents.
    // Journal bytes are decoded on-chain to verify semantic fields
    // (agent, proposal_id, position) match the instruction arguments.
    //
    pub fn issue_verified_receipt(
        ctx: Context<IssueVerifiedReceipt>,
        proposal_id: [u8; 32],
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        public_inputs: [[u8; 32]; 5],
        image_id: [u8; 32],
        journal_bytes: Vec<u8>,
        position: u8,
    ) -> Result<()> {

        // Check 1 — image ID must match canonical constant
        let expected_image_id = image_id_to_bytes(&SIGIL_V1_IMAGE_ID);
        require!(image_id == expected_image_id, SigilError::InvalidImageId);

        // Check 2 — position must be 0 or 1
        require!(position <= 1, SigilError::InvalidPosition);

        // Check 3 — Groth16 proof must verify
        //
        // groth16-solana expects proof_a to be the negated G1 point (-A),
        // but risc0's seal provides the non-negated A. Negate on-chain.
        let proof_a_neg = negate_g1_be(&proof_a);

        let vk = Groth16Verifyingkey {
            nr_pubinputs: 5,
            vk_alpha_g1: VK_ALPHA_G1,
            vk_beta_g2: VK_BETA_G2,
            vk_gamme_g2: VK_GAMMA_G2,
            vk_delta_g2: VK_DELTA_G2,
            vk_ic: &VK_IC,
        };

        let mut verifier = Groth16Verifier::new(
            &proof_a_neg,
            &proof_b,
            &proof_c,
            &public_inputs,
            &vk,
        ).map_err(|_| SigilError::ProofVerificationFailed)?;

        verifier.verify()
            .map_err(|_| SigilError::ProofVerificationFailed)?;

        // Check 4 — decode and verify journal contents
        //
        // risc0 env::commit() serializes ScoringOutput using risc0's custom
        // word-aligned format: each u8 is stored as a u32 LE word (4 bytes),
        // u32 values are stored as u32 LE words.
        //
        // ScoringOutput layout in journal:
        //   agent_pubkey: [u8; 32] → 32 × 4 = 128 bytes
        //   proposal_id:  [u8; 32] → 32 × 4 = 128 bytes
        //   position:     u8       → 1 × 4  = 4 bytes
        //   score:        u32      → 1 × 4  = 4 bytes
        //   Total:                            264 bytes
        let (journal_agent, journal_proposal, journal_position, _journal_score) =
            decode_scoring_journal(&journal_bytes)
                .ok_or(SigilError::JournalDecodeFailed)?;

        // Check 4a — journal agent must match transaction signer
        require!(
            journal_agent == ctx.accounts.agent.key().to_bytes(),
            SigilError::JournalMismatch
        );

        // Check 4b — journal proposal must match instruction arg
        require!(
            journal_proposal == proposal_id,
            SigilError::JournalMismatch
        );

        // Check 4c — journal position must match instruction arg
        require!(
            journal_position == position,
            SigilError::JournalMismatch
        );

        // Compute journal digest (SHA-256 of raw journal bytes)
        let journal_digest = hashv(&[&journal_bytes]).to_bytes();

        // Reconstruct claim_digest from public_inputs[2..3]
        let claim_digest = reconstruct_digest(&public_inputs[2], &public_inputs[3]);

        // All checks passed — write receipt
        let receipt = &mut ctx.accounts.receipt;
        let clock = Clock::get()?;

        receipt.agent = ctx.accounts.agent.key();
        receipt.image_id = image_id;
        receipt.journal_digest = journal_digest;
        receipt.claim_digest = claim_digest;
        receipt.proposal_id = proposal_id;
        receipt.position = position;
        receipt.slot = clock.slot;
        receipt.is_settled = false;
        receipt.proof_type = 0; // ZK_ARITHMETIC — only value in v1

        // Compute receipt integrity hash
        let receipt_hash = compute_receipt_hash(receipt);
        receipt.receipt_hash = receipt_hash;

        msg!(
            "Sigil v1: receipt issued for proposal {:?}, position {}",
            proposal_id,
            position
        );

        Ok(())
    }

    // ── mark_settled ──────────────────────────────────────────────────────────
    pub fn mark_settled(ctx: Context<MarkSettled>) -> Result<()> {
        // Constraints already enforced by account constraints:
        // - agent == receipt.agent
        // - !receipt.is_settled
        ctx.accounts.receipt.is_settled = true;

        msg!("Sigil v1: receipt marked settled");
        Ok(())
    }

    // ── close_receipt ─────────────────────────────────────────────────────────
    pub fn close_receipt(_ctx: Context<CloseReceipt>) -> Result<()> {
        // Constraints already enforced:
        // - agent == receipt.agent
        // - receipt.is_settled
        // Anchor handles rent reclaim via close = agent
        msg!("Sigil v1: receipt closed, rent reclaimed");
        Ok(())
    }
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

/// Negate a BN254 G1 point (big-endian) by computing -y = Fq - y.
///
/// groth16-solana's pairing equation uses e(-A, B), so proof_a must be negated.
/// risc0's Groth16 seal provides the non-negated A point.
///
/// BN254 base field (Fq) modulus:
/// 0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47
fn negate_g1_be(point: &[u8; 64]) -> [u8; 64] {
    const FQ: [u8; 32] = [
        0x30, 0x64, 0x4e, 0x72, 0xe1, 0x31, 0xa0, 0x29,
        0xb8, 0x50, 0x45, 0xb6, 0x81, 0x81, 0x58, 0x5d,
        0x97, 0x81, 0x6a, 0x91, 0x68, 0x71, 0xca, 0x8d,
        0x3c, 0x20, 0x8c, 0x16, 0xd8, 0x7c, 0xfd, 0x47,
    ];

    let mut result = [0u8; 64];
    result[..32].copy_from_slice(&point[..32]); // x unchanged

    // Check if y is zero (point at infinity)
    if point[32..64].iter().all(|&b| b == 0) {
        return result;
    }

    // Compute Fq - y with big-endian borrow chain
    let mut borrow: u16 = 0;
    for i in (0..32).rev() {
        let sub = (FQ[i] as u16).wrapping_sub(point[32 + i] as u16).wrapping_sub(borrow);
        result[32 + i] = sub as u8;
        borrow = if sub > 0xFF { 1 } else { 0 };
    }

    result
}

fn image_id_to_bytes(id: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in id.iter().enumerate() {
        let bytes = word.to_le_bytes();
        out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    out
}

/// Decode ScoringOutput from risc0 journal bytes.
///
/// risc0 env::commit() uses a custom word-aligned serialization:
/// each u8 occupies a full u32 LE word (4 bytes), u32 values occupy one u32 LE word.
///
/// Returns (agent_pubkey, proposal_id, position, score).
fn decode_scoring_journal(data: &[u8]) -> Option<([u8; 32], [u8; 32], u8, u32)> {
    const EXPECTED_LEN: usize = 32 * 4 + 32 * 4 + 4 + 4; // 264 bytes
    if data.len() < EXPECTED_LEN {
        return None;
    }

    let mut agent = [0u8; 32];
    for i in 0..32 {
        agent[i] = data[i * 4]; // low byte of each u32 LE word
    }

    let mut proposal = [0u8; 32];
    for i in 0..32 {
        proposal[i] = data[128 + i * 4]; // offset 128 = 32 * 4
    }

    let position = data[256]; // offset 256 = 128 + 128
    let score = u32::from_le_bytes([data[260], data[261], data[262], data[263]]);

    Some((agent, proposal, position, score))
}

/// Reconstruct a 32-byte digest from two split public input halves.
///
/// risc0 splits digests into two BN254 field elements (128 bits each, big-endian,
/// zero-padded to 32 bytes). pi_low contains the low 128 bits at bytes [16..32],
/// pi_high contains the high 128 bits at bytes [16..32].
fn reconstruct_digest(pi_low: &[u8; 32], pi_high: &[u8; 32]) -> [u8; 32] {
    let mut digest = [0u8; 32];
    digest[0..16].copy_from_slice(&pi_high[16..32]); // high 128 bits
    digest[16..32].copy_from_slice(&pi_low[16..32]); // low 128 bits
    digest // big-endian representation
}

fn compute_receipt_hash(receipt: &VerifiedComputeReceipt) -> [u8; 32] {
    let result = hashv(&[
        receipt.agent.as_ref(),
        &receipt.image_id,
        &receipt.journal_digest,
        &receipt.claim_digest,
        &receipt.proposal_id,
        &[receipt.position],
        &receipt.slot.to_le_bytes(),
        &[receipt.proof_type],
    ]);
    result.to_bytes()
}
