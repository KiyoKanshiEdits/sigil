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
    pub agent: Pubkey,           // 32
    pub image_id: [u8; 32],      // 32
    pub input_hash: [u8; 32],    // 32
    pub output_hash: [u8; 32],   // 32
    pub journal_hash: [u8; 32],  // 32
    pub proposal_id: [u8; 32],   // 32
    pub position: u8,            // 1  — 0=PASS 1=FAIL
    pub slot: u64,               // 8
    pub is_settled: bool,        // 1
    pub proof_type: u8,          // 1  — 0=ZK_ARITHMETIC (v1 only writes 0)
    pub receipt_hash: [u8; 32],  // 32
}

impl VerifiedComputeReceipt {
    // 8 discriminator + fields
    pub const LEN: usize = 8 + 32 + 32 + 32 + 32 + 32 + 32 + 1 + 8 + 1 + 1 + 32;
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
    #[msg("Journal hash does not match public inputs commitment")]
    JournalMismatch,
    #[msg("Output hash is inconsistent with position")]
    OutputMismatch,
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
    // Public input slot layout (Groth16, 5 inputs):
    //   public_inputs[0] — journal hash commitment
    //   public_inputs[1] — input hash (committed inputs to scoring function)
    //   public_inputs[2] — agent pubkey (first 32 bytes)
    //   public_inputs[3] — proposal ID
    //   public_inputs[4] — image ID commitment
    //
    pub fn issue_verified_receipt(
        ctx: Context<IssueVerifiedReceipt>,
        proposal_id: [u8; 32],
        proof_a: [u8; 64],
        proof_b: [u8; 128],
        proof_c: [u8; 64],
        public_inputs: [[u8; 32]; 5],
        image_id: [u8; 32],
        input_hash: [u8; 32],
        output_hash: [u8; 32],
        journal_hash: [u8; 32],
        position: u8,
    ) -> Result<()> {

        // Check 1 — image ID must match canonical constant
        let expected_image_id = image_id_to_bytes(&SIGIL_V1_IMAGE_ID);
        require!(image_id == expected_image_id, SigilError::InvalidImageId);

        // Check 2 — position must be 0 or 1
        require!(position <= 1, SigilError::InvalidPosition);

        // Check 3 — Groth16 proof must verify
        let vk = Groth16Verifyingkey {
            nr_pubinputs: 5,
            vk_alpha_g1: VK_ALPHA_G1,
            vk_beta_g2: VK_BETA_G2,
            vk_gamme_g2: VK_GAMMA_G2,
            vk_delta_g2: VK_DELTA_G2,
            vk_ic: &VK_IC,
        };

        let mut verifier = Groth16Verifier::new(
            &proof_a,
            &proof_b,
            &proof_c,
            &public_inputs,
            &vk,
        ).map_err(|_| SigilError::ProofVerificationFailed)?;

        verifier.verify()
            .map_err(|_| SigilError::ProofVerificationFailed)?;

        // Check 4 — journal hash must match public inputs commitment
        // public_inputs[0] contains the journal hash commitment
        require!(
            journal_hash == public_inputs[0],
            SigilError::JournalMismatch
        );

        // Check 4b — input hash must match public inputs commitment
        // public_inputs[1] contains the input hash (ZK-attested, not agent-supplied)
        require!(
            input_hash == public_inputs[1],
            SigilError::JournalMismatch
        );

        // Check 5 — output hash must be consistent with position
        // We derive expected output hash from position and verify it matches
        let expected_output = derive_output_hash(&position, &proposal_id);
        require!(output_hash == expected_output, SigilError::OutputMismatch);

        // All checks passed — write receipt
        let receipt = &mut ctx.accounts.receipt;
        let clock = Clock::get()?;

        receipt.agent = ctx.accounts.agent.key();
        receipt.image_id = image_id;
        receipt.input_hash = input_hash;
        receipt.output_hash = output_hash;
        receipt.journal_hash = journal_hash;
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

fn image_id_to_bytes(id: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, word) in id.iter().enumerate() {
        let bytes = word.to_le_bytes();
        out[i * 4..(i + 1) * 4].copy_from_slice(&bytes);
    }
    out
}

fn derive_output_hash(position: &u8, proposal_id: &[u8; 32]) -> [u8; 32] {
    let pos_bytes = [*position];
    let result = hashv(&[b"sigil_output_v1", pos_bytes.as_ref(), proposal_id.as_ref()]);
    result.to_bytes()
}

fn compute_receipt_hash(receipt: &VerifiedComputeReceipt) -> [u8; 32] {
    let result = hashv(&[
        receipt.agent.as_ref(),
        &receipt.image_id,
        &receipt.input_hash,
        &receipt.output_hash,
        &receipt.journal_hash,
        &receipt.proposal_id,
        &[receipt.position],
        &receipt.slot.to_le_bytes(),
        &[receipt.proof_type],
    ]);
    result.to_bytes()
}
