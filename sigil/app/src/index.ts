import * as anchor from "@coral-xyz/anchor";
import { Connection, Keypair, PublicKey, SystemProgram } from "@solana/web3.js";
import { execSync } from "child_process";
import { createHash } from "crypto";
import * as fs from "fs";
import * as path from "path";
import dotenv from "dotenv";

dotenv.config();

// ── CONFIG ────────────────────────────────────────────────────────────────────

const PROGRAM_ID = new PublicKey("9Jnn4EvBvxfhixwVwbjxaZ3pacHtaKEoAzyRitiseBAV");
const RPC_URL = process.env.RPC_URL || "http://127.0.0.1:8899";
const AGENT_KEYPAIR_PATH = process.env.AGENT_KEYPAIR || `${process.env.HOME}/.config/solana/id.json`;
const SCORING_FUNCTION_PATH = process.env.SCORING_FUNCTION_PATH || path.join(__dirname, "../../scoring-function");

// ── TYPES ─────────────────────────────────────────────────────────────────────

interface Proposal {
  id: Buffer;           // 32 bytes
  title: string;
  proposalType: string;
  requestedAmount?: number;
  description: string;
}

interface ProofOutput {
  proofA: number[];
  proofB: number[];
  proofC: number[];
  publicInputs: number[][];
  journalBytes: Buffer;
  position: number;
  score: number;
}

// ── HELPERS ───────────────────────────────────────────────────────────────────

function loadKeypair(filepath: string): Keypair {
  const raw = JSON.parse(fs.readFileSync(filepath, "utf8"));
  return Keypair.fromSecretKey(Uint8Array.from(raw));
}

function sha256(data: Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

function getReceiptPda(programId: PublicKey, agentKey: PublicKey, proposalId: Buffer): [PublicKey, number] {
  return PublicKey.findProgramAddressSync(
    [
      Buffer.from("sigil"),
      Buffer.from("v1"),
      Buffer.from("receipt"),
      agentKey.toBuffer(),
      proposalId,
    ],
    programId
  );
}

// ── PROOF GENERATION ──────────────────────────────────────────────────────────

function generateProof(proposal: Proposal, agentPubkey: PublicKey): ProofOutput {
  console.log(`  Generating ZK proof for proposal: ${proposal.title}`);

  // Write proposal input to temp file for the host binary
  const inputPath = "/tmp/sigil-proposal-input.json";
  const input = {
    agent_pubkey: Array.from(agentPubkey.toBuffer()),
    proposal_id: Array.from(proposal.id),
    proposal_type: proposal.proposalType,
    requested_amount: proposal.requestedAmount || 0,
    description: proposal.description,
  };
  fs.writeFileSync(inputPath, JSON.stringify(input));

  // Run the RISC Zero host binary
  const hostBinary = path.join(SCORING_FUNCTION_PATH, "target/release/host");
  const result = execSync(`${hostBinary} ${inputPath}`, {
    cwd: SCORING_FUNCTION_PATH,
    timeout: 300000, // 5 min max for proof generation
  }).toString();

  // Parse proof output from host binary stdout
  const output = JSON.parse(result);

  return {
    proofA: output.proof_a,
    proofB: output.proof_b,
    proofC: output.proof_c,
    publicInputs: output.public_inputs,
    journalBytes: Buffer.from(output.journal_bytes),
    position: output.position,
    score: output.score,
  };
}

// ── SUBMIT RECEIPT ────────────────────────────────────────────────────────────

async function submitReceipt(
  program: anchor.Program,
  agent: Keypair,
  proposal: Proposal,
  proof: ProofOutput
): Promise<string> {
  const [receipt] = getReceiptPda(PROGRAM_ID, agent.publicKey, proposal.id);

  // Check if receipt already exists
  const existing = await program.provider.connection.getAccountInfo(receipt);
  if (existing) {
    console.log(`  Receipt already exists for proposal ${proposal.title} — skipping`);
    return "already-exists";
  }

  const imageId = getImageId();

  const tx = await (program.methods as any)
    .issueVerifiedReceipt(
      Array.from(proposal.id),
      proof.proofA,
      proof.proofB,
      proof.proofC,
      proof.publicInputs,
      imageId,
      proof.journalBytes,
      proof.position
    )
    .accounts({
      agent: agent.publicKey,
      receipt,
      systemProgram: SystemProgram.programId,
    })
    .signers([agent])
    .rpc();

  return tx;
}

// ── IMAGE ID ──────────────────────────────────────────────────────────────────

function getImageId(): number[] {
  // SIGIL_V1_IMAGE_ID — matches hardcoded constant in programs/sigil/src/constants.rs
  const buf = Buffer.alloc(32);
  const words = [357791285, 2944447908, 1179490828, 357895610, 3805270980, 138964069, 3709529647, 1803849831];
  words.forEach((w, i) => buf.writeUInt32LE(w, i * 4));
  return Array.from(buf);
}

// ── MOCK PROPOSALS (replace with live feed later) ─────────────────────────────

function getMockProposals(): Proposal[] {
  return [
    {
      id: Buffer.alloc(32, 1),
      title: "Treasury Spend: Developer Grants Q2",
      proposalType: "TreasurySpend",
      requestedAmount: 50000,
      description: "Allocate 50,000 USDC for developer grants in Q2 2026",
    },
    {
      id: Buffer.alloc(32, 2),
      title: "Parameter Change: Reduce voting period",
      proposalType: "ParameterChange",
      description: "Reduce voting period from 7 days to 5 days",
    },
  ];
}

// ── MAIN LOOP ─────────────────────────────────────────────────────────────────

async function main() {
  console.log("Sigil Agent starting...");
  console.log(`RPC: ${RPC_URL}`);

  // Load keypair and set up provider
  const agent = loadKeypair(AGENT_KEYPAIR_PATH);
  console.log(`Agent pubkey: ${agent.publicKey.toBase58()}`);

  const connection = new Connection(RPC_URL, "confirmed");
  const wallet = new anchor.Wallet(agent);
  const provider = new anchor.AnchorProvider(connection, wallet, {
    commitment: "confirmed",
  });
  anchor.setProvider(provider);

  // Load IDL
  const idlPath = path.join(__dirname, "../../target/idl/sigil.json");
  const idl = JSON.parse(fs.readFileSync(idlPath, "utf8"));
  const program = new anchor.Program(idl as any, provider);

  console.log(`Program ID: ${PROGRAM_ID.toBase58()}`);
  console.log("Ready. Processing proposals...\n");

  // Get proposals (mock for now — replace with live MetaDAO feed)
  const proposals = getMockProposals();

  for (const proposal of proposals) {
    console.log(`Processing: ${proposal.title}`);

    try {
      // Generate ZK proof
      const proof = generateProof(proposal, agent.publicKey);
      console.log(`  Score: ${proof.score}, Position: ${proof.position === 0 ? "PASS" : "FAIL"}`);

      // Submit on-chain
      const tx = await submitReceipt(program, agent, proposal, proof);
      if (tx !== "already-exists") {
        console.log(`  Receipt issued: ${tx}`);
      }
    } catch (err: any) {
      console.error(`  Error processing ${proposal.title}: ${err.message}`);
    }

    console.log();
  }

  console.log("Done.");
}

main().catch(console.error);
