import { Connection, PublicKey } from "@solana/web3.js";
import { createHash } from "crypto";

const AUTOCRAT_PROGRAM_ID = new PublicKey("meta3cxKzFBmWYgCVozmvCQAS3y9b3fGxrG9HkHL7Wi");

export interface MetaDAOProposal {
  id: Buffer;
  pubkey: string;
  descriptionUrl: string;
  title: string;
  proposalType: string;
  description: string;
}

function extractUrl(data: Buffer): string | null {
  const str = data.toString("latin1");
  const match = str.match(/https?:\/\/[\x21-\x7E]{10,}/);
  if (!match) return null;
  return match[0].replace(/[^\x20-\x7E]/g, "").trim();
}

function proposalIdFromPubkey(pubkey: PublicKey): Buffer {
  return Buffer.from(pubkey.toBytes());
}

export async function fetchMetaDAOProposals(rpcUrl: string): Promise<MetaDAOProposal[]> {
  const connection = new Connection(rpcUrl, "confirmed");
  const accounts = await connection.getProgramAccounts(AUTOCRAT_PROGRAM_ID);

  const proposals: MetaDAOProposal[] = [];

  for (const { pubkey, account } of accounts) {
    if (account.data.length < 200) continue;

    const url = extractUrl(account.data);
    if (!url) continue;

    let title = "Unknown Proposal";
    let description = "";
    let proposalType = "Generic";

    try {
      const res = await fetch(url.replace("?view", ""), {
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(5000),
      });
      if (res.ok) {
        const text = await res.text();
        const titleMatch = text.match(/<title>([^<]+)<\/title>/);
        if (titleMatch) title = titleMatch[1].replace(" - HackMD", "").trim();
        description = text.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").slice(0, 500);
        if (/treasury|spend|fund|usdc|sol/i.test(description)) proposalType = "TreasurySpend";
        else if (/parameter|config|setting|threshold/i.test(description)) proposalType = "ParameterChange";
        else if (/upgrade|deploy|program/i.test(description)) proposalType = "ProgramUpgrade";
      }
    } catch {
      title = `Proposal ${pubkey.toBase58().slice(0, 8)}`;
      description = `See: ${url}`;
    }

    proposals.push({
      id: proposalIdFromPubkey(pubkey),
      pubkey: pubkey.toBase58(),
      descriptionUrl: url,
      title,
      proposalType,
      description,
    });
  }

  return proposals;
}
