import { Connection, PublicKey } from "@solana/web3.js";

const AUTOCRAT_PROGRAM_ID = new PublicKey("meta3cxKzFBmWYgCVozmvCQAS3y9b3fGxrG9HkHL7Wi");
const RPC = "https://api.mainnet-beta.solana.com";

function extractUrl(data: Buffer): string | null {
  const str = data.toString("utf8");
  const match = str.match(/https?:\/\/[^\x00-\x1F\x7F-\xFF\s]{10,}/);
  return match ? match[0] : null;
}

async function main() {
  const connection = new Connection(RPC, "confirmed");
  const accounts = await connection.getProgramAccounts(AUTOCRAT_PROGRAM_ID);
  console.log(`Found ${accounts.length} proposal accounts\n`);

  for (const { pubkey, account } of accounts) {
    const url = extractUrl(account.data);
    if (url) {
      console.log("Pubkey:", pubkey.toBase58());
      console.log("Description URL:", url);
      console.log("Data size:", account.data.length);
      console.log();
    }
  }
}

main().catch(console.error);
