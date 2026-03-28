use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

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

fn treasury_health_score(spend_bps: u64) -> u32 {
    if spend_bps <= 200 { 90 }
    else if spend_bps <= 500 { 75 }
    else if spend_bps <= 1000 { 55 }
    else if spend_bps <= 2000 { 30 }
    else if spend_bps <= 4000 { 10 }
    else { 0 }
}

fn dilution_score(dilution_bps: u64) -> u32 {
    if dilution_bps <= 100 { 90 }
    else if dilution_bps <= 300 { 70 }
    else if dilution_bps <= 500 { 50 }
    else if dilution_bps <= 1000 { 25 }
    else { 5 }
}

fn market_signal_score(pass_twap: u64, fail_twap: u64) -> u32 {
    if fail_twap == 0 { return 55; }
    let spread_bps: i64 = if pass_twap >= fail_twap {
        let diff = pass_twap - fail_twap;
        ((diff as i128 * 10_000) / fail_twap as i128) as i64
    } else {
        let diff = fail_twap - pass_twap;
        -(((diff as i128 * 10_000) / fail_twap as i128) as i64)
    };
    if spread_bps >= 500 { 90 }
    else if spread_bps >= 200 { 75 }
    else if spread_bps >= 0 { 55 }
    else if spread_bps >= -200 { 40 }
    else if spread_bps >= -500 { 25 }
    else { 10 }
}

fn liquidity_score(liquidity_micro_usd: u64) -> u32 {
    let usd = liquidity_micro_usd / 1_000_000;
    if usd >= 100_000 { 85 }
    else if usd >= 50_000 { 70 }
    else if usd >= 20_000 { 55 }
    else if usd >= 10_000 { 40 }
    else { 25 }
}

fn timing_score(days_elapsed: u8) -> u32 {
    match days_elapsed {
        1 => 80,
        0 => 55,
        2 => 65,
        _ => 40,
    }
}

fn compute_score(input: &ScoringInput) -> u32 {
    let token_value = (input.treasury_token as u128
        * input.token_price_usd as u128
        / 1_000_000) as u64;
    let treasury_usd = input.treasury_usdc.saturating_add(token_value);
    let th = if treasury_usd == 0 { 0u32 } else {
        let spend_usd = input.proposed_usdc_spend.saturating_add(
            (input.proposed_token_issuance as u128
                * input.token_price_usd as u128
                / 1_000_000) as u64,
        );
        let bps = ((spend_usd as u128 * 10_000) / treasury_usd as u128) as u64;
        treasury_health_score(bps)
    };
    let di = if input.circulating_supply == 0 { 75u32 } else {
        let bps = ((input.proposed_token_issuance as u128 * 10_000)
            / input.circulating_supply as u128) as u64;
        dilution_score(bps)
    };
    let ms = market_signal_score(input.pass_twap, input.fail_twap);
    let ml = liquidity_score(input.market_liquidity_usd);
    let tm = timing_score(input.days_elapsed);
    let score_x100 = match input.proposal_type {
        ProposalType::TreasurySpend => th*35 + di*5 + ms*35 + ml*15 + tm*10,
        ProposalType::TokenIssuance => di*45 + ms*30 + ml*15 + tm*10,
        ProposalType::ParameterChange => ms*55 + ml*25 + tm*15 + th*5,
        ProposalType::LaunchpadGovernance => ms*50 + ml*20 + tm*15 + th*15,
    };
    score_x100 / 100
}

fn main() {
    let input: ScoringInput = env::read();
    let score = compute_score(&input);
    let position: u8 = if score > 50 { 0 } else { 1 };
    let output = ScoringOutput {
        agent_pubkey: input.agent_pubkey,
        proposal_id: input.proposal_id,
        position,
        score,
    };
    env::commit(&output);
}
