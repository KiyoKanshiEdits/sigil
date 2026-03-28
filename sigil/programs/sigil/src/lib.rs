use anchor_lang::prelude::*;

declare_id!("9Jnn4EvBvxfhixwVwbjxaZ3pacHtaKEoAzyRitiseBAV");

#[program]
pub mod sigil {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        msg!("Greetings from: {:?}", ctx.program_id);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize {}
