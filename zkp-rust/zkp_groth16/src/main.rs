
mod groth16;
mod KZG_Plonk;

use color_eyre::Result;
use groth16::groth16_proof;
use KZG_Plonk::KZG_plonk;

#[tokio::main]
async fn main() -> Result<()>{
    color_eyre::install()?;
    groth16_proof().await?;
    KZG_plonk().await?;
    Ok(())
}
