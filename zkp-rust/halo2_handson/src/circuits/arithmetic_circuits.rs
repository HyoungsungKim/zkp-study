use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{Circuit, ConstraintSystem, Error},
    poly::Rotation,
};
use group::ff::Field;

#[derive(Default, Clone)]
pub struct MultiplyChainCircuit<F: Field> {
    pub c1: Value<F>,
    pub c2: Value<F>,
    pub c3: Value<F>,
    pub c4: Value<F>,
    pub c5: Value<F>,
    pub c6: Value<F>,
    pub c7: Value<F>,
    pub c8: Value<F>,
    pub c9: Value<F>,
}

#[derive(Clone)]
pub struct MulChainConfig {
   a: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
   b: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
   c: halo2_proofs::plonk::Column<halo2_proofs::plonk::Advice>,
   s_mul: halo2_proofs::plonk::Selector,
}

impl <F: Field> Circuit<F> for MultiplyChainCircuit<F> {
    type Config = MulChainConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let s_mul = meta.selector();

        meta.create_gate("mul", |meta| {
            let a_exp = meta.query_advice(a, Rotation::cur());
            let b_exp = meta.query_advice(b, Rotation::cur());
            let c_exp = meta.query_advice(c, Rotation::cur());
            let s_mul_exp = meta.query_selector(s_mul);
            vec![(a_exp * b_exp - c_exp)*s_mul_exp]
        });
        MulChainConfig { a, b, c, s_mul }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "mul",
            |mut region| {

            // Gate1: c1 * c2 = c7 (정확)
            config.s_mul.enable(&mut region, 0)?;
            region.assign_advice(|| "a", config.a, 0, || self.c1)?;
            region.assign_advice(|| "b", config.b, 0, || self.c2)?;
            region.assign_advice(|| "c", config.c, 0, || self.c7)?;

            // Gate2: c7 * (c3 + c4) = c8
            config.s_mul.enable(&mut region, 1)?;
            region.assign_advice(|| "a", config.a, 1, || self.c7)?; 
            region.assign_advice(|| "b", config.b, 1, || self.c3 + self.c4)?;  
            region.assign_advice(|| "c", config.c, 1, || self.c8)?;  

            // Gate3: c8 * (c5 + c6) = c9
            config.s_mul.enable(&mut region, 2)?;
            region.assign_advice(|| "a", config.a, 2, || self.c3 + self.c4)?; 
            region.assign_advice(|| "b", config.b, 2, || self.c5 + self.c6)?;  
            region.assign_advice(|| "c", config.c, 2, || self.c9)?;

            Ok(())
            },
        )   
    }
}