use zkhash::{
    fields::{bn256::FpBN256},
    poseidon::{poseidon::Poseidon, poseidon_instance_bn256::POSEIDON_BN_PARAMS},
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS},
    gmimc::{gmimc::Gmimc, gmimc_instance_bn256::GMIMC_BN_3_PARAMS},
};
type Scalar = FpBN256;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn poseidon_bn256(c: &mut Criterion) {
    let poseidon = Poseidon::new(&POSEIDON_BN_PARAMS);
    let t = poseidon.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

    c.bench_function("Poseidon BN256 plain (t = 3)", move |bench| {
        bench.iter(|| {
            let perm = poseidon.permutation(black_box(&input));
            black_box(perm)
        });
    });
}

fn poseidon2_bn256(c: &mut Criterion) {
    let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS);
    let t = poseidon2.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

    c.bench_function("Poseidon2 BN256 plain (t = 3)", move |bench| {
        bench.iter(|| {
            let perm = poseidon2.permutation(black_box(&input));
            black_box(perm)
        });
    });
}

fn gmimc_bn256(c: &mut Criterion) {
    let gmimc = Gmimc::new(&GMIMC_BN_3_PARAMS);
    let t = gmimc.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

    c.bench_function("GMiMC BN256 plain (t = 3)", move |bench| {
        bench.iter(|| {
            let perm = gmimc.permutation_not_opt(black_box(&input));
            black_box(perm)
        });
    });
}

fn gmimc_opt_bn256(c: &mut Criterion) {
    let gmimc = Gmimc::new(&GMIMC_BN_3_PARAMS);
    let t = gmimc.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

    c.bench_function("GMiMC (opt) BN256 plain (t = 3)", move |bench| {
        bench.iter(|| {
            let perm = gmimc.permutation(black_box(&input));
            black_box(perm)
        });
    });
}

fn criterion_benchmark_plain_bn256(c: &mut Criterion) {
    poseidon_bn256(c);
    poseidon2_bn256(c);
    gmimc_bn256(c);
    gmimc_opt_bn256(c);
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_plain_bn256
);
criterion_main!(benches);
