use zkhash::{
    fields::{vesta::FpVesta},
    poseidon::{poseidon::Poseidon, poseidon_instance_vesta::POSEIDON_VESTA_PARAMS},
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_vesta::POSEIDON2_VESTA_PARAMS},
    gmimc::{gmimc::Gmimc, gmimc_instance_vesta::GMIMC_VESTA_3_PARAMS},
};
type Scalar = FpVesta;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn poseidon_vesta(c: &mut Criterion) {
    let poseidon = Poseidon::new(&POSEIDON_VESTA_PARAMS);
    let t = poseidon.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

    c.bench_function("Poseidon Vesta plain (t = 3)", move |bench| {
        bench.iter(|| {
            let perm = poseidon.permutation(black_box(&input));
            black_box(perm)
        });
    });
}

fn poseidon2_vesta(c: &mut Criterion) {
    let poseidon2 = Poseidon2::new(&POSEIDON2_VESTA_PARAMS);
    let t = poseidon2.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

    c.bench_function("Poseidon2 Vesta plain (t = 3)", move |bench| {
        bench.iter(|| {
            let perm = poseidon2.permutation(black_box(&input));
            black_box(perm)
        });
    });
}

fn gmimc_vesta(c: &mut Criterion) {
    let gmimc = Gmimc::new(&GMIMC_VESTA_3_PARAMS);
    let t = gmimc.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

    c.bench_function("GMiMC Vesta plain (t = 3)", move |bench| {
        bench.iter(|| {
            let perm = gmimc.permutation_not_opt(black_box(&input));
            black_box(perm)
        });
    });
}

fn gmimc_opt_vesta(c: &mut Criterion) {
    let gmimc = Gmimc::new(&GMIMC_VESTA_3_PARAMS);
    let t = gmimc.get_t();
    let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

    c.bench_function("GMiMC (opt) Vesta plain (t = 3)", move |bench| {
        bench.iter(|| {
            let perm = gmimc.permutation(black_box(&input));
            black_box(perm)
        });
    });
}

fn criterion_benchmark_plain_vesta(c: &mut Criterion) {
    poseidon_vesta(c);
    poseidon2_vesta(c);
    gmimc_vesta(c);
    gmimc_opt_vesta(c);
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_plain_vesta
);
criterion_main!(benches);
