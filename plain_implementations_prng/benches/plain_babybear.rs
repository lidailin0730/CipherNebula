use zkhash::{
    fields::{babybear::FpBabyBear},
    poseidon::{poseidon::Poseidon, poseidon_instance_babybear::{
        POSEIDON_BABYBEAR_16_PARAMS,
        POSEIDON_BABYBEAR_24_PARAMS,
    }},
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_babybear::{
        POSEIDON2_BABYBEAR_16_PARAMS,
        POSEIDON2_BABYBEAR_24_PARAMS,
    }},
    neptune::{neptune::Neptune, neptune_instances::{
        NEPTUNE_BABYBEAR_16_PARAMS,
        NEPTUNE_BABYBEAR_24_PARAMS,
    }},
    gmimc::{gmimc::Gmimc, gmimc_instance_babybear::{
        GMIMC_BABYBEAR_16_PARAMS,
        GMIMC_BABYBEAR_24_PARAMS,
    }},
    // poseidon::{poseidon::Poseidon, poseidon_instance_babybear::POSEIDON_BABYBEAR_PARAMS},
    // poseidon2::{poseidon2::Poseidon2, poseidon2_instance_babybear::POSEIDON2_BABYBEAR_PARAMS},
    // neptune::{neptune::Neptune, neptune_instances::NEPTUNE_BABYBEAR_PARAMS},
    // gmimc::{gmimc::Gmimc, gmimc_instance_babybear::GMIMC_BABYBEAR_PARAMS},
};
type Scalar = FpBabyBear;
// use ark_ff::UniformRand;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn poseidon_babybear(c: &mut Criterion) {
    let instances = vec![
        Poseidon::new(&POSEIDON_BABYBEAR_16_PARAMS),
        Poseidon::new(&POSEIDON_BABYBEAR_24_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
        c.bench_function(format!("Poseidon BabyBear plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn poseidon2_babybear(c: &mut Criterion) {
    let instances = vec![
        Poseidon2::new(&POSEIDON2_BABYBEAR_16_PARAMS),
        Poseidon2::new(&POSEIDON2_BABYBEAR_24_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("Poseidon2 BabyBear plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn neptune_babybear(c: &mut Criterion) {
    let instances = vec![
        Neptune::new(&NEPTUNE_BABYBEAR_16_PARAMS),
        Neptune::new(&NEPTUNE_BABYBEAR_24_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("Neptune BabyBear plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn gmimc_babybear(c: &mut Criterion) {
    let instances = vec![
        Gmimc::new(&GMIMC_BABYBEAR_16_PARAMS),
        Gmimc::new(&GMIMC_BABYBEAR_24_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("GMiMC BabyBear plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation_not_opt(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn gmimc_opt_babybear(c: &mut Criterion) {
    let instances = vec![
        Gmimc::new(&GMIMC_BABYBEAR_16_PARAMS),
        Gmimc::new(&GMIMC_BABYBEAR_24_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("GMiMC (opt) BabyBear plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn criterion_benchmark_plain_babybear(c: &mut Criterion) {
    poseidon_babybear(c);
    poseidon2_babybear(c);
    neptune_babybear(c);
    gmimc_babybear(c);
    gmimc_opt_babybear(c);
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_plain_babybear
);
criterion_main!(benches);
