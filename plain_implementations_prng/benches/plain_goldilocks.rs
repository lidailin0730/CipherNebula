use zkhash::{
    fields::{goldilocks::FpGoldiLocks},
    poseidon::{poseidon::Poseidon, poseidon_instance_goldilocks::{
        POSEIDON_GOLDILOCKS_8_PARAMS,
        POSEIDON_GOLDILOCKS_12_PARAMS,
        POSEIDON_GOLDILOCKS_16_PARAMS,
        POSEIDON_GOLDILOCKS_20_PARAMS,
    }},
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_goldilocks::{
        POSEIDON2_GOLDILOCKS_8_PARAMS,
        POSEIDON2_GOLDILOCKS_12_PARAMS,
        POSEIDON2_GOLDILOCKS_16_PARAMS,
        POSEIDON2_GOLDILOCKS_20_PARAMS,
    }},
    neptune::{neptune::Neptune, neptune_instances::{
        NEPTUNE_GOLDILOCKS_8_PARAMS,
        NEPTUNE_GOLDILOCKS_12_PARAMS,
        NEPTUNE_GOLDILOCKS_16_PARAMS,
        NEPTUNE_GOLDILOCKS_20_PARAMS,
    }},
    gmimc::{gmimc::Gmimc, gmimc_instance_goldilocks::{
        GMIMC_GOLDILOCKS_8_PARAMS,
        GMIMC_GOLDILOCKS_12_PARAMS,
        GMIMC_GOLDILOCKS_16_PARAMS,
        GMIMC_GOLDILOCKS_20_PARAMS,
    }},
};
type Scalar = FpGoldiLocks;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn poseidon(c: &mut Criterion) {
    let instances = vec![
        Poseidon::new(&POSEIDON_GOLDILOCKS_8_PARAMS),
        Poseidon::new(&POSEIDON_GOLDILOCKS_12_PARAMS),
        Poseidon::new(&POSEIDON_GOLDILOCKS_16_PARAMS),
        Poseidon::new(&POSEIDON_GOLDILOCKS_20_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
        c.bench_function(format!("Poseidon Goldilocks plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn poseidon2(c: &mut Criterion) {
    let instances = vec![
        Poseidon2::new(&POSEIDON2_GOLDILOCKS_8_PARAMS),
        Poseidon2::new(&POSEIDON2_GOLDILOCKS_12_PARAMS),
        Poseidon2::new(&POSEIDON2_GOLDILOCKS_16_PARAMS),
        Poseidon2::new(&POSEIDON2_GOLDILOCKS_20_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
        c.bench_function(format!("Poseidon2 Goldilocks plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn neptune(c: &mut Criterion) {
    let instances = vec![
        Neptune::new(&NEPTUNE_GOLDILOCKS_8_PARAMS),
        Neptune::new(&NEPTUNE_GOLDILOCKS_12_PARAMS),
        Neptune::new(&NEPTUNE_GOLDILOCKS_16_PARAMS),
        Neptune::new(&NEPTUNE_GOLDILOCKS_20_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
        c.bench_function(format!("Neptune Goldilocks plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn gmimc(c: &mut Criterion) {
    let instances = vec![
        Gmimc::new(&GMIMC_GOLDILOCKS_8_PARAMS),
        Gmimc::new(&GMIMC_GOLDILOCKS_12_PARAMS),
        Gmimc::new(&GMIMC_GOLDILOCKS_16_PARAMS),
        Gmimc::new(&GMIMC_GOLDILOCKS_20_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
        c.bench_function(format!("GMiMC Goldilocks plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation_not_opt(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn gmimc_opt(c: &mut Criterion) {
    let instances = vec![
        Gmimc::new(&GMIMC_GOLDILOCKS_8_PARAMS),
        Gmimc::new(&GMIMC_GOLDILOCKS_12_PARAMS),
        Gmimc::new(&GMIMC_GOLDILOCKS_16_PARAMS),
        Gmimc::new(&GMIMC_GOLDILOCKS_20_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
        c.bench_function(format!("GMiMC (opt) Goldilocks plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn criterion_benchmark_plain(c: &mut Criterion) {
    poseidon(c);
    poseidon2(c);
    neptune(c);
    gmimc(c);
    gmimc_opt(c);
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_plain
);
criterion_main!(benches);
