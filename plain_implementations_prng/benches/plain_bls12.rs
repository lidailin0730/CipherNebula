use zkhash::{
    fields::{bls12::FpBLS12},
    neptune::{neptune::Neptune, neptune_instances::{
        NEPTUNE_BLS_4_PARAMS,
        NEPTUNE_BLS_8_PARAMS,
    }},
    gmimc::{gmimc::Gmimc, gmimc_instance_bls12::{
        GMIMC_BLS_2_PARAMS,
        GMIMC_BLS_3_PARAMS,
        GMIMC_BLS_4_PARAMS,
        GMIMC_BLS_8_PARAMS,
    }},
    poseidon::{poseidon::Poseidon, poseidon_instance_bls12::{
        POSEIDON_BLS_2_PARAMS,
        POSEIDON_BLS_3_PARAMS,
        POSEIDON_BLS_4_PARAMS,
        POSEIDON_BLS_8_PARAMS,
    }},
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bls12::{
        POSEIDON2_BLS_2_PARAMS,
        POSEIDON2_BLS_3_PARAMS,
        POSEIDON2_BLS_4_PARAMS,
        POSEIDON2_BLS_8_PARAMS,
    }},
};
type Scalar = FpBLS12;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn poseidon(c: &mut Criterion) {
    let instances = vec![
        Poseidon::new(&POSEIDON_BLS_2_PARAMS),
        Poseidon::new(&POSEIDON_BLS_3_PARAMS),
        Poseidon::new(&POSEIDON_BLS_4_PARAMS),
        Poseidon::new(&POSEIDON_BLS_8_PARAMS)
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
        c.bench_function(format!("Poseidon BLS12 plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn poseidon2(c: &mut Criterion) {
    let instances = vec![
        Poseidon2::new(&POSEIDON2_BLS_2_PARAMS),
        Poseidon2::new(&POSEIDON2_BLS_3_PARAMS),
        Poseidon2::new(&POSEIDON2_BLS_4_PARAMS),
        Poseidon2::new(&POSEIDON2_BLS_8_PARAMS)
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("Poseidon2 BLS12 plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn gmimc(c: &mut Criterion) {
    let instances = vec![
        Gmimc::new(&GMIMC_BLS_2_PARAMS),
        Gmimc::new(&GMIMC_BLS_3_PARAMS),
        Gmimc::new(&GMIMC_BLS_4_PARAMS),
        Gmimc::new(&GMIMC_BLS_8_PARAMS)
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("GMiMC BLS12 plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation_not_opt(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn gmimc_opt(c: &mut Criterion) {
    let instances = vec![
        Gmimc::new(&GMIMC_BLS_2_PARAMS),
        Gmimc::new(&GMIMC_BLS_3_PARAMS),
        Gmimc::new(&GMIMC_BLS_4_PARAMS),
        Gmimc::new(&GMIMC_BLS_8_PARAMS)
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("GMiMC (opt) BLS12 plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn neptune(c: &mut Criterion) {
    let instances = vec![
        Neptune::new(&NEPTUNE_BLS_4_PARAMS),
        Neptune::new(&NEPTUNE_BLS_8_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("Neptune BLS12 plain (t = {})", t).as_str(), move |bench| {
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
    gmimc(c);
    gmimc_opt(c);
    neptune(c);
}

criterion_group!(
    name = benches;
    config = Criterion::default();
    targets = criterion_benchmark_plain
);
criterion_main!(benches);
