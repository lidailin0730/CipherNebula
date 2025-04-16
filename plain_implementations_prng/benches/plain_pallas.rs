#[allow(unused_imports)]
use zkhash::{
    fields::{pallas::FpPallas},
    neptune::{neptune::Neptune, neptune_instances::{
        NEPTUNE_PALLAS_4_PARAMS,
        NEPTUNE_PALLAS_8_PARAMS,
    }},
    gmimc::{gmimc::Gmimc, gmimc_instance_pallas::{
        GMIMC_PALLAS_3_PARAMS,
        GMIMC_PALLAS_4_PARAMS,
        GMIMC_PALLAS_8_PARAMS,
    }},
    poseidon::{poseidon::Poseidon, poseidon_instance_pallas::{
        POSEIDON_PALLAS_3_PARAMS,
        POSEIDON_PALLAS_4_PARAMS,
        POSEIDON_PALLAS_8_PARAMS,
    }},
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_pallas::{
        POSEIDON2_PALLAS_3_PARAMS,
        POSEIDON2_PALLAS_4_PARAMS,
        POSEIDON2_PALLAS_8_PARAMS,
    }},
};
type Scalar = FpPallas;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn poseidon(c: &mut Criterion) {
    let instances = vec![
        Poseidon::new(&POSEIDON_PALLAS_3_PARAMS),
        Poseidon::new(&POSEIDON_PALLAS_4_PARAMS),
        Poseidon::new(&POSEIDON_PALLAS_8_PARAMS)
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();
        c.bench_function(format!("Poseidon Pallas plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn poseidon2(c: &mut Criterion) {
    let instances = vec![
        Poseidon2::new(&POSEIDON2_PALLAS_3_PARAMS),
        Poseidon2::new(&POSEIDON2_PALLAS_4_PARAMS),
        Poseidon2::new(&POSEIDON2_PALLAS_8_PARAMS)
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("Poseidon2 Pallas plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn gmimc(c: &mut Criterion) {
    let instances = vec![
        Gmimc::new(&GMIMC_PALLAS_3_PARAMS),
        Gmimc::new(&GMIMC_PALLAS_4_PARAMS),
        Gmimc::new(&GMIMC_PALLAS_8_PARAMS)
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("GMiMC Pallas plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation_not_opt(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn gmimc_opt(c: &mut Criterion) {
    let instances = vec![
        Gmimc::new(&GMIMC_PALLAS_3_PARAMS),
        Gmimc::new(&GMIMC_PALLAS_4_PARAMS),
        Gmimc::new(&GMIMC_PALLAS_8_PARAMS)
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("GMiMC (opt) Pallas plain (t = {})", t).as_str(), move |bench| {
            bench.iter(|| {
                let perm = instance.permutation(black_box(&input));
                black_box(perm)
            });
        });
    }
}

fn neptune(c: &mut Criterion) {
    let instances = vec![
        Neptune::new(&NEPTUNE_PALLAS_4_PARAMS),
        Neptune::new(&NEPTUNE_PALLAS_8_PARAMS),
    ];
    for instance in instances {
        let t = instance.get_t();
        let input: Vec<Scalar> = (0..t).map(|i| Scalar::from(i as u64)).collect();

        c.bench_function(format!("Neptune Pallas plain (t = {})", t).as_str(), move |bench| {
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
