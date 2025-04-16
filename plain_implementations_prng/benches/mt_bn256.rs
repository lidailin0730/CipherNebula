use criterion::{black_box, criterion_group, criterion_main, Criterion};
use zkhash::{
    fields::{bn256::FpBN256},
    merkle_tree::merkle_tree_fp::MerkleTree,
    neptune::{neptune::Neptune, neptune_instances::NEPTUNE_BN_PARAMS},
    poseidon::{poseidon::Poseidon, poseidon_instance_bn256::POSEIDON_BN_PARAMS},
    poseidon2::{poseidon2::Poseidon2, poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS},
};
type Scalar = FpBN256;

fn sample_set(set_size: usize) -> Vec<Scalar> {
    (0..set_size).map(|i| Scalar::from(i as u64)).collect()
}

fn poseidon(c: &mut Criterion, log_set_size: usize) {
    let perm = Poseidon::new(&POSEIDON_BN_PARAMS);
    let mut mt = MerkleTree::new(perm);
    let set_size = 1 << log_set_size;
    let set: Vec<Scalar> = sample_set(set_size);

    let id = format!("Poseidon BN256 MT (set_size = 2^{})", log_set_size);

    c.bench_function(&id, move |bench| {
        bench.iter(|| {
            mt.accumulate(black_box(&set));
        });
    });
}

fn poseidon2(c: &mut Criterion, log_set_size: usize) {
    let perm = Poseidon2::new(&POSEIDON2_BN256_PARAMS);
    let mut mt = MerkleTree::new(perm);
    let set_size = 1 << log_set_size;
    let set: Vec<Scalar> = sample_set(set_size);

    let id = format!("Poseidon2 BN256 MT (set_size = 2^{})", log_set_size);

    c.bench_function(&id, move |bench| {
        bench.iter(|| {
            mt.accumulate(black_box(&set));
        });
    });
}

fn neptune(c: &mut Criterion, log_set_size: usize) {
    let perm = Neptune::new(&NEPTUNE_BN_PARAMS);
    let mut mt = MerkleTree::new(perm);
    let set_size = 1 << log_set_size;
    let set: Vec<Scalar> = sample_set(set_size);

    let id = format!("Neptune BN256 MT (set_size = 2^{})", log_set_size);

    c.bench_function(&id, move |bench| {
        bench.iter(|| {
            mt.accumulate(black_box(&set));
        });
    });
}

fn criterion_benchmark_mt_bn(c: &mut Criterion) {
    let log_set_sizes = vec![20];

    for log_set_size in log_set_sizes {
        poseidon(c, log_set_size);
        poseidon2(c, log_set_size);
        neptune(c, log_set_size);
    }
}

criterion_group!(
    name = benches;
    config = Criterion::default().sample_size(10);
    targets = criterion_benchmark_mt_bn
);
criterion_main!(benches);
