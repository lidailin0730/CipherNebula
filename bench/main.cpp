#include "bench/bench_rescue_prime.hpp"
#include "benchmark/benchmark.h"

// Register for benchmarking Rescue permutation
BENCHMARK(bench_rphash::permutation)->UseManualTime();

// Register for benchmarking Rescue Prime element hasher
BENCHMARK(bench_rphash::hash)->Arg(4)->UseManualTime();
BENCHMARK(bench_rphash::hash)->Arg(8)->UseManualTime();
BENCHMARK(bench_rphash::hash)->Arg(16)->UseManualTime();
BENCHMARK(bench_rphash::hash)->Arg(32)->UseManualTime();
BENCHMARK(bench_rphash::hash)->Arg(64)->UseManualTime();
BENCHMARK(bench_rphash::hash)->Arg(128)->UseManualTime();

BENCHMARK_MAIN();