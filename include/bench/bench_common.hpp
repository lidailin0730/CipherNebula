#pragma once
#include <algorithm>
#include <benchmark/benchmark.h>
#include <chrono>
#include <vector>

// Benchmark Rescue Prime hash and its components, using google-benchmark
namespace bench_rphash {

// Alias for casting duration to second level granularity, used for manual
// timing using chrono high resolution clock
using seconds_t = std::chrono::duration<double>;
// Alias for casting duration to nanosecond level granularity, used for timing
// minimum, median and maximum execution times
using nano_t = std::chrono::nanoseconds;

}
