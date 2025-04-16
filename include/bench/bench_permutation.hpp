#pragma once
#include "bench_common.hpp"
#include "permutation.hpp"

// Benchmark Rescue Prime hash and its components, using google-benchmark
namespace bench_rphash {

// Benchmark Rescue permutation
inline void
permutation(benchmark::State& state)
{
  alignas(32) ff::ff_t st[rescue::STATE_WIDTH];

  std::vector<uint64_t> durations;

  for (auto _ : state) {
    for (size_t i = 0; i < rescue::STATE_WIDTH; i++) {
      st[i] = ff::ff_t::random();
    }

    const auto t0 = std::chrono::high_resolution_clock::now();

    rescue::permute(st);
    benchmark::DoNotOptimize(st);
    benchmark::ClobberMemory();

    const auto t1 = std::chrono::high_resolution_clock::now();

    const auto sdur = std::chrono::duration_cast<seconds_t>(t1 - t0);
    const auto nsdur = std::chrono::duration_cast<nano_t>(t1 - t0);

    state.SetIterationTime(sdur.count());
    durations.push_back(nsdur.count());
  }

  state.SetItemsProcessed(static_cast<int64_t>(state.iterations()));

  const auto min_idx = std::min_element(durations.begin(), durations.end());
  const auto min = durations.at(std::distance(durations.begin(), min_idx));
  state.counters["min_exec_time (ns)"] = static_cast<double>(min);

  const auto max_idx = std::max_element(durations.begin(), durations.end());
  const auto max = durations.at(std::distance(durations.begin(), max_idx));
  state.counters["max_exec_time (ns)"] = static_cast<double>(max);

  const auto lenby2 = durations.size() / 2;
  const auto mid_idx = durations.begin() + lenby2;
  std::nth_element(durations.begin(), mid_idx, durations.end());
  const auto mid = durations[lenby2];
  state.counters["median_exec_time (ns)"] = static_cast<double>(mid);
}

}
