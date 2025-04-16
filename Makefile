CXX = g++
CXXFLAGS = -std=c++20 -Wall -Wextra -pedantic
OPTFLAGS = -O3 -march=native -mtune=native
IFLAGS = -I ./include
DUSE_AVX2 = -DUSE_AVX2=$(or $(AVX2),0)
DUSE_NEON = -DUSE_NEON=$(or $(NEON),0)

all: testing

test/a.out: test/main.cpp include/*.hpp include/test/*.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DUSE_AVX2) $(DUSE_NEON) $< -o $@

testing: test/a.out
	./$<

clean:
	find . -name '*.out' -o -name '*.o' -o -name '*.so' -o -name '*.gch' | xargs rm -rf

format:
	find . -name '*.hpp' -o -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla

bench/a.out: bench/main.cpp include/*.hpp include/bench/*.hpp
	# make sure you've google-benchmark globally installed;
	# see https://github.com/google/benchmark/tree/da652a7#installation
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $(DUSE_AVX2) $(DUSE_NEON) $< -lbenchmark -o $@

benchmark: bench/a.out
	./$< --benchmark_time_unit=ns --benchmark_counters_tabular=true
