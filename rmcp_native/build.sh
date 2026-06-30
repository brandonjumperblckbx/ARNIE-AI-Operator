#!/usr/bin/env bash
# ============================================================================
#  Build the RMCP native C++ module (policy core + cluster watch engine).
#  Part of ARNIE AI by BLCKBX. Built on the RMCP engine.
# ============================================================================
set -euo pipefail

CXX="${CXX:-g++}"
STD="-std=c++20"
OPT="-O2"
WARN="-Wall -Wextra"
THREADS="-pthread"

echo "Building RMCP native core with ${CXX} ..."

# Compile the core objects.
${CXX} ${STD} ${OPT} ${WARN} -c rmcp_policy_core.cpp   -o rmcp_policy_core.o
${CXX} ${STD} ${OPT} ${WARN} -c rmcp_cluster_watch.cpp -o rmcp_cluster_watch.o

# Static library other components (and the Python binding) can link against.
ar rcs librmcp_native.a rmcp_policy_core.o rmcp_cluster_watch.o
echo "  -> librmcp_native.a"

# Build the tests.
${CXX} ${STD} ${OPT} ${WARN} ${THREADS} rmcp_policy_core.cpp test_policy_core.cpp -o test_policy
${CXX} ${STD} ${OPT} ${WARN} ${THREADS} rmcp_policy_core.cpp rmcp_cluster_watch.cpp test_integration.cpp -o test_integration
echo "  -> test_policy, test_integration"

echo "Build complete. Run ./test_policy and ./test_integration to verify."
