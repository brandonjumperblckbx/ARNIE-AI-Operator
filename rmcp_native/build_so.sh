#!/usr/bin/env bash
# Build the RMCP native shared library for the Python binding (ctypes).
# Produces librmcp_native.so next to rmcp_native.py.
set -euo pipefail

CXX="${CXX:-g++}"
echo "Building librmcp_native.so with ${CXX} ..."
${CXX} -std=c++20 -O2 -Wall -Wextra -fPIC -shared -pthread \
    rmcp_policy_core.cpp rmcp_cluster_watch.cpp rmcp_capi.cpp \
    -o librmcp_native.so
echo "  -> librmcp_native.so"
echo "Done. The Python binding (rmcp_native.py) will load it automatically."
