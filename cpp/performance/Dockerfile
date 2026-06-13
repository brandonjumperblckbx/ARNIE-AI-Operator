FROM gcc:13 AS builder
WORKDIR /build
COPY . .
RUN mkdir -p build && cd build && \
    cmake .. -DCMAKE_BUILD_TYPE=Release && \
    make -j$(nproc)

FROM debian:bookworm-slim
COPY --from=builder /build/build/arnie_perf_service /usr/local/bin/
ENTRYPOINT ["arnie_perf_service"]
