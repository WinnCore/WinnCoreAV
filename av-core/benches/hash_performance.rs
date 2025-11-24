use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use sha2::{Digest, Sha512};

fn bench_sha512(c: &mut Criterion) {
    let data = vec![0u8; 1024 * 1024]; // 1 MiB
    let mut group = c.benchmark_group("hash_performance");
    group.throughput(Throughput::Bytes(data.len() as u64));
    group.bench_function("sha512_1mb", |b| {
        b.iter(|| {
            let mut hasher = Sha512::new();
            hasher.update(black_box(&data));
            black_box(hasher.finalize());
        });
    });
    group.finish();
}

criterion_group!(benches, bench_sha512);
criterion_main!(benches);
