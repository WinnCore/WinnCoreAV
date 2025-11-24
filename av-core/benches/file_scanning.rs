use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::fs;

fn bench_file_scan(c: &mut Criterion) {
    let files: Vec<_> = fs::read_dir("/usr/bin")
        .unwrap_or_else(|_| panic!("bench requires /usr/bin corpus"))
        .filter_map(|e| e.ok())
        .take(200)
        .map(|e| e.path())
        .collect();

    let mut group = c.benchmark_group("file_scanning");
    group.throughput(Throughput::Elements(files.len() as u64));
    group.bench_function("scan_200_files_read_head", |b| {
        b.iter(|| {
            for f in &files {
                let _ = black_box(fs::read(f).unwrap());
            }
        });
    });
    group.finish();
}

criterion_group!(benches, bench_file_scan);
criterion_main!(benches);
