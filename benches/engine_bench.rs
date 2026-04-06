use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rust_dbms::engine::QueryEngine;
use rust_dbms::parser::Column;
use std::time::Duration;

fn setup_db_with_rows(db_name: &str, num_rows: usize) -> QueryEngine {
    let _ = std::fs::remove_file(db_name);
    let mut engine = QueryEngine::with_database(db_name);
    
    let _ = engine.execute_create_table(
        "users".to_string(),
        vec![
            Column { name: "id".to_string(), data_type: "INTEGER".to_string() },
            Column { name: "name".to_string(), data_type: "TEXT".to_string() },
        ],
    );

    if num_rows > 0 {
        let mut bulk_data = Vec::with_capacity(num_rows);
        for i in 0..num_rows {
            bulk_data.push(vec![i.to_string(), format!("User{}", i)]);
        }
        engine.execute_insert_bulk("users".to_string(), bulk_data).unwrap();
    }
    
    engine
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("Engine_Insert");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    for size in [10_000, 100_000, 1_000_000].iter() {
        let db_name = format!("bench_insert_{}.db", size);
        let mut engine = setup_db_with_rows(&db_name, *size);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &_size| {
            let mut i = *size;
            b.iter(|| {
                i += 1;
                engine.execute_insert(
                    "users".to_string(),
                    vec![i.to_string(), format!("User{}", i)],
                ).unwrap();
            });
        });

        // Cleanup
        let _ = std::fs::remove_file(&db_name);
    }
    group.finish();
}

fn bench_select(c: &mut Criterion) {
    let mut group = c.benchmark_group("Engine_Select");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));

    for size in [10_000, 100_000, 1_000_000].iter() {
        let db_name = format!("bench_select_{}.db", size);
        let engine = setup_db_with_rows(&db_name, *size);

        group.bench_with_input(BenchmarkId::from_parameter(size), size, |b, &_size| {
            b.iter(|| {
                // Select query against the populated table
                engine.execute_select(
                    "users".to_string(),
                    vec!["*".to_string()],
                    None,
                ).unwrap();
            });
        });

        // Cleanup
        let _ = std::fs::remove_file(&db_name);
    }
    group.finish();
}

criterion_group!(benches, bench_insert, bench_select);
criterion_main!(benches);
