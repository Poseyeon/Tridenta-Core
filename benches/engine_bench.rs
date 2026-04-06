use criterion::{criterion_group, criterion_main, Criterion};
use rust_dbms::engine::QueryEngine;
use rust_dbms::parser::Column;

fn bench_insert(c: &mut Criterion) {
    let db_name = "bench_insert.db";
    // Ensure clean state
    let _ = std::fs::remove_file(db_name);
    
    let mut engine = QueryEngine::with_database(db_name);
    
    // Setup
    let _ = engine.execute_create_table(
        "users".to_string(),
        vec![
            Column { name: "id".to_string(), data_type: "INTEGER".to_string() },
            Column { name: "name".to_string(), data_type: "TEXT".to_string() },
        ],
    );

    let mut group = c.benchmark_group("Engine_Insert");
    group.bench_function("insert_single_row", |b| {
        let mut i = 0;
        b.iter(|| {
            i += 1;
            engine.execute_insert(
                "users".to_string(),
                vec![i.to_string(), format!("User{}", i)],
            ).unwrap();
        });
    });
    group.finish();

    // Cleanup
    let _ = std::fs::remove_file(db_name);
}

fn bench_select(c: &mut Criterion) {
    let db_name = "bench_select.db";
    // Ensure clean state
    let _ = std::fs::remove_file(db_name);
    
    let mut engine = QueryEngine::with_database(db_name);
    
    // Setup
    let _ = engine.execute_create_table(
        "users".to_string(),
        vec![
            Column { name: "id".to_string(), data_type: "INTEGER".to_string() },
            Column { name: "name".to_string(), data_type: "TEXT".to_string() },
        ],
    );

    for i in 0..100 {
        engine.execute_insert(
            "users".to_string(),
            vec![i.to_string(), format!("User{}", i)],
        ).unwrap();
    }

    let mut group = c.benchmark_group("Engine_Select");
    group.bench_function("select_all_100_rows", |b| {
        b.iter(|| {
            engine.execute_select(
                "users".to_string(),
                vec!["*".to_string()],
                None,
            ).unwrap();
        });
    });
    group.finish();

    // Cleanup
    let _ = std::fs::remove_file(db_name);
}

criterion_group!(benches, bench_insert, bench_select);
criterion_main!(benches);
