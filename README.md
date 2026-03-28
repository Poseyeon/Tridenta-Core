# TridentaDB

## Folder Structure

```yaml
TridentaDB
├─ src/
│   ├─ engine.rs
│   ├─ main.rs
│   ├─ parser.rs
│   ├─ storage.rs
│   └─ wal.rs
├─ target/
├─ .gitignore
├─ Cargo.lock
├─ Cargo.toml
├─ data.db
├─ data.wal
└─ README.md
```

## Build and Run

To build the project type this in your terminal

```bash
cargo build
```

To run the project type this in your terminal:

```bash
# CLI
cargo run --bin tridenta_db_cli

# Server
cargo run --bin tridenta_db_server

# GUI
npm run tauri dev
```

To run the GUI run this:

```bash
npm run tauri dev
```