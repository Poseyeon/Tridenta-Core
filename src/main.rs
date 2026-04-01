// src/main.rs

use std::io::{self, Write};
// The CLI now uses the library crate for all core logic.
use rust_dbms::{
    parser::Parser,
    engine::QueryEngine,
    execute_line,
};

fn main() {
    println!("TridentaDB v0.1.0");
    println!("Type 'help' for commands, 'exit' to quit\n");

    // Engine during auth is only needed for execute_line's signature; CREATE DATABASE / LOGIN
    // open files themselves. A pre-auth engine often points at data.db, while setup switches
    // the active DB to e.g. my_app.db — we must rebuild the engine after auth so the REPL uses
    // the same file as tridenta_active.bin.
    let mut query_engine = QueryEngine::new();
    let parser = Parser::new();
    if !authenticate_cli(&mut query_engine, &parser) {
        return;
    }
    query_engine = QueryEngine::new();

    // The REPL loop is now much simpler.
    loop {
        print!("tridenta> ");
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            println!("Error reading input");
            continue;
        }

        let input = input.trim();

        // Handle process-specific commands like 'exit' or 'quit'.
        // The `execute_line` function does not handle these, as it's stateless.
        match input.to_lowercase().as_str() {
            "exit" | "quit" => {
                println!("Goodbye!");
                break;
            }
            _ => {
                // All other commands are passed to the centralized execution function.
                let result = execute_line(input, &mut query_engine, &parser);
                if !result.is_empty() {
                    println!("{}", result);
                }
            }
        }
    }
}

fn authenticate_cli(query_engine: &mut QueryEngine, parser: &Parser) -> bool {
    loop {
        println!("Authentication required.");
        println!("1) Initial setup (create database)");
        println!("2) Login");
        println!("3) Exit");

        let choice = prompt("Select an option [1/2/3]: ");
        let ok = match choice.trim() {
            "1" => setup_flow(query_engine, parser),
            "2" => login_flow(query_engine, parser),
            "3" => return false,
            _ => {
                println!("Invalid option.");
                false
            }
        };

        if ok {
            return true;
        }
    }
}

fn setup_flow(query_engine: &mut QueryEngine, parser: &Parser) -> bool {
    let db_name = prompt("Database name: ");
    let username = prompt("Username: ");
    let password = prompt("Password: ");

    let sql = format!(
        "CREATE DATABASE {}\nWITH USER {}\nSET PASSWORD {};",
        db_name.trim(),
        username.trim(),
        password.trim()
    );
    let result = execute_line(&sql, query_engine, parser);
    println!("{}", result);
    result.to_lowercase().contains("created successfully")
}

fn login_flow(query_engine: &mut QueryEngine, parser: &Parser) -> bool {
    let username = prompt("Username: ");
    let password = prompt("Password: ");
    let sql = format!(
        "LOGIN USER {} SET PASSWORD {};",
        username.trim(),
        password.trim()
    );
    let result = execute_line(&sql, query_engine, parser);
    println!("{}", result);
    result.eq_ignore_ascii_case("Login successful")
}

fn prompt(label: &str) -> String {
    print!("{}", label);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    if io::stdin().read_line(&mut input).is_err() {
        return String::new();
    }
    input.trim().to_string()
}