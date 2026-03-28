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

    // Initialize the query engine and parser from the library.
    let mut query_engine = QueryEngine::new();
    let parser = Parser::new();

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