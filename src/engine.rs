use crate::parser::{Column, WhereClause};
use regex::Regex;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Table {
    pub name: String,
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Row {
    pub values: Vec<String>,
}

pub struct Catalog {
    tables: Vec<Table>,
}

impl Catalog {
    pub fn new() -> Self {
        Catalog {
            tables: Vec::new(),
        }
    }

    pub fn create_table(&mut self, name: String, columns: Vec<Column>) -> Result<(), String> {
        // Check if table already exists
        if self.tables.iter().any(|t| t.name == name) {
            return Err(format!("Table '{}' already exists", name));
        }

        let table = Table {
            name,
            columns,
            rows: Vec::new(),
        };
        self.tables.push(table);
        Ok(())
    }

    pub fn find_table_mut(&mut self, name: &str) -> Option<&mut Table> {
        self.tables.iter_mut().find(|t| t.name.to_lowercase() == name.to_lowercase())
    }

    pub fn find_table(&self, name: &str) -> Option<&Table> {
        self.tables.iter().find(|t| t.name.to_lowercase() == name.to_lowercase())
    }

    pub fn list_tables(&self) -> Vec<&str> {
        self.tables.iter().map(|t| t.name.as_str()).collect()
    }

    pub fn get_all_tables(&self) -> &Vec<Table> {
        &self.tables
    }

    pub fn load_tables(&mut self, tables: Vec<Table>) {
        for table in tables {
            if !self.tables.iter().any(|t| t.name == table.name) {
                self.tables.push(table);
            }
        }
    }
    
    pub fn add_table(&mut self, table: Table) {
        if !self.tables.iter().any(|t| t.name.to_lowercase() == table.name.to_lowercase()) {
            self.tables.push(table);
        }
    }
}

pub struct QueryEngine {
    catalog: Catalog,
    database: crate::database::Database,
}

impl QueryEngine {
    pub fn new() -> Self {
        let db_path = crate::database::resolve_active_database_path()
            .unwrap_or_else(|| "data.db".to_string());
        Self::with_database(&db_path)
    }

    pub fn with_database(path: &str) -> Self {
        let mut database = crate::database::Database::new(path)
            .expect("Failed to initialize database");
        
        let catalog = database.load_catalog()
            .unwrap_or_else(|e| {
                eprintln!("Warning: Failed to load catalog: {}. Starting with empty database.", e);
                Catalog::new()
            });

        QueryEngine {
            catalog,
            database,
        }
    }

    fn evaluate_condition(
        row_value: &str,
        operator: &str,
        clause_value: &str,
        column_type: &str,
    ) -> bool {
        if column_type == "INTEGER" {
            let row_val: Result<i64, _> = row_value.parse();
            let clause_val: Result<i64, _> = clause_value.parse();

            if let (Ok(row_val), Ok(clause_val)) = (row_val, clause_val) {
                match operator {
                    "=" => row_val == clause_val,
                    "!=" => row_val != clause_val,
                    ">" => row_val > clause_val,
                    "<" => row_val < clause_val,
                    ">=" => row_val >= clause_val,
                    "<=" => row_val <= clause_val,
                    _ => false,
                }
            } else {
                false // Could not parse one of the values as an integer
            }
        } else {
            // Default to TEXT comparison
            match operator {
                "=" => row_value.eq_ignore_ascii_case(clause_value),
                "!=" => !row_value.eq_ignore_ascii_case(clause_value),
                "LIKE" => {
                    let pattern = clause_value.replace('%', ".*").replace('_', ".");
                    let re = match Regex::new(&format!("(?i)^{}$", pattern)) {
                        Ok(re) => re,
                        Err(_) => return false, // Invalid regex pattern
                    };
                    re.is_match(row_value)
                }
                "NOT LIKE" => {
                    let pattern = clause_value.replace('%', ".*").replace('_', ".");
                    let re = match Regex::new(&format!("(?i)^{}$", pattern)) {
                        Ok(re) => re,
                        Err(_) => return false, // Invalid regex pattern
                    };
                    !re.is_match(row_value)
                }
                // GT, LT etc. for text are not part of this implementation
                _ => false,
            }
        }
    }

    pub fn execute_create_table(&mut self, name: String, columns: Vec<Column>) -> Result<(), String> {
        self.catalog.create_table(name.clone(), columns.clone())?;
        
        // Get the table we just created and save it to disk
        let table = self.catalog.find_table(&name)
            .ok_or_else(|| format!("Failed to find table '{}' after creation", name))?
            .clone();
        
        self.database.save_table(&table, true)?;
        Ok(())
    }

    pub fn execute_insert(&mut self, table: String, values: Vec<String>) -> Result<(), String> {
        let table_ref = self
            .catalog
            .find_table_mut(&table)
            .ok_or_else(|| format!("Table '{}' does not exist", table))?;

        // Validate column count
        if values.len() != table_ref.columns.len() {
            return Err(format!(
                "Column count mismatch: expected {}, got {}",
                table_ref.columns.len(),
                values.len()
            ));
        }

        table_ref.rows.push(Row { values });
        
        // Save updated table to disk
        let table_clone = table_ref.clone();
        self.database.update_table_data(&table_clone)?;
        Ok(())
    }

    pub fn execute_insert_bulk(&mut self, table: String, values_list: Vec<Vec<String>>) -> Result<(), String> {
        let table_ref = self
            .catalog
            .find_table_mut(&table)
            .ok_or_else(|| format!("Table '{}' does not exist", table))?;

        for values in values_list {
            if values.len() != table_ref.columns.len() {
                return Err(format!(
                    "Column count mismatch: expected {}, got {}",
                    table_ref.columns.len(),
                    values.len()
                ));
            }
            table_ref.rows.push(Row { values });
        }
        
        // Save updated table to disk
        let table_clone = table_ref.clone();
        self.database.update_table_data(&table_clone)?;
        Ok(())
    }

    pub fn execute_select(&self, table_name: String, columns: Vec<String>, where_clause: Option<WhereClause>) -> Result<(Vec<String>, Vec<Row>), String> {
        let table = self
            .catalog
            .find_table(&table_name)
            .ok_or_else(|| format!("Table '{}' does not exist", table_name))?;

        let mut rows = table.rows.clone();

        if let Some(clause) = where_clause {
            let column_index = table.columns.iter().position(|c| c.name.to_lowercase() == clause.column.to_lowercase());

            if let Some(index) = column_index {
                let column = &table.columns[index];
                rows = rows.into_iter().filter(|row| {
                    if let Some(value) = row.values.get(index) {
                        return Self::evaluate_condition(value, &clause.operator, &clause.value, &column.data_type);
                    }
                    false
                }).collect();
            } else {
                return Err(format!("Column '{}' not found in table '{}'", clause.column, table.name));
            }
        }

        let selected_columns;
        let final_rows;

        if columns.contains(&"*".to_string()) {
            selected_columns = table.columns.iter().map(|c| c.name.clone()).collect();
            final_rows = rows;
        } else {
            // Find indices for each requested column, returning a specific error for any not found.
            let mut column_indices = Vec::new();
            for col_name in &columns {
                match table.columns.iter().position(|c| c.name.to_lowercase() == col_name.to_lowercase()) {
                    Some(index) => column_indices.push(index),
                    None => return Err(format!("Column '{}' not found in table '{}'", col_name, table.name)),
                }
            }

            selected_columns = columns.clone();

            final_rows = rows.into_iter().map(|row| {
                let selected_values = column_indices.iter().map(|&index| {
                    row.values.get(index).cloned().unwrap_or_default()
                }).collect();
                Row { values: selected_values }
            }).collect();
        }

        Ok((selected_columns, final_rows))
    }

    pub fn execute_update(&mut self, table_name: String, set_clause: (String, String), where_clause: Option<WhereClause>) -> Result<usize, String> {
        let table = self
            .catalog
            .find_table_mut(&table_name)
            .ok_or_else(|| format!("Table '{}' does not exist", table_name))?;

        let (column_to_set, new_value) = set_clause;

        let column_to_set_index = table.columns.iter().position(|c| c.name.to_lowercase() == column_to_set.to_lowercase());

        let set_col_idx = match column_to_set_index {
            Some(index) => index,
            None => return Err(format!("Column '{}' not found in table '{}'", column_to_set, table.name)),
        };

        let mut updated_count = 0;

        // If there's a WHERE clause, filter by it. Otherwise, update all rows.
        if let Some(clause) = where_clause {
            let where_column_index = table.columns.iter().position(|c| c.name.to_lowercase() == clause.column.to_lowercase());

            if let Some(where_idx) = where_column_index {
                let column = table.columns[where_idx].clone();
                for row in table.rows.iter_mut() {
                    if let Some(value) = row.values.get(where_idx) {
                        if Self::evaluate_condition(value, &clause.operator, &clause.value, &column.data_type) {
                            if let Some(val_to_update) = row.values.get_mut(set_col_idx) {
                                *val_to_update = new_value.clone();
                                updated_count += 1;
                            }
                        }
                    }
                }
            } else {
                return Err(format!("Column '{}' not found in table '{}'", clause.column, table.name));
            }
        } else {
            // No WHERE clause, update all rows
            for row in table.rows.iter_mut() {
                if let Some(val_to_update) = row.values.get_mut(set_col_idx) {
                    *val_to_update = new_value.clone();
                    updated_count += 1;
                }
            }
        }
        
        let table_clone = table.clone();
        self.database.update_table_data(&table_clone)?;

        Ok(updated_count)
    }

    pub fn execute_truncate_table(&mut self, table_name: String) -> Result<(), String> {
        let table = self
            .catalog
            .find_table_mut(&table_name)
            .ok_or_else(|| format!("Table '{}' does not exist", table_name))?;

        table.rows.clear();
        
        let table_clone = table.clone();
        self.database.update_table_data(&table_clone)?;

        Ok(())
    }

    pub fn get_table_schema(&self, table: &str) -> Option<&Table> {
        self.catalog.find_table(table)
    }

    pub fn get_all_tables(&self) -> &Vec<Table> {
        self.catalog.get_all_tables()
    }
}