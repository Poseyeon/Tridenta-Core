use serde::Serialize;

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct WhereClause {
    pub column: String,
    pub operator: String,
    pub value: String,
}

#[derive(Debug, PartialEq)]
pub enum Command {
    CreateDatabase {
        name: String,
        username: String,
        password: String,
    },
    Login {
        username: String,
        password: String,
    },
    CreateTable {
        name: String,
        columns: Vec<Column>,
    },
    Insert {
        table: String,
        values: Vec<String>,
    },
    Select {
        table: String,
        columns: Vec<String>,
        where_clause: Option<WhereClause>,
    },
    Update {
        table: String,
        set_column: String,
        set_value: String,
        where_clause: Option<WhereClause>,
    },
    Truncate {
        table: String,
    },
    Get {
        table: String,
        format: String,
    },
    ShowTables,
    InspectTable {
        name: String,
    },
    Unknown(String),
}

#[derive(Debug, PartialEq, Clone, Serialize)]
pub struct Column {
    pub name: String,
    pub data_type: String,
}

pub struct Parser {}

impl Parser {
    pub fn new() -> Self {
        Parser {}
    }

    pub fn parse(&self, input: &str) -> Command {
        let input = input.trim();
        let input_upper = input.to_uppercase();

        if input_upper.starts_with("CREATE DATABASE") {
            self.parse_create_database(input)
        } else if input_upper.starts_with("LOGIN USER") {
            self.parse_login(input)
        } else if input_upper.starts_with("CREATE TABLE") {
            self.parse_create_table(input)
        } else if input_upper.starts_with("INSERT INTO") {
            self.parse_insert(input)
        } else if input_upper.starts_with("SELECT") {
            self.parse_select(input)
        } else if input_upper.starts_with("UPDATE") {
            self.parse_update(input)
        } else if input_upper.starts_with("TRUNCATE TABLE") {
            self.parse_truncate(input)
        } else if input_upper.starts_with("GET") {
            self.parse_get(input)
        } else if input_upper.starts_with("SHOW TABLES") {
            Command::ShowTables
        } else if input_upper.starts_with("INSPECT") {
            self.parse_inspect(input)
        } else {
            Command::Unknown(input.to_string())
        }
    }

    /// Parses a simple WHERE clause with operators =, !=, <, >, <=, >=, LIKE, and NOT LIKE.
    fn parse_where_clause(&self, where_str: &str) -> Option<WhereClause> {
        let where_upper = where_str.to_uppercase();
        let operator_str;
        let operator_len;

        if where_upper.contains("NOT LIKE") {
            operator_str = "NOT LIKE";
            operator_len = 8;
        } else if where_upper.contains("LIKE") {
            operator_str = "LIKE";
            operator_len = 4;
        } else if where_upper.contains("<=") {
            operator_str = "<=";
            operator_len = 2;
        } else if where_upper.contains(">=") {
            operator_str = ">=";
            operator_len = 2;
        } else if where_upper.contains("!=") {
            operator_str = "!=";
            operator_len = 2;
        } else if where_upper.contains('<') {
            operator_str = "<";
            operator_len = 1;
        } else if where_upper.contains('>') {
            operator_str = ">";
            operator_len = 1;
        } else if where_upper.contains('=') {
            operator_str = "=";
            operator_len = 1;
        } else {
            return None; // No supported operator found
        };

        if let Some(op_pos) = where_upper.find(operator_str) {
            let column = where_str[..op_pos].trim().to_string();
            let value = where_str[op_pos + operator_len..].trim().trim_matches('"').trim_matches('\'').to_string();
            Some(WhereClause {
                column,
                operator: operator_str.to_string(),
                value,
            })
        } else {
            None // Should not happen if we found the operator string
        }
    }

    fn parse_create_table(&self, input: &str) -> Command {
        // Format: CREATE TABLE name (col1 TYPE, col2 TYPE)
        let input_upper = input.to_uppercase();
        let rest = match input_upper.strip_prefix("CREATE TABLE") {
            Some(r) => r.trim(),
            None => return Command::Unknown(input.to_string()),
        };

        // Find the opening parenthesis
        let parts: Vec<&str> = rest.splitn(2, '(').collect();
        if parts.len() != 2 {
            return Command::Unknown(input.to_string());
        }

        let table_name = parts[0].trim().to_string();
        let columns_str = parts[1].trim_end_matches(')').trim();

        // Parse columns: "col1 TYPE, col2 TYPE"
        let columns: Vec<Column> = columns_str
            .split(',')
            .filter_map(|col| {
                let parts: Vec<&str> = col.trim().split_whitespace().collect();
                if parts.len() >= 2 {
                    Some(Column {
                        name: parts[0].to_string(),
                        data_type: parts[1].to_uppercase(),
                    })
                } else if parts.len() == 1 && !parts[0].is_empty() {
                    // Default to TEXT if no type specified
                    Some(Column {
                        name: parts[0].to_string(),
                        data_type: "TEXT".to_string(),
                    })
                } else {
                    None
                }
            })
            .collect();

        Command::CreateTable {
            name: table_name,
            columns,
        }
    }

    fn parse_create_database(&self, input: &str) -> Command {
        let compact = input
            .trim()
            .trim_end_matches(';')
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        let upper = compact.to_uppercase();

        let db_prefix = "CREATE DATABASE ";
        let user_marker = " WITH USER ";
        let pass_marker = " SET PASSWORD ";

        if !upper.starts_with(db_prefix.trim_end()) {
            return Command::Unknown(input.to_string());
        }

        let rest = compact[db_prefix.len()..].trim();
        let rest_upper = rest.to_uppercase();

        let user_pos = match rest_upper.find(user_marker) {
            Some(pos) => pos,
            None => return Command::Unknown(input.to_string()),
        };

        let database_name = rest[..user_pos].trim().to_string();
        if database_name.is_empty() {
            return Command::Unknown(input.to_string());
        }

        let after_user = &rest[user_pos + user_marker.len()..];
        let after_user_upper = after_user.to_uppercase();

        let pass_pos = match after_user_upper.find(pass_marker) {
            Some(pos) => pos,
            None => return Command::Unknown(input.to_string()),
        };

        let username = after_user[..pass_pos].trim().to_string();
        let password = after_user[pass_pos + pass_marker.len()..]
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();

        if username.is_empty() || password.is_empty() {
            return Command::Unknown(input.to_string());
        }

        Command::CreateDatabase {
            name: database_name,
            username,
            password,
        }
    }

    fn parse_login(&self, input: &str) -> Command {
        let compact = input
            .trim()
            .trim_end_matches(';')
            .split_whitespace()
            .collect::<Vec<&str>>()
            .join(" ");
        let upper = compact.to_uppercase();
        let prefix = "LOGIN USER ";
        let pass_marker = " SET PASSWORD ";

        if !upper.starts_with(prefix.trim_end()) {
            return Command::Unknown(input.to_string());
        }

        let rest = compact[prefix.len()..].trim();
        let rest_upper = rest.to_uppercase();
        let pass_pos = match rest_upper.find(pass_marker) {
            Some(pos) => pos,
            None => return Command::Unknown(input.to_string()),
        };

        let username = rest[..pass_pos].trim().to_string();
        let password = rest[pass_pos + pass_marker.len()..]
            .trim()
            .trim_matches('"')
            .trim_matches('\'')
            .to_string();

        if username.is_empty() || password.is_empty() {
            return Command::Unknown(input.to_string());
        }

        Command::Login { username, password }
    }

    fn parse_insert(&self, input: &str) -> Command {
        // Format: INSERT INTO table VALUES (val1, val2)
        let input_upper = input.to_uppercase();
        if !input_upper.starts_with("INSERT INTO") {
            return Command::Unknown(input.to_string());
        }

        let after_insert = &input[11..].trim_start(); // Skip "INSERT INTO" (11 chars)
        let values_pos_original = match after_insert.to_uppercase().find("VALUES") {
            Some(pos) => pos,
            None => return Command::Unknown(input.to_string()),
        };
        
        let table_name = after_insert[..values_pos_original].trim().to_string();
        let values_str = after_insert[values_pos_original + 6..].trim().trim_start_matches('(').trim_end_matches(')');

        let values: Vec<String> = values_str
            .split(',')
            .map(|v| v.trim().trim_matches('"').trim_matches('"').to_string())
            .collect();

        Command::Insert {
            table: table_name,
            values,
        }
    }

    fn parse_select(&self, input: &str) -> Command {
        // Format: SELECT col1, col2 FROM table WHERE col = val
        let input_upper = input.to_uppercase();
        let after_select = &input[6..].trim_start(); // Skip "SELECT "
        let after_select_upper = &input_upper[6..].trim_start();

        let from_pos = match after_select_upper.find("FROM ") {
            Some(pos) => pos,
            None => return Command::Unknown(input.to_string()),
        };

        let columns_str = after_select[..from_pos].trim();
        let after_from = &after_select[from_pos + 5..].trim_start(); // Skip "FROM "
        let after_from_upper = &after_select_upper[from_pos + 5..].trim_start();

        let where_pos = after_from_upper.find("WHERE ");

        let (table_name, where_clause) = if let Some(pos) = where_pos {
            let table_part = &after_from[..pos].trim();
            let where_part = &after_from[pos + 6..].trim(); // Skip "WHERE "
            (table_part.to_string(), self.parse_where_clause(where_part))
        } else {
            (after_from.to_string(), None)
        };

        let columns: Vec<String> = if columns_str == "*" {
            vec!["*".to_string()]
        } else {
            columns_str
                .split(',')
                .map(|c| c.trim().to_string())
                .collect()
        };

        Command::Select {
            table: table_name,
            columns,
            where_clause,
        }
    }

    fn parse_update(&self, input: &str) -> Command {
        // Format: UPDATE table SET col = val WHERE other_col = other_val
        let input_upper = input.to_uppercase();
    
        let set_pos = match input_upper.find(" SET ") {
            Some(pos) => pos,
            None => return Command::Unknown(input.to_string()),
        };
    
        // "UPDATE ".len() is 7
        let table_name = input[7..set_pos].trim().to_string();
        // " SET ".len() is 5
        let after_set = &input[set_pos + 5..];
        let after_set_upper = &input_upper[set_pos + 5..];
    
        let where_pos = after_set_upper.find(" WHERE ");
    
        let (set_part, where_clause) = if let Some(pos) = where_pos {
            // " WHERE ".len() is 7
            let where_part_str = &after_set[pos + 7..].trim();
            (
                after_set[..pos].trim(),
                self.parse_where_clause(where_part_str),
            )
        } else {
            (after_set.trim(), None)
        };
    
        // Parse SET part: "col = val"
        let set_parts: Vec<&str> = set_part.split('=').map(|s| s.trim()).collect();
        if set_parts.len() != 2 {
            return Command::Unknown(format!("Invalid SET clause: {}", set_part));
        }
        let set_column = set_parts[0].to_string();
        let set_value = set_parts[1].trim_matches('"').trim_matches('"').to_string();
    
        Command::Update {
            table: table_name,
            set_column,
            set_value,
            where_clause,
        }
    }

    fn parse_truncate(&self, input: &str) -> Command {
        // Format: TRUNCATE TABLE table_name
        let input_upper = input.to_uppercase();
        let rest = match input_upper.strip_prefix("TRUNCATE TABLE") {
            Some(r) => r.trim(),
            None => return Command::Unknown(input.to_string()),
        };

        if rest.is_empty() {
            return Command::Unknown(input.to_string());
        }

        Command::Truncate {
            table: rest.to_string(),
        }
    }

    fn parse_get(&self, input: &str) -> Command {
        // Format: GET <tablename> AS JSON
        let input_upper = input.to_uppercase();
        let rest = match input_upper.strip_prefix("GET") {
            Some(r) => r.trim(),
            None => return Command::Unknown(input.to_string()),
        };

        let parts: Vec<&str> = rest.split(" AS ").collect();
        if parts.len() != 2 {
            return Command::Unknown(input.to_string());
        }

        let table_name = parts[0].trim().to_string();
        let format = parts[1].trim().to_string();

        if format.to_uppercase() == "JSON" {
            Command::Get {
                table: table_name,
                format,
            }
        } else {
            Command::Unknown(format!("Unsupported format: {}", format))
        }
    }

    fn parse_inspect(&self, input: &str) -> Command {
        let input_upper = input.to_uppercase();
        let rest = match input_upper.strip_prefix("INSPECT") {
            Some(r) => r.trim(),
            None => return Command::Unknown(input.to_string()),
        };

        if rest.is_empty() {
            return Command::Unknown(input.to_string());
        }

        Command::InspectTable {
            name: rest.to_string(),
        }
    }
}