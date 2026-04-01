use crate::engine::{Catalog, Row, Table};
use crate::parser::Column;
use crate::storage::{Page, StorageEngine};
use std::fs;
use std::io::Read;

// Database file format constants
const MAGIC_NUMBER: u64 = 0x4953454E54414442; // "ISENTADB" in hex
/// v1 stored UTF-8 strings in plaintext in pages. v2 obfuscates all string payloads (binary).
const DB_VERSION: u32 = 2;
const HEADER_PAGE_ID: u64 = 0;

// Salt tags for deterministic XOR keystream seeds (not encryption — storage obfuscation).
const SALT_AUTH_DB_NAME: u32 = 0xA0_01;
const SALT_AUTH_USERNAME: u32 = 0xA0_02;
const SALT_AUTH_PASSWORD: u32 = 0xA0_03;
const SALT_SCHEMA_TABLE_NAME: u32 = 0xB0_01;
const SALT_SCHEMA_COL_NAME: u32 = 0xB0_02;
const SALT_SCHEMA_COL_TYPE: u32 = 0xB0_03;
const SALT_ROW_TEXT: u32 = 0xC0_00;

// Value type tags for binary encoding
const TYPE_NULL: u8 = 0;
const TYPE_INT: u8 = 1;
const TYPE_TEXT: u8 = 2;

// Header page layout (Page 0):
// Offset 0-7:   Magic number (u64)
// Offset 8-11:  Version (u32)
// Offset 12-19: Schema root page ID (u64)
// Offset 20-23: Number of tables (u32)
// Offset 24:    Auth initialized flag (u8: 0/1)
// Offset 25-28: Database name length (u32)
// Offset 29-92: Database name (max 64 bytes)
// Offset 93-96: Username length (u32)
// Offset 97-160: Username (max 64 bytes)
// Offset 161-164: Password length (u32)
// Offset 165-292: Password (max 128 bytes)

const ACTIVE_DB_FILE: &str = "tridenta_active.bin";
/// Legacy active-db pointer (UTF-8 path written in plaintext after header).
const ACTIVE_DB_MAGIC_V1: u32 = 0x54445241; // "TDRA"
/// v2: path bytes are XOR-obfuscated (not human-readable in a hex editor).
const ACTIVE_DB_MAGIC_V2: u32 = 0x54445242; // "TDRB"

fn active_path_seed() -> u64 {
    (ACTIVE_DB_MAGIC_V2 as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ (MAGIC_NUMBER ^ 0x5041_5448_5441_43)
}
const AUTH_FLAG_OFFSET: usize = 24;
const DB_NAME_LEN_OFFSET: usize = 25;
const DB_NAME_OFFSET: usize = 29;
const DB_NAME_MAX: usize = 64;
const USERNAME_LEN_OFFSET: usize = 93;
const USERNAME_OFFSET: usize = 97;
const USERNAME_MAX: usize = 64;
const PASSWORD_LEN_OFFSET: usize = 161;
const PASSWORD_OFFSET: usize = 165;
const PASSWORD_MAX: usize = 128;

fn blob_seed(page_id: u64, tag: u32, sub: u64) -> u64 {
    MAGIC_NUMBER
        ^ ((DB_VERSION as u64) << 32)
        ^ page_id.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ ((tag as u64) << 20)
        ^ sub
}

/// XOR obfuscation for stored string blobs. Symmetric: apply twice to recover.
fn xor_obfuscate_buffer(buf: &mut [u8], mut seed: u64) {
    for b in buf.iter_mut() {
        seed = seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        *b ^= (seed >> 56) as u8;
    }
}

fn row_text_seed_sub(row_index: usize, col_idx: usize) -> u64 {
    (row_index as u64).wrapping_shl(24) ^ (col_idx as u64)
}

pub struct Database {
    storage: StorageEngine,
}

fn validate_db_file_version(header: &Page) -> Result<(), String> {
    let magic = u64::from_le_bytes(
        header.data[0..8]
            .try_into()
            .map_err(|_| "Failed to read magic number")?,
    );
    if magic != MAGIC_NUMBER {
        return Ok(());
    }
    let version = u32::from_le_bytes(
        header.data[8..12]
            .try_into()
            .map_err(|_| "Failed to read database version")?,
    );
    if version != DB_VERSION {
        if version == 1 {
            return Err(
                "Legacy plaintext database format (v1) is no longer supported. \
                 Create a new database with CREATE DATABASE and migrate any data manually."
                    .to_string(),
            );
        }
        return Err(format!(
            "Unsupported database format version {} (expected {}).",
            version, DB_VERSION
        ));
    }
    Ok(())
}

impl Database {
    pub fn new(path: &str) -> Result<Self, String> {
        let storage = StorageEngine::new(path);
        let mut db = Database { storage };

        // Initialize database if it's new
        db.initialize_if_needed()?;

        Ok(db)
    }

    pub fn configure_auth(
        &mut self,
        database_name: &str,
        username: &str,
        password: &str,
    ) -> Result<(), String> {
        let mut header = self.storage.read_page(HEADER_PAGE_ID);

        Self::write_string_field(
            &mut header,
            DB_NAME_LEN_OFFSET,
            DB_NAME_OFFSET,
            DB_NAME_MAX,
            database_name,
            "database name",
            blob_seed(HEADER_PAGE_ID, SALT_AUTH_DB_NAME, 0),
        )?;
        Self::write_string_field(
            &mut header,
            USERNAME_LEN_OFFSET,
            USERNAME_OFFSET,
            USERNAME_MAX,
            username,
            "username",
            blob_seed(HEADER_PAGE_ID, SALT_AUTH_USERNAME, 0),
        )?;
        Self::write_string_field(
            &mut header,
            PASSWORD_LEN_OFFSET,
            PASSWORD_OFFSET,
            PASSWORD_MAX,
            password,
            "password",
            blob_seed(HEADER_PAGE_ID, SALT_AUTH_PASSWORD, 0),
        )?;

        header.data[AUTH_FLAG_OFFSET] = 1;
        self.storage.write_page(&header);
        Ok(())
    }

    pub fn auth_exists(&mut self) -> bool {
        let header = self.storage.read_page(HEADER_PAGE_ID);
        header.data[AUTH_FLAG_OFFSET] == 1
    }

    pub fn verify_login(&mut self, username: &str, password: &str) -> Result<bool, String> {
        let header = self.storage.read_page(HEADER_PAGE_ID);
        if header.data[AUTH_FLAG_OFFSET] != 1 {
            return Ok(false);
        }

        let stored_username = Self::read_string_field(
            &header,
            USERNAME_LEN_OFFSET,
            USERNAME_OFFSET,
            USERNAME_MAX,
            "username",
            blob_seed(HEADER_PAGE_ID, SALT_AUTH_USERNAME, 0),
        )?;
        let stored_password = Self::read_string_field(
            &header,
            PASSWORD_LEN_OFFSET,
            PASSWORD_OFFSET,
            PASSWORD_MAX,
            "password",
            blob_seed(HEADER_PAGE_ID, SALT_AUTH_PASSWORD, 0),
        )?;

        Ok(stored_username == username && stored_password == password)
    }

    fn write_string_field(
        page: &mut Page,
        len_offset: usize,
        data_offset: usize,
        max_len: usize,
        value: &str,
        label: &str,
        seed: u64,
    ) -> Result<(), String> {
        let bytes = value.as_bytes();
        if bytes.is_empty() {
            return Err(format!("{} must not be empty", label));
        }
        if bytes.len() > max_len {
            return Err(format!("{} is too long (max {} bytes)", label, max_len));
        }

        page.data[len_offset..len_offset + 4].copy_from_slice(&(bytes.len() as u32).to_le_bytes());
        page.data[data_offset..data_offset + max_len].fill(0);
        page.data[data_offset..data_offset + bytes.len()].copy_from_slice(bytes);
        xor_obfuscate_buffer(&mut page.data[data_offset..data_offset + bytes.len()], seed);
        Ok(())
    }

    fn read_string_field(
        page: &Page,
        len_offset: usize,
        data_offset: usize,
        max_len: usize,
        label: &str,
        seed: u64,
    ) -> Result<String, String> {
        let len = u32::from_le_bytes(
            page.data[len_offset..len_offset + 4]
                .try_into()
                .map_err(|_| format!("Failed to read {} length", label))?,
        ) as usize;

        if len == 0 || len > max_len {
            return Err(format!("Invalid stored {} length", label));
        }

        let mut buf = page.data[data_offset..data_offset + len].to_vec();
        xor_obfuscate_buffer(&mut buf, seed);
        String::from_utf8(buf).map_err(|_| format!("Invalid stored {} encoding", label))
    }

    fn initialize_if_needed(&mut self) -> Result<(), String> {
        // Check if database file exists and has content
        let file_len = self.storage.file().metadata()
            .map_err(|e| format!("Failed to get file metadata: {}", e))?
            .len();
        
        // If file is empty or doesn't exist, initialize it
        if file_len == 0 {
            let mut header = Page::new(HEADER_PAGE_ID);

            // Write magic number
            header.data[0..8].copy_from_slice(&MAGIC_NUMBER.to_le_bytes());
            // Write version
            header.data[8..12].copy_from_slice(&DB_VERSION.to_le_bytes());
            // Write schema root page (0 = no tables yet)
            header.data[12..20].copy_from_slice(&0u64.to_le_bytes());
            // Write table count (0 initially)
            header.data[20..24].copy_from_slice(&0u32.to_le_bytes());

            self.storage.write_page(&header);
            return Ok(());
        }

        // File exists - verify it's a valid database file
        let header = self.storage.read_page(HEADER_PAGE_ID);
        let magic = u64::from_le_bytes(
            header.data[0..8]
                .try_into()
                .map_err(|_| "Failed to read magic number")?,
        );

        if magic == MAGIC_NUMBER {
            validate_db_file_version(&header)?;
        }

        // Only overwrite if magic number is completely wrong (not just zero)
        // If magic is 0 but file has content, it might be corrupted - but don't auto-fix
        if magic != 0 && magic != MAGIC_NUMBER {
            return Err(format!(
                "Invalid database file: expected magic number 0x{:016X}, got 0x{:016X}. File may be corrupted or not a database file.",
                MAGIC_NUMBER, magic
            ));
        }

        // If magic is 0 but file has content, it's likely corrupted
        // But we'll let load_catalog handle it (it will return empty catalog)
        if magic == 0 && file_len > 0 {
            // File exists but has no valid header - this is suspicious
            // Don't overwrite, but log a warning
            eprintln!("Warning: Database file exists but has invalid header. Attempting to load anyway...");
        }

        Ok(())
    }

    pub fn load_catalog(&mut self) -> Result<Catalog, String> {
        let mut header = self.storage.read_page(HEADER_PAGE_ID);
        validate_db_file_version(&header)?;
        let num_tables = u32::from_le_bytes(
            header.data[20..24]
                .try_into()
                .map_err(|_| "Failed to read table count")?,
        );

        let schema_root = u64::from_le_bytes(
            header.data[12..20]
                .try_into()
                .map_err(|_| "Failed to read schema root")?,
        );

        // Validate and repair inconsistencies
        if num_tables == 0 {
            // If table_count is 0, schema_root should also be 0
            if schema_root != 0 {
                header.data[12..20].copy_from_slice(&0u64.to_le_bytes());
                self.storage.write_page(&header);
            }
            return Ok(Catalog::new());
        }

        if schema_root == 0 {
            // If schema_root is 0 but table_count > 0, reset table_count
            if num_tables > 0 {
                header.data[20..24].copy_from_slice(&0u32.to_le_bytes());
                self.storage.write_page(&header);
            }
            return Ok(Catalog::new());
        }

        // Try to load tables
        let mut tables = Vec::new();
        let mut current_page_id = schema_root;
        let mut tables_loaded = 0;
        let mut pages_visited = std::collections::HashSet::new();

        // Read schema pages and load tables
        while tables_loaded < num_tables && current_page_id != 0 {
            // Prevent infinite loops
            if pages_visited.contains(&current_page_id) {
                eprintln!("Warning: Circular reference detected in schema chain at page {}", current_page_id);
                break;
            }
            pages_visited.insert(current_page_id);

            match self.read_table_from_page(current_page_id)? {
                Some((table, next_page)) => {
                    tables.push(table);
                    tables_loaded += 1;
                    current_page_id = next_page;
                }
                None => {
                    // Invalid page - stop loading
                    eprintln!("Warning: Invalid table page at {}", current_page_id);
                    break;
                }
            }
        }

        // If we loaded fewer tables than expected, update the count
        if tables_loaded != num_tables {
            eprintln!("Warning: Expected {} tables but only loaded {}. Repairing database...", num_tables, tables_loaded);
            header.data[20..24].copy_from_slice(&(tables_loaded as u32).to_le_bytes());
            self.storage.write_page(&header);
        }

        let mut catalog = Catalog::new();
        for table in tables {
            catalog.add_table(table);
        }

        Ok(catalog)
    }

    fn read_table_from_page(&mut self, page_id: u64) -> Result<Option<(Table, u64)>, String> {
        let page = self.storage.read_page(page_id);

        // Check if page is empty (all zeros)
        if page.data.iter().all(|&b| b == 0) {
            return Ok(None);
        }

        let mut offset = 0;

        // Read table name length and name
        if offset + 4 > page.data.len() {
            return Ok(None);
        }
        let name_len = u32::from_le_bytes(
            page.data[offset..offset + 4]
                .try_into()
                .map_err(|_| "Failed to read table name length")?,
        ) as usize;
        offset += 4;

        if name_len == 0 || name_len > 255 || offset + name_len > page.data.len() {
            return Ok(None);
        }

        let mut name_buf = page.data[offset..offset + name_len].to_vec();
        xor_obfuscate_buffer(&mut name_buf, blob_seed(page_id, SALT_SCHEMA_TABLE_NAME, 0));
        let name = String::from_utf8(name_buf).map_err(|_| "Invalid table name encoding")?;
        offset += name_len;

        // Read number of columns
        if offset + 4 > page.data.len() {
            return Ok(None);
        }
        let num_cols = u32::from_le_bytes(
            page.data[offset..offset + 4]
                .try_into()
                .map_err(|_| "Failed to read column count")?,
        );
        offset += 4;

        // Read columns
        let mut columns = Vec::new();
        for col_idx in 0..num_cols {
            // Column name length and name
            if offset + 4 > page.data.len() {
                return Ok(None);
            }
            let col_name_len = u32::from_le_bytes(
                page.data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| "Failed to read column name length")?,
            ) as usize;
            offset += 4;

            if offset + col_name_len > page.data.len() {
                return Ok(None);
            }
            let mut col_name_buf = page.data[offset..offset + col_name_len].to_vec();
            xor_obfuscate_buffer(
                &mut col_name_buf,
                blob_seed(page_id, SALT_SCHEMA_COL_NAME, col_idx as u64),
            );
            let col_name =
                String::from_utf8(col_name_buf).map_err(|_| "Invalid column name encoding")?;
            offset += col_name_len;

            // Data type length and type
            if offset + 4 > page.data.len() {
                return Ok(None);
            }
            let type_len = u32::from_le_bytes(
                page.data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| "Failed to read data type length")?,
            ) as usize;
            offset += 4;

            if offset + type_len > page.data.len() {
                return Ok(None);
            }
            let mut type_buf = page.data[offset..offset + type_len].to_vec();
            xor_obfuscate_buffer(
                &mut type_buf,
                blob_seed(page_id, SALT_SCHEMA_COL_TYPE, col_idx as u64),
            );
            let data_type =
                String::from_utf8(type_buf).map_err(|_| "Invalid data type encoding")?;
            offset += type_len;

            columns.push(Column {
                name: col_name,
                data_type,
            });
        }

        // Read data page ID (where rows are stored)
        if offset + 8 > page.data.len() {
            return Ok(None);
        }
        let data_page_id = u64::from_le_bytes(
            page.data[offset..offset + 8]
                .try_into()
                .map_err(|_| "Failed to read data page ID")?,
        );
        offset += 8;

        // Read next schema page ID
        if offset + 8 > page.data.len() {
            return Ok(None);
        }
        let next_page = u64::from_le_bytes(
            page.data[offset..offset + 8]
                .try_into()
                .map_err(|_| "Failed to read next page ID")?,
        );

        // Load rows from data pages
        let rows = if data_page_id > 0 {
            self.load_rows_from_pages(data_page_id, &columns, 0)?
        } else {
            Vec::new()
        };

        Ok(Some((
            Table {
                name,
                columns,
                rows,
            },
            next_page,
        )))
    }

    fn load_rows_from_pages(
        &mut self,
        start_page_id: u64,
        columns: &[Column],
        base_row_index: usize,
    ) -> Result<Vec<Row>, String> {
        let mut rows = Vec::new();
        let mut current_page_id = start_page_id;
        let mut global_row = base_row_index;

        loop {
            let page = self.storage.read_page(current_page_id);

            // Check if page is empty
            if page.data.iter().all(|&b| b == 0) {
                break;
            }

            let mut offset = 0;

            // Read number of rows in this page
            if offset + 4 > page.data.len() {
                break;
            }
            let num_rows = u32::from_le_bytes(
                page.data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| "Failed to read row count")?,
            );
            offset += 4;

            if num_rows == 0 {
                break;
            }

            // Read rows
            for _ in 0..num_rows {
                let row_seed_index = global_row;
                let mut row_values = Vec::new();

                for (col_idx, _col) in columns.iter().enumerate() {
                    // Read value type tag
                    if offset + 1 > page.data.len() {
                        break;
                    }
                    let value_type = page.data[offset];
                    offset += 1;

                    match value_type {
                        TYPE_NULL => {
                            row_values.push(String::new());
                        }
                        TYPE_INT => {
                            // Read 8-byte integer
                            if offset + 8 > page.data.len() {
                                break;
                            }
                            let int_val = i64::from_le_bytes(
                                page.data[offset..offset + 8]
                                    .try_into()
                                    .map_err(|_| "Failed to read integer value")?,
                            );
                            offset += 8;
                            row_values.push(int_val.to_string());
                        }
                        TYPE_TEXT => {
                            // Read text length and value
                            if offset + 4 > page.data.len() {
                                break;
                            }
                            let text_len = u32::from_le_bytes(
                                page.data[offset..offset + 4]
                                    .try_into()
                                    .map_err(|_| "Failed to read text length")?,
                            ) as usize;
                            offset += 4;

                            if text_len == 0 {
                                row_values.push(String::new());
                                continue;
                            }

                            if offset + text_len > page.data.len() {
                                break;
                            }
                            let mut buf = page.data[offset..offset + text_len].to_vec();
                            xor_obfuscate_buffer(
                                &mut buf,
                                blob_seed(
                                    current_page_id,
                                    SALT_ROW_TEXT,
                                    row_text_seed_sub(row_seed_index, col_idx),
                                ),
                            );
                            let value =
                                String::from_utf8(buf).map_err(|_| "Invalid text encoding")?;
                            offset += text_len;
                            row_values.push(value);
                        }
                        _ => {
                            // Unknown type - try to read as legacy string format for backward compatibility
                            if offset + 4 > page.data.len() {
                                break;
                            }
                            let val_len = u32::from_le_bytes(
                                page.data[offset..offset + 4]
                                    .try_into()
                                    .map_err(|_| "Failed to read value length")?,
                            ) as usize;
                            offset += 4;

                            if val_len == 0 {
                                row_values.push(String::new());
                                continue;
                            }

                            if offset + val_len > page.data.len() {
                                break;
                            }
                            let mut buf = page.data[offset..offset + val_len].to_vec();
                            xor_obfuscate_buffer(
                                &mut buf,
                                blob_seed(
                                    current_page_id,
                                    SALT_ROW_TEXT,
                                    row_text_seed_sub(row_seed_index, col_idx),
                                ),
                            );
                            let value =
                                String::from_utf8(buf).map_err(|_| "Invalid value encoding")?;
                            offset += val_len;
                            row_values.push(value);
                        }
                    }
                }

                if row_values.len() == columns.len() {
                    rows.push(Row { values: row_values });
                    global_row += 1;
                }
            }

            // Read next data page ID
            if offset + 8 > page.data.len() {
                break;
            }
            let next_page = u64::from_le_bytes(
                page.data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| "Failed to read next page ID")?,
            );

            if next_page == 0 {
                break;
            }
            current_page_id = next_page;
        }

        Ok(rows)
    }

    fn find_table_schema_page(&mut self, table_name: &str) -> Result<Option<u64>, String> {
        let header = self.storage.read_page(HEADER_PAGE_ID);
        let schema_root = u64::from_le_bytes(
            header.data[12..20]
                .try_into()
                .map_err(|_| "Failed to read schema root")?,
        );

        if schema_root == 0 {
            return Ok(None);
        }

        let mut current_page_id = schema_root;

        loop {
            let page = self.storage.read_page(current_page_id);

            if page.data.iter().all(|&b| b == 0) {
                break;
            }

            let mut offset = 0;

            // Read table name
            if offset + 4 > page.data.len() {
                break;
            }
            let name_len = u32::from_le_bytes(
                page.data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| "Failed to read table name length")?,
            ) as usize;
            offset += 4;

            if name_len > 255 || offset + name_len > page.data.len() {
                break;
            }

            let mut name_buf = page.data[offset..offset + name_len].to_vec();
            xor_obfuscate_buffer(
                &mut name_buf,
                blob_seed(current_page_id, SALT_SCHEMA_TABLE_NAME, 0),
            );
            let name = String::from_utf8(name_buf).map_err(|_| "Invalid table name encoding")?;

            if name.to_lowercase() == table_name.to_lowercase() {
                return Ok(Some(current_page_id));
            }

            // Skip to next page pointer
            // We need to skip: columns count, all columns, and data page ID
            offset += name_len;
            if offset + 4 > page.data.len() {
                break;
            }
            let num_cols = u32::from_le_bytes(
                page.data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| "Failed to read column count")?,
            );
            offset += 4;

            // Skip columns
            for _ in 0..num_cols {
                // Column name
                if offset + 4 > page.data.len() {
                    break;
                }
                let col_name_len = u32::from_le_bytes(
                    page.data[offset..offset + 4]
                        .try_into()
                        .map_err(|_| "Failed to read column name length")?,
                ) as usize;
                offset += 4;
                if offset + col_name_len > page.data.len() {
                    break;
                }
                offset += col_name_len;

                // Column type
                if offset + 4 > page.data.len() {
                    break;
                }
                let type_len = u32::from_le_bytes(
                    page.data[offset..offset + 4]
                        .try_into()
                        .map_err(|_| "Failed to read data type length")?,
                ) as usize;
                offset += 4;
                if offset + type_len > page.data.len() {
                    break;
                }
                offset += type_len;
            }

            // Skip data page ID
            offset += 8;

            // Read next page
            if offset + 8 > page.data.len() {
                break;
            }
            let next_page = u64::from_le_bytes(
                page.data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| "Failed to read next page ID")?,
            );

            if next_page == 0 {
                break;
            }
            current_page_id = next_page;
        }

        Ok(None)
    }

    pub fn save_table(&mut self, table: &Table, is_new: bool) -> Result<(), String> {
        // Save the table schema and data to pages
        let schema_page = self.storage.allocate_page();
        let schema_page_id = schema_page.id;
        let mut page = Page::new(schema_page.id);
        let mut offset = 0;

        // Write table name
        let name_bytes = table.name.as_bytes();
        if offset + 4 + name_bytes.len() > page.data.len() {
            return Err("Table name too long".to_string());
        }
        page.data[offset..offset + 4].copy_from_slice(&(name_bytes.len() as u32).to_le_bytes());
        offset += 4;
        page.data[offset..offset + name_bytes.len()].copy_from_slice(name_bytes);
        xor_obfuscate_buffer(
            &mut page.data[offset..offset + name_bytes.len()],
            blob_seed(schema_page_id, SALT_SCHEMA_TABLE_NAME, 0),
        );
        offset += name_bytes.len();

        // Write number of columns
        if offset + 4 > page.data.len() {
            return Err("Page overflow".to_string());
        }
        page.data[offset..offset + 4].copy_from_slice(&(table.columns.len() as u32).to_le_bytes());
        offset += 4;

        // Write columns
        for (col_idx, col) in table.columns.iter().enumerate() {
            let col_name_bytes = col.name.as_bytes();
            if offset + 4 + col_name_bytes.len() > page.data.len() {
                return Err("Column name too long".to_string());
            }
            page.data[offset..offset + 4]
                .copy_from_slice(&(col_name_bytes.len() as u32).to_le_bytes());
            offset += 4;
            page.data[offset..offset + col_name_bytes.len()].copy_from_slice(col_name_bytes);
            xor_obfuscate_buffer(
                &mut page.data[offset..offset + col_name_bytes.len()],
                blob_seed(schema_page_id, SALT_SCHEMA_COL_NAME, col_idx as u64),
            );
            offset += col_name_bytes.len();

            let type_bytes = col.data_type.as_bytes();
            if offset + 4 + type_bytes.len() > page.data.len() {
                return Err("Data type too long".to_string());
            }
            page.data[offset..offset + 4].copy_from_slice(&(type_bytes.len() as u32).to_le_bytes());
            offset += 4;
            page.data[offset..offset + type_bytes.len()].copy_from_slice(type_bytes);
            xor_obfuscate_buffer(
                &mut page.data[offset..offset + type_bytes.len()],
                blob_seed(schema_page_id, SALT_SCHEMA_COL_TYPE, col_idx as u64),
            );
            offset += type_bytes.len();
        }

        // Allocate data page for rows
        let data_page = if !table.rows.is_empty() {
            self.save_rows_to_pages(&table.rows, &table.columns, None, 0)?
        } else {
            self.storage.allocate_page()
        };

        // Write data page ID
        if offset + 8 > page.data.len() {
            return Err("Page overflow".to_string());
        }
        page.data[offset..offset + 8].copy_from_slice(&data_page.id.to_le_bytes());
        offset += 8;

        // If this is not a new table, we need to update the existing schema chain
        if !is_new {
            // For now, we'll just save the table with no next page
            // In a real implementation, you'd want to update the existing chain
            page.data[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
            self.storage.write_page(&page);
            return Ok(());
        }

        // For new tables, we need to update the schema chain
        let mut header = self.storage.read_page(HEADER_PAGE_ID);
        let schema_root = u64::from_le_bytes(
            header.data[12..20]
                .try_into()
                .map_err(|_| "Failed to read schema root")?,
        );

        // If this is the first table, update the schema root
        if schema_root == 0 {
            // This is the first table, update the header
            header.data[12..20].copy_from_slice(&schema_page.id.to_le_bytes());
            // Write header immediately to persist the schema_root
            self.storage.write_page(&header);
        } else {
            // Find the last table in the chain and update its next pointer
            let mut current_page_id = schema_root;
            loop {
                let mut current_page = self.storage.read_page(current_page_id);
    
                // Parse the current page to find the offset of the next_page pointer
                let mut next_page_offset = 0;
    
                // Read table name
                let name_len = u32::from_le_bytes(current_page.data[next_page_offset..next_page_offset + 4].try_into().unwrap()) as usize;
                next_page_offset += 4 + name_len;
    
                // Read columns
                let num_cols = u32::from_le_bytes(current_page.data[next_page_offset..next_page_offset + 4].try_into().unwrap());
                next_page_offset += 4;
    
                for _ in 0..num_cols {
                    let col_name_len = u32::from_le_bytes(current_page.data[next_page_offset..next_page_offset + 4].try_into().unwrap()) as usize;
                    next_page_offset += 4 + col_name_len;
    
                    let type_len = u32::from_le_bytes(current_page.data[next_page_offset..next_page_offset + 4].try_into().unwrap()) as usize;
                    next_page_offset += 4 + type_len;
                }
    
                // Read data page ID
                next_page_offset += 8;
    
                // Now, next_page_offset is at the location of the next_page pointer
                let next_page_id = u64::from_le_bytes(current_page.data[next_page_offset..next_page_offset + 8].try_into().unwrap());
    
                if next_page_id == 0 {
                    // This is the last page, update its next pointer
                    current_page.data[next_page_offset..next_page_offset + 8].copy_from_slice(&schema_page.id.to_le_bytes());
                    self.storage.write_page(&current_page);
                    break;
                }
                current_page_id = next_page_id;
            }
        }

        // Mark the end of the chain for this table
        page.data[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());

        // Save the schema page
        self.storage.write_page(&page);

        // Update the table count (re-read header in case it was modified)
        let mut header = self.storage.read_page(HEADER_PAGE_ID);
        let table_count = u32::from_le_bytes(
            header.data[20..24]
                .try_into()
                .map_err(|_| "Failed to read table count")?,
        );
        header.data[20..24].copy_from_slice(&(table_count + 1).to_le_bytes());
        // Also ensure schema_root is set correctly if this was the first table
        let current_schema_root = u64::from_le_bytes(
            header.data[12..20]
                .try_into()
                .map_err(|_| "Failed to read schema root")?,
        );
        if current_schema_root == 0 {
            header.data[12..20].copy_from_slice(&schema_page.id.to_le_bytes());
        }
        self.storage.write_page(&header);

        Ok(())
    }

    fn save_rows_to_pages(
        &mut self,
        rows: &[Row],
        columns: &[Column],
        start_page_id: Option<u64>,
        base_row_index: usize,
    ) -> Result<Page, String> {
        let page_id = if let Some(id) = start_page_id {
            id
        } else {
            self.storage.allocate_page().id
        };

        let mut page = Page::new(page_id);
        let mut offset = 0;

        // Calculate how many rows fit in a page
        // We'll write rows until we run out of space
        let mut rows_written = 0;

        // Write number of rows (we'll update this later)
        let row_count_offset = offset;
        offset += 4;

        // Write rows
        for (row_idx, row) in rows.iter().enumerate() {
            let global_row = base_row_index + row_idx;
            let row_start_offset = offset;

            // Try to write the row
            for (col_idx, (value, col)) in row.values.iter().zip(columns.iter()).enumerate() {
                let col_type = col.data_type.to_uppercase();

                // Write value type tag
                if offset + 1 > page.data.len() {
                    break;
                }

                if value.is_empty() {
                    page.data[offset] = TYPE_NULL;
                    offset += 1;
                } else if col_type == "INT" || col_type == "INTEGER" {
                    // Parse and write as integer
                    match value.parse::<i64>() {
                        Ok(int_val) => {
                            page.data[offset] = TYPE_INT;
                            offset += 1;
                            if offset + 8 > page.data.len() {
                                break;
                            }
                            page.data[offset..offset + 8].copy_from_slice(&int_val.to_le_bytes());
                            offset += 8;
                        }
                        Err(_) => {
                            // Fallback to text if parsing fails
                            page.data[offset] = TYPE_TEXT;
                            offset += 1;
                            let val_bytes = value.as_bytes();
                            if offset + 4 + val_bytes.len() > page.data.len() {
                                break;
                            }
                            page.data[offset..offset + 4]
                                .copy_from_slice(&(val_bytes.len() as u32).to_le_bytes());
                            offset += 4;
                            page.data[offset..offset + val_bytes.len()].copy_from_slice(val_bytes);
                            xor_obfuscate_buffer(
                                &mut page.data[offset..offset + val_bytes.len()],
                                blob_seed(
                                    page_id,
                                    SALT_ROW_TEXT,
                                    row_text_seed_sub(global_row, col_idx),
                                ),
                            );
                            offset += val_bytes.len();
                        }
                    }
                } else {
                    // Write as text
                    page.data[offset] = TYPE_TEXT;
                    offset += 1;
                    let val_bytes = value.as_bytes();
                    if offset + 4 + val_bytes.len() > page.data.len() {
                        break;
                    }
                    page.data[offset..offset + 4]
                        .copy_from_slice(&(val_bytes.len() as u32).to_le_bytes());
                    offset += 4;
                    page.data[offset..offset + val_bytes.len()].copy_from_slice(val_bytes);
                    xor_obfuscate_buffer(
                        &mut page.data[offset..offset + val_bytes.len()],
                        blob_seed(
                            page_id,
                            SALT_ROW_TEXT,
                            row_text_seed_sub(global_row, col_idx),
                        ),
                    );
                    offset += val_bytes.len();
                }
            }

            // Check if we successfully wrote the entire row
            if row.values.len() == columns.len() && offset <= page.data.len() - 8 {
                rows_written += 1;
            } else {
                // Row didn't fit, rollback
                offset = row_start_offset;
                break;
            }
        }

        // Write actual row count
        page.data[row_count_offset..row_count_offset + 4]
            .copy_from_slice(&(rows_written as u32).to_le_bytes());

        // If there are more rows, allocate next page and chain
        if rows.len() > rows_written {
            let next_page = self.save_rows_to_pages(
                &rows[rows_written..],
                columns,
                None,
                base_row_index + rows_written,
            )?;
            if offset + 8 > page.data.len() {
                return Err("Page overflow".to_string());
            }
            page.data[offset..offset + 8].copy_from_slice(&next_page.id.to_le_bytes());
        } else {
            if offset + 8 > page.data.len() {
                return Err("Page overflow".to_string());
            }
            page.data[offset..offset + 8].copy_from_slice(&0u64.to_le_bytes());
        }

        self.storage.write_page(&page);
        Ok(page)
    }

    pub fn update_table_data(&mut self, table: &Table) -> Result<(), String> {
        // Find the existing schema page for this table
        if let Some(schema_page_id) = self.find_table_schema_page(&table.name)? {
            // Read the existing schema page to get the data page ID
            let schema_page = self.storage.read_page(schema_page_id);
            
            // Parse to find data page ID
            let mut offset = 0;
            
            // Skip table name
            let name_len = u32::from_le_bytes(
                schema_page.data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| "Failed to read table name length")?,
            ) as usize;
            offset += 4 + name_len;
            
            // Skip columns
            let num_cols = u32::from_le_bytes(
                schema_page.data[offset..offset + 4]
                    .try_into()
                    .map_err(|_| "Failed to read column count")?,
            );
            offset += 4;
            
            for _ in 0..num_cols {
                let col_name_len = u32::from_le_bytes(
                    schema_page.data[offset..offset + 4]
                        .try_into()
                        .map_err(|_| "Failed to read column name length")?,
                ) as usize;
                offset += 4 + col_name_len;
                
                let type_len = u32::from_le_bytes(
                    schema_page.data[offset..offset + 4]
                        .try_into()
                        .map_err(|_| "Failed to read data type length")?,
                ) as usize;
                offset += 4 + type_len;
            }
            
            // Read existing data page ID
            let existing_data_page_id = u64::from_le_bytes(
                schema_page.data[offset..offset + 8]
                    .try_into()
                    .map_err(|_| "Failed to read data page ID")?,
            );
            
            // Update data pages, reusing the first page if possible
            let first_data_page = if existing_data_page_id > 0 {
                self.save_rows_to_pages(
                    &table.rows,
                    &table.columns,
                    Some(existing_data_page_id),
                    0,
                )?
            } else {
                self.save_rows_to_pages(&table.rows, &table.columns, None, 0)?
            };
            
            // Update the schema page with the new data page ID
            let mut updated_schema_page = schema_page;
            updated_schema_page.data[offset..offset + 8].copy_from_slice(&first_data_page.id.to_le_bytes());
            self.storage.write_page(&updated_schema_page);
            
            Ok(())
        } else {
            // Table not found, create it as new
            self.save_table(table, true)
        }
    }
}

pub fn write_active_database_path(path: &str) -> Result<(), String> {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
        return Err("Active database path must not be empty".to_string());
    }
    if bytes.len() > u16::MAX as usize {
        return Err("Active database path is too long".to_string());
    }

    let mut body = bytes.to_vec();
    xor_obfuscate_buffer(&mut body, active_path_seed());

    let mut payload = Vec::with_capacity(6 + body.len());
    payload.extend_from_slice(&ACTIVE_DB_MAGIC_V2.to_le_bytes());
    payload.extend_from_slice(&(body.len() as u16).to_le_bytes());
    payload.extend_from_slice(&body);

    fs::write(ACTIVE_DB_FILE, payload)
        .map_err(|e| format!("Failed to write active database metadata: {}", e))
}

pub fn read_active_database_path() -> Option<String> {
    let content = fs::read(ACTIVE_DB_FILE).ok()?;
    if content.len() < 6 {
        return None;
    }

    let magic = u32::from_le_bytes(content[0..4].try_into().ok()?);
    let len = u16::from_le_bytes(content[4..6].try_into().ok()?) as usize;
    if content.len() < 6 + len || len == 0 {
        return None;
    }

    let body = &content[6..6 + len];
    match magic {
        ACTIVE_DB_MAGIC_V2 => {
            let mut buf = body.to_vec();
            xor_obfuscate_buffer(&mut buf, active_path_seed());
            String::from_utf8(buf).ok()
        }
        ACTIVE_DB_MAGIC_V1 => String::from_utf8(body.to_vec()).ok(),
        _ => None,
    }
}

pub fn resolve_active_database_path() -> Option<String> {
    if let Some(path) = read_active_database_path() {
        if database_has_auth(&path) {
            return Some(path);
        }
    }

    let mut discovered: Vec<String> = fs::read_dir(".")
        .ok()?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let path = entry.path();
            if path.extension()?.to_str()? != "db" {
                return None;
            }
            let candidate = path.to_string_lossy().to_string();
            if database_has_auth(&candidate) {
                Some(candidate)
            } else {
                None
            }
        })
        .collect();

    discovered.sort();
    let selected = discovered.into_iter().next()?;
    let _ = write_active_database_path(&selected);
    Some(selected)
}

fn database_has_auth(path: &str) -> bool {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(_) => return false,
    };

    let mut header = [0u8; 4096];
    if file.read(&mut header).is_err() {
        return false;
    }

    let magic = u64::from_le_bytes(match header[0..8].try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    });

    if magic != MAGIC_NUMBER {
        return false;
    }

    let version = match header[8..12].try_into() {
        Ok(b) => u32::from_le_bytes(b),
        Err(_) => return false,
    };
    if version != DB_VERSION {
        return false;
    }

    header[AUTH_FLAG_OFFSET] == 1
}
