use blake3::Hasher;
use rusqlite::{params, Connection, Result, Row};
use std::fmt;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

pub struct EncryptedDb {
    conn: Connection,
}

impl fmt::Debug for EncryptedDb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncryptedDb").finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct FolderMetadata {
    pub id: Uuid,
    pub name: String,
    #[allow(dead_code)]
    pub parent_id: Option<Uuid>,
}

#[derive(Clone, Debug)]
pub struct FileMetadata {
    pub id: Uuid,
    pub name: String,
    pub size: usize,
    pub compressed_size: usize,
    pub created_at: i64,
    #[allow(dead_code)]
    pub folder_id: Option<Uuid>,
    pub checksum: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortColumn {
    Name,
    Size,
    EncryptedSize,
    Modified,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SortDirection {
    Asc,
    Desc,
}

#[derive(Clone, Debug, Default)]
pub struct VaultStats {
    pub total_files: usize,
    pub total_bytes: usize,
    pub compressed_bytes: usize,
}

fn sanitize_db_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let p_ref = path.as_ref();
    let s = p_ref.to_string_lossy();
    if s.starts_with(r"\\?\") {
        PathBuf::from(&s[4..])
    } else {
        p_ref.to_path_buf()
    }
}

impl EncryptedDb {
    pub fn open<P: AsRef<Path>>(path: P, key: &str) -> Result<Self> {
        let clean_path = sanitize_db_path(path);
        let conn = Connection::open(&clean_path)?;

        conn.pragma_update(None, "key", key)?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;

        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "synchronous", "NORMAL")?;
        let _ = conn.pragma_update(None, "mmap_size", 268435456);
        let _ = conn.pragma_update(None, "cache_size", -64000);
        conn.pragma_update(None, "temp_store", "MEMORY")?;
        conn.pragma_update(None, "auto_vacuum", "INCREMENTAL")?;

        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS folders (
                id BLOB PRIMARY KEY,
                name TEXT NOT NULL,
                parent_id BLOB,
                FOREIGN KEY (parent_id) REFERENCES folders(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS files (
                id BLOB PRIMARY KEY,
                name TEXT NOT NULL,
                size INTEGER NOT NULL,
                compressed_size INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                folder_id BLOB,
                checksum TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (folder_id) REFERENCES folders(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS chunks (
                file_id BLOB NOT NULL,
                chunk_index INTEGER NOT NULL,
                data BLOB NOT NULL,
                PRIMARY KEY (file_id, chunk_index),
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS vault_stats (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                total_files INTEGER NOT NULL DEFAULT 0,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                compressed_bytes INTEGER NOT NULL DEFAULT 0
            );
            INSERT OR IGNORE INTO vault_stats (id, total_files, total_bytes, compressed_bytes) VALUES (1, 0, 0, 0);

            CREATE INDEX IF NOT EXISTS idx_folders_nav ON folders(parent_id, name);
            CREATE INDEX IF NOT EXISTS idx_files_covering ON files(folder_id, name, size, compressed_size, created_at);
            CREATE INDEX IF NOT EXISTS idx_chunks_file ON chunks(file_id);"
        )?;

        let _ = conn.query_row("SELECT id FROM vault_stats WHERE id = 1", [], |_| Ok(()))?;
        Ok(Self { conn })
    }

    pub fn change_key(&self, new_key: &str) -> Result<()> {
        self.conn.pragma_update(None, "rekey", new_key)
    }

    pub fn vacuum_compact(&self) -> Result<()> {
        self.conn.execute_batch("VACUUM;")
    }

    pub fn get_vault_stats(&self) -> Result<VaultStats> {
        self.conn.query_row(
            "SELECT total_files, total_bytes, compressed_bytes FROM vault_stats WHERE id = 1",
            [],
            |row| {
                Ok(VaultStats {
                    total_files: row.get(0)?,
                    total_bytes: row.get(1)?,
                    compressed_bytes: row.get(2)?,
                })
            },
        )
    }

    fn parse_folder(row: &Row) -> Result<FolderMetadata> {
        let id_bytes: Vec<u8> = row.get(0)?;
        let pid_bytes: Option<Vec<u8>> = row.get(2)?;
        Ok(FolderMetadata {
            id: Uuid::from_slice(&id_bytes).unwrap_or_default(),
            name: row.get(1)?,
            parent_id: pid_bytes.and_then(|b| Uuid::from_slice(&b).ok()),
        })
    }

    fn parse_file(row: &Row) -> Result<FileMetadata> {
        let id_bytes: Vec<u8> = row.get(0)?;
        let fid_bytes: Option<Vec<u8>> = row.get(5)?;
        Ok(FileMetadata {
            id: Uuid::from_slice(&id_bytes).unwrap_or_default(),
            name: row.get(1)?,
            size: row.get(2)?,
            compressed_size: row.get(3)?,
            created_at: row.get(4)?,
            folder_id: fid_bytes.and_then(|b| Uuid::from_slice(&b).ok()),
            checksum: row.get(6)?,
        })
    }

    pub fn list_folders(&self, parent_id: Option<Uuid>) -> Result<Vec<FolderMetadata>> {
        let mut stmt = match parent_id {
            Some(_) => self.conn.prepare("SELECT id, name, parent_id FROM folders WHERE parent_id = ?1 ORDER BY name ASC")?,
            None => self.conn.prepare("SELECT id, name, parent_id FROM folders WHERE parent_id IS NULL ORDER BY name ASC")?,
        };

        let rows = match parent_id {
            Some(pid) => stmt.query_map(params![pid.as_bytes().to_vec()], Self::parse_folder)?,
            None => stmt.query_map([], Self::parse_folder)?,
        };

        let mut folders = Vec::new();
        for r in rows {
            folders.push(r?);
        }
        Ok(folders)
    }

    pub fn list_files_query(
        &self,
        folder_id: Option<Uuid>,
        filter: Option<&str>,
        sort_col: SortColumn,
        sort_dir: SortDirection,
        limit: usize,
    ) -> Result<Vec<FileMetadata>> {
        let col_name = match sort_col {
            SortColumn::Name => "name",
            SortColumn::Size => "size",
            SortColumn::EncryptedSize => "compressed_size",
            SortColumn::Modified => "created_at",
        };
        let dir_sql = match sort_dir {
            SortDirection::Asc => "ASC",
            SortDirection::Desc => "DESC",
        };

        let mut files = Vec::new();

        if let Some(query) = filter {
            let search_pattern = format!("%{}%", query.trim());
            let sql = format!(
                "SELECT id, name, size, compressed_size, created_at, folder_id, checksum 
                 FROM files 
                 WHERE name LIKE ?1 
                 ORDER BY {} {} LIMIT ?2",
                col_name, dir_sql
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = stmt.query_map(params![search_pattern, limit], Self::parse_file)?;
            for r in rows { files.push(r?); }
        } else {
            let sql = match folder_id {
                Some(_) => format!(
                    "SELECT id, name, size, compressed_size, created_at, folder_id, checksum 
                     FROM files 
                     WHERE folder_id = ?1 
                     ORDER BY {} {} LIMIT ?2",
                    col_name, dir_sql
                ),
                None => format!(
                    "SELECT id, name, size, compressed_size, created_at, folder_id, checksum 
                     FROM files 
                     WHERE folder_id IS NULL 
                     ORDER BY {} {} LIMIT ?1",
                    col_name, dir_sql
                ),
            };
            let mut stmt = self.conn.prepare(&sql)?;
            let rows = match folder_id {
                Some(fid) => stmt.query_map(params![fid.as_bytes().to_vec(), limit], Self::parse_file)?,
                None => stmt.query_map(params![limit], Self::parse_file)?,
            };
            for r in rows { files.push(r?); }
        }

        Ok(files)
    }

    pub fn create_folder(&self, name: &str, parent_id: Option<Uuid>) -> Result<Uuid> {
        let folder_id = Uuid::new_v4();
        self.conn.execute(
            "INSERT INTO folders (id, name, parent_id) VALUES (?1, ?2, ?3)",
            params![folder_id.as_bytes(), name, parent_id.map(|id| id.as_bytes().to_vec())],
        )?;
        Ok(folder_id)
    }

    pub fn stream_insert_file<P: AsRef<Path>, F>(
        &mut self,
        source_path: P,
        folder_id: Option<Uuid>,
        mut progress_cb: F,
    ) -> Result<Uuid>
    where
        F: FnMut(usize, usize),
    {
        const CHUNK_SIZE: usize = 1024 * 1024;
        let file_path = source_path.as_ref();
        let name = file_path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();

        let f = File::open(file_path)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let metadata = f
            .metadata()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let total_size = metadata.len() as usize;

        let mut reader = BufReader::with_capacity(CHUNK_SIZE, f);
        let file_id = Uuid::new_v4();
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let mut hasher = Hasher::new();
        let mut total_compressed = 0;

        let tx = self.conn.transaction()?;

        tx.execute(
            "INSERT INTO files (id, name, size, compressed_size, created_at, folder_id, checksum) 
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                file_id.as_bytes(),
                name,
                total_size,
                0,
                created_at,
                folder_id.map(|id| id.as_bytes().to_vec()),
                ""
            ],
        )?;

        {
            let mut chunk_stmt = tx.prepare(
                "INSERT INTO chunks (file_id, chunk_index, data) VALUES (?1, ?2, ?3)"
            )?;

            let mut buffer = vec![0u8; CHUNK_SIZE];
            let mut chunk_index = 0;
            let mut bytes_processed = 0;

            loop {
                let bytes_read = reader
                    .read(&mut buffer)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                if bytes_read == 0 {
                    break;
                }

                hasher.update(&buffer[..bytes_read]);

                let compressed = zstd::encode_all(&buffer[..bytes_read], 3)
                    .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
                total_compressed += compressed.len();

                chunk_stmt.execute(params![
                    file_id.as_bytes(),
                    chunk_index,
                    compressed
                ])?;

                bytes_processed += bytes_read;
                chunk_index += 1;
                progress_cb(bytes_processed, total_size);
            }
        }

        let checksum = hasher.finalize().to_hex().to_string();

        tx.execute(
            "UPDATE files SET compressed_size = ?1, checksum = ?2 WHERE id = ?3",
            params![total_compressed, checksum, file_id.as_bytes()],
        )?;

        tx.execute(
            "UPDATE vault_stats SET total_files = total_files + 1, total_bytes = total_bytes + ?1, compressed_bytes = compressed_bytes + ?2 WHERE id = 1",
            params![total_size, total_compressed],
        )?;

        tx.commit()?;
        Ok(file_id)
    }

    pub fn stream_export_file<P: AsRef<Path>, F>(
        &self,
        file_id: Uuid,
        target_path: P,
        total_size: usize,
        mut progress_cb: F,
    ) -> Result<()>
    where
        F: FnMut(usize, usize),
    {
        let clean_path = sanitize_db_path(target_path);
        let f = File::create(clean_path)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        let mut writer = BufWriter::with_capacity(1024 * 1024, f);

        let mut stmt = self.conn.prepare(
            "SELECT data FROM chunks WHERE file_id = ?1 ORDER BY chunk_index ASC"
        )?;
        let mut rows = stmt.query(params![file_id.as_bytes()])?;

        let mut bytes_processed = 0;
        while let Some(row) = rows.next()? {
            let compressed_chunk: Vec<u8> = row.get(0)?;
            let raw_chunk = zstd::decode_all(&compressed_chunk[..])
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            writer
                .write_all(&raw_chunk)
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            bytes_processed += raw_chunk.len();
            progress_cb(bytes_processed, total_size);
        }

        writer
            .flush()
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
        Ok(())
    }

    pub fn load_file_preview_bytes(&self, file_id: Uuid, max_bytes: usize) -> Result<Vec<u8>> {
        let mut stmt = self.conn.prepare(
            "SELECT data FROM chunks WHERE file_id = ?1 ORDER BY chunk_index ASC"
        )?;
        let mut rows = stmt.query(params![file_id.as_bytes()])?;
        let mut collected = Vec::new();

        while let Some(row) = rows.next()? {
            let compressed_chunk: Vec<u8> = row.get(0)?;
            let raw_chunk = zstd::decode_all(&compressed_chunk[..])
                .map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;

            collected.extend_from_slice(&raw_chunk);
            if collected.len() >= max_bytes {
                collected.truncate(max_bytes);
                break;
            }
        }
        Ok(collected)
    }

    pub fn verify_integrity<F>(&self, mut progress_cb: F) -> Result<Vec<(String, bool)>>
    where
        F: FnMut(usize, usize, &str),
    {
        let mut stmt = self.conn.prepare("SELECT id, name, checksum FROM files")?;
        let rows = stmt.query_map([], |r| {
            let id_b: Vec<u8> = r.get(0)?;
            Ok((
                Uuid::from_slice(&id_b).unwrap_or_default(),
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;

        let file_list: Vec<_> = rows.filter_map(|x| x.ok()).collect();
        let total = file_list.len();
        let mut results = Vec::new();

        for (i, (fid, name, stored_hash)) in file_list.into_iter().enumerate() {
            progress_cb(i + 1, total, &name);

            let mut chunk_stmt = self.conn.prepare(
                "SELECT data FROM chunks WHERE file_id = ?1 ORDER BY chunk_index ASC"
            )?;
            let mut chunk_rows = chunk_stmt.query(params![fid.as_bytes()])?;
            let mut hasher = Hasher::new();
            let mut valid = true;

            while let Some(cr) = chunk_rows.next()? {
                let compressed: Vec<u8> = cr.get(0)?;
                match zstd::decode_all(&compressed[..]) {
                    Ok(decompressed) => {
                        hasher.update(&decompressed);
                    }
                    Err(_) => {
                        valid = false;
                        break;
                    }
                }
            }

            if valid {
                let computed = hasher.finalize().to_hex().to_string();
                results.push((name, computed == stored_hash));
            } else {
                results.push((name, false));
            }
        }

        Ok(results)
    }

    pub fn rename_item(&self, id: Uuid, new_name: &str, is_folder: bool) -> Result<()> {
        let table = if is_folder { "folders" } else { "files" };
        let sql = format!("UPDATE {} SET name = ?1 WHERE id = ?2", table);
        self.conn.execute(&sql, params![new_name, id.as_bytes()])?;
        Ok(())
    }

    pub fn delete_item(&self, id: Uuid, is_folder: bool) -> Result<()> {
        let tx = self.conn.unchecked_transaction()?;

        if !is_folder {
            let (file_size, comp_size): (usize, usize) = tx.query_row(
                "SELECT size, compressed_size FROM files WHERE id = ?1",
                params![id.as_bytes()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).unwrap_or((0, 0));

            tx.execute("DELETE FROM files WHERE id = ?1", params![id.as_bytes()])?;
            tx.execute(
                "UPDATE vault_stats SET total_files = total_files - 1, total_bytes = total_bytes - ?1, compressed_bytes = compressed_bytes - ?2 WHERE id = 1",
                params![file_size, comp_size],
            )?;
        } else {
            tx.execute(
                "WITH RECURSIVE subfolders(fid) AS (
                    SELECT id FROM folders WHERE id = ?1
                    UNION ALL
                    SELECT f.id FROM folders f JOIN subfolders s ON f.parent_id = s.fid
                )
                UPDATE vault_stats SET 
                    total_files = total_files - (SELECT COUNT(*) FROM files WHERE folder_id IN (SELECT fid FROM subfolders)),
                    total_bytes = total_bytes - COALESCE((SELECT SUM(size) FROM files WHERE folder_id IN (SELECT fid FROM subfolders)), 0),
                    compressed_bytes = compressed_bytes - COALESCE((SELECT SUM(compressed_size) FROM files WHERE folder_id IN (SELECT fid FROM subfolders)), 0)
                WHERE id = 1",
                params![id.as_bytes()],
            )?;

            tx.execute("DELETE FROM folders WHERE id = ?1", params![id.as_bytes()])?;
        }

        tx.commit()?;
        Ok(())
    }
}