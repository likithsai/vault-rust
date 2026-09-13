use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[derive(Clone, Debug, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EncryptedFile {
    #[zeroize(skip)]
    pub id: Uuid,
    #[zeroize(skip)]
    pub file_name: String,
    #[zeroize(skip)]
    pub file_size_bytes: usize,
    // Sensitive file contents are zeroized in RAM on drop
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VaultData {
    pub files: Vec<EncryptedFile>,
}

impl VaultData {
    pub fn add_file(&mut self, file_name: String, data: Vec<u8>) -> Uuid {
        let id = Uuid::new_v4();
        let file_size_bytes = data.len();
        self.files.push(EncryptedFile {
            id,
            file_name,
            file_size_bytes,
            data,
        });
        id
    }

    pub fn rename_file(&mut self, id: Uuid, new_name: String) -> bool {
        if let Some(f) = self.files.iter_mut().find(|f| f.id == id) {
            f.file_name = new_name;
            true
        } else {
            false
        }
    }

    pub fn delete_file(&mut self, id: Uuid) -> bool {
        let initial_len = self.files.len();
        self.files.retain(|f| f.id != id);
        self.files.len() < initial_len
    }
}