use aes::Aes256;
use byteorder::{LittleEndian, ReadBytesExt};
use cipher::{BlockCipherDecrypt, KeyInit as _};
use std::{
    fs,
    io::{self, Cursor, Read, Seek},
};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

trait ReadBytes: Read {
    fn read_bytes(&mut self, n_bytes: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; n_bytes];
        self.read_exact(&mut buffer)?;
        Ok(buffer)
    }

    // doesnt return words, just calculation helper
    fn read_words(&mut self, n_words: usize) -> io::Result<Vec<u8>> {
        self.read_bytes(n_words * 2)
    }
}

impl<T: Read + ?Sized> ReadBytes for T {}

trait Deserializable: Sized {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self>;
}

#[derive(Debug)]
struct FGuid {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl Deserializable for FGuid {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            a: reader.read_u32::<LittleEndian>()?,
            b: reader.read_u32::<LittleEndian>()?,
            c: reader.read_u32::<LittleEndian>()?,
            d: reader.read_u32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
struct FString {
    inner: String,
    is_unicode: bool,
}

impl Deserializable for FString {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        let length = reader.read_i32::<LittleEndian>()?;
        let is_unicode = length < 0;

        let decoded = if is_unicode {
            let n_words = -length as usize;

            let mut raw = Cursor::new(reader.read_words(n_words)?);
            let mut utf16s = Vec::with_capacity(n_words);
            // - 1 for null terminator
            for _ in 0..(n_words - 1) {
                let word = raw.read_u16::<LittleEndian>()?;
                utf16s.push(word);
            }

            String::from_utf16(&utf16s)?
        } else {
            let n_letters = length as usize;
            let mut raw = reader.read_bytes(n_letters)?;
            raw.pop(); // null terminator
            String::from_utf8(raw)?
        };

        Ok(Self {
            inner: decoded,
            is_unicode,
        })
    }
}

#[derive(Debug)]
struct TArray<T: Deserializable> {
    inner: Vec<T>,
}

impl<T: Deserializable> Deserializable for TArray<T> {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        let length = reader.read_i32::<LittleEndian>()? as usize;
        let mut list = Vec::with_capacity(length);
        for _ in 0..length {
            let element = T::deserialize(reader)?;
            list.push(element);
        }

        Ok(Self { inner: list })
    }
}

impl Deserializable for i32 {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        let val = reader.read_i32::<LittleEndian>()?;
        Ok(val)
    }
}

#[derive(Debug)]
struct FGenerationInfo {
    export_count: i32,
    name_count: i32,
    net_object_count: i32,
}

impl Deserializable for FGenerationInfo {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            export_count: reader.read_i32::<LittleEndian>()?,
            name_count: reader.read_i32::<LittleEndian>()?,
            net_object_count: reader.read_i32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
struct FCompressedChunkInfo {
    uncompressed_offset: i64,
    uncompressed_size: i32,
    compressed_offset: i64,
    compressed_size: i32,
}

impl Deserializable for FCompressedChunkInfo {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            uncompressed_offset: reader.read_i64::<LittleEndian>()?,
            uncompressed_size: reader.read_i32::<LittleEndian>()?,
            compressed_offset: reader.read_i64::<LittleEndian>()?,
            compressed_size: reader.read_i32::<LittleEndian>()?,
        })
    }
}

// nobody knows
#[derive(Debug)]
struct FUnknownTypeInFPackageFileSummary {
    unknown_1: i32,
    unknown_2: i32,
    unknown_3: i32,
    unknown_4: i32,
    unknown_5: i32,
    unknown_6: TArray<i32>,
}

impl Deserializable for FUnknownTypeInFPackageFileSummary {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            unknown_1: reader.read_i32::<LittleEndian>()?,
            unknown_2: reader.read_i32::<LittleEndian>()?,
            unknown_3: reader.read_i32::<LittleEndian>()?,
            unknown_4: reader.read_i32::<LittleEndian>()?,
            unknown_5: reader.read_i32::<LittleEndian>()?,
            unknown_6: TArray::deserialize(reader)?,
        })
    }
}

const PACKAGE_FILE_TAG: u32 = 0x9E2A83C1;

#[derive(Debug)]
struct FPackageFileSummary {
    tag: u32,
    file_version: u16,
    licensee_version: u16,
    total_header_size: i32,
    folder_name: FString,
    package_flags: u32,

    name_count: i32,
    name_offset: i32,
    export_count: i32,
    export_offset: i32,
    import_count: i32,
    import_offset: i32,
    depends_offset: i32,

    unknown_1: i32,
    unknown_2: i32,
    unknown_3: i32,
    unknown_4: i32,

    guid: FGuid,
    generations: TArray<FGenerationInfo>,

    engine_version: u32,
    cooker_version: u32,
    _compression_flags: i32, // bitmask but it doesnt matter

    compressed_chunks: TArray<FCompressedChunkInfo>,
    unknown_5: i32,

    unknown_6: TArray<FString>,
    unknown_7: TArray<FUnknownTypeInFPackageFileSummary>,

    garbage_size: i32,
    compressed_chunk_info_offset: i32,
    last_aes_block_size: i32,
}

impl Deserializable for FPackageFileSummary {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            tag: reader.read_u32::<LittleEndian>()?,
            file_version: reader.read_u16::<LittleEndian>()?,
            licensee_version: reader.read_u16::<LittleEndian>()?,
            total_header_size: reader.read_i32::<LittleEndian>()?,
            folder_name: FString::deserialize(reader)?,
            package_flags: reader.read_u32::<LittleEndian>()?,

            name_count: reader.read_i32::<LittleEndian>()?,
            name_offset: reader.read_i32::<LittleEndian>()?,
            export_count: reader.read_i32::<LittleEndian>()?,
            export_offset: reader.read_i32::<LittleEndian>()?,
            import_count: reader.read_i32::<LittleEndian>()?,
            import_offset: reader.read_i32::<LittleEndian>()?,
            depends_offset: reader.read_i32::<LittleEndian>()?,

            unknown_1: reader.read_i32::<LittleEndian>()?,
            unknown_2: reader.read_i32::<LittleEndian>()?,
            unknown_3: reader.read_i32::<LittleEndian>()?,
            unknown_4: reader.read_i32::<LittleEndian>()?,

            guid: FGuid::deserialize(reader)?,
            generations: TArray::deserialize(reader)?,

            engine_version: reader.read_u32::<LittleEndian>()?,
            cooker_version: reader.read_u32::<LittleEndian>()?,
            _compression_flags: reader.read_i32::<LittleEndian>()?,

            compressed_chunks: TArray::deserialize(reader)?,
            unknown_5: reader.read_i32::<LittleEndian>()?,

            unknown_6: TArray::deserialize(reader)?,
            unknown_7: TArray::deserialize(reader)?,

            garbage_size: reader.read_i32::<LittleEndian>()?,
            compressed_chunk_info_offset: reader.read_i32::<LittleEndian>()?,
            last_aes_block_size: reader.read_i32::<LittleEndian>()?,
        })
    }
}

const AES_KEY: [u8; 32] = [
    0xC7, 0xDF, 0x6B, 0x13, 0x25, 0x2A, 0xCC, 0x71, 0x47, 0xBB, 0x51, 0xC9, 0x8A, 0xD7, 0xE3, 0x4B,
    0x7F, 0xE5, 0x00, 0xB7, 0x7F, 0xA5, 0xFA, 0xB2, 0x93, 0xE2, 0xF2, 0x4E, 0x6B, 0x17, 0xE7, 0x79,
];

// note: in-place
fn decrypt(buffer: &mut [u8]) {
    let cipher = Aes256::new((&AES_KEY).into());
    for chunk in buffer.chunks_exact_mut(16) {
        cipher.decrypt_block(chunk.try_into().unwrap());
    }
}

#[derive(Debug)]
struct FNameRef {
    name_index: i32,
    instance_number: i32,
}

impl Deserializable for FNameRef {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            name_index: reader.read_i32::<LittleEndian>()?,
            instance_number: reader.read_i32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
struct FImportEntry {
    class_package: FNameRef,
    class_name: FNameRef,
    outer_index: i32,
    object_name: FNameRef,
}

impl Deserializable for FImportEntry {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            class_package: FNameRef::deserialize(reader)?,
            class_name: FNameRef::deserialize(reader)?,
            outer_index: reader.read_i32::<LittleEndian>()?,
            object_name: FNameRef::deserialize(reader)?,
        })
    }
}

#[derive(Debug)]
struct FNameEntry {
    name: FString,
    flags: u64,
}

impl Deserializable for FNameEntry {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            name: FString::deserialize(reader)?,
            flags: reader.read_u64::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
struct FExportEntry {
    class_index: i32,
    super_index: i32,
    outer_index: i32,
    object_name: FNameRef,
    archetype_index: i32,
    object_flags: u64,
    serial_size: i32,
    serial_offset: i64,
    export_flags: i32,
    net_objects: TArray<i32>,
    package_guid: FGuid,
    package_flags: i32,
}

impl Deserializable for FExportEntry {
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            class_index: reader.read_i32::<LittleEndian>()?,
            super_index: reader.read_i32::<LittleEndian>()?,
            outer_index: reader.read_i32::<LittleEndian>()?,
            object_name: FNameRef::deserialize(reader)?,
            archetype_index: reader.read_i32::<LittleEndian>()?,
            object_flags: reader.read_u64::<LittleEndian>()?,
            serial_size: reader.read_i32::<LittleEndian>()?,
            serial_offset: reader.read_i64::<LittleEndian>()?,
            export_flags: reader.read_i32::<LittleEndian>()?,
            net_objects: TArray::deserialize(reader)?,
            package_guid: FGuid::deserialize(reader)?,
            package_flags: reader.read_i32::<LittleEndian>()?,
        })
    }
}

#[derive(Debug)]
struct Upk {
    summary: FPackageFileSummary,
    names: Vec<FNameEntry>,
    imports: Vec<FImportEntry>,
    exports: Vec<FExportEntry>,
}

impl Upk {
    fn new(mut reader: impl Read + Seek) -> AnyResult<Self> {
        let summary = FPackageFileSummary::deserialize(&mut reader)?;
        if summary.tag == PACKAGE_FILE_TAG {
            println!("package tag is correct :)");
        } else {
            println!("package tag is incorrect :( (got {})", summary.tag);
            return Err("Package tag is incorrect".into());
        }

        let actual_encrypted_size =
            summary.total_header_size - summary.garbage_size - summary.name_offset;
        let encrypted_size = (actual_encrypted_size + 15) & !15; // roudns up to nearest aes block
        reader.seek(io::SeekFrom::Start(summary.name_offset as u64))?;
        let mut package = vec![0u8; encrypted_size as usize];

        reader.read_exact(&mut package)?;
        decrypt(&mut package);

        let mut reader = Cursor::new(package);

        // after this point, the summary offsets are wrong because the reader's ZERO is
        // actually summary.name_offset. so, we have to subtract summary.name_offset for stuff

        let mut names = Vec::with_capacity(summary.name_count as usize);
        for _ in 0..summary.name_count {
            let entry = FNameEntry::deserialize(&mut reader)?;
            names.push(entry);
        }

        reader.seek(io::SeekFrom::Start(
            (summary.import_offset - summary.name_offset) as u64,
        ))?;
        let mut imports = Vec::with_capacity(summary.import_count as usize);
        for _ in 0..summary.import_count {
            let entry = FImportEntry::deserialize(&mut reader)?;
            imports.push(entry);
        }

        reader.seek(io::SeekFrom::Start(
            (summary.export_offset - summary.name_offset) as u64,
        ))?;
        let mut exports = Vec::with_capacity(summary.export_count as usize);
        for _ in 0..summary.export_count {
            let entry = FExportEntry::deserialize(&mut reader)?;
            exports.push(entry);
        }

        Ok(Self {
            summary,
            names,
            imports,
            exports,
        })
    }
}

fn main() -> AnyResult<()> {
    let upk = Upk::new(fs::File::open("body_grain_SF.upk")?)?;
    println!("{:#?}", upk.names);

    Ok(())
}
