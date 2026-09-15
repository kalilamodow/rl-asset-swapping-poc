use aes::Aes256;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt as _};
use cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit as _};
use std::{
    fs,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

trait ReadBytes: Read {
    fn read_bytes(&mut self, n_bytes: usize) -> io::Result<Vec<u8>> {
        let mut buffer = vec![0u8; n_bytes];
        self.read_exact(&mut buffer).unwrap();
        Ok(buffer)
    }

    // doesnt return words, just calculation helper
    fn read_words(&mut self, n_words: usize) -> io::Result<Vec<u8>> {
        self.read_bytes(n_words * 2)
    }
}

impl<T: Read + ?Sized> ReadBytes for T {}

trait UPKPart: Sized {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()>;
    fn deserialize(reader: &mut impl Read) -> AnyResult<Self>;
}

#[derive(Debug, Clone)]
struct FGuid {
    a: u32,
    b: u32,
    c: u32,
    d: u32,
}

impl UPKPart for FGuid {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer.write_u32::<LittleEndian>(self.a).unwrap();
        writer.write_u32::<LittleEndian>(self.b).unwrap();
        writer.write_u32::<LittleEndian>(self.c).unwrap();
        writer.write_u32::<LittleEndian>(self.d).unwrap();
        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            a: reader.read_u32::<LittleEndian>().unwrap(),
            b: reader.read_u32::<LittleEndian>().unwrap(),
            c: reader.read_u32::<LittleEndian>().unwrap(),
            d: reader.read_u32::<LittleEndian>().unwrap(),
        })
    }
}

#[derive(Debug, Clone)]
struct FString {
    inner: String,
    is_unicode: bool,
}

impl UPKPart for FString {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        if self.is_unicode {
            let utf16: Vec<_> = self.inner.encode_utf16().collect();
            writer
                .write_i32::<LittleEndian>(-i32::try_from(utf16.len() + 1).unwrap())
                .unwrap();

            for word in utf16 {
                writer.write_u16::<LittleEndian>(word).unwrap();
            }

            // null terminator
            writer.write_u16::<LittleEndian>(0).unwrap();
        } else {
            let utf8 = self.inner.as_bytes();
            writer
                .write_i32::<LittleEndian>(i32::try_from(utf8.len() + 1).unwrap())
                .unwrap();
            for byte in utf8 {
                writer.write_u8(*byte).unwrap();
            }
            writer.write_u8(0).unwrap();
        }

        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        let length = reader.read_i32::<LittleEndian>().unwrap();
        let is_unicode = length < 0;

        let decoded = if is_unicode {
            let n_words = -length as usize;

            let mut raw = Cursor::new(reader.read_words(n_words).unwrap());
            let mut utf16s = Vec::with_capacity(n_words);
            // - 1 for null terminator
            for _ in 0..(n_words - 1) {
                let word = raw.read_u16::<LittleEndian>().unwrap();
                utf16s.push(word);
            }

            String::from_utf16(&utf16s).unwrap()
        } else {
            let n_letters = length as usize;
            let mut raw = reader.read_bytes(n_letters).unwrap();
            raw.pop(); // null terminator
            String::from_utf8(raw).unwrap()
        };

        Ok(Self {
            inner: decoded,
            is_unicode,
        })
    }
}

#[derive(Debug, Clone)]
struct TArray<T: UPKPart> {
    inner: Vec<T>,
}

impl<T: UPKPart> UPKPart for TArray<T> {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer
            .write_i32::<LittleEndian>(self.inner.len() as i32)
            .unwrap();
        for element in &self.inner {
            element.serialize(writer).unwrap();
        }

        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        let length = reader.read_i32::<LittleEndian>().unwrap() as usize;
        let mut list = Vec::with_capacity(length);
        for _ in 0..length {
            let element = T::deserialize(reader).unwrap();
            list.push(element);
        }

        Ok(Self { inner: list })
    }
}

impl UPKPart for i32 {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer.write_i32::<LittleEndian>(*self).unwrap();
        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        let val = reader.read_i32::<LittleEndian>().unwrap();
        Ok(val)
    }
}

#[derive(Debug, Clone)]
struct FGenerationInfo {
    export_count: i32,
    name_count: i32,
    net_object_count: i32,
}

impl UPKPart for FGenerationInfo {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer.write_i32::<LittleEndian>(self.export_count).unwrap();
        writer.write_i32::<LittleEndian>(self.name_count).unwrap();
        writer
            .write_i32::<LittleEndian>(self.net_object_count)
            .unwrap();

        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            export_count: reader.read_i32::<LittleEndian>().unwrap(),
            name_count: reader.read_i32::<LittleEndian>().unwrap(),
            net_object_count: reader.read_i32::<LittleEndian>().unwrap(),
        })
    }
}

#[derive(Debug, Clone)]
struct FCompressedChunkInfo {
    uncompressed_offset: i64,
    uncompressed_size: i32,
    compressed_offset: i64,
    compressed_size: i32,
}

impl UPKPart for FCompressedChunkInfo {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer
            .write_i64::<LittleEndian>(self.uncompressed_offset)
            .unwrap();
        writer
            .write_i32::<LittleEndian>(self.uncompressed_size)
            .unwrap();
        writer
            .write_i64::<LittleEndian>(self.compressed_offset)
            .unwrap();
        writer
            .write_i32::<LittleEndian>(self.compressed_size)
            .unwrap();
        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            uncompressed_offset: reader.read_i64::<LittleEndian>().unwrap(),
            uncompressed_size: reader.read_i32::<LittleEndian>().unwrap(),
            compressed_offset: reader.read_i64::<LittleEndian>().unwrap(),
            compressed_size: reader.read_i32::<LittleEndian>().unwrap(),
        })
    }
}

// i dont know why this is necessary, but by analyzing it seems to match up.
// it's an array of the same length as FCompressedChunkInfo, not a TArray
// It occurs right after TArray<FCompressedChunkInfo> in the encrypted region
// DO NOT adjust the offsets afaik
// this exists in Summary licensee version 33 but not 32 afaik
#[derive(Debug, Clone)]
struct FCompressedChunkAdditionalInfo {
    offset: i64,
    size: i32,
}

impl UPKPart for FCompressedChunkAdditionalInfo {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer.write_i64::<LittleEndian>(self.offset).unwrap();
        writer.write_i32::<LittleEndian>(self.size).unwrap();
        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            offset: reader.read_i64::<LittleEndian>().unwrap(),
            size: reader.read_i32::<LittleEndian>().unwrap(),
        })
    }
}

// nobody knows
#[derive(Debug, Clone)]
struct FUnknownTypeInFPackageFileSummary {
    unknown_1: i32,
    unknown_2: i32,
    unknown_3: i32,
    unknown_4: i32,
    unknown_5: i32,
    unknown_6: TArray<i32>,
}

impl UPKPart for FUnknownTypeInFPackageFileSummary {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer.write_i32::<LittleEndian>(self.unknown_1).unwrap();
        writer.write_i32::<LittleEndian>(self.unknown_2).unwrap();
        writer.write_i32::<LittleEndian>(self.unknown_3).unwrap();
        writer.write_i32::<LittleEndian>(self.unknown_4).unwrap();
        writer.write_i32::<LittleEndian>(self.unknown_5).unwrap();
        TArray::serialize(&self.unknown_6, writer).unwrap();

        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            unknown_1: reader.read_i32::<LittleEndian>().unwrap(),
            unknown_2: reader.read_i32::<LittleEndian>().unwrap(),
            unknown_3: reader.read_i32::<LittleEndian>().unwrap(),
            unknown_4: reader.read_i32::<LittleEndian>().unwrap(),
            unknown_5: reader.read_i32::<LittleEndian>().unwrap(),
            unknown_6: TArray::deserialize(reader).unwrap(),
        })
    }
}

const PACKAGE_FILE_TAG: u32 = 0x9E2A83C1;

#[derive(Debug, Clone)]
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

impl UPKPart for FPackageFileSummary {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer.write_u32::<LittleEndian>(self.tag).unwrap();
        writer.write_u16::<LittleEndian>(self.file_version).unwrap();
        writer
            .write_u16::<LittleEndian>(self.licensee_version)
            .unwrap();
        writer
            .write_i32::<LittleEndian>(self.total_header_size)
            .unwrap();
        FString::serialize(&self.folder_name, writer).unwrap();
        writer
            .write_u32::<LittleEndian>(self.package_flags)
            .unwrap();

        writer.write_i32::<LittleEndian>(self.name_count).unwrap();
        writer.write_i32::<LittleEndian>(self.name_offset).unwrap();
        writer.write_i32::<LittleEndian>(self.export_count).unwrap();
        writer
            .write_i32::<LittleEndian>(self.export_offset)
            .unwrap();
        writer.write_i32::<LittleEndian>(self.import_count).unwrap();
        writer
            .write_i32::<LittleEndian>(self.import_offset)
            .unwrap();
        writer
            .write_i32::<LittleEndian>(self.depends_offset)
            .unwrap();

        writer.write_i32::<LittleEndian>(self.unknown_1).unwrap();
        writer.write_i32::<LittleEndian>(self.unknown_2).unwrap();
        writer.write_i32::<LittleEndian>(self.unknown_3).unwrap();
        writer.write_i32::<LittleEndian>(self.unknown_4).unwrap();

        FGuid::serialize(&self.guid, writer).unwrap();
        TArray::serialize(&self.generations, writer).unwrap();

        writer
            .write_u32::<LittleEndian>(self.engine_version)
            .unwrap();
        writer
            .write_u32::<LittleEndian>(self.cooker_version)
            .unwrap();
        writer
            .write_i32::<LittleEndian>(self._compression_flags)
            .unwrap();

        TArray::serialize(&self.compressed_chunks, writer).unwrap();
        writer.write_i32::<LittleEndian>(self.unknown_5).unwrap();

        TArray::serialize(&self.unknown_6, writer).unwrap();
        TArray::serialize(&self.unknown_7, writer).unwrap();

        writer.write_i32::<LittleEndian>(self.garbage_size).unwrap();
        writer
            .write_i32::<LittleEndian>(self.compressed_chunk_info_offset)
            .unwrap();
        writer
            .write_i32::<LittleEndian>(self.last_aes_block_size)
            .unwrap();

        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            tag: reader.read_u32::<LittleEndian>().unwrap(),
            file_version: reader.read_u16::<LittleEndian>().unwrap(),
            licensee_version: reader.read_u16::<LittleEndian>().unwrap(),
            total_header_size: reader.read_i32::<LittleEndian>().unwrap(),
            folder_name: FString::deserialize(reader).unwrap(),
            package_flags: reader.read_u32::<LittleEndian>().unwrap(),

            name_count: reader.read_i32::<LittleEndian>().unwrap(),
            name_offset: reader.read_i32::<LittleEndian>().unwrap(),
            export_count: reader.read_i32::<LittleEndian>().unwrap(),
            export_offset: reader.read_i32::<LittleEndian>().unwrap(),
            import_count: reader.read_i32::<LittleEndian>().unwrap(),
            import_offset: reader.read_i32::<LittleEndian>().unwrap(),
            depends_offset: reader.read_i32::<LittleEndian>().unwrap(),

            unknown_1: reader.read_i32::<LittleEndian>().unwrap(),
            unknown_2: reader.read_i32::<LittleEndian>().unwrap(),
            unknown_3: reader.read_i32::<LittleEndian>().unwrap(),
            unknown_4: reader.read_i32::<LittleEndian>().unwrap(),

            guid: FGuid::deserialize(reader).unwrap(),
            generations: TArray::deserialize(reader).unwrap(),

            engine_version: reader.read_u32::<LittleEndian>().unwrap(),
            cooker_version: reader.read_u32::<LittleEndian>().unwrap(),
            _compression_flags: reader.read_i32::<LittleEndian>().unwrap(),

            compressed_chunks: TArray::deserialize(reader).unwrap(),
            unknown_5: reader.read_i32::<LittleEndian>().unwrap(),

            unknown_6: TArray::deserialize(reader).unwrap(),
            unknown_7: TArray::deserialize(reader).unwrap(),

            garbage_size: reader.read_i32::<LittleEndian>().unwrap(),
            compressed_chunk_info_offset: reader.read_i32::<LittleEndian>().unwrap(),
            last_aes_block_size: reader.read_i32::<LittleEndian>().unwrap(),
        })
    }
}

const AES_KEY: [u8; 32] = [
    0xC7, 0xDF, 0x6B, 0x13, 0x25, 0x2A, 0xCC, 0x71, 0x47, 0xBB, 0x51, 0xC9, 0x8A, 0xD7, 0xE3, 0x4B,
    0x7F, 0xE5, 0x00, 0xB7, 0x7F, 0xA5, 0xFA, 0xB2, 0x93, 0xE2, 0xF2, 0x4E, 0x6B, 0x17, 0xE7, 0x79,
];

fn encrypt(buffer: &mut [u8]) {
    if buffer.len() % 16 != 0 {
        panic!("encryption: buffer size isnt divisible by 16!");
    }

    let cipher = Aes256::new((&AES_KEY).into());
    for chunk in buffer.chunks_exact_mut(16) {
        cipher.encrypt_block(chunk.try_into().unwrap());
    }
}

fn decrypt(buffer: &mut [u8]) {
    if buffer.len() % 16 != 0 {
        panic!("decryption: buffer size isnt divisible by 16!");
    }

    let cipher = Aes256::new((&AES_KEY).into());
    for chunk in buffer.chunks_exact_mut(16) {
        cipher.decrypt_block(chunk.try_into().unwrap());
    }
}

#[derive(Debug, Clone)]
struct FNameRef {
    name_index: i32,
    instance_number: i32,
}

impl UPKPart for FNameRef {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer.write_i32::<LittleEndian>(self.name_index).unwrap();
        writer
            .write_i32::<LittleEndian>(self.instance_number)
            .unwrap();
        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            name_index: reader.read_i32::<LittleEndian>().unwrap(),
            instance_number: reader.read_i32::<LittleEndian>().unwrap(),
        })
    }
}

#[derive(Debug, Clone)]
struct FImportEntry {
    class_package: FNameRef,
    class_name: FNameRef,
    outer_index: i32,
    object_name: FNameRef,
}

impl UPKPart for FImportEntry {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        FNameRef::serialize(&self.class_package, writer).unwrap();
        FNameRef::serialize(&self.class_name, writer).unwrap();
        writer.write_i32::<LittleEndian>(self.outer_index).unwrap();
        FNameRef::serialize(&self.object_name, writer).unwrap();

        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            class_package: FNameRef::deserialize(reader).unwrap(),
            class_name: FNameRef::deserialize(reader).unwrap(),
            outer_index: reader.read_i32::<LittleEndian>().unwrap(),
            object_name: FNameRef::deserialize(reader).unwrap(),
        })
    }
}

#[derive(Debug, Clone)]
struct FNameEntry {
    name: FString,
    flags: u64,
}

impl UPKPart for FNameEntry {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        FString::serialize(&self.name, writer).unwrap();
        writer.write_u64::<LittleEndian>(self.flags).unwrap();

        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            name: FString::deserialize(reader).unwrap(),
            flags: reader.read_u64::<LittleEndian>().unwrap(),
        })
    }
}

#[derive(Debug, Clone)]
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

impl UPKPart for FExportEntry {
    fn serialize(&self, writer: &mut impl Write) -> AnyResult<()> {
        writer.write_i32::<LittleEndian>(self.class_index).unwrap();
        writer.write_i32::<LittleEndian>(self.super_index).unwrap();
        writer.write_i32::<LittleEndian>(self.outer_index).unwrap();
        FNameRef::serialize(&self.object_name, writer).unwrap();
        writer
            .write_i32::<LittleEndian>(self.archetype_index)
            .unwrap();
        writer.write_u64::<LittleEndian>(self.object_flags).unwrap();
        writer.write_i32::<LittleEndian>(self.serial_size).unwrap();
        writer
            .write_i64::<LittleEndian>(self.serial_offset)
            .unwrap();
        writer.write_i32::<LittleEndian>(self.export_flags).unwrap();
        TArray::serialize(&self.net_objects, writer).unwrap();
        FGuid::serialize(&self.package_guid, writer).unwrap();
        writer
            .write_i32::<LittleEndian>(self.package_flags)
            .unwrap();

        Ok(())
    }

    fn deserialize(reader: &mut impl Read) -> AnyResult<Self> {
        Ok(Self {
            class_index: reader.read_i32::<LittleEndian>().unwrap(),
            super_index: reader.read_i32::<LittleEndian>().unwrap(),
            outer_index: reader.read_i32::<LittleEndian>().unwrap(),
            object_name: FNameRef::deserialize(reader).unwrap(),
            archetype_index: reader.read_i32::<LittleEndian>().unwrap(),
            object_flags: reader.read_u64::<LittleEndian>().unwrap(),
            serial_size: reader.read_i32::<LittleEndian>().unwrap(),
            serial_offset: reader.read_i64::<LittleEndian>().unwrap(),
            export_flags: reader.read_i32::<LittleEndian>().unwrap(),
            net_objects: TArray::deserialize(reader).unwrap(),
            package_guid: FGuid::deserialize(reader).unwrap(),
            package_flags: reader.read_i32::<LittleEndian>().unwrap(),
        })
    }
}

#[derive(Debug, Clone)]
struct FHeaderEncryptedRegion {
    names: Vec<FNameEntry>,
    imports: Vec<FImportEntry>,
    exports: Vec<FExportEntry>,
    compressed_chunk_info: TArray<FCompressedChunkInfo>,
    compressed_chunk_extra: Option<Vec<FCompressedChunkAdditionalInfo>>,
    read_region_size: i32,
}

impl FHeaderEncryptedRegion {
    fn extract(summary: &FPackageFileSummary, global_reader: &mut (impl Read + Seek)) -> Self {
        let actual_encrypted_size =
            summary.total_header_size - summary.garbage_size - summary.name_offset;
        let encrypted_size = (actual_encrypted_size + 15) & !15; // roudns up to nearest aes block

        global_reader
            .seek(SeekFrom::Start(summary.name_offset as u64))
            .unwrap();

        let mut tables_data = vec![0u8; encrypted_size as usize];
        global_reader.read_exact(&mut tables_data).unwrap();
        fs::write("encrypted_tables.bin", &tables_data).unwrap();
        decrypt(&mut tables_data);
        fs::write("decrypted_tables.bin", &tables_data).unwrap();

        println!("decrypted!");
        let mut tables_reader = Cursor::new(tables_data);

        let mut names = Vec::with_capacity(summary.name_count as usize);
        for _ in 0..summary.name_count {
            let entry = FNameEntry::deserialize(&mut tables_reader).unwrap();
            names.push(entry);
        }

        let mut imports = Vec::with_capacity(summary.import_count as usize);
        for _ in 0..summary.import_count {
            let entry = FImportEntry::deserialize(&mut tables_reader).unwrap();
            imports.push(entry);
        }

        let mut exports = Vec::with_capacity(summary.export_count as usize);
        for _ in 0..summary.export_count {
            let entry = FExportEntry::deserialize(&mut tables_reader).unwrap();
            exports.push(entry);
        }

        println!(
            "finished exports. current position: {}",
            tables_reader.stream_position().unwrap()
        );
        println!(
            "compressed chunk info position: {}",
            summary.compressed_chunk_info_offset
        );
        let compressed_chunk_info = TArray::deserialize(&mut tables_reader).unwrap();
        println!(
            "finished compressed info. current position: {}",
            tables_reader.stream_position().unwrap()
        );
        println!(
            "qty compressed chunks: {}",
            compressed_chunk_info.inner.len()
        );
        let compressed_chunk_extra = (summary.licensee_version > 32).then(|| {
            let mut compressed_chunk_extra = Vec::with_capacity(compressed_chunk_info.inner.len());
            for _ in 0..compressed_chunk_info.inner.len() {
                let info = FCompressedChunkAdditionalInfo::deserialize(&mut tables_reader).unwrap();
                compressed_chunk_extra.push(info);
            }
            println!(
                "compressed chunks: {:?}\nextra: {:?}",
                compressed_chunk_info, compressed_chunk_extra
            );
            compressed_chunk_extra
        });
        println!(
            "finished compressed chunk extra. current position: {}",
            tables_reader.stream_position().unwrap()
        );

        Self {
            names,
            imports,
            exports,
            compressed_chunk_info,
            compressed_chunk_extra,
            read_region_size: encrypted_size,
        }
    }

    fn re_encrypt(
        &self,
        summary_size: i32,
        summary_padding_size: i32,
        new_summary: &mut FPackageFileSummary,
    ) -> Vec<u8> {
        let mut header = Cursor::new(Vec::new());
        let global_to_local_offset = |offset: i32| offset - summary_padding_size - summary_size;
        let current_global_offset = |header: &mut Cursor<Vec<u8>>| {
            header.stream_position().unwrap() as i32 + summary_size + summary_padding_size
        };

        new_summary.name_offset = current_global_offset(&mut header);
        for name in &self.names {
            name.serialize(&mut header).unwrap();
        }

        new_summary.import_offset = current_global_offset(&mut header);
        for import in &self.imports {
            import.serialize(&mut header).unwrap();
        }

        new_summary.export_offset = current_global_offset(&mut header);
        for export in &self.exports {
            export.serialize(&mut header).unwrap();
        }

        println!(
            "serialized exports. stream position: {}",
            header.stream_position().unwrap()
        );
        new_summary.compressed_chunk_info_offset = header.stream_position().unwrap() as i32;
        new_summary.depends_offset = current_global_offset(&mut header);
        self.compressed_chunk_info.serialize(&mut header).unwrap();

        if let Some(compressed_chunk_extra) = &self.compressed_chunk_extra {
            for extra in compressed_chunk_extra {
                extra.serialize(&mut header).unwrap();
            }
        }

        header.write(&[0u8; 1000]).unwrap(); // yay this can be whatever

        // aes padding
        let new_header_size = header.position();
        let new_header_size_full = (new_header_size + 15) & !15;
        for i in 0..dbg!(new_header_size_full - new_header_size) {
            let pos = new_header_size + i;
            let byte = (pos % 0xFF) as u8;
            header.write_u8(byte).unwrap();
        }

        let header_size_change = new_header_size_full as i32 - self.read_region_size;

        new_summary.total_header_size =
            new_header_size as i32 + new_summary.garbage_size + new_summary.name_offset;

        println!("header size changed by {header_size_change}");
        let mut new_exports = self.exports.clone();
        for export in &mut new_exports {
            export.serial_offset += header_size_change as i64;
        }
        header.set_position(global_to_local_offset(new_summary.export_offset) as u64);
        for export in new_exports {
            export.serialize(&mut header).unwrap();
        }

        header.set_position(new_summary.compressed_chunk_info_offset as u64);
        let mut new_compressed_chunk_info = self.compressed_chunk_info.clone();
        for chunk in &mut new_compressed_chunk_info.inner {
            chunk.compressed_offset += header_size_change as i64;

            // idk why but if you do the one with 0 size it freezes the game
            if chunk.uncompressed_size != 0 {
                chunk.uncompressed_offset += header_size_change as i64;
            }
        }
        new_compressed_chunk_info.serialize(&mut header).unwrap();

        if let Some(compressed_chunk_extra) = &self.compressed_chunk_extra {
            let mut new_compressed_chunk_extra = compressed_chunk_extra.clone();
            for extra in &mut new_compressed_chunk_extra {
                extra.offset += header_size_change as i64;
            }

            for extra in new_compressed_chunk_extra {
                extra.serialize(&mut header).unwrap();
            }
        }

        let mut header = header.into_inner();
        fs::write("decrypted_tables_my_own.bin", &header).unwrap();
        encrypt(&mut header);
        fs::write("encrypted_tables_my_own.bin", &header).unwrap();
        header
    }
}

#[derive(Debug)]
struct Upk {
    summary: FPackageFileSummary,
    decrypted: FHeaderEncryptedRegion,
    compressed_data: Vec<u8>,
}

impl Upk {
    fn new(mut reader: impl Read + Seek) -> AnyResult<Self> {
        let summary = FPackageFileSummary::deserialize(&mut reader).unwrap();
        println!("{summary:#?}");
        if summary.tag == PACKAGE_FILE_TAG {
            println!("package tag is correct :)");
        } else {
            println!("package tag is incorrect :( (got {})", summary.tag);
            return Err("Package tag is incorrect".into());
        }

        let decrypted = FHeaderEncryptedRegion::extract(&summary, &mut reader);

        // remaining data just after tables
        let tables_end = summary.name_offset + decrypted.read_region_size;
        let mut compressed_data = Vec::new();
        reader.seek(SeekFrom::Start(tables_end as u64)).unwrap();
        reader.read_to_end(&mut compressed_data).unwrap();

        fs::write("compressed.bin", &compressed_data).unwrap();

        Ok(Self {
            summary,
            decrypted,
            compressed_data,
        })
    }

    fn serialize(&self) -> AnyResult<Vec<u8>> {
        let summary_size = {
            let mut serialized_summary = Vec::new();
            self.summary.serialize(&mut serialized_summary).unwrap();
            serialized_summary.len()
        };
        let mut modified_summary = self.summary.clone(); // will perform surgery after
        let summary_padding_size = self.summary.name_offset - summary_size as i32;

        let encrypted_header = self.decrypted.re_encrypt(
            summary_size as i32,
            summary_padding_size,
            &mut modified_summary,
        );

        let mut serialized = Vec::new();
        modified_summary.serialize(&mut serialized).unwrap();
        serialized.extend(vec![0u8; summary_padding_size as usize]);
        fs::write("summary_my_own.bin", &serialized).unwrap();
        serialized.write(&encrypted_header).unwrap();
        serialized.write(&self.compressed_data).unwrap();

        Ok(serialized)
    }
}

fn main() -> AnyResult<()> {
    // let bubbles = Upk::new(fs::File::open("boost_Bubble_SF.upk").unwrap()).unwrap();
    // let bubbles = Upk::new(fs::File::open("boost_Bubble_SF_2.upk").unwrap()).unwrap();

    let upk = Upk::new(fs::File::open("boost_bubble_sf.upk").unwrap()).unwrap();
    let serialized = upk.serialize().unwrap();
    fs::write("boost_bubble_sf_2.upk", &serialized).unwrap();

    Ok(())
}
