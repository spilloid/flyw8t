/// Minimal PE headers and data for the offline version reader, with no executable code.
pub fn versioned_image(version: &str) -> Vec<u8> {
    const PE_START: usize = 64;
    const OPTIONAL_START: usize = PE_START + 24;
    const OPTIONAL_SIZE: u16 = 240;
    const SECTION_START: usize = OPTIONAL_START + OPTIONAL_SIZE as usize;
    const DATA_START: u32 = 512;

    let mut image = vec![0; DATA_START as usize];
    image[..2].copy_from_slice(b"MZ");
    image[0x3c..0x40].copy_from_slice(&(PE_START as u32).to_le_bytes());
    let pe = &mut image[PE_START..OPTIONAL_START];
    pe[..6].copy_from_slice(b"PE\0\0\x64\x86");
    pe[6..8].copy_from_slice(&1u16.to_le_bytes());
    pe[20..22].copy_from_slice(&OPTIONAL_SIZE.to_le_bytes());
    let optional = &mut image[OPTIONAL_START..SECTION_START];
    optional[..2].copy_from_slice(b"\x0b\x02");
    optional[60..64].copy_from_slice(&DATA_START.to_le_bytes());
    optional[108..112].copy_from_slice(&16u32.to_le_bytes());

    let size = (version.len() + 1) as u32;
    let section = &mut image[SECTION_START..SECTION_START + 40];
    section[..8].copy_from_slice(b".fw8tver");
    section[8..12].copy_from_slice(&size.to_le_bytes());
    section[16..20].copy_from_slice(&size.to_le_bytes());
    section[20..24].copy_from_slice(&DATA_START.to_le_bytes());
    section[36..40].copy_from_slice(&0x4000_0040u32.to_le_bytes());

    image.extend_from_slice(version.as_bytes());
    image.push(0);
    image.extend_from_slice(b"FLYW8T_WINDOWS_ENROLLMENT_PACKAGE_V1 test suffix");
    image
}
