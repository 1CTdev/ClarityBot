use windows_sys::Win32::System::Diagnostics::Debug::IMAGE_LOAD_CONFIG_CODE_INTEGRITY;



pub static IMAGE_SCN_TYPE_NO_PAD                 : u32= 0x00000008;  // Reserved.
pub static IMAGE_SCN_CNT_CODE                    : u32= 0x00000020;  // Section contains code.
pub static IMAGE_SCN_CNT_INITIALIZED_DATA        : u32= 0x00000040;  // Section contains initialized data.
pub static IMAGE_SCN_CNT_UNINITIALIZED_DATA      : u32= 0x00000080;  // Section contains uninitialized data.
pub static IMAGE_SCN_LNK_OTHER                   : u32= 0x00000100;  // Reserved.
pub static IMAGE_SCN_LNK_INFO                    : u32= 0x00000200;  // Section contains comments or some other type of information.
pub static IMAGE_SCN_LNK_REMOVE                  : u32= 0x00000800;  // Section contents will not become part of image.
pub static IMAGE_SCN_LNK_COMDAT                  : u32= 0x00001000;  // Section contents comdat.
pub static IMAGE_SCN_NO_DEFER_SPEC_EXC           : u32= 0x00004000;  // Reset speculative exceptions handling bits in the TLB entries for this section.
pub static IMAGE_SCN_GPREL                       : u32= 0x00008000;  // Section content can be accessed relative to GP
pub static IMAGE_SCN_MEM_FARDATA                 : u32= 0x00008000;
pub static IMAGE_SCN_MEM_PURGEABLE               : u32= 0x00020000;
pub static IMAGE_SCN_MEM_16BIT                   : u32= 0x00020000;
pub static IMAGE_SCN_MEM_LOCKED                  : u32= 0x00040000;
pub static IMAGE_SCN_MEM_PRELOAD                 : u32= 0x00080000;
pub static IMAGE_SCN_ALIGN_1BYTES                : u32= 0x00100000;  //
pub static IMAGE_SCN_ALIGN_2BYTES                : u32= 0x00200000;  //
pub static IMAGE_SCN_ALIGN_4BYTES                : u32= 0x00300000;  //
pub static IMAGE_SCN_ALIGN_8BYTES                : u32= 0x00400000;  //
pub static IMAGE_SCN_ALIGN_16BYTES               : u32= 0x00500000;  // Default alignment if no others are specified.
pub static IMAGE_SCN_ALIGN_32BYTES               : u32= 0x00600000;  //
pub static IMAGE_SCN_ALIGN_64BYTES               : u32= 0x00700000;  //
pub static IMAGE_SCN_ALIGN_128BYTES              : u32= 0x00800000;  //
pub static IMAGE_SCN_ALIGN_256BYTES              : u32= 0x00900000;  //
pub static IMAGE_SCN_ALIGN_512BYTES              : u32= 0x00A00000;  //
pub static IMAGE_SCN_ALIGN_1024BYTES             : u32= 0x00B00000;  //
pub static IMAGE_SCN_ALIGN_2048BYTES             : u32= 0x00C00000;  //
pub static IMAGE_SCN_ALIGN_4096BYTES             : u32= 0x00D00000;  //
pub static IMAGE_SCN_ALIGN_8192BYTES             : u32= 0x00E00000;  //
pub static IMAGE_SCN_ALIGN_MASK                  : u32= 0x00F00000;
pub static IMAGE_SCN_LNK_NRELOC_OVFL             : u32= 0x01000000;  // Section contains extended relocations.
pub static IMAGE_SCN_MEM_DISCARDABLE             : u32= 0x02000000;  // Section can be discarded.
pub static IMAGE_SCN_MEM_NOT_CACHED              : u32= 0x04000000;  // Section is not cachable.
pub static IMAGE_SCN_MEM_NOT_PAGED               : u32= 0x08000000;  // Section is not pageable.
pub static IMAGE_SCN_MEM_SHARED                  : u32= 0x10000000;  // Section is shareable.
pub static IMAGE_SCN_MEM_EXECUTE                 : u32= 0x20000000;  // Section is executable.
pub static IMAGE_SCN_MEM_READ                    : u32= 0x40000000;  // Section is readable.
pub static IMAGE_SCN_MEM_WRITE                   : u32= 0x80000000;  // Section is writeable.


static IMAGE_NUMBEROF_DIRECTORY_ENTRIES:usize = 16;

#[repr(C, packed)]
pub struct IMAGE_DOS_HEADER {
    pub E_magic    :u16,
	pub E_cblp     :u16,
	pub E_cp       :u16,
	pub E_crlc     :u16,
	pub E_cparhdr  :u16,
	pub E_minalloc :u16,
	pub E_maxalloc :u16,
	pub E_ss       :u16,
	pub E_sp       :u16,
	pub E_csum     :u16,
	pub E_ip       :u16,
	pub E_cs       :u16,
	pub E_lfarlc   :u16,
	pub E_ovno     :u16,
	pub E_res      :[u16;4],
	pub E_oemid    :u16,
	pub E_oeminfo  :u16,
	pub E_res2     :[u16;10],
	pub E_lfanew   :u32,
}

#[repr(C, packed)]
pub struct IMAGE_FILE_HEADER {
	pub Machine              :u16,
	pub NumberOfSections     :u16,
	pub TimeDateStamp        :u32,
	pub PointerToSymbolTable :u32,
	pub NumberOfSymbols      :u32,
	pub SizeOfOptionalHeader :u16,
	pub Characteristics      :u16,
}

#[repr(C, packed)]
pub struct IMAGE_OPTIONAL_HEADER32 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode:u32,
    pub ImageBase:u64,
    pub SectionAlignment:u32,
    pub FileAlignment:u32,
    pub MajorOperatingSystemVersion:u16,
    pub MinorOperatingSystemVersion:u16,
    pub MajorImageVersion:u16,
    pub MinorImageVersion:u16,
    pub MajorSubsystemVersion:u16,
    pub MinorSubsystemVersion:u16,
    pub Win32VersionValue:u32,
    pub SizeOfImage:u32,
    pub SizeOfHeaders:u32,
    pub CheckSum:u32,
    pub Subsystem:u16,
    pub DllCharacteristics:u16,
    pub SizeOfStackReserve:u32,
    pub SizeOfStackCommit:u32,
    pub SizeOfHeapReserve:u32,
    pub SizeOfHeapCommit:u32,
    pub LoaderFlags:u32,
    pub NumberOfRvaAndSizes:u32,
    pub IMAGE_DATA_DIRECTORY:[IMAGE_DATA_DIRECTORY;IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}

#[repr(C, packed)]
pub struct IMAGE_OPTIONAL_HEADER64 {
    pub Magic: u16,
    pub MajorLinkerVersion: u8,
    pub MinorLinkerVersion: u8,
    pub SizeOfCode: u32,
    pub SizeOfInitializedData: u32,
    pub SizeOfUninitializedData: u32,
    pub AddressOfEntryPoint: u32,
    pub BaseOfCode:u32,
    pub ImageBase:u64,
    pub SectionAlignment:u32,
    pub FileAlignment:u32,
    pub MajorOperatingSystemVersion:u16,
    pub MinorOperatingSystemVersion:u16,
    pub MajorImageVersion:u16,
    pub MinorImageVersion:u16,
    pub MajorSubsystemVersion:u16,
    pub MinorSubsystemVersion:u16,
    pub Win32VersionValue:u32,
    pub SizeOfImage:u32,
    pub SizeOfHeaders:u32,
    pub CheckSum:u32,
    pub Subsystem:u16,
    pub DllCharacteristics:u16,
    pub SizeOfStackReserve:u64,
    pub SizeOfStackCommit:u64,
    pub SizeOfHeapReserve:u64,
    pub SizeOfHeapCommit:u64,
    pub LoaderFlags:u32,
    pub NumberOfRvaAndSizes:u32,
    pub IMAGE_DATA_DIRECTORY:[IMAGE_DATA_DIRECTORY;IMAGE_NUMBEROF_DIRECTORY_ENTRIES],
}


#[repr(C, packed)]
pub struct IMAGE_DATA_DIRECTORY{
	pub VirtualAddress  :u32,
	pub Size            :u32,
}

//size 264
#[repr(C, packed)]
pub struct IMAGE_NT_HEADERS64 {
    pub Signature:u32,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader:IMAGE_OPTIONAL_HEADER64,
}

#[repr(C, packed)]
pub struct IMAGE_NT_HEADERS32 {
    pub Signature:u32,
    pub FileHeader:IMAGE_FILE_HEADER,
    pub OptionalHeader:IMAGE_OPTIONAL_HEADER32,
}

static IMAGE_SIZEOF_SHORT_NAME:usize = 8;

//size 40
#[repr(C, packed)]
pub struct IMAGE_SECTION_HEADER {
    pub Name:[u8;IMAGE_SIZEOF_SHORT_NAME],
    pub Misc:Misc,
    pub VirtualAddress:u32,
    pub SizeOfRawData:u32,
    pub PointerToRawData:u32,
    pub PointerToRelocations:u32,
    pub PointerToLineNumbers:u32,
    pub NumberOfRelocations:u16,
    pub NumberOfLineNumbers:u16,
    pub Characteristics:u32,
}

#[repr(C, packed)]
pub union Misc {
    pub PhysicalAddress: u32,
    pub VirtualSize: f32,
}
#[derive(Clone,Copy,Default)]
#[repr(C, packed)]
pub struct SECTION_IMAGE_INFORMATION {
    pub TransferAddress:usize,
    pub ZeroBits: u64,
    pub MaximumStackSize:usize,
    pub CommittedStackSize:usize,
    pub SubSystemType:u32,
    pub SubSystemVersion:u32,
    pub OperatingSystemVersion:u32,
    pub ImageCharacteristics:u16,
    pub DllCharacteristics:u16,
    pub Machine:u16,
    pub ImageContainsCode:u8,
    pub ImageFlags:u8,
    pub LoaderFlags:u32,
    pub ImageFileSize:u32,
    pub CheckSum:u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_LOAD_CONFIG_DIRECTORY64 {
    pub Size: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub GlobalFlagsClear: u32,
    pub GlobalFlagsSet: u32,
    pub CriticalSectionDefaultTimeout: u32,
    pub DeCommitFreeBlockThreshold: u64,
    pub DeCommitTotalFreeThreshold: u64,
    pub LockPrefixTable: u64,
    pub MaximumAllocationSize: u64,
    pub VirtualMemoryThreshold: u64,
    pub ProcessAffinityMask: u64,
    pub ProcessHeapFlags: u32,
    pub CSDVersion: u16,
    pub DependentLoadFlags: u16,
    pub EditList: u64,
    pub SecurityCookie: u64,
    pub SEHandlerTable: u64,
    pub SEHandlerCount: u64,
    pub GuardCFCheckFunctionPointer: u64,
    pub GuardCFDispatchFunctionPointer: u64,
    pub GuardCFFunctionTable: u64,
    pub GuardCFFunctionCount: u64,
    pub GuardFlags: u32,
    pub CodeIntegrity: IMAGE_LOAD_CONFIG_CODE_INTEGRITY,
    pub GuardAddressTakenIatEntryTable: u64,
    pub GuardAddressTakenIatEntryCount: u64,
    pub GuardLongJumpTargetTable: u64,
    pub GuardLongJumpTargetCount: u64,
    pub DynamicValueRelocTable: u64,
    pub CHPEMetadataPointer: u64,
    pub GuardRFFailureRoutine: u64,
    pub GuardRFFailureRoutineFunctionPointer: u64,
    pub DynamicValueRelocTableOffset: u32,
    pub DynamicValueRelocTableSection: u16,
    pub Reserved2: u16,
    pub GuardRFVerifyStackPointerFunctionPointer: u64,
    pub HotPatchTableOffset: u32,
    pub Reserved3: u32,
    pub EnclaveConfigurationPointer: u64,
    pub VolatileMetadataPointer: u64,
    pub GuardEHContinuationTable: u64,
    pub GuardEHContinuationCount: u64,
    pub GuardXFGCheckFunctionPointer: u64,
    pub GuardXFGDispatchFunctionPointer: u64,
    pub GuardXFGTableDispatchFunctionPointer: u64,
    pub CastGuardOsDeterminedFailureMode: u64,
    pub GuardMemcpyFunctionPointer: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_LOAD_CONFIG_DIRECTORY32 {
    pub Size: u32,
    pub TimeDateStamp: u32,
    pub MajorVersion: u16,
    pub MinorVersion: u16,
    pub GlobalFlagsClear: u32,
    pub GlobalFlagsSet: u32,
    pub CriticalSectionDefaultTimeout: u32,
    pub DeCommitFreeBlockThreshold: u32,
    pub DeCommitTotalFreeThreshold: u32,
    pub LockPrefixTable: u32,
    pub MaximumAllocationSize: u32,
    pub VirtualMemoryThreshold: u32,
    pub ProcessHeapFlags: u32,
    pub ProcessAffinityMask: u32,
    pub CSDVersion: u16,
    pub DependentLoadFlags: u16,
    pub EditList: u32,
    pub SecurityCookie: u32,
    pub SEHandlerTable: u32,
    pub SEHandlerCount: u32,
    pub GuardCFCheckFunctionPointer: u32,
    pub GuardCFDispatchFunctionPointer: u32,
    pub GuardCFFunctionTable: u32,
    pub GuardCFFunctionCount: u32,
    pub GuardFlags: u32,
    pub CodeIntegrity: IMAGE_LOAD_CONFIG_CODE_INTEGRITY,
    pub GuardAddressTakenIatEntryTable: u32,
    pub GuardAddressTakenIatEntryCount: u32,
    pub GuardLongJumpTargetTable: u32,
    pub GuardLongJumpTargetCount: u32,
    pub DynamicValueRelocTable: u32,
    pub CHPEMetadataPointer: u32,
    pub GuardRFFailureRoutine: u32,
    pub GuardRFFailureRoutineFunctionPointer: u32,
    pub DynamicValueRelocTableOffset: u32,
    pub DynamicValueRelocTableSection: u16,
    pub Reserved2: u16,
    pub GuardRFVerifyStackPointerFunctionPointer: u32,
    pub HotPatchTableOffset: u32,
    pub Reserved3: u32,
    pub EnclaveConfigurationPointer: u32,
    pub VolatileMetadataPointer: u32,
    pub GuardEHContinuationTable: u32,
    pub GuardEHContinuationCount: u32,
    pub GuardXFGCheckFunctionPointer: u32,
    pub GuardXFGDispatchFunctionPointer: u32,
    pub GuardXFGTableDispatchFunctionPointer: u32,
    pub CastGuardOsDeterminedFailureMode: u32,
    pub GuardMemcpyFunctionPointer: u32,
}