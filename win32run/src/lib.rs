use windows_sys::Win32::{
    Security::{AllocateAndInitializeSid,SID_IDENTIFIER_AUTHORITY,CheckTokenMembership},
    UI::WindowsAndMessaging::MessageBoxW,
    Foundation::{GetLastError,PSID},
    System::{
        Registry::{RegCreateKeyExA,RegSetValueExA},
        WindowsProgramming::GetComputerNameA,
        Diagnostics::Debug::*,
        Threading::{CreateProcessWithLogonW,STARTUPINFOW,PROCESS_INFORMATION}}};
use std::result::Result;
use std::ptr;
use std::mem::size_of_val;
pub fn Runas(user:String,domino:String,pswd:String,exec:String)->Result<(),String>{
    println!("exec:{}",exec);
    let (user,domino,pswd,exec)=(s_to_vec(user),s_to_vec(domino),s_to_vec(pswd),s_to_vec(exec));
    let si=STARTUPINFOW::new();
    let mut pi=PROCESS_INFORMATION::new();
    let mut err=1;
    unsafe{
    err=CreateProcessWithLogonW(
        user.as_ptr() as *mut u16,
        domino.as_ptr() as *mut u16, 
        pswd.as_ptr() as *mut u16, 
        0,
        ptr::null(),
        exec.as_ptr() as *mut u16, 
        0,ptr::null_mut(),
        ptr::null_mut(),
        &si,&mut pi);
    }
    if err==0{
        return Err(LastErrorToString());
    }
    Ok(())
}
fn LastErrorToString()->String{
    let mut info:Vec<u16> =vec![0;1024];
    let mut error;
    unsafe{
        error=GetLastError();
        if error!=0{
            let err=FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,
                ptr::null_mut(),error,0u32,info.as_mut_ptr(),1023,ptr::null_mut());
        }
        else{

        }
    }
    String::from_utf16(&info[..]).expect("转换错误")
}
trait si{
    fn new()->STARTUPINFOW;
}
impl  si for STARTUPINFOW{
    fn new()->STARTUPINFOW{
        let mut s=STARTUPINFOW{
            cb:0,
            lpReserved: ptr::null_mut(),
            lpDesktop: ptr::null_mut(),
            lpTitle: ptr::null_mut(),
            dwX: 0,
            dwY: 0,
            dwXSize:0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: 1,
            wShowWindow: 1,
            cbReserved2: 0,
            lpReserved2: ptr::null_mut(),
            hStdInput: 0,
            hStdOutput: 0,
            hStdError:0,
        };
        s.cb=size_of_val(&s) as u32;
        s
    }
}
trait pi {
    fn new()->PROCESS_INFORMATION;
}
impl pi for PROCESS_INFORMATION{
    fn new()->PROCESS_INFORMATION{
        PROCESS_INFORMATION{
            hProcess: 0,
            hThread:0,
            dwProcessId: 0,
            dwThreadId: 0,}
    }
}
fn s_to_vec(s:String)->Vec<u16>{
    let mut out:Vec<u16>=s.encode_utf16().collect();
    out.push(0);
    out
}
pub fn Message(title:String,msg:String){
    let (mut title,mut msg)=(title,msg);
    msg.push('\0');
    title.push('\0');
    let msgu16:Vec<u16>=msg.encode_utf16().collect();
    let titleu16:Vec<u16>=title.encode_utf16().collect();
    unsafe{
    MessageBoxW(0, msgu16.as_ptr(), titleu16.as_ptr(), 0u32);
    }
}
pub fn GetComputerName()->String{
    let mut name=vec![0u8;1024];
    let mut size=name.len() as u32;
    unsafe{
        GetComputerNameA(name.as_mut_ptr(), &mut size);
    }
    String::from_utf8(name).unwrap()
}

pub fn isAdministrator()->bool{
    let mut isadmin=0;
    let mut ntauthority=SID_IDENTIFIER_AUTHORITY{Value:[0u8,0u8,0u8,0u8,0u8,5u8]};
    let mut psid:PSID=std::ptr::null_mut();
    unsafe {
        if AllocateAndInitializeSid(&ntauthority, 
            2, 
            32, 
            544, 
            0, 0, 0, 0, 0, 0, 
            &mut psid)==0
            {
                Message("错误AllocateAndInitializeSid\0".to_string(), LastErrorToString());
            };
        if CheckTokenMembership(0,psid,&mut isadmin)==0{
            Message("错误CheckTokenMembership".to_string(), LastErrorToString());
        }
        };
    
    isadmin!=0
}

pub fn setAutoRun(valuename:String,exepath:String){
    let hkeyroot="HKEY_LOCAL_MACHINE";
    let regaddr="SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\0";
    let mut autorunexepath=exepath;
    let mut valuename=valuename;
    let mut hkey=0isize;
    let mut err=0;
    unsafe{
        err=RegCreateKeyExA(-2_147_483_646isize, 
            regaddr.as_ptr(), 
            0, 
            ptr::null(), 
            0u32, 
            983103u32, 
            ptr::null(), 
            &mut hkey, 
            ptr::null_mut());
    }
    if err!=0{
        Message("错误RegCreateKeyExA".to_string(),LastErrorToString());
    }
    else{
        unsafe{
            autorunexepath.push('\0');
            valuename.push('\0');
            err=RegSetValueExA(
                hkey, 
                valuename.as_ptr(),
                0, 
                1u32, 
                autorunexepath.as_ptr(), 
                autorunexepath.len()as u32)
        }
        if err!=0{
            Message("错误RegSetValueExA".to_string(),LastErrorToString());
        }
    }
    Message("提示".to_string(), "已添加至注册表自启动".to_string())
}