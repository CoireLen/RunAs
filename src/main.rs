use std::ptr;
use std::mem::size_of_val;
use windows::{
    core::*,
    Win32::{
        Foundation::GetLastError,
        System::{
    WindowsProgramming::*,
    }}};
use windows_sys::Win32::System::Threading::{CreateProcessWithLogonW,STARTUPINFOW,PROCESS_INFORMATION};
use autoaes;
fn main(){
    let config_vec=configster::parse_file("./config.conf", ',').unwrap();
    let (mut user,mut exec,mut pswd,mut domino)=(String::new(),String::new(),String::new(),String::new());
    let caes=autoaes::C_AES::new("hotron123".to_string());
    
    for i in &config_vec{
        if i.option=="user"{
            //user=i.value.primary.clone();
            user=caes.decrypt(autoaes::AesPswd::from_string(i.value.primary.clone()));
        }
        else if i.option=="pswd"{
            pswd=caes.decrypt(autoaes::AesPswd::from_string(i.value.primary.clone()));
        }
        else if i.option=="exec"{
            exec=caes.decrypt(autoaes::AesPswd::from_string(i.value.primary.clone()));
        }
        else if i.option=="domino"{
            domino=caes.decrypt(autoaes::AesPswd::from_string(i.value.primary.clone()));
        }
    }
    if domino==""{
        let mut computername=vec![0u8;100];
        let mut namelength=100;
        let pstr=PSTR{0:computername.as_mut_ptr()};
        unsafe{
        GetComputerNameA(pstr,&mut namelength);}
        domino=String::from_utf8(computername.clone()).unwrap();
    }
    unsafe{
        let mut si=STARTUPINFOW{
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
        si.cb=size_of_val(&si) as u32;

        let mut pi=PROCESS_INFORMATION{
            hProcess: 0,
            hThread:0,
            dwProcessId: 0,
            dwThreadId: 0,
        };
        let mut vexec:Vec<u16>=Vec::new();
        for i in exec.as_bytes(){
            vexec.push(*i as u16);
        }
        vexec.push(0);
        //let pwstr=PWSTR{0:vexec.as_mut_ptr()};
        let mut vuser:Vec<u16>=Vec::new();
        for i in user.as_bytes(){
            vuser.push(*i as u16);
        }
        vuser.push(0);
        //let vuser_ptr=PCWSTR{0:vuser.as_ptr()};
        let mut vdomino:Vec<u16>=Vec::new();
        for i in domino.as_bytes(){
            vdomino.push(*i as u16);
        }
        vdomino .push(0);
        //let vdomino_ptr=PCWSTR{0:vdomino.as_ptr()};
        let mut vpswd:Vec<u16>=Vec::new();
        for i in pswd.as_bytes(){
            vpswd.push(*i as u16);
        }
        vpswd.push(0);
        let a=CreateProcessWithLogonW(vuser.as_ptr() as *mut u16,vdomino.as_ptr() as *mut u16, vpswd.as_ptr() as *mut u16, 0 ,ptr::null_mut(),vexec.as_ptr() as *mut u16, 0,ptr::null_mut(),ptr::null_mut(),&si,&mut pi);
        if a==0{
            println!("{:?}",GetLastError());
        }
    }
    
}
