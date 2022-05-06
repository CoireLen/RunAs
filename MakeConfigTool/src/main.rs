use autoaes;
use std::sync::{Arc,Mutex};
use std::fs::File;
use std::io::Write;
use md5;
use std::io::prelude::*;
use win32run::*;
use fltk::{app, button::{Button,CheckButton}, frame::Frame, prelude::*, window::Window,input::{FileInput,Input},dialog};
fn main() {
    let app = app::App::default();
    let mut pswd=Arc::new(Mutex::new("".to_string()));
    let mut wind = Window::new(100, 100, 400, 320, "配置文件生成工具");
    let mut fileinput=Arc::new(Mutex::new(FileInput::new(70,10,240,50,"软件:")));
    let mut filebutton=Button::new(320,10,70,50,"选择");
    let mut dominoinput=Arc::new(Mutex::new(Input::new(70,70,240,40,"域名:")));
    let mut userinput=Arc::new(Mutex::new(Input::new(70,120,240,40,"用户名:")));
    let mut pswdbutton=Button::new(70,170,240,40,"输入密码");
    let mut usehashcheckbtn=Arc::new(Mutex::new(CheckButton::new(70,220,240,40,"启用Hash校验")));
    let mut butok = Button::new(70, 270, 240, 40, "确定");
    let mut butautostart = Button::new(320, 270, 70, 40, "设置自起");
    let mut fi1=fileinput.clone();
    filebutton.set_callback(move|_| {
        let mut dialog = dialog::NativeFileChooser::new(dialog::NativeFileChooserType::BrowseFile);
        dialog.show();
        fi1.lock().unwrap().set_value(dialog.filename().to_str().unwrap());
    });
    let mut pw1=pswd.clone();
    pswdbutton.set_callback(move|_| {
        // password and input also takes a second arg which is the default value
        let pass = dialog::password_default("输入密码:", "");
        if let Some(pass) = pass {
            pw1.lock().unwrap().push_str(pass.as_str());
        }
    });
    let (mut pswdout,mut execout,mut dominoout,mut userout,mut filehash)=(pswd.clone(),fileinput.clone(),dominoinput.clone(),userinput.clone(),usehashcheckbtn.clone());
    butok.set_callback(move|_| {
        let mut file = File::create("config.conf").unwrap();
        let caes=autoaes::C_AES::new("hotron123".to_string());
        let exec={execout.lock().unwrap().value()};
        file.write(format!("{}={}\n","user",caes.encrypt(userout.lock().unwrap().value()).to_string()).as_bytes());
        file.write(format!("{}={}\n","pswd",caes.encrypt(pswdout.lock().unwrap().clone()).to_string()).as_bytes());
        file.write(format!("{}={}\n","domino",caes.encrypt(dominoout.lock().unwrap().value()).to_string()).as_bytes());
        file.write(format!("{}={}\n","exec",caes.encrypt(format!("\"{}\"",exec)).to_string()).as_bytes());
        if usehashcheckbtn.lock().unwrap().value(){
            let mut needopenfile=File::open(exec.clone()).unwrap();
            let mut filedata=Vec::new();
            needopenfile.read_to_end(&mut filedata).unwrap();
            println!("filedatalen={}",&filedata[..].len());
            let hash=md5::compute(&filedata[..]);
            file.write(format!("{}={}\n","md5",caes.encrypt(format!("{:X}",hash)).to_string()).as_bytes());
        }
        file.sync_all().unwrap();
    });
    let (mut pswdout,mut execout,mut dominoout,mut userout)=(pswd.clone(),fileinput.clone(),dominoinput.clone(),userinput.clone());
    butautostart.set_callback(move|_|{
        //Message("IsAdministrator".to_string(), format!("it is {}",isAdministrator()));// 开发时 检查是否拥有管理员权限
        if isAdministrator(){
            //此处添加Runas 自启到注册表
        }
        else
        {
            //以管理员权限启动自己

            //如果成功则关闭当前窗口
            std::process::exit(0);
        }
    });
    //从文件读取配置文件

    
    wind.end();
    wind.show();
    app.run().unwrap();
}
