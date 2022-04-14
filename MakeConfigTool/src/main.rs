use autoaes;
use std::sync::{Arc,Mutex};
use std::fs::File;
use std::io::Write;
use fltk::{app, button::Button, frame::Frame, prelude::*, window::Window,input::{FileInput,Input},dialog};
fn main() {
    let app = app::App::default();
    let mut pswd=Arc::new(Mutex::new("".to_string()));
    let mut wind = Window::new(100, 100, 400, 300, "配置文件生成工具");
    let mut fileinput=Arc::new(Mutex::new(FileInput::new(70,10,240,50,"软件:")));
    let mut filebutton=Button::new(320,10,70,50,"选择");
    let mut dominoinput=Arc::new(Mutex::new(Input::new(70,70,240,40,"域名:")));
    let mut userinput=Arc::new(Mutex::new(Input::new(70,120,240,40,"用户名:")));
    let mut pswdbutton=Button::new(70,170,240,40,"输入密码");
    let mut butok = Button::new(70, 220, 240, 40, "确定");
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
    let (mut pswdout,mut execout,mut dominoout,mut userout)=(pswd.clone(),fileinput.clone(),dominoinput.clone(),userinput.clone());
    butok.set_callback(move|_| {
        let mut file = File::create("config.conf").unwrap();
        let caes=autoaes::C_AES::new("hotron123".to_string());
        file.write(format!("{}={}\n","user",caes.encrypt(userout.lock().unwrap().value()).to_string()).as_bytes());
        file.write(format!("{}={}\n","pswd",caes.encrypt(pswdout.lock().unwrap().clone()).to_string()).as_bytes());
        file.write(format!("{}={}\n","domino",caes.encrypt(dominoout.lock().unwrap().value()).to_string()).as_bytes());
        file.write(format!("{}={}\n","exec",caes.encrypt(format!("\"{}\"",execout.lock().unwrap().value())).to_string()).as_bytes());
        file.sync_all().unwrap();
    });
    wind.end();
    wind.show();
    app.run().unwrap();
}
