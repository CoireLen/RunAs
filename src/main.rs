use autoaes;
use win32run::*;
use md5;
use std::fs::File;
use std::io::*;
use configster;
use std::env;
fn main(){
    let mut path=env::current_exe().unwrap();
    path.pop();
    env::set_current_dir(path);
    //Message("Tips".to_string(), env::current_dir().unwrap().display().to_string());
    let config_vec=configster::parse_file("./config.conf", ',').unwrap();
    let (mut user,mut exec,mut pswd,mut domino,mut filemd5)=(String::new(),String::new(),String::new(),String::new(),String::new());
    let caes=autoaes::C_AES::new("pswd123".to_string());
    
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
        else if i.option=="md5"{
            filemd5=caes.decrypt(autoaes::AesPswd::from_string(i.value.primary.clone()));
        }
    }
    if filemd5!=""{
        let  path=exec.clone();
        let mut usepath=path.to_string();
        let mut needopenfile=File::open(usepath.clone()).expect(usepath.as_str());
        let mut filedata=Vec::new();
        needopenfile.read_to_end(&mut filedata).unwrap();
        println!("filedatalen={}",&filedata[..].len());
        let hash=format!("{:X}",md5::compute(&filedata[..]));
        let mut hashxiaoyan=0;
        if hash[0..hash.len()-1]!=filemd5[0..hash.len()-1]
        {
            println!("文件hash校验失败;{},{}",hash.len(),filemd5.len());
            Message("错误提示\0".to_string(),"文件hash校验失败\0".to_string());
            return;
        }
    }
    if domino==""{
        domino=GetComputerName();
    }
    let mut count=0;
    let mut exec=format!("\"{}\"",exec);
    for argv in  std::env::args(){
        if count!=0{
            if argv.len()!=0{
                exec.push(' ');
                exec.push_str(argv.as_str());
            }
        }
        count +=1;
    }
    println!("{}",exec);
    if let Err(s)=Runas(user, domino, pswd, exec){
        println!("Error:{}",s);
        Message("错误提示\0".to_string(),s);
    }
    
}
