use aes::Aes128;
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use std::boxed::Box;
use std::collections::HashMap;
pub struct C_AES{
    key:String
}
pub struct AesPswd{
    pub pswd:Vec<u8>
}
impl AesPswd{
    fn new(input:Vec<u8>)->AesPswd{
        AesPswd{pswd:input}
    }
    pub fn to_string(&self)->String{
        let mut res=String::new();
        let vlist="0123456789ABCDEF".as_bytes();
        for i in 0..self.pswd.len(){
            res.push(vlist[(self.pswd[i]&0xF)as usize]as char);
            res.push(vlist[((self.pswd[i]>>4)&0xF)as usize]as char);
        }
        res
    }
    pub fn from_string(s:String)->AesPswd{
        let mut res:Vec<u8>=Vec::new();
        let vlist="0123456789ABCDEF".as_bytes();
        let mut map:HashMap<u8,u8> =HashMap::new();
        for i in 0..vlist.len(){
            map.insert(vlist[i], i as u8);
        }
        for i in 0..s.len()/2{
            let o=i*2;
            let mut value=0u8;
            value|=map[&s.as_bytes()[o]];
            value|=map[&s.as_bytes()[o+1]]<<4;
            res.push(value);
        }
        AesPswd::new(res)
    }
}
impl C_AES{
    pub fn new(key:String)->C_AES{
        if key.len()>16{
            println!("密钥过长");
        }
        C_AES{key:key}
    }
    pub fn encrypt(&self,s:String)->AesPswd{
        let mut res:Vec<u8> =Vec::new();
        let mut listkey=[0u8;16];
        for i in 0..self.key.len(){
            listkey[i]=self.key.as_bytes()[i];
        }
        let gkey=GenericArray::from(listkey);  

        let cipher = Aes128::new(&gkey);
        let mut slen=s.len();
        for o in 0..s.len()/16+1{
            println!("循环:{} 字符长度:{}",o,slen);
            let mut list_pswd=[0u8;16];
            let mut p=16;
            if slen<16{
                p=slen;
            }else{
                slen=slen-16;
            }
            
            for i in 0..p{
                list_pswd[i]=s.as_bytes()[i+o*16];
            }
            let mut pwsd_block = GenericArray::from(list_pswd);

            cipher.encrypt_block(&mut pwsd_block);
            for i in pwsd_block{
                res.push(i);
            }
        }
        AesPswd::new(res)
    }
    pub fn decrypt(&self,v:AesPswd)->String{
        let v=v.pswd;
        let mut listkey=[0u8;16];
        let mut resdata:Vec<u8>=Vec::new();
        for i in 0..self.key.len(){
            listkey[i]=self.key.as_bytes()[i];
        }
        let gkey=GenericArray::from(listkey);  

        let cipher = Aes128::new(&gkey);
        let mut vlen=v.len();
        for o in 0..v.len()/16{
            println!("循环:{} 字符长度:{}",o,vlen);
            let mut list_pswd=[0u8;16];
            let mut p=16;
            if vlen<16{
                p=vlen;
            }else{
                vlen=vlen-16;
            }
            
            for i in 0..p{
                list_pswd[i]=v[i+o*16];
            }
            let mut pwsd_block = GenericArray::from(list_pswd);

            cipher.decrypt_block(&mut pwsd_block);
            for i in pwsd_block{
                resdata.push(i);
            }
        }
        String::from_utf8(resdata).unwrap()
    }
}