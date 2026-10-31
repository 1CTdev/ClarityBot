use std::env;

use loader::cfg_free_images;

fn main() {
    unsafe {
        let args:Vec<String> = env::args().collect();
        if args.len() >= 2 {
        let module_size:i64 = args[1].parse().expect("need a number");
        let images = cfg_free_images(r"C:\Windows\System32".to_string(),".exe".to_string(),module_size);
        println!("{:?}",images);
        } else {
            println!("{} <min module size>",args[0]);
        }
    }
}