mod parse_tests {
    use loader::cfg_free_images;


    #[test]
    fn cfg_free_images_test() {
        let images = unsafe { cfg_free_images(r"C:\Windows\System32".to_string(),".dll".to_string(),600000) };
        println!("{:?}",images);
    }

    #[test]
    fn path_directories() {
    //search alternative directories in the path environment variable for cfg free images.
    }
}