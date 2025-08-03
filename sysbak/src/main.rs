use std::{io, process};
mod pkg_get;
mod pkg_mgmt;

fn main() {
    println!("Hello, world!");

    loop {
        println!("\n--- Main Menu ---");
        println!("1. Package Menu");
        println!("2. Option 2");
        println!("0. Exit");
        print!("Enter your choice: ");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read line");
        let choice = choice.trim();

        match choice {
            "1" => {
                println!("You selected Package Menu.");
                match pkg_get::package_menu() {
                    Ok(_) => {}, // The package_menu handles its own output
                    Err(e) => eprintln!("Error opening Package Menu: {}", e),
                }
            }
            "2" => {
                println!("You selected Option 2.");
                // Add your logic for Option 2 here
            }
            "0" => {
                println!("\nExiting program. Goodbye!");
                process::exit(0);
            }
            _ => {
                println!("Invalid choice. Please try again.");
            }
        }
    }
}
