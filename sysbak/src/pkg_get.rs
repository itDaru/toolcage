//! Module with functions for listing and saving packages across various Linux distributions.
use crate::pkg_mgmt;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output};
use std::{io, process};
use serde_json::json;
use serde_json::Value;
use std::path::Path;

/// Package Menu

pub fn package_menu() -> io::Result<()> {
    loop {
        println!("\n--- Package Menu ---");
        println!("1. Detect Package Managers");
        println!("2. List Packages");
        println!("3. Save Package List");
        println!("4. Install Packages from List");
        println!("0. Back to Main Menu");
        print!("Enter your choice: ");

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let choice = choice.trim();

        match choice {
            "1" => {
                match pkg_mgmt::detect_package_managers() {
                    Ok(output) => println!("{}", String::from_utf8_lossy(&output.stdout)),
                    Err(e) => eprintln!("Error detecting package managers: {}", e),
                }
            },
            "2" => {
                match list_all_packages() {
                    Ok(output) => {
                        println!("{}", String::from_utf8_lossy(&output.stdout));
                    },
                    Err(e) => eprintln!("Error listing packages: {}", e),
                }
            },
            "3" => {
                match list_all_packages() {
                    Ok(output) => {
                        if let Err(e) = pkg_mgmt::save_package_list(&output) {
                            eprintln!("Error saving package list: {}", e);
                        }
                    },
                    Err(e) => eprintln!("Error listing packages to save: {}", e),
                }
            },
            "4" => {
                if Path::new("SysBackup/package_list.json").exists() {
                    if let Err(e) = pkg_mgmt::install_packages() {
                        eprintln!("Error installing packages: {}", e);
                    }
                } else {
                    println!("package_list.json not found. Please save a package list first.");
                }
            },
            "0" => return Ok(()), // Back to Main Menu
            _ => println!("Invalid choice. Please try again."),
        }
    }
}

/// Lists packages for all detected package managers.
/// This function orchestrates the detection of package managers,
/// calls the appropriate listing functions, and combines their JSON outputs.
pub fn list_all_packages() -> io::Result<Output> {
    println!("Detecting package managers and listing packages...");

    // 1. Detect package managers
    let detected_managers_output = pkg_mgmt::detect_package_managers()?;
    let detected_managers_json_str = String::from_utf8_lossy(&detected_managers_output.stdout);
    let detected_managers_value: Value = serde_json::from_str(&detected_managers_json_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse detected managers JSON: {}", e)))?;

    let detected_managers_map = detected_managers_value["detected_package_managers"]
        .as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Expected 'detected_package_managers' object"))?;

    let mut package_listing_results: Vec<io::Result<Output>> = Vec::new();

    // 2. Correlate detected package managers with needed calls
    for (manager_name, is_present_value) in detected_managers_map.iter() {
        if is_present_value.as_bool().unwrap_or(false) {
            println!("Detected {}. Listing packages...", manager_name);
            let result = match manager_name.as_str() {
                "apt" => get_apt_packages(),
                "yum_dnf" => get_yum_dnf_packages(),
                "portage" => get_portage_packages(),
                "pacman" => get_pacman_packages(),
                "flatpak" => get_flatpak_packages(),
                "snap" => get_snap_packages(),
                "xbps" => get_xbps_packages(),
                _ => {
                    println!("No listing function for unknown package manager: {}", manager_name);
                    continue; // Skip unknown managers
                }
            };
            package_listing_results.push(result);
        }
    }

    // 3. Merge the JSON output of all listed packages and print it
    if package_listing_results.is_empty() {
        let no_packages_json = json!({"message": "No package managers detected or no packages listed."});
        let pretty_json = serde_json::to_string_pretty(&no_packages_json)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to serialize JSON: {}", e)))?;
        Ok(Output {
            stdout: pretty_json.into_bytes(),
            stderr: Vec::new(),
            status: process::ExitStatus::from_raw(0),
        })
    } else { 
        pkg_mgmt::combine_json_outputs(package_listing_results)
    }
}

/// Package Listings

/// List apt packages
pub fn get_apt_packages() -> io::Result<Output> {
    println!("Listing APT packages...");

    let output = Command::new("apt")
        .arg("list")
        .arg("--installed")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<&str> = stdout.lines()
        .filter(|line| line.contains('/'))
        .map(|line| line.split('/').next().unwrap_or("").trim())
        .filter(|s| !s.is_empty())
        .collect();

    let json_output = json!({"apt": packages});
    let pretty_json = serde_json::to_string_pretty(&json_output).unwrap_or_else(|_| json_output.to_string());
    Ok(Output { stdout: pretty_json.into_bytes(), stderr: output.stderr, status: output.status })
}

/// Get yum/dnf packages
pub fn get_yum_dnf_packages() -> io::Result<Output> {
    println!("Listing YUM/DNF packages...");

    let output = Command::new("dnf")
        .arg("list")
        .arg("installed")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<&str> = stdout.lines()
        .filter(|line| line.contains('.')) // Heuristic to filter package lines
        .map(|line| line.split('.').next().unwrap_or("").trim())
        .filter(|s| !s.is_empty())
        .collect();

    let json_output = json!({"yum_dnf": packages});
    let pretty_json = serde_json::to_string_pretty(&json_output).unwrap_or_else(|_| json_output.to_string());
    Ok(Output { stdout: pretty_json.into_bytes(), stderr: output.stderr, status: output.status })
}

/// Get portage packages
pub fn get_portage_packages() -> io::Result<Output> {
    println!("Listing Portage packages...");

    let output = Command::new("qlist")
        .arg("-I") // Installed packages
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<&str> = stdout.lines()
        .filter(|s| !s.is_empty())
        .collect();

    let json_output = json!({"portage": packages});
    let pretty_json = serde_json::to_string_pretty(&json_output).unwrap_or_else(|_| json_output.to_string());
    Ok(Output { stdout: pretty_json.into_bytes(), stderr: output.stderr, status: output.status })
}

/// Get pacman packages
pub fn get_pacman_packages() -> io::Result<Output> {
    println!("Listing Pacman packages...");

    let output = Command::new("pacman")
        .arg("-Q") // Query the local package database
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<&str> = stdout.lines()
        .filter_map(|line| line.split_whitespace().next()) // Get package name
        .collect();

    let json_output = json!({"pacman": packages});
    let pretty_json = serde_json::to_string_pretty(&json_output).unwrap_or_else(|_| json_output.to_string());
    Ok(Output { stdout: pretty_json.into_bytes(), stderr: output.stderr, status: output.status })
}

/// Get flatpak packages
pub fn get_flatpak_packages() -> io::Result<Output> {
    println!("Listing Flatpak packages...");

    let output = Command::new("flatpak")
        .arg("list")
        .arg("--app") // List installed applications
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<&str> = stdout.lines()
        .filter_map(|line| line.split('\t').next()) // Flatpak list output is tab-separated
        .collect();
    let json_output = json!({"flatpak": packages});
    let pretty_json = serde_json::to_string_pretty(&json_output).unwrap_or_else(|_| json_output.to_string());
    Ok(Output { stdout: pretty_json.into_bytes(), stderr: output.stderr, status: output.status })
}

/// Get snap packages
pub fn get_snap_packages() -> io::Result<Output> {
    println!("Listing Snap packages...");

    let output = Command::new("snap")
        .arg("list")
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<&str> = stdout.lines()
        .skip(1) // Skip header line
        .filter_map(|line| line.split_whitespace().next())
        .collect();

    let json_output = json!({"snap": packages});
    let pretty_json = serde_json::to_string_pretty(&json_output).unwrap_or_else(|_| json_output.to_string());
    Ok(Output { stdout: pretty_json.into_bytes(), stderr: output.stderr, status: output.status })
}

/// Get xbps packages
pub fn get_xbps_packages() -> io::Result<Output> {
    println!("Listing XBPS packages...");

    let output = Command::new("xbps-query")
        .arg("-l") // List installed packages
        .output()?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let packages: Vec<&str> = stdout.lines()
        .filter_map(|line| {
            // Example line: "ii  package-name-1.0_1"
            line.split_whitespace().nth(1) // Get the package name part
                .and_then(|pkg_version| pkg_version.rsplit_once('-')) // Split by last '-' for version
                .map(|(pkg_name, _)| pkg_name) // Take only the package name
        })
        .collect();

    let json_output = json!({"xbps": packages});
    let pretty_json = serde_json::to_string_pretty(&json_output).unwrap_or_else(|_| json_output.to_string());
    Ok(Output { stdout: pretty_json.into_bytes(), stderr: output.stderr, status: output.status })
}