use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Command, Output, ExitStatus};
use serde_json::{json, Value};

/// Detects which package managers are present on the system.
pub fn detect_package_managers() -> io::Result<Output> {
    println!("Detecting package managers...");

    let mut detected_managers = serde_json::Map::new();

    let managers = [
        ("apt", "apt"),
        ("yum_dnf", "dnf"), // Check for dnf, as it's the modern replacement for yum
        ("portage", "emerge"),
        ("pacman", "pacman"),
        ("flatpak", "flatpak"),
        ("snap", "snap"),
        ("xbps", "xbps-query"),
    ];

    for (name, command) in managers.iter() {
        let is_present = Command::new(command)
            .arg("--version") // A common argument to check if a command exists and is executable
            .output()
            .map_or(false, |output| output.status.success());

        detected_managers.insert(name.to_string(), json!(is_present));
    }

    let json_output = json!({"detected_package_managers": detected_managers});
    let pretty_json = serde_json::to_string_pretty(&json_output)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to serialize JSON: {}", e)))?;

    Ok(Output {
        stdout: pretty_json.into_bytes(),
        stderr: Vec::new(),
        status: ExitStatus::from_raw(0), // Indicate success
    })
}

pub fn combine_json_outputs(results: Vec<io::Result<Output>>) -> io::Result<Output> {
    let mut combined_map = serde_json::Map::new();

    for result in results {
        let output = result?; // Propagate any error from the individual command
        let json_str = String::from_utf8_lossy(&output.stdout);
        // Handle empty or non-JSON output gracefully by skipping
        if json_str.trim().is_empty() { continue; }

        let value: serde_json::Value = serde_json::from_str(&json_str.trim())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse JSON: {}", e)))?;

        if let serde_json::Value::Object(map) = value {
            combined_map.extend(map);
        } else {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "Expected JSON object from package listing"));
        }
    }

    let combined_json = serde_json::Value::Object(combined_map);
    let pretty_json = serde_json::to_string_pretty(&combined_json)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("Failed to serialize combined JSON: {}", e)))?;

    Ok(Output {
        stdout: pretty_json.into_bytes(),
        stderr: Vec::new(), // Stderr from individual commands is not aggregated here
        status: ExitStatus::from_raw(0), // Indicate success
    })
}

pub fn save_package_list(output: &Output) -> io::Result<()> {
    let json_str = String::from_utf8_lossy(&output.stdout);
    let dir_path = "SysBackup";
    let file_path = Path::new(dir_path).join("package_list.json");

    std::fs::create_dir_all(dir_path)?; // Create the directory if it doesn't exist

    let mut file = File::create(&file_path)?;
    file.write_all(json_str.as_bytes())?;
    println!("Package list saved to {}", file_path.display());
    Ok(())
}

pub fn install_packages() -> io::Result<()> {
    println!("Starting package installation process...");

    // 1. Read the package_list.json file
    let package_list_str = fs::read_to_string("SysBackup/package_list.json")
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, format!("Failed to read package_list.json: {}", e)))?;
    let package_list_json: Value = serde_json::from_str(&package_list_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse package_list.json: {}", e)))?;
    let package_list_map = package_list_json.as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "package_list.json is not a valid JSON object"))?;

    // 2. Detect available package managers
    let detected_managers_output = detect_package_managers()?;
    let detected_managers_json_str = String::from_utf8_lossy(&detected_managers_output.stdout);
    let detected_managers_value: Value = serde_json::from_str(&detected_managers_json_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("Failed to parse detected managers JSON: {}", e)))?;
    let detected_managers_map = detected_managers_value["detected_package_managers"].as_object()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "Expected 'detected_package_managers' object"))?;

    let mut already_installed = Vec::new();
    let mut newly_installed = Vec::new();
    let mut failed_to_install = Vec::new();

    // 3. Iterate through package managers and packages from the list
    for (manager_name, packages_value) in package_list_map.iter() {
        if detected_managers_map.get(manager_name).and_then(|v| v.as_bool()).unwrap_or(false) {
            println!("
Processing packages for {}...", manager_name);
            if let Some(packages) = packages_value.as_array() {
                for package_value in packages {
                    if let Some(package_name) = package_value.as_str() {
                        // 4. Check if package is already installed
                        if is_package_installed(manager_name, package_name)? {
                            already_installed.push(format!("{} ({})", package_name, manager_name));
                        } else {
                            // 5. Install the package if it's not already present
                            println!("Attempting to install {} with {}...", package_name, manager_name);
                            if install_single_package(manager_name, package_name) {
                                newly_installed.push(format!("{} ({})", package_name, manager_name));
                            } else {
                                failed_to_install.push(format!("{} ({})", package_name, manager_name));
                            }
                        }
                    }
                }
            }
        } else {
            println!("
Skipping package manager '{}' (not detected on this system).", manager_name);
        }
    }

    // 6. Report the results
    println!("
--- Installation Summary ---");
    if !already_installed.is_empty() {
        println!("
Already Installed Packages:");
        for pkg in &already_installed {
            println!("- {}", pkg);
        }
    }
    if !newly_installed.is_empty() {
        println!("
Successfully Installed Packages:");
        for pkg in &newly_installed {
            println!("- {}", pkg);
        }
    }
    if !failed_to_install.is_empty() {
        println!("
Failed to Install Packages:");
        for pkg in &failed_to_install {
            println!("- {}", pkg);
        }
    }
    if newly_installed.is_empty() && failed_to_install.is_empty() {
        println!("
No new packages were installed.");
    }

    Ok(())
}

/// Checks if a specific package is installed using the given package manager.
fn is_package_installed(manager: &str, package: &str) -> io::Result<bool> {
    let mut cmd = match manager {
        "apt" => Command::new("dpkg"),
        "yum_dnf" => Command::new("dnf"),
        "pacman" => Command::new("pacman"),
        "flatpak" => Command::new("flatpak"),
        "snap" => Command::new("snap"),
        "portage" => Command::new("qlist"),
        "xbps" => Command::new("xbps-query"),
        _ => return Ok(false), // Unknown manager
    };

    let args = match manager {
        "apt" => vec!["-s", package],
        "yum_dnf" => vec!["list", "installed", package],
        "pacman" => vec!["-Q", package],
        "flatpak" => vec!["info", package],
        "snap" => vec!["list", package],
        "portage" => vec!["-I", package],
        "xbps" => vec!["-S", package],
        _ => vec![],
    };

    let output = cmd.args(&args).output()?;
    Ok(output.status.success())
}

/// Installs a single package using the appropriate package manager.
/// Returns true if installation was successful, false otherwise.
fn install_single_package(manager: &str, package: &str) -> bool {
    let (command, sudo) = match manager {
        "apt" => ("apt", true),
        "yum_dnf" => ("dnf", true),
        "pacman" => ("pacman", true),
        "flatpak" => ("flatpak", false),
        "snap" => ("snap", true),
        "portage" => ("emerge", true),
        "xbps" => ("xbps-install", true),
        _ => return false,
    };

    let mut cmd;
    if sudo {
        cmd = Command::new("sudo");
        cmd.arg(command);
    } else {
        cmd = Command::new(command);
    }

    let args = match manager {
        "apt" | "yum_dnf" => vec!["install", "-y", package],
        "pacman" => vec!["-S", "--noconfirm", package],
        "flatpak" => vec!["install", "-y", package],
        "snap" => vec!["install", package],
        "portage" => vec![package],
        "xbps" => vec!["-S", "-y", package],
        _ => vec![],
    };

    let status = cmd.args(&args)
        .stdout(std::process::Stdio::null()) // Suppress stdout for cleaner output
        .stderr(std::process::Stdio::null()) // Suppress stderr for cleaner output
        .status();

    match status {
        Ok(exit_status) => {
            if exit_status.success() {
                println!("Successfully installed {}.", package);
                true
            } else {
                eprintln!("Failed to install {}. Exit code: {:?}", package, exit_status.code());
                false
            }
        }
        Err(e) => {
            eprintln!("Error executing install command for {}: {}", package, e);
            false
        }
    }
}