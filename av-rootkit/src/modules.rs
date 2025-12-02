use std::fs;

#[derive(Debug, Clone)]
pub struct KernelModule {
    pub name: String,
    pub size: u64,
    pub used_by: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct KernelModuleResult {
    pub modules: Vec<KernelModule>,
    pub suspicious_modules: Vec<String>,
}

pub fn scan_kernel_modules() -> KernelModuleResult {
    let modules = get_loaded_modules();
    let suspicious = modules
        .iter()
        .filter(|m| m.name.to_lowercase().contains("rk"))
        .map(|m| m.name.clone())
        .collect();
    KernelModuleResult {
        modules,
        suspicious_modules: suspicious,
    }
}

fn get_loaded_modules() -> Vec<KernelModule> {
    let mut modules = Vec::new();
    if let Ok(content) = fs::read_to_string("/proc/modules") {
        for line in content.lines() {
            if let Some(module) = parse_module_line(line) {
                modules.push(module);
            }
        }
    }
    modules
}

fn parse_module_line(line: &str) -> Option<KernelModule> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 3 {
        return None;
    }
    let name = parts[0].to_string();
    let size: u64 = parts[1].parse().ok()?;
    let used_by: Vec<String> = if parts.len() > 3 && parts[3] != "-" {
        parts[3]
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect()
    } else {
        Vec::new()
    };
    Some(KernelModule {
        name,
        size,
        used_by,
    })
}
