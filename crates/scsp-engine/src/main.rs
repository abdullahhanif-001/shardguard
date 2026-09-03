// scsp-engine — IR lift hot path (semantic node counts)
use std::env;
use std::fs;
use std::path::Path;
use walkdir::WalkDir;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: scsp-engine <path> [--ir-lift]");
        std::process::exit(1);
    }
    let root = Path::new(&args[1]);
    let ir_mode = args.iter().any(|a| a == "--ir-lift");
    let exts = ["js", "mjs", "cjs", "py", "go", "rs", "java", "c", "cpp"];
    let mut files = 0usize;
    let mut semantic_nodes = 0usize;

    let walk = |p: &Path| {
        if p.components().any(|c| c.as_os_str() == "node_modules") {
            return;
        }
        if !p.is_file() {
            return;
        }
        let ext = p.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !exts.contains(&ext) {
            return;
        }
        files += 1;
        if ir_mode {
            if let Ok(text) = fs::read_to_string(p) {
                for line in text.lines() {
                    if line.contains("import") || line.contains("require(") || line.contains("eval(") {
                        semantic_nodes += 1;
                    }
                    if line.contains("process.env") || line.contains("exec(") {
                        semantic_nodes += 1;
                    }
                }
            }
        }
    };

    if root.is_file() {
        walk(root);
    } else if root.is_dir() {
        for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
            walk(entry.path());
        }
    }

    if ir_mode {
        println!("{{\"files\":{},\"semantic_nodes\":{}}}", files, semantic_nodes);
    } else {
        println!("{}", files);
    }
}
