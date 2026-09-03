from pathlib import Path

rust = 'fn main(){let mut v=Vec::new();for i in 0..10{v.push(i);}std::process::Command::new("sh").spawn().unwrap();}'
swift = 'import Foundation;class R{func go(){let p=Process();p.executableURL=URL(fileURLWithPath:"/bin/sh");try?p.run()}}'
for i in range(3):
    Path(f"benchmarks/hidden/rust/minified-{i:02d}/main.rs").write_text(rust + "\n", encoding="utf-8")
    Path(f"benchmarks/hidden/swift/minified-{i:02d}/main.swift").write_text(swift + "\n", encoding="utf-8")
print("ok")
