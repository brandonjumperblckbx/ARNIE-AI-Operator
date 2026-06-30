fn main() {
    let lib_dir = "/home/brandon/IdeaProjects/ARNIE-AI-Operator/rmcp_native";
    println!("cargo:rustc-link-search=native={}", lib_dir);
    println!("cargo:rustc-link-lib=dylib=rmcp_native");
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", lib_dir);
}
