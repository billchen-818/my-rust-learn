fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::Config::new()
        .out_dir("src/pb") // 生成的 Rust 代码输出目录
        .compile_protos(
            &["proto/tutorial.proto"], // .proto 文件列表
            &["proto/"],               // 搜索路径（import 其他 .proto 时用到）
        )?;

    Ok(())
}
