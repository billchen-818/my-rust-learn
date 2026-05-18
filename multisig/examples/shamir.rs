use multisig::shamir;

fn main() {
    let secret: u64 = 0x1fff_ffff_dead_beef; // 模拟私钥片段（需小于 PRIME = 2^61-1）

    // 拆分：3-of-5
    let shares = shamir::shamir::split(secret, 3, 5);
    println!("原始秘密: {:#018x}", secret);
    println!("生成 {} 份碎片:", shares.len());
    for (x, y) in &shares {
        println!("  share[{x}] = {y:#018x}");
    }

    // 用任意 3 份还原
    let recovered = shamir::shamir::combine(&shares[0..3]);
    println!("\n用前 3 份还原: {:#018x}", recovered);
    assert_eq!(recovered, secret, "还原失败！");
    println!("✓ 还原成功");

    // 用不同的 3 份还原
    let recovered2 = shamir::shamir::combine(&[shares[1], shares[3], shares[4]]);
    assert_eq!(recovered2, secret);
    println!("✓ 用第 2、4、5 份也能还原");

    // 2 份无法还原（结果错误但不会 panic）
    let wrong = shamir::shamir::combine(&shares[0..2]);
    println!("\n只用 2 份尝试还原: {:#018x}（应与原值不同）", wrong);
    assert_ne!(wrong, secret);
    println!("✓ 不足份数无法正确还原");
}
