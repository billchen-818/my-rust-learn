use multisig::MultiSigPolicy;
use multisig::MultiSigSession;
use multisig::sign_session;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== m-of-n 多签演示 ===\n");

    // 创建 3-of-5 多签策略
    let n = 5;
    let m = 3;
    let (signing_keys, mut policy) = MultiSigPolicy::generate_test_keys(n);
    policy.threshold = m; // 覆盖为 3-of-5

    println!("策略: {m}-of-{n} 多签");
    println!("参与方数量: {}", policy.participants.len());

    // 创建一笔需要审批的"转账提案"
    let proposal = serde_json::json!({
        "action": "transfer",
        "to": "0xdeadbeef...",
        "amount": "1000000000000000000", // 1 ETH in wei
        "nonce": 42,
    });
    let message = proposal.to_string().into_bytes();

    println!("\n待审批消息: {}", String::from_utf8_lossy(&message));

    // 创建多签会话
    let mut session = MultiSigSession::new(policy.clone(), message);

    // 模拟参与方逐一签名
    for i in 0..n {
        let sig = sign_session(&session, &signing_keys[i]);
        match session.submit_signature(i, sig) {
            Ok(()) => println!(
                "参与方 {i} 签名成功，当前签名数: {}",
                session.signature_count()
            ),
            Err(e) => println!("参与方 {i} 签名失败: {e}"),
        }
        if session.is_complete() {
            println!("\n✓ 已达到阈值 {m}，无需等待剩余参与方");
            break;
        }
    }

    // 最终确认
    let approved_by = session.finalize()?;
    println!("\n交易已获批准，批准方索引: {approved_by:?}");

    // 演示：阈值不足时的错误处理
    println!("\n--- 演示阈值不足的情况 ---");
    let mut insufficient_session = MultiSigSession::new(policy.clone(), b"another tx".to_vec());
    let sig0 = sign_session(&insufficient_session, &signing_keys[0]);
    let sig1 = sign_session(&insufficient_session, &signing_keys[1]);
    insufficient_session.submit_signature(0, sig0)?;
    insufficient_session.submit_signature(1, sig1)?;
    match insufficient_session.finalize() {
        Err(e) => println!("预期错误: {e}"),
        Ok(_) => println!("不应该到这里"),
    }

    // 演示：伪造签名被拒绝
    println!("\n--- 演示伪造签名被拒绝 ---");
    let mut forge_session = MultiSigSession::new(policy.clone(), b"tx to forge".to_vec());
    // 参与方 0 用自己的私钥签，但声称是参与方 1 的签名
    let forged_sig = sign_session(&forge_session, &signing_keys[0]);
    match forge_session.submit_signature(1, forged_sig) {
        Err(e) => println!("伪造签名被拒绝: {e}"),
        Ok(_) => println!("不应该通过"),
    }

    Ok(())
}
