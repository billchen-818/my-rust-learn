use k256::ecdsa::signature::Verifier;
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

/// 多签配置
#[derive(Debug, Clone)]
pub struct MultiSigPolicy {
    /// 最少需要多少个签名
    pub threshold: usize,
    /// 所有授权参与方的公钥（indexed by participant ID）
    pub participants: Vec<VerifyingKey>,
}

/// 单个参与方的部分签名
#[allow(unused)]
#[derive(Debug, Clone)]
pub struct PartialSignature {
    /// 参与方在 participants 列表中的索引
    pub participant_idx: usize,
    /// 签名字节（DER 编码）
    pub signature: Signature,
}

/// 多签会话——收集签名的过程
pub struct MultiSigSession {
    pub policy: MultiSigPolicy,
    /// 待签消息（原始字节，验证时会先做 SHA-256）
    pub message: Vec<u8>,
    /// 已收集的签名
    pub collected: HashMap<usize, Signature>,
}

#[derive(Debug, thiserror::Error)]
pub enum MultiSigError {
    #[error("participant index {0} out of range")]
    InvalidParticipant(usize),
    #[error("signature from participant {0} is invalid")]
    InvalidSignature(usize),
    #[error("duplicate signature from participant {0}")]
    DuplicateSignature(usize),
    #[error("threshold not met: need {need}, got {got}")]
    ThresholdNotMet { need: usize, got: usize },
}

impl MultiSigPolicy {
    /// 创建一个 m-of-n 策略
    pub fn new(threshold: usize, participants: Vec<VerifyingKey>) -> Self {
        assert!(
            threshold > 0 && threshold <= participants.len(),
            "threshold must satisfy 1 ≤ m ≤ n"
        );
        Self {
            threshold,
            participants,
        }
    }

    /// 生成 n 个随机密钥对（用于测试）
    pub fn generate_test_keys(n: usize) -> (Vec<SigningKey>, Self) {
        let signing_keys: Vec<SigningKey> =
            (0..n).map(|_| SigningKey::random(&mut OsRng)).collect();
        let verifying_keys: Vec<VerifyingKey> =
            signing_keys.iter().map(|sk| *sk.verifying_key()).collect();
        (signing_keys, Self::new(n, verifying_keys)) // 暂时 n-of-n，调用方可按需修改
    }
}

impl MultiSigSession {
    pub fn new(policy: MultiSigPolicy, message: Vec<u8>) -> Self {
        Self {
            policy,
            message,
            collected: HashMap::new(),
        }
    }

    /// 消息摘要（所有操作都基于此摘要）
    pub fn message_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        // 加入域分隔前缀，防止跨协议签名重放
        hasher.update(b"multisig-v1:");
        hasher.update(&self.message);
        hasher.finalize().into()
    }

    /// 参与方提交签名
    pub fn submit_signature(
        &mut self,
        participant_idx: usize,
        signature: Signature,
    ) -> Result<(), MultiSigError> {
        // 边界检查
        if participant_idx >= self.policy.participants.len() {
            return Err(MultiSigError::InvalidParticipant(participant_idx));
        }
        // 防止重复提交
        if self.collected.contains_key(&participant_idx) {
            return Err(MultiSigError::DuplicateSignature(participant_idx));
        }
        // 验证签名有效性——注意：这里验证的是摘要
        let digest = self.message_digest();
        let vk = &self.policy.participants[participant_idx];
        vk.verify(&digest, &signature)
            .map_err(|_| MultiSigError::InvalidSignature(participant_idx))?;

        self.collected.insert(participant_idx, signature);
        Ok(())
    }

    /// 当前有效签名数量
    pub fn signature_count(&self) -> usize {
        self.collected.len()
    }

    /// 是否已满足阈值
    pub fn is_complete(&self) -> bool {
        self.collected.len() >= self.policy.threshold
    }

    /// 最终验证并导出已收集的签名列表
    /// 返回满足阈值的参与方索引列表
    pub fn finalize(&self) -> Result<Vec<usize>, MultiSigError> {
        if !self.is_complete() {
            return Err(MultiSigError::ThresholdNotMet {
                need: self.policy.threshold,
                got: self.collected.len(),
            });
        }
        let mut indices: Vec<usize> = self.collected.keys().copied().collect();
        indices.sort(); // 确定性顺序
        Ok(indices)
    }
}
