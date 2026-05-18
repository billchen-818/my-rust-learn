mod sig;

use k256::ecdsa::signature::Signer;
use k256::ecdsa::{Signature, SigningKey};

pub use sig::MultiSigPolicy;
pub use sig::MultiSigSession;

/// 参与方使用自己的私钥对会话消息签名
pub fn sign_session(session: &MultiSigSession, signing_key: &SigningKey) -> Signature {
    let digest = session.message_digest();
    // k256 的 sign 方法内部使用 RFC6979 确定性 nonce，安全可靠
    signing_key.sign(&digest)
}
