/// 简单的 Shamir 秘密共享实现（教学用途，字段为 u64，生产环境应使用大质数有限域）
///
/// 注意：生产环境请使用 vsss-rs 等专业库
pub mod shamir {
    use rand::RngExt;

    // 使用一个足够大的质数作为有限域模数
    // 生产环境应使用 2^256 级别的质数（与私钥空间匹配）
    const PRIME: u64 = 2_305_843_009_213_693_951; // 梅森素数 2^61 - 1

    fn mod_add(a: u64, b: u64) -> u64 {
        ((a as u128 + b as u128) % PRIME as u128) as u64
    }

    fn mod_mul(a: u64, b: u64) -> u64 {
        ((a as u128 * b as u128) % PRIME as u128) as u64
    }

    /// 模逆元（费马小定理：a^(p-2) mod p）
    fn mod_inv(a: u64) -> u64 {
        mod_pow(a, PRIME - 2)
    }

    fn mod_pow(mut base: u64, mut exp: u64) -> u64 {
        let mut result = 1u64;
        base %= PRIME;
        while exp > 0 {
            if exp & 1 == 1 {
                result = mod_mul(result, base);
            }
            exp >>= 1;
            base = mod_mul(base, base);
        }
        result
    }

    /// 将秘密 secret 拆分为 n 份，需要 threshold 份才能还原
    pub fn split(secret: u64, threshold: usize, n: usize) -> Vec<(u64, u64)> {
        assert!(threshold >= 2 && threshold <= n);
        assert!(secret < PRIME);

        let mut rng = rand::rng();

        // 构造一个随机的 (threshold-1) 次多项式，常数项为 secret
        // f(x) = secret + a1*x + a2*x^2 + ... + a_{t-1}*x^{t-1}
        let mut coefficients = vec![secret];
        for _ in 1..threshold {
            coefficients.push(rng.random_range(1..PRIME));
        }

        // 计算 n 个点 (i, f(i))，i 从 1 开始（避免 x=0）
        (1..=(n as u64))
            .map(|x| {
                let y = coefficients
                    .iter()
                    .enumerate()
                    .fold(0u64, |acc, (i, &coef)| {
                        mod_add(acc, mod_mul(coef, mod_pow(x, i as u64)))
                    });
                (x, y)
            })
            .collect()
    }

    /// 用拉格朗日插值从 shares 还原秘密（shares 数量需 ≥ threshold）
    pub fn combine(shares: &[(u64, u64)]) -> u64 {
        // 计算 f(0) 的拉格朗日插值
        shares.iter().enumerate().fold(0u64, |acc, (i, &(xi, yi))| {
            let lagrange = shares.iter().enumerate().fold(1u64, |prod, (j, &(xj, _))| {
                if i == j {
                    prod
                } else {
                    // 分子：(0 - xj) mod p = (p - xj) mod p
                    let num = (PRIME - xj) % PRIME;
                    // 分母：(xi - xj) mod p
                    let den = if xi > xj {
                        xi - xj
                    } else {
                        PRIME - (xj - xi) % PRIME
                    };
                    mod_mul(prod, mod_mul(num, mod_inv(den)))
                }
            });
            mod_add(acc, mod_mul(yi, lagrange))
        })
    }
}
