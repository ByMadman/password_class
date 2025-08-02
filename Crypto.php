<?php
/**
 * 加密算法工具类
 * 包含多种常用加密算法的实现
 */
class Crypto {
    // 哈希算法常量
    const HASH_MD5 = 'md5';
    const HASH_SHA1 = 'sha1';
    const HASH_SHA256 = 'sha256';
    const HASH_SHA512 = 'sha512';
    const HASH_CRC32 = 'crc32';
    const HASH_CRC32B = 'crc32b';
    
    // 对称加密算法常量
    const SYMMETRIC_AES_128_CBC = 'aes-128-cbc';
    const SYMMETRIC_AES_256_CBC = 'aes-256-cbc';
    const SYMMETRIC_AES_128_GCM = 'aes-128-gcm';
    const SYMMETRIC_AES_256_GCM = 'aes-256-gcm';
    const SYMMETRIC_DES = 'des-cbc';
    const SYMMETRIC_3DES = 'des-ede3-cbc';
    
    // 非对称加密算法常量
    const ASYMMETRIC_RSA = 'rsa';
    
    /**
     * 生成随机加密密钥
     * 
     * @param int $length 密钥长度
     * @return string 随机密钥
     */
    public static function generateRandomKey($length = 32) {
        return openssl_random_pseudo_bytes($length);
    }
    
    /**
     * 生成随机IV (初始化向量)
     * 
     * @param string $cipher 加密算法
     * @return string 随机IV
     */
    public static function generateIV($cipher) {
        $ivLength = openssl_cipher_iv_length($cipher);
        return openssl_random_pseudo_bytes($ivLength);
    }
    
    /**
     * 计算哈希值
     * 
     * @param string $data 要哈希的数据
     * @param string $algorithm 哈希算法
     * @param bool $rawOutput 是否返回原始二进制数据
     * @return string 哈希结果
     */
    public static function hash($data, $algorithm = self::HASH_SHA256, $rawOutput = false) {
        switch ($algorithm) {
            case self::HASH_MD5:
                return md5($data, $rawOutput);
            case self::HASH_SHA1:
                return sha1($data, $rawOutput);
            case self::HASH_CRC32:
                $hash = crc32($data);
                return $rawOutput ? pack('N', $hash) : sprintf('%u', $hash);
            case self::HASH_CRC32B:
                $hash = crc32b($data);
                return $rawOutput ? pack('N', $hash) : sprintf('%u', $hash);
            default:
                return hash($algorithm, $data, $rawOutput);
        }
    }
    
    /**
     * 密码哈希 (推荐用于密码存储)
     * 
     * @param string $password 原始密码
     * @param int $cost 算法复杂度
     * @return string 哈希后的密码
     */
    public static function passwordHash($password, $cost = 12) {
        return password_hash($password, PASSWORD_DEFAULT, ['cost' => $cost]);
    }
    
    /**
     * 验证密码哈希
     * 
     * @param string $password 原始密码
     * @param string $hash 哈希后的密码
     * @return bool 验证结果
     */
    public static function passwordVerify($password, $hash) {
        return password_verify($password, $hash);
    }
    
    /**
     * 对称加密
     * 
     * @param string $data 要加密的数据
     * @param string $key 加密密钥
     * @param string $algorithm 加密算法
     * @param string $iv 初始化向量 (可选)
     * @param string $tag 用于GCM模式的认证标签 (引用传递)
     * @return string 加密后的数据
     */
    public static function symmetricEncrypt($data, $key, $algorithm = self::SYMMETRIC_AES_256_CBC, &$tag = null, $iv = null) {
        // 确保密钥长度符合算法要求
        $key = self::adjustKeyLength($key, $algorithm);
        
        // 如果未提供IV，则生成一个
        if ($iv === null) {
            $iv = self::generateIV($algorithm);
        }
        
        // 对于GCM模式，需要生成认证标签
        $options = 0;
        $additionalData = '';
        
        if (strpos($algorithm, 'gcm') !== false) {
            $encrypted = openssl_encrypt(
                $data, 
                $algorithm, 
                $key, 
                $options, 
                $iv, 
                $tag, 
                $additionalData
            );
        } else {
            $encrypted = openssl_encrypt(
                $data, 
                $algorithm, 
                $key, 
                $options, 
                $iv
            );
        }
        
        // 返回IV和加密数据的组合，使用分号分隔
        return base64_encode($iv) . ';' . $encrypted;
    }
    
    /**
     * 对称解密
     * 
     * @param string $data 要解密的数据 (包含IV)
     * @param string $key 解密密钥
     * @param string $algorithm 解密算法
     * @param string $tag 用于GCM模式的认证标签
     * @return string 解密后的数据
     */
    public static function symmetricDecrypt($data, $key, $algorithm = self::SYMMETRIC_AES_256_CBC, $tag = null) {
        // 分离IV和加密数据
        list($ivBase64, $encryptedData) = explode(';', $data, 2);
        $iv = base64_decode($ivBase64);
        
        // 确保密钥长度符合算法要求
        $key = self::adjustKeyLength($key, $algorithm);
        
        $options = 0;
        $additionalData = '';
        
        if (strpos($algorithm, 'gcm') !== false) {
            return openssl_decrypt(
                $encryptedData, 
                $algorithm, 
                $key, 
                $options, 
                $iv, 
                $tag, 
                $additionalData
            );
        } else {
            return openssl_decrypt(
                $encryptedData, 
                $algorithm, 
                $key, 
                $options, 
                $iv
            );
        }
    }
    
    /**
     * 生成非对称加密密钥对
     * 
     * @param string $algorithm 算法
     * @param int $bits 密钥长度
     * @return array 包含私钥和公钥的数组
     */
    public static function generateAsymmetricKeys($algorithm = self::ASYMMETRIC_RSA, $bits = 2048) {
        $config = [
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        
        // 生成新的私钥
        $privateKey = openssl_pkey_new($config);
        
        // 提取公钥
        $publicKey = openssl_pkey_get_details($privateKey);
        $publicKey = $publicKey['key'];
        
        return [
            'private' => $privateKey,
            'public' => $publicKey
        ];
    }
    
    /**
     * 非对称加密 (使用公钥加密)
     * 
     * @param string $data 要加密的数据
     * @param string $publicKey 公钥
     * @param string $algorithm 算法
     * @return string 加密后的数据
     */
    public static function asymmetricEncrypt($data, $publicKey, $algorithm = self::ASYMMETRIC_RSA) {
        $encrypted = '';
        openssl_public_encrypt($data, $encrypted, $publicKey);
        return base64_encode($encrypted);
    }
    
    /**
     * 非对称解密 (使用私钥解密)
     * 
     * @param string $data 要解密的数据
     * @param string $privateKey 私钥
     * @param string $algorithm 算法
     * @return string 解密后的数据
     */
    public static function asymmetricDecrypt($data, $privateKey, $algorithm = self::ASYMMETRIC_RSA) {
        $decrypted = '';
        $data = base64_decode($data);
        openssl_private_decrypt($data, $decrypted, $privateKey);
        return $decrypted;
    }
    
    /**
     * 使用私钥签名数据
     * 
     * @param string $data 要签名的数据
     * @param string $privateKey 私钥
     * @param string $hashAlgorithm 哈希算法
     * @return string 签名结果
     */
    public static function sign($data, $privateKey, $hashAlgorithm = self::HASH_SHA256) {
        $signature = '';
        openssl_sign($data, $signature, $privateKey, $hashAlgorithm);
        return base64_encode($signature);
    }
    
    /**
     * 验证数据签名
     * 
     * @param string $data 原始数据
     * @param string $signature 签名
     * @param string $publicKey 公钥
     * @param string $hashAlgorithm 哈希算法
     * @return bool 验证结果
     */
    public static function verifySignature($data, $signature, $publicKey, $hashAlgorithm = self::HASH_SHA256) {
        $signature = base64_decode($signature);
        $result = openssl_verify($data, $signature, $publicKey, $hashAlgorithm);
        return $result === 1;
    }
    
    /**
     * 调整密钥长度以适应算法要求
     * 
     * @param string $key 原始密钥
     * @param string $algorithm 加密算法
     * @return string 调整后的密钥
     */
    private static function adjustKeyLength($key, $algorithm) {
        $keyLength = 0;
        
        switch ($algorithm) {
            case self::SYMMETRIC_AES_128_CBC:
            case self::SYMMETRIC_AES_128_GCM:
                $keyLength = 16; // 128位 = 16字节
                break;
            case self::SYMMETRIC_AES_256_CBC:
            case self::SYMMETRIC_AES_256_GCM:
                $keyLength = 32; // 256位 = 32字节
                break;
            case self::SYMMETRIC_DES:
                $keyLength = 8; // 64位 = 8字节
                break;
            case self::SYMMETRIC_3DES:
                $keyLength = 24; // 192位 = 24字节
                break;
        }
        
        if ($keyLength > 0 && strlen($key) !== $keyLength) {
            // 使用哈希函数调整密钥长度
            $key = self::hash($key, self::HASH_SHA256, true);
            $key = substr($key, 0, $keyLength);
        }
        
        return $key;
    }
}
?>