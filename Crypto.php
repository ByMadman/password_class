<?php
/**
 * CMS系统加密算法集合类
 * 封装了主流CMS使用的各类加密算法，方便统一调用
 */
class CMSCrypto {
    
    // WordPress相关常量
    const WP_OLD_SALT_LENGTH = 9;
    const WP_BCRYPT_COST = 10;
    
    // Drupal相关常量
    const DRUPAL7_ITERATIONS = 1000;
    const DRUPAL7_HASH_LENGTH = 64;
    const DRUPAL_ARGON2_MEMORY_COST = 65536;
    const DRUPAL_ARGON2_TIME_COST = 4;
    const DRUPAL_ARGON2_THREADS = 3;
    
    // Joomla相关常量
    const JOOMLA3_SALT_LENGTH = 32;
    
    // Magento相关常量
    const MAGENTO_SALT_LENGTH = 32;
    const MAGENTO_ITERATIONS = 2;
    
    // Typo3相关常量
    const TYPO3_PBKDF2_ITERATIONS = 1000;
    const TYPO3_PBKDF2_LENGTH = 64;
    
    // Discuz! (DZ)相关常量
    const DISCUZ_SALT_LENGTH = 6;
    const DISCUZ_HASH_PREFIX = 'U';
    
    // 织梦(DedeCMS)相关常量
    const DEDECMS_MAGIC_STRING = 'dedecms';
    
    // 优易CMS相关常量
    const YOUYICMS_SALT_LENGTH = 8;
    const YOUYICMS_ITERATIONS = 3;
    
    // 通用加密常量
    const AES_256_CBC_IV_LENGTH = 16;
    const AES_256_GCM_IV_LENGTH = 12;
    const AES_256_GCM_TAG_LENGTH = 16;
    
    /**
     * WordPress密码加密
     * 支持旧版本MD5和新版本bcrypt
     * 
     * @param string $password 密码
     * @param bool $useOldAlgorithm 是否使用旧版算法
     * @param string $salt 盐值，为null则自动生成
     * @return string 加密后的密码
     */
    public static function wordpressHash($password, $useOldAlgorithm = false, $salt = null) {
        if ($useOldAlgorithm) {
            // WordPress旧版本加密方式: MD5 + 盐值
            if ($salt === null) {
                $salt = self::generateRandomString(self::WP_OLD_SALT_LENGTH);
            }
            return '$P$' . $salt . md5($salt . $password);
        } else {
            // WordPress新版本加密方式: bcrypt
            return password_hash($password, PASSWORD_BCRYPT, [
                'cost' => self::WP_BCRYPT_COST
            ]);
        }
    }
    
    /**
     * WordPress密码验证
     * 
     * @param string $password 原始密码
     * @param string $hashedPassword 加密后的密码
     * @return bool 验证结果
     */
    public static function wordpressVerify($password, $hashedPassword) {
        // 检查是否是旧版MD5哈希
        if (substr($hashedPassword, 0, 3) === '$P$') {
            $salt = substr($hashedPassword, 3, self::WP_OLD_SALT_LENGTH);
            $computedHash = '$P$' . $salt . md5($salt . $password);
            return hash_equals($computedHash, $hashedPassword);
        } else {
            // 新版bcrypt验证
            return password_verify($password, $hashedPassword);
        }
    }
    
    /**
     * Drupal密码加密
     * 支持Drupal7和Drupal8+的加密方式
     * 
     * @param string $password 密码
     * @param bool $useDrupal7Algorithm 是否使用Drupal7算法
     * @param string $salt 盐值，为null则自动生成
     * @return string 加密后的密码
     */
    public static function drupalHash($password, $useDrupal7Algorithm = false, $salt = null) {
        if ($useDrupal7Algorithm) {
            // Drupal7加密方式: SHA-512 + 盐值 + 迭代
            if ($salt === null) {
                $salt = self::generateRandomString(16);
            }
            $hash = hash('sha512', $salt . $password, true);
            for ($i = 1; $i < self::DRUPAL7_ITERATIONS; $i++) {
                $hash = hash('sha512', $hash . $password, true);
            }
            return '$S$' . $salt . base64_encode($hash);
        } else {
            // Drupal8+加密方式: 优先使用Argon2i，否则使用bcrypt
            if (defined('PASSWORD_ARGON2I')) {
                return password_hash($password, PASSWORD_ARGON2I, [
                    'memory_cost' => self::DRUPAL_ARGON2_MEMORY_COST,
                    'time_cost' => self::DRUPAL_ARGON2_TIME_COST,
                    'threads' => self::DRUPAL_ARGON2_THREADS
                ]);
            } else {
                return password_hash($password, PASSWORD_BCRYPT);
            }
        }
    }
    
    /**
     * Drupal密码验证
     * 
     * @param string $password 原始密码
     * @param string $hashedPassword 加密后的密码
     * @return bool 验证结果
     */
    public static function drupalVerify($password, $hashedPassword) {
        // 检查是否是Drupal7哈希
        if (substr($hashedPassword, 0, 3) === '$S$') {
            $salt = substr($hashedPassword, 3, 16);
            $storedHash = base64_decode(substr($hashedPassword, 19));
            
            $computedHash = hash('sha512', $salt . $password, true);
            for ($i = 1; $i < self::DRUPAL7_ITERATIONS; $i++) {
                $computedHash = hash('sha512', $computedHash . $password, true);
            }
            
            return hash_equals($computedHash, $storedHash);
        } else {
            // Drupal8+使用password_verify
            return password_verify($password, $hashedPassword);
        }
    }
    
    /**
     * Joomla密码加密
     * 支持Joomla3和Joomla4+的加密方式
     * 
     * @param string $password 密码
     * @param bool $useJoomla3Algorithm 是否使用Joomla3算法
     * @param string $salt 盐值，为null则自动生成
     * @return string 加密后的密码
     */
    public static function joomlaHash($password, $useJoomla3Algorithm = false, $salt = null) {
        if ($useJoomla3Algorithm) {
            // Joomla3加密方式: MD5 + 盐值
            if ($salt === null) {
                $salt = self::generateRandomString(self::JOOMLA3_SALT_LENGTH);
            }
            return md5($password . $salt) . ':' . $salt;
        } else {
            // Joomla4+加密方式: bcrypt
            return password_hash($password, PASSWORD_BCRYPT);
        }
    }
    
    /**
     * Joomla密码验证
     * 
     * @param string $password 原始密码
     * @param string $hashedPassword 加密后的密码
     * @return bool 验证结果
     */
    public static function joomlaVerify($password, $hashedPassword) {
        // 检查是否是Joomla3哈希
        if (strpos($hashedPassword, ':') !== false) {
            list($hash, $salt) = explode(':', $hashedPassword, 2);
            $computedHash = md5($password . $salt);
            return hash_equals($computedHash, $hash);
        } else {
            // Joomla4+使用password_verify
            return password_verify($password, $hashedPassword);
        }
    }
    
    /**
     * Magento密码加密
     * 
     * @param string $password 密码
     * @param string $salt 盐值，为null则自动生成
     * @return string 加密后的密码
     */
    public static function magentoHash($password, $salt = null) {
        // Magento加密方式: SHA-256 + 盐值 + 迭代
        if ($salt === null) {
            $salt = self::generateRandomString(self::MAGENTO_SALT_LENGTH);
        }
        
        $hash = $password;
        for ($i = 0; $i < self::MAGENTO_ITERATIONS; $i++) {
            $hash = hash('sha256', $hash . $salt);
        }
        
        return $hash . ':' . $salt;
    }
    
    /**
     * Magento密码验证
     * 
     * @param string $password 原始密码
     * @param string $hashedPassword 加密后的密码
     * @return bool 验证结果
     */
    public static function magentoVerify($password, $hashedPassword) {
        list($hash, $salt) = explode(':', $hashedPassword, 2);
        
        $computedHash = $password;
        for ($i = 0; $i < self::MAGENTO_ITERATIONS; $i++) {
            $computedHash = hash('sha256', $computedHash . $salt);
        }
        
        return hash_equals($computedHash, $hash);
    }
    
    /**
     * Typo3密码加密
     * 使用PBKDF2基于SHA-256
     * 
     * @param string $password 密码
     * @param string $salt 盐值，为null则自动生成
     * @return string 加密后的密码
     */
    public static function typo3Hash($password, $salt = null) {
        if ($salt === null) {
            $salt = self::generateRandomString(16);
        }
        
        $hash = hash_pbkdf2(
            'sha256',
            $password,
            $salt,
            self::TYPO3_PBKDF2_ITERATIONS,
            self::TYPO3_PBKDF2_LENGTH,
            true
        );
        
        return '$pbkdf2-sha256$' . self::TYPO3_PBKDF2_ITERATIONS . '$' . 
               base64_encode($salt) . '$' . base64_encode($hash);
    }
    
    /**
     * Typo3密码验证
     * 
     * @param string $password 原始密码
     * @param string $hashedPassword 加密后的密码
     * @return bool 验证结果
     */
    public static function typo3Verify($password, $hashedPassword) {
        $parts = explode('$', $hashedPassword);
        
        // 验证格式是否正确
        if (count($parts) !== 5 || $parts[1] !== 'pbkdf2-sha256') {
            return false;
        }
        
        $iterations = (int)$parts[2];
        $salt = base64_decode($parts[3]);
        $storedHash = base64_decode($parts[4]);
        
        $computedHash = hash_pbkdf2(
            'sha256',
            $password,
            $salt,
            $iterations,
            strlen($storedHash),
            true
        );
        
        return hash_equals($computedHash, $storedHash);
    }
    
    /**
     * Discuz! (DZ)密码加密
     * 
     * @param string $password 密码
     * @param string $salt 盐值，为null则自动生成
     * @return string 加密后的密码
     */
    public static function discuzHash($password, $salt = null) {
        // Discuz!加密方式: md5(md5(password) + salt)
        if ($salt === null) {
            $salt = self::generateRandomString(self::DISCUZ_SALT_LENGTH);
        }
        
        $hash = md5(md5($password) . $salt);
        return self::DISCUZ_HASH_PREFIX . $salt . $hash;
    }
    
    /**
     * Discuz! (DZ)密码验证
     * 
     * @param string $password 原始密码
     * @param string $hashedPassword 加密后的密码
     * @return bool 验证结果
     */
    public static function discuzVerify($password, $hashedPassword) {
        // 检查是否是Discuz!哈希格式
        if (substr($hashedPassword, 0, 1) !== self::DISCUZ_HASH_PREFIX) {
            return false;
        }
        
        $salt = substr($hashedPassword, 1, self::DISCUZ_SALT_LENGTH);
        $storedHash = substr($hashedPassword, 1 + self::DISCUZ_SALT_LENGTH);
        $computedHash = md5(md5($password) . $salt);
        
        return hash_equals($computedHash, $storedHash);
    }
    
    /**
     * 织梦(DedeCMS)密码加密
     * 
     * @param string $password 密码
     * @param bool $useOldAlgorithm 是否使用旧版算法
     * @return string 加密后的密码
     */
    public static function dedecmsHash($password, $useOldAlgorithm = false) {
        if ($useOldAlgorithm) {
            // 织梦旧版本加密方式: 简单MD5
            return md5($password);
        } else {
            // 织梦新版本加密方式: md5(password + 固定字符串)
            return md5($password . self::DEDECMS_MAGIC_STRING);
        }
    }
    
    /**
     * 织梦(DedeCMS)密码验证
     * 
     * @param string $password 原始密码
     * @param string $hashedPassword 加密后的密码
     * @param bool $useOldAlgorithm 是否使用旧版算法验证
     * @return bool 验证结果
     */
    public static function dedecmsVerify($password, $hashedPassword, $useOldAlgorithm = false) {
        if ($useOldAlgorithm) {
            $computedHash = md5($password);
        } else {
            $computedHash = md5($password . self::DEDECMS_MAGIC_STRING);
        }
        
        return hash_equals($computedHash, $hashedPassword);
    }
    
    /**
     * 优易CMS密码加密
     * 
     * @param string $password 密码
     * @param string $salt 盐值，为null则自动生成
     * @return string 加密后的密码
     */
    public static function youyicmsHash($password, $salt = null) {
        // 优易CMS加密方式: SHA-1 + 盐值 + 多次迭代
        if ($salt === null) {
            $salt = self::generateRandomString(self::YOUYICMS_SALT_LENGTH);
        }
        
        $hash = $password . $salt;
        for ($i = 0; $i < self::YOUYICMS_ITERATIONS; $i++) {
            $hash = sha1($hash);
        }
        
        return $hash . ':' . $salt;
    }
    
    /**
     * 优易CMS密码验证
     * 
     * @param string $password 原始密码
     * @param string $hashedPassword 加密后的密码
     * @return bool 验证结果
     */
    public static function youyicmsVerify($password, $hashedPassword) {
        list($hash, $salt) = explode(':', $hashedPassword, 2);
        
        $computedHash = $password . $salt;
        for ($i = 0; $i < self::YOUYICMS_ITERATIONS; $i++) {
            $computedHash = sha1($computedHash);
        }
        
        return hash_equals($computedHash, $hash);
    }
    
    /**
     * AES-256-CBC加密
     * 用于敏感数据加密，如配置信息
     * 
     * @param string $data 要加密的数据
     * @param string $key 加密密钥(32字节)
     * @param string $iv 初始化向量，为null则自动生成
     * @return string 加密后的数据，格式: iv.base64(encrypted)
     */
    public static function aes256cbcEncrypt($data, $key, $iv = null) {
        // 确保密钥长度正确
        $key = self::adjustKeyLength($key, 32);
        
        if ($iv === null) {
            $iv = openssl_random_pseudo_bytes(self::AES_256_CBC_IV_LENGTH);
        }
        
        $encrypted = openssl_encrypt(
            $data,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
        
        return base64_encode($iv) . '.' . base64_encode($encrypted);
    }
    
    /**
     * AES-256-CBC解密
     * 
     * @param string $data 要解密的数据
     * @param string $key 解密密钥(32字节)
     * @return string 解密后的数据
     */
    public static function aes256cbcDecrypt($data, $key) {
        // 确保密钥长度正确
        $key = self::adjustKeyLength($key, 32);
        
        list($ivBase64, $encryptedBase64) = explode('.', $data, 2);
        $iv = base64_decode($ivBase64);
        $encrypted = base64_decode($encryptedBase64);
        
        return openssl_decrypt(
            $encrypted,
            'aes-256-cbc',
            $key,
            OPENSSL_RAW_DATA,
            $iv
        );
    }
    
    /**
     * AES-256-GCM加密
     * 用于需要认证的敏感数据加密
     * 
     * @param string $data 要加密的数据
     * @param string $key 加密密钥(32字节)
     * @param string $tag 认证标签，引用传递
     * @param string $iv 初始化向量，为null则自动生成
     * @return string 加密后的数据，格式: iv.base64(encrypted)
     */
    public static function aes256gcmEncrypt($data, $key, &$tag, $iv = null) {
        // 确保密钥长度正确
        $key = self::adjustKeyLength($key, 32);
        
        if ($iv === null) {
            $iv = openssl_random_pseudo_bytes(self::AES_256_GCM_IV_LENGTH);
        }
        
        $encrypted = openssl_encrypt(
            $data,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            '',
            self::AES_256_GCM_TAG_LENGTH
        );
        
        return base64_encode($iv) . '.' . base64_encode($encrypted);
    }
    
    /**
     * AES-256-GCM解密
     * 
     * @param string $data 要解密的数据
     * @param string $key 解密密钥(32字节)
     * @param string $tag 认证标签
     * @return string 解密后的数据
     */
    public static function aes256gcmDecrypt($data, $key, $tag) {
        // 确保密钥长度正确
        $key = self::adjustKeyLength($key, 32);
        
        list($ivBase64, $encryptedBase64) = explode('.', $data, 2);
        $iv = base64_decode($ivBase64);
        $encrypted = base64_decode($encryptedBase64);
        
        return openssl_decrypt(
            $encrypted,
            'aes-256-gcm',
            $key,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
    }
    
    /**
     * 生成HMAC-SHA256签名
     * 用于API认证等场景
     * 
     * @param string $data 要签名的数据
     * @param string $key 密钥
     * @return string 签名结果
     */
    public static function hmacSha256($data, $key) {
        return hash_hmac('sha256', $data, $key);
    }
    
    /**
     * 验证HMAC-SHA256签名
     * 
     * @param string $data 原始数据
     * @param string $signature 待验证的签名
     * @param string $key 密钥
     * @return bool 验证结果
     */
    public static function verifyHmacSha256($data, $signature, $key) {
        $computedSignature = self::hmacSha256($data, $key);
        return hash_equals($computedSignature, $signature);
    }
    
    /**
     * 生成RSA签名 (SHA-256)
     * 
     * @param string $data 要签名的数据
     * @param string $privateKey 私钥
     * @return string 签名结果(base64编码)
     */
    public static function rsaSign($data, $privateKey) {
        openssl_sign($data, $signature, $privateKey, OPENSSL_ALGO_SHA256);
        return base64_encode($signature);
    }
    
    /**
     * 验证RSA签名 (SHA-256)
     * 
     * @param string $data 原始数据
     * @param string $signature 待验证的签名(base64编码)
     * @param string $publicKey 公钥
     * @return bool 验证结果
     */
    public static function rsaVerify($data, $signature, $publicKey) {
        $signature = base64_decode($signature);
        $result = openssl_verify($data, $signature, $publicKey, OPENSSL_ALGO_SHA256);
        return $result === 1;
    }
    
    /**
     * 生成RSA密钥对
     * 
     * @param int $bits 密钥长度
     * @return array 包含私钥和公钥的数组
     */
    public static function generateRsaKeys($bits = 2048) {
        $config = [
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ];
        
        $privateKey = openssl_pkey_new($config);
        $publicKey = openssl_pkey_get_details($privateKey);
        
        return [
            'private' => $privateKey,
            'public' => $publicKey['key']
        ];
    }
    
    /**
     * 调整密钥长度
     * 
     * @param string $key 原始密钥
     * @param int $length 目标长度
     * @return string 调整后的密钥
     */
    private static function adjustKeyLength($key, $length) {
        if (strlen($key) !== $length) {
            $key = hash('sha256', $key, true);
            $key = substr($key, 0, $length);
        }
        return $key;
    }
    
    /**
     * 生成随机字符串
     * 
     * @param int $length 字符串长度
     * @return string 随机字符串
     */
    private static function generateRandomString($length) {
        $chars = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charsLength = strlen($chars);
        $randomString = '';
        
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $chars[rand(0, $charsLength - 1)];
        }
        
        return $randomString;
    }
}
?>