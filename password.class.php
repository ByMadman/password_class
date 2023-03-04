<?php
/*
* File：密码加密类
* Author：孤独的封装
* url：www.chahash.com
* 方便自己也方便别人
*/
class password{
	
	//mysql323  老MYSQL数据库用的，16位，且第1位和第7位必须为0-8
	public function MYSQL323 ($input, $hex = true){
		$nr = 1345345333; $add = 7; $nr2 = 0x12345671; $tmp = null;
		$inlen = strlen($input);
		for ($i = 0; $i < $inlen; $i++) {
			$byte = substr($input, $i, 1);
			if ($byte == ' ' || $byte == "\t") continue;
			$tmp = ord($byte);
			$nr ^= ((($nr & 63) + $add) * $tmp) + (($nr << 8) & 0xFFFFFFFF);
			$nr2 += (($nr2 << 8) & 0xFFFFFFFF) ^ $nr;
			$add += $tmp;
		}
		$out_a = $nr & ((1 << 31) - 1);
		$out_b = $nr2 & ((1 << 31) - 1);
		$output = sprintf("%08x%08x", $out_a, $out_b);
		if ($hex) return $output;
		return $this->hex_hash_to_bin($output);
	}
	
	//mysql5以上的版本 	新版本MySql数据库用的
	public function MYSQL5($input, $hex = true){
		$sha1_stage1 = sha1($input, true);
		$output = sha1($sha1_stage1, !$hex);
		return '*'.strtoupper($output);
	}
	
	//SHA1  //密文长度必须为40位
	public function Get_SHA1($data,$raw=false){
		return strtoupper(sha1($data, $raw));
	}
	
	//md5(md5($pass)) //第一次加密后，结果转换成小写，对结果再加密一次
	public function md5_md5($data){
		return strtoupper(md5(md5($data)));
	}
	
	//md5(md5(md5($pass))) //第一次加密后，结果转换成小写，对结果再加密一次,结果转换成小写，对结果再加密一次
	public function md5_md5_md5($data){
		return md5(md5(md5($data)));
	}
	
	//md5(md5($pass).$salt); //适用于dz,vB等论坛程序，discuz的salt长度是6位，vBulletin的salt长度是3位或30位。
	public function md5_md5_salt($data,$salt){
		return md5(md5($data).$salt);
	}
	
	//md5(md5($salt).md5($pass))IPB  //salt长度5位
	public function md5_md5_IPB($data,$salt){
		return md5(md5($salt).md5($data));
	}
	
	//用于SMF
	public function SHA1_SMF($data,$salt){
		return sha1($salt.$data);
	}
	
	//sha256
	public function SHA256($data){
		return hash("sha256", utf8_encode($data));
	}
	
	//sha256($pass.$salt)
	public function SHA256_SALT($data,$salt){
		return hash("sha256", utf8_encode($data.$salt));
	}
	
	//sha256($salt.$pass)
	public function SALT_SHA256($salt,$data){
		return hash("sha256", utf8_encode($salt.$data));
	}
	
	/**
	* Computes each hexidecimal pair into the corresponding binary octet.
	* Similar to mysql hex2octet function.
	**/
	public function hex_hash_to_bin($hex){
		$bin = "";
		$len = strlen($hex);
		for ($i = 0; $i < $len; $i += 2) {
			$byte_hex = substr($hex, $i, 2);
			$byte_dec = hexdec($byte_hex);
			$byte_char = chr($byte_dec);
			$bin .= $byte_char;
		}
		return $bin;
	}
}