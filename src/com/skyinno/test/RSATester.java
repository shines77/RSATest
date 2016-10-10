/**
 * RSATester
 */
package com.skyinno.test;

import com.skyinno.security.*;
import java.util.Map;

/**
 * @author ousinka, @modify by shines77
 * 
 * See: https://my.oschina.net/ousinka/blog/338099
 * 
 */
public class RSATester {
	
    static String publicKey;
    static String privateKey;
    static final int keySize = 2048;

    static {
        try {
            Map<String, Object> keyMap = RSAUtils.genKeyPair(keySize);
            publicKey = RSAUtils.getPublicKey(keyMap);
            privateKey = RSAUtils.getPrivateKey(keyMap);
            System.out.println("密钥长度：" + keySize + " 位\r\n");
            System.out.println("公钥：\r\n" + publicKey + "\r\n");
            System.out.println("私钥：\r\n" + privateKey + "\r\n");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }	
	
    static void test() throws Exception {
    	String source = "这是一行没有任何意义的文字，你看完了等于没看，不是吗？";
        System.out.println("公钥加密——私钥解密" + "\r\n");
        System.out.println("加密前文字：\r\n" + source + "\r\n");
        byte[] data = source.getBytes();
        byte[] encodedData = RSAUtils.encryptByPublicKey(data, publicKey, keySize);
        System.out.println("加密后文字：\r\n" + new String(encodedData) + "\r\n");
        byte[] decodedData = RSAUtils.decryptByPrivateKey(encodedData, privateKey, keySize);
        String target = new String(decodedData);
        System.out.println("解密后文字：\r\n" + target + "\r\n");
    }

    static void testSign() throws Exception {
    	String source = "这是一行测试RSA数字签名的无意义文字";
        System.out.println("私钥加密——公钥解密" + "\r\n");
        System.out.println("原文字：\r\n" + source + "\r\n");
        byte[] data = source.getBytes();
        byte[] encodedData = RSAUtils.encryptByPrivateKey(data, privateKey, keySize);
        System.out.println("加密后：\r\n" + new String(encodedData) + "\r\n");
        byte[] decodedData = RSAUtils.decryptByPublicKey(encodedData, publicKey, keySize);
        String target = new String(decodedData);
        System.out.println("解密后：\r\n" + target + "\r\n");
        System.out.println("私钥签名——公钥验证签名" + "\r\n");
        String sign = RSAUtils.sign(encodedData, privateKey);
        System.out.println("签名：\r\n" + sign + "\r\n");
        boolean status = RSAUtils.verify(encodedData, publicKey, sign);
        System.out.println("验证结果：\r\n" + status + "\r\n");
    }	

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		// test
		test();
		testSign();
	}

}
