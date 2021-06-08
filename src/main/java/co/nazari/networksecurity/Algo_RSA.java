/* 
RSA or Rivest–Shamir–Adleman is an algorithm employed by modern computers to 
encrypt and decrypt messages. It is an asymmetric cryptographic algorithm. 
Asymmetric means that there are two different keys. This is also called public-key 
cryptography because one among the keys are often given to anyone. The other is the 
private key which is kept private. The algorithm is predicated on the very fact 
that finding the factors of an outsized number is difficult: when the factors 
are prime numbers, the matter is named prime factorization. It is also a key pair 
(public and personal key) generator.

Implementation of RSA Algorithm:
1. Consider two prime numbers p and q.
2. Compute N = p*q
3. Compute phi = ϕ(n) = (p – 1) * (q – 1)
4. Choose 1 < e < ϕ(n) and gcd(e , ϕ(n) ) = 1 , greatest common divisor (GCD) of two integers
5. Calculate 1 < d < ϕ(n) and e*d mod ϕ(n) = 1
6. Public Key {e,n} Private Key {d,n}
7. Cipher text C = Pe modulo N where P = plaintext
8. For Decryption D = Dd modulo N where D will refund the plaintext.
*/
package co.nazari.networksecurity;

import java.io.DataInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Random;
/**
 *
 * @author alireza nazari (alireza.ginbox@gmail.com)
 */
public class Algo_RSA {
    private BigInteger p;
    private BigInteger q;
    private BigInteger N;
    private BigInteger phi;
    private BigInteger e;
    private BigInteger d;
    private int        bitlength = 1024;
    private Random     r;
 
    public Algo_RSA()
    {
        r = new Random();
        p = BigInteger.probablePrime(bitlength, r);
        q = BigInteger.probablePrime(bitlength, r);
        N = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        e = BigInteger.probablePrime(bitlength / 2, r);
        while (phi.gcd(e).compareTo(BigInteger.ONE) > 0 && e.compareTo(phi) < 0)
        {
            e.add(BigInteger.ONE);
        }
        d = e.modInverse(phi);
    }
 
    @SuppressWarnings("deprecation")
    public static void main(String[] args) throws IOException
    {
        Algo_RSA rsa = new Algo_RSA();
        DataInputStream in = new DataInputStream(System.in);
        String plainText;
        System.out.println("Enter the plain text:");
        plainText = in.readLine();
        // encrypt
        byte[] encrypted = rsa.encrypt(plainText.getBytes());
        System.out.println("Encrypting String: " + encrypted.toString());
//        System.out.println("String in Bytes: " + bytesToString(encrypted.toString().getBytes()));
        // decrypt
        byte[] decrypted = rsa.decrypt(encrypted);
        System.out.println("Decrypted String: " + new String(decrypted));
//        System.out.println("Decrypting Bytes: " + bytesToString(decrypted));
        System.out.println("\nPublic Key: " + rsa.getEK() );
        System.out.println("Private Key: " + rsa.getDK() );
    }
 
    private static String bytesToString(byte[] encrypted)
    {
        String test = "";
        for (byte b : encrypted)
        {
            test += Byte.toString(b);
        }
        return test;
    }
 
    // Encrypt message
    public byte[] encrypt(byte[] message)
    {
        return (new BigInteger(message)).modPow(e, N).toByteArray();
    }
 
    // Decrypt message
    public byte[] decrypt(byte[] message)
    {
        return (new BigInteger(message)).modPow(d, N).toByteArray();
    }
    
    public BigInteger getEK(){ return this.e; }
    public BigInteger getDK(){ return this.d; }
    
   
}

//1. p = 11 q = 3
//2. n = 33
//3. phi = 20
//4. e = 3
//5. d = 7
//6. en(33, 3), de(33, 7)
//7. C = (plain text = 7)^3 mod 33 = (343) mod 33 = 13
//8. D = (C = 13)^7 mod 33 = (plain text 7)
