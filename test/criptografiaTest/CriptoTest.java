package criptografiaTest;

import static org.junit.Assert.*;

import hash.HashingImpl;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;

import org.junit.Test;


import criptografia.CriptoImpl;

public class CriptoTest {

	@Test
	public void testCriptografaDesKeyByteArray() {
		KeyGenerator gerador;
		byte [] mensagem = "teste1234".getBytes();
		try {
			CriptoImpl cripto = new CriptoImpl();
			gerador = KeyGenerator.getInstance("DES");
			gerador.init(56);
			Key chave = gerador.generateKey();
			
			Cipher cifra = Cipher.getInstance("DES");
			cifra.init(Cipher.ENCRYPT_MODE, chave);

			assertEquals(cripto.toHex(cifra.doFinal(mensagem)), cripto.toHex(cripto.criptografaDes(chave, mensagem)));			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

	@Test
	public void testCriptografaRsaKeyByteArray() {
		KeyPairGenerator gerador;
		byte [] mensagem = "teste1234".getBytes();
		try {
			CriptoImpl cripto = new CriptoImpl();
			gerador = KeyPairGenerator.getInstance("RSA");
			gerador.initialize(1024);
			KeyPair chaves = gerador.generateKeyPair();			
			Cipher cifra = Cipher.getInstance("RSA");
			cifra.init(Cipher.ENCRYPT_MODE, chaves.getPublic());			
			byte[] mensagemCript = cifra.doFinal(mensagem);			
			cifra.init(Cipher.DECRYPT_MODE, chaves.getPrivate());
			//Como a cada execucao do algoritmo a criptografia RSA gera uma string encriptada diferente,
			//criptografamos e descriptografamos, e testamos a igualdade das strings descriptografadas.
			assertEquals(cripto.toHex(cifra.doFinal(mensagemCript)), cripto.toHex(cripto.descriptografaRsa(chaves.getPrivate(), cripto.criptografaRsa(chaves.getPublic(), mensagem))));			
		} catch (Exception e) {
			e.printStackTrace();
		}
		

	}


	@Test
	public void testCriptografaRsaKeyStringString() {
		KeyPairGenerator gerador;
		HashingImpl hash = new HashingImpl();
		byte [] mensagem = "teste1234".getBytes();
		try {
			CriptoImpl cripto = new CriptoImpl();
			gerador = KeyPairGenerator.getInstance("RSA");
			gerador.initialize(1024);
			KeyPair chaves = gerador.generateKeyPair();			
	
			cripto.criptografaRsa(chaves.getPublic(), "res/teste.txt", "res/testeRsa.txt");
			cripto.descriptografaRsa(chaves.getPrivate(), "res/testeRsa.txt", "res/testeRsaDecript.txt");
			
			assertEquals(cripto.toHex(hash.md5("res/teste.txt")), cripto.toHex(hash.md5("res/testeRsaDecript.txt")));
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		


	}

	@Test
	public void testCriptografaDesKeyStringString() {
		KeyGenerator gerador;
		HashingImpl hash = new HashingImpl();
		try {
			CriptoImpl cripto = new CriptoImpl();
			gerador = KeyGenerator.getInstance("DES");
			gerador.init(56);
			Key chave = gerador.generateKey();			
	
			cripto.criptografaDes(chave, "res/teste.txt", "res/testeDes.txt");
			cripto.descriptografaDes(chave, "res/testeDes.txt", "res/testeDesDecript.txt");
			
			assertEquals(cripto.toHex(hash.md5("res/teste.txt")), cripto.toHex(hash.md5("res/testeDesDecript.txt")));
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		




	}

	@Test
	public void testDescriptografaRsaKeyByteArray() {
		KeyPairGenerator gerador;
		byte [] mensagem = "teste1234".getBytes();
		try {
			CriptoImpl cripto = new CriptoImpl();
			gerador = KeyPairGenerator.getInstance("RSA");
			gerador.initialize(1024);
			KeyPair chaves = gerador.generateKeyPair();
			Cipher cifra = Cipher.getInstance("RSA");
			cifra.init(Cipher.ENCRYPT_MODE, chaves.getPublic());
			byte[] mensagemCript = cifra.doFinal(mensagem);
			cifra.init(Cipher.DECRYPT_MODE, chaves.getPrivate());
			assertEquals(cripto.toHex(cifra.doFinal(mensagemCript)), cripto.toHex(cripto.descriptografaRsa(chaves.getPrivate(), cripto.criptografaRsa(chaves.getPublic(), mensagem))));			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		
	}

	@Test
	public void testDescriptografaDesKeyByteArray() {
		KeyGenerator gerador;
		byte [] mensagem = "teste1234".getBytes();
		try {
			CriptoImpl cripto = new CriptoImpl();
			gerador = KeyGenerator.getInstance("DES");
			gerador.init(56);
			Key chave = gerador.generateKey();
			
			Cipher cifra = Cipher.getInstance("DES");
			cifra.init(Cipher.ENCRYPT_MODE, chave);

			byte[] mensagemCript = cifra.doFinal(mensagem);
			cifra.init(Cipher.DECRYPT_MODE, chave);

			assertEquals(cripto.toHex(cifra.doFinal(mensagemCript)), cripto.toHex(cripto.descriptografaDes(chave, mensagemCript)));			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

	@Test
	public void testDescriptografaRsaKeyStringString() {
		KeyPairGenerator gerador;
		HashingImpl hash = new HashingImpl();
		try {
			CriptoImpl cripto = new CriptoImpl();
			gerador = KeyPairGenerator.getInstance("RSA");
			gerador.initialize(1024);
			KeyPair chaves = gerador.generateKeyPair();			
	
			cripto.criptografaRsa(chaves.getPublic(), "res/teste.txt", "res/testeRsa.txt");
			cripto.descriptografaRsa(chaves.getPrivate(), "res/testeRsa.txt", "res/testeRsaDecript.txt");
			
			assertEquals(cripto.toHex(hash.md5("res/teste.txt")), cripto.toHex(hash.md5("res/testeRsaDecript.txt")));
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testDescriptografaDesKeyStringString() {
		KeyGenerator gerador;
		HashingImpl hash = new HashingImpl();
		try {
			CriptoImpl cripto = new CriptoImpl();
			gerador = KeyGenerator.getInstance("DES");
			gerador.init(56);
			Key chave = gerador.generateKey();			
	
			cripto.criptografaDes(chave, "res/teste.txt", "res/testeDes.txt");
			cripto.descriptografaDes(chave, "res/testeDes.txt", "res/testeDesDecript.txt");
			
			assertEquals(cripto.toHex(hash.md5("res/teste.txt")), cripto.toHex(hash.md5("res/testeDesDecript.txt")));
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		


	}

}
