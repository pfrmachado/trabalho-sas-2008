package criptografiaTest;

import static org.junit.Assert.*;

import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

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

//			System.out.println(cripto.toHex(cifra.doFinal(mensagem)));
			assertTrue(cripto.toHex(cifra.doFinal(mensagem)).compareTo(cripto.toHex(cripto.criptografaDes(chave, mensagem)))==0);			
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
			assertTrue(cripto.toHex(cifra.doFinal(mensagemCript)).compareTo(cripto.toHex(cripto.descriptografaRsa(chaves.getPrivate(), cripto.criptografaRsa(chaves.getPublic(), mensagem))))==0);			
		} catch (Exception e) {
			e.printStackTrace();
		}
		

	}


	@Test
	public void testCriptografaRsaKeyStringString() {
//		fail("Not yet implemented");
	}

	@Test
	public void testCriptografaDesKeyStringString() {
		KeyGenerator gerador;
		byte [] mensagem = "teste1234".getBytes();
		try {
			CriptoImpl cripto = new CriptoImpl();
			gerador = KeyGenerator.getInstance("DES");
			gerador.init(56);
			Key chave = gerador.generateKey();
			
			Cipher cifra = Cipher.getInstance("DES");
			cifra.init(Cipher.ENCRYPT_MODE, chave);

//			System.out.println(cripto.toHex(cifra.doFinal(mensagem)));
			assertTrue(cripto.toHex(cifra.doFinal(mensagem)).compareTo(cripto.toHex(cripto.criptografaDes(chave, mensagem)))==0);			
		} catch (Exception e) {
			e.printStackTrace();
		}
		

		//		fail("Not yet implemented");
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
			assertTrue(cripto.toHex(cifra.doFinal(mensagemCript)).compareTo(cripto.toHex(cripto.descriptografaRsa(chaves.getPrivate(), cripto.criptografaRsa(chaves.getPublic(), mensagem))))==0);			
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
//			System.out.println(cripto.toHex(cripto.descriptografaDes(chave, mensagemCript)));

			assertTrue(cripto.toHex(cifra.doFinal(mensagemCript)).compareTo(cripto.toHex(cripto.descriptografaDes(chave, mensagemCript)))==0);			
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}

	@Test
	public void testDescriptografaRsaKeyStringString() {
//		fail("Not yet implemented");
	}

	@Test
	public void testDescriptografaDesKeyStringString() {
//		fail("Not yet implemented");
	}

}
