package assinaturasTest;

import static org.junit.Assert.*;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import org.junit.Test;

import assinaturas.AssinaturaDigitalImpl;

public class AssinaturaDigitalTest {

	@Test
	public void testAssinaString() {
		try {
			AssinaturaDigitalImpl ass = new AssinaturaDigitalImpl();
			
			KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
			gerador.initialize(1024);
			KeyPair chaves = gerador.generateKeyPair();
			byte[] mensagem = "teste123".getBytes();
			byte[] assinatura = ass.assinaString(chaves.getPrivate(), mensagem, "MD5WithRSA");
			
			Signature sig = Signature.getInstance("MD5WithRSA");
			sig.initVerify(chaves.getPublic());
			sig.update(mensagem);
			assertTrue(sig.verify(assinatura));
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Test
	public void testVerificaAssinaturastring() {
		try{
		AssinaturaDigitalImpl ass = new AssinaturaDigitalImpl();
		
		KeyPairGenerator gerador = KeyPairGenerator.getInstance("RSA");
		gerador.initialize(1024);
		KeyPair chaves = gerador.generateKeyPair();
		byte[] mensagem = "teste123".getBytes();
		
		
		Signature sig = Signature.getInstance("MD5WithRSA");
		sig.initSign(chaves.getPrivate());
		sig.update(mensagem);
		byte[] assinada = sig.sign();
		
		
		
		
		assertTrue(ass.verificaAssinatura(chaves.getPublic(), assinada, mensagem, "MD5WithRSA"));
		
//		System.out.println(original.toString() + " aaaaaaaaaaaaaaaaaaaaaaaaaaa"+mensagem.toString());
//		assertEquals(0, original.toString().compareTo(mensagem.toString()));
		
		
	} catch (Exception e) {
		e.printStackTrace();
	}
	}

	@Test
	public void testVerificaAssinaturaArquivo() {
		AssinaturaDigitalImpl ass = new AssinaturaDigitalImpl();
		
		KeyPairGenerator gerador=null;
		try {
			gerador = KeyPairGenerator.getInstance("RSA");

		} catch (Exception e) {
			e.printStackTrace();
		}
		gerador.initialize(1024);
		KeyPair chaves = gerador.generateKeyPair();
		ass.assinaArquivo(chaves.getPrivate(), "res/teste2.txt.sig", "res/teste.txt", "MD5WithRSA");
		
		assertTrue(ass.verificaAssinatura(chaves.getPublic(), "res/teste2.txt.sig", "res/teste.txt", "MD5WithRSA"));
	}

	@Test
	public void testAssinaArquivo() {
		AssinaturaDigitalImpl ass = new AssinaturaDigitalImpl();
		
		KeyPairGenerator gerador=null;
		try {
			gerador = KeyPairGenerator.getInstance("RSA");

		} catch (Exception e) {
			e.printStackTrace();
		}
		gerador.initialize(1024);
		KeyPair chaves = gerador.generateKeyPair();

		
		
		ass.assinaArquivo(chaves.getPrivate(), "res/teste.txt.sig", "res/teste.txt", "MD5WithRSA");
		
		assertTrue(ass.verificaAssinatura(chaves.getPublic(), "res/teste.txt.sig", "res/teste.txt", "MD5WithRSA"));
	}

}
