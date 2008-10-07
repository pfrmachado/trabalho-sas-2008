package assinaturasTest;

import static org.junit.Assert.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.cert.Certificate;

import org.junit.Test;

import repositorio.RepositorioImpl;

import assinaturas.AssinaturaDigitalImpl;

public class AssinaturaDigitalTest {
	
	
	@Test
	public void testValidaCertificado(){
		AssinaturaDigitalImpl ass = new AssinaturaDigitalImpl();
		RepositorioImpl repositorio;
		try {
			repositorio = new RepositorioImpl("res/sas2.jks", "sas", "JCEKS",  "sas123");
			//Como foi gerado um certificado auto-assinado atrav�s
			//da ferramenta keytool, isto �, a chave p�blica do certificado
			//assinou o pr�prio certificado, a valida��o do certificado com
			//sua chave p�blica deve retornar "true".
			assertTrue(ass.validaCertificado(repositorio.getCertificate("sas"), repositorio.getCertificate("sas").getPublicKey()));

		} catch (Exception e) {
			e.printStackTrace();
		}
		
			
		
	}
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
	
	@Test
	public void testAssinaArquivoCertificado() {
		File cert = new File("res/sas.jks");
		String alias = "sas";
		String password = "sas123";
		AssinaturaDigitalImpl ass = new AssinaturaDigitalImpl();
		
        KeyStore ks;
		try {
			ks = KeyStore.getInstance ( "JCEKS" );
	        char[] pwd = password.toCharArray();
	        InputStream is = new FileInputStream( cert );
	        ks.load( is, pwd );
	        Key key = ks.getKey( alias, pwd );
	        
	        Certificate c = ks.getCertificate( alias );
	        
	        ass.assinaArquivo((PrivateKey) key, "res/testecert.txt.sig", "res/teste.txt", "MD5WithRSA");

	        assertTrue(ass.verificaAssinatura(c, "res/testecert.txt.sig", "res/teste.txt", "MD5WithRSA"));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	@Test

	public void testAssinaStringCertificado() {
		File cert = new File("res/sas.jks");
		String alias = "sas";
		String password = "sas123";
		AssinaturaDigitalImpl ass = new AssinaturaDigitalImpl();
		
        KeyStore ks;
		try {
			ks = KeyStore.getInstance ( "JCEKS" );
	        char[] pwd = password.toCharArray();
	        InputStream is = new FileInputStream( cert );
	        ks.load( is, pwd );
	        Key key = ks.getKey( alias, pwd );
			byte[] mensagem = "teste123".getBytes();
			
	        Certificate c = ks.getCertificate( alias );
	        assertTrue(ass.verificaAssinatura(c, ass.assinaString((PrivateKey) key, mensagem, "MD5WithRSA"), mensagem, "MD5WithRSA"));
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

}
