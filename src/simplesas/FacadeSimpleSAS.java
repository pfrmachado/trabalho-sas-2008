package simplesas;

import hash.Hashing;
import hash.HashingImpl;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import criptografia.Cripto;
import criptografia.CriptoImpl;

import assinaturas.AssinaturaDigital;
import assinaturas.AssinaturaDigitalImpl;

import repositorio.Repositorio;
import repositorio.RepositorioImpl;

public class FacadeSimpleSAS {

	Repositorio repositorio = null;
	AssinaturaDigital assinatura = new AssinaturaDigitalImpl();
	Cripto cripto = new CriptoImpl();
	Hashing hashing = new HashingImpl();
	
	
	/**
	 * Este construtor obtem dados necessários para acessar o
	 * repositório criado pela ferramenta keytool.
	 * 
	 * @param arquivoRepositorio
	 * @param alias
	 * @param tipoInstancia
	 * @param passwordRepositorio
	 * @throws Exception
	 */
	public FacadeSimpleSAS(String arquivoRepositorio, String alias, String tipoInstancia, String passwordRepositorio){

	try {
		Repositorio repositorio = new RepositorioImpl("res/sas.jks", "sas", "JCEKS",  "sas123");
		this.repositorio = repositorio;
	} catch (Exception e) {
		e.printStackTrace();
	}
	}
	/**
	 * Assina digitalmente uma String.
	 * 
	 * @param alias identificador da chave privada
	 * @param password senha de proteção da chave privada
	 * @param stringOriginal sequencia de bytes contendo a string 
	 * @param algoritmoAssinatura MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return
	 */
	public byte[] assinaString(String alias, String password, byte[] stringOriginal, String algoritmoAssinatura){
		PrivateKey privk = repositorio.getPrivateKey(alias, password);
		return assinatura.assinaString(privk, stringOriginal, algoritmoAssinatura);
	}

	public boolean verificaAssinatura(String alias, byte[] stringAssinada, byte[] stringOriginal, String algoritmoAssinatura){
		Certificate cert = repositorio.getCertificate(alias);
		return assinatura.verificaAssinatura(cert, stringAssinada, stringOriginal, algoritmoAssinatura);
	}
	
	public boolean verificaAssinatura(String alias, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura){
		Certificate cert = repositorio.getCertificate(alias);
 		return assinatura.verificaAssinatura(cert, arquivoAssinado, arquivoOriginal, algoritmoAssinatura);
	}
	
	
	public void assinaArquivo(String alias, String password, String arquivoaAssinar, String arquivoOriginal, String algoritmoAssinatura){
		PrivateKey privk = repositorio.getPrivateKey(alias, password);
		assinatura.assinaArquivo(privk, arquivoaAssinar, arquivoOriginal, algoritmoAssinatura);
	}

	public boolean validaCertificado(String aliasCert, String aliasPubk){
		Certificate cert = repositorio.getCertificate(aliasCert);
		PublicKey pubk = repositorio.getPublicKey(aliasPubk);
		return assinatura.validaCertificado(cert, pubk);

	}

}
