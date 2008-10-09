package simplesas;

import hash.Hashing;
import hash.HashingImpl;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import criptografia.Cripto;
import criptografia.CriptoImpl;

import assinaturas.AssinaturaDigital;
import assinaturas.AssinaturaDigitalImpl;

import repositorio.Repositorio;
import repositorio.RepositorioImpl;

/**
 * Biblioteca com o objetivo de fornecer serviços "mais abstratos"
 * que aqueles oferecidos pela plataforma Java para
 * criptografia de informações (tanto usando algoritmos simétricos quanto
 * assimétricos) assim como emprego de certificação e assinatura digital de
 * documentos por parte de aplicações em Java.
 * 
 * @author Leandro Alexandre, Sérgio Daniel, Rafael Duarte, Thiago Rosa
 * @version 0.6
 */
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
	 * @param tipoInstancia "JCEKS", "JKS", "SUN"
	 * @param passwordRepositorio
	 * @throws Exception
	 */
	public FacadeSimpleSAS(String arquivoRepositorio, String alias, String tipoInstancia, String passwordRepositorio){

	try {
		//Repositorio repositorio = new RepositorioImpl("res/sas.jks", "sas", "JCEKS",  "sas123");
		Repositorio repositorio = new RepositorioImpl(arquivoRepositorio, alias, tipoInstancia,  passwordRepositorio);
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
	 * @return bytes com a string assinada
	 */
	public byte[] assinaString(String alias, String password, byte[] stringOriginal, String algoritmoAssinatura){
		PrivateKey privk = repositorio.getPrivateKey(alias, password);
		return assinatura.assinaString(privk, stringOriginal, algoritmoAssinatura);
	}

	/**
	 * Verifica assinatura da sequencia de bytes através do certificado
	 * @param alias identificador do certificado
	 * @param stringAssinada 
	 * @param stringOriginal
	 * @param algoritmoAssinatura MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return true se assinatura confere, false caso contrário 
	 */
	public boolean verificaAssinaturaCert(String alias, byte[] stringAssinada, byte[] stringOriginal, String algoritmoAssinatura){
		Certificate cert = repositorio.getCertificate(alias);
		return assinatura.verificaAssinatura(cert, stringAssinada, stringOriginal, algoritmoAssinatura);
	}


	/**
	 * Verifica assinatura da sequencia de bytes através da chave pública
	 * @param alias identificador da chave pública
	 * @param stringAssinada 
	 * @param stringOriginal
	 * @param algoritmoAssinatura MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return true se assinatura confere, false caso contrário 
	 */
	public boolean verificaAssinaturaPubk(String alias, byte[] stringAssinada, byte[] stringOriginal, String algoritmoAssinatura){
		PublicKey pubk = repositorio.getPublicKey(alias);
		return assinatura.verificaAssinatura(pubk, stringAssinada, stringOriginal, algoritmoAssinatura);
	}


	/**
	 * Verifica assinatura do arquivo através de um certificado
	 * @param alias Identificador do certificado
	 * @param arquivoAssinado
	 * @param arquivoOriginal
	 * @param algoritmoAssinatura MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return true se assinatura confere, false caso contrário
	 */
	public boolean verificaAssinaturaCert(String alias, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura){
		Certificate cert = repositorio.getCertificate(alias);
 		return assinatura.verificaAssinatura(cert, arquivoAssinado, arquivoOriginal, algoritmoAssinatura);
	}

	/**
	 * Verifica assinatura do arquivo através de uma chave pública
	 * @param alias Identificador da chave pública
	 * @param arquivoAssinado
	 * @param arquivoOriginal
	 * @param algoritmoAssinatura MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return true se assinatura confere, false caso contrário
	 */
	public boolean verificaAssinaturaPubk(String alias, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura){
		PublicKey pubk = repositorio.getPublicKey(alias);
 		return assinatura.verificaAssinatura(pubk, arquivoAssinado, arquivoOriginal, algoritmoAssinatura);
	}

	/**
	 * Assina um arquivo digitalmente através da chave privada
	 * @param alias identificador da chave privada
	 * @param password senha de acesso a chave privada
	 * @param arquivoaAssinar nome e caminho de arquivo para armazenar o arquivo assinado
	 * @param arquivoOriginal arquivo a ser assinado
	 * @param algoritmoAssinatura MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 */
	public void assinaArquivo(String alias, String password, String arquivoaAssinar, String arquivoOriginal, String algoritmoAssinatura){
		PrivateKey privk = repositorio.getPrivateKey(alias, password);
		assinatura.assinaArquivo(privk, arquivoaAssinar, arquivoOriginal, algoritmoAssinatura);
	}

	/**
	 * Valida um certificado digital através da chave publica da entidade certificadora
	 * @param aliasCert identificador do certificado
	 * @param aliasPubk identificador da chave publica da entidade certificadora
	 * @return true se o certificado é válido para a chave pública da entidade certificadora, false caso contrário.
	 */
	public boolean validaCertificado(String aliasCert, String aliasPubk){
		Certificate cert = repositorio.getCertificate(aliasCert);
		PublicKey pubk = repositorio.getPublicKey(aliasPubk);
		return assinatura.validaCertificado(cert, pubk);
	}
	
    /**
     * Obtém o valor de hash md5 para o arquivo fornecido.
     * @param nomeArquivo 
     * @return Valor de hash.
     */
    public byte[] md5(String nomeArquivo){
    	return hashing.md5(nomeArquivo);
    }
    /**
     * Obtém o valor de hash sha1 para o arquivo fornecido.
     * @param nomeArquivo 
     * @return Valor de hash.
     */

    public byte[] sha1(String nomeArquivo){
    	return hashing.sha1(nomeArquivo);
    }
    /**
     * Obtém o valor de hash md5 para a entrada fornecida.
     * @param entrada 
     * @return Valor de hash.
     */

    public byte[] md5(byte[] entrada){
    	return hashing.md5(entrada);
    }

    /**
     * Obtém o valor de hash sha1 para a entrada fornecida.
     * @param entrada entrada a ser obtido o sha1
     * @return Valor de hash.
     */
    public byte[] sha1(byte[] entrada){
    	return hashing.sha1(entrada);
    }

    
    /**
     * Criptografa a entrada com o algoritmo de chaves assimétricas RSA.
     * @param aliasPubk Identificador da chave pública
     * @param entrada entrada a ser criptografada
     * @return entrada criptografada
     */
    public byte[] criptografaRsa(String aliasPubk, byte[] entrada){
		PublicKey pubk = repositorio.getPublicKey(aliasPubk);
		return cripto.criptografaRsa(pubk, entrada);
	}
    /**
     * Criptografa a entrada com o algoritmo de chave simétrica DES.
     * @param aliasSecretk Identificador da chave simétrica
     * @param password Senha de acesso a chave no repositorio
     * @param entrada entrada a ser criptografada
     * @return entrada criptografada
     */
    public byte[] criptografaDes(String aliasSecretk, String password, byte[] entrada){
		Key key = repositorio.getSecretKey(aliasSecretk, password);
		return cripto.criptografaDes(key, entrada);
	}

    /**
     * Criptografa arquivo com o algoritmo de chaves assimétricas RSA.
     * @param aliasPubk Identificador da chave pública
     * @param arquivoEntrada arquivo a ser criptografada
     * @param arquivoSaida nome e caminho de arquivo para armazenar o arquivo criptografado.
     */
    public void criptografaRsa(String aliasPubk, String arquivoEntrada, String arquivoSaida){
		PublicKey pubk = repositorio.getPublicKey(aliasPubk);
		cripto.criptografaRsa(pubk, arquivoEntrada, arquivoSaida);
	}

    /**
     * Criptografa arquivo com o algoritmo de chave simétrica DES.
     * @param aliasSecretk Identificador da chave simétrica 
     * @param password Senha de acesso a chave no repositorio
     * @param arquivoEntrada arquivo a ser criptografada
     * @param arquivoSaida nome e caminho de arquivo para armazenar o arquivo criptografado
     */

    public void criptografaDes(String aliasSecretk, String password, String arquivoEntrada, String arquivoSaida){
		Key key = repositorio.getSecretKey(aliasSecretk, password);
		cripto.criptografaDes(key, arquivoEntrada, arquivoSaida);
	}


	/**
	 * Descriptografa entrada com o algoritmo de chaves assimétricas RSA. 
	 * @param aliasPrivk Identificador da chave privada de descriptografia
	 * @param password senha de acesso a chave privada.
	 * @param entrada entrada a ser descriptografada
	 * @return entrada descriptograda
	 */
    public byte[] descriptografaRsa(String aliasPrivk, String password, byte[] entrada){
		PrivateKey privk = repositorio.getPrivateKey(aliasPrivk, password);
		return cripto.descriptografaRsa(privk, entrada);
	}
    /**
     * Descriptografa entrada com o algoritmo de chave simétrica DES.
     * @param aliasSecretk Identificador da chave simétrica 
     * @param password Senha de acesso a chave no repositorio
     * @param entrada entrada a ser descriptografada
     * @return entrada descriptografada
     */
	public byte[] descriptografaDes(String aliasSecretk, String password, byte[] entrada){
		Key key = repositorio.getSecretKey(aliasSecretk, password);
		return cripto.descriptografaDes(key, entrada);
	}
/**
 * Descriptografa arquivo com o algoritmo de chaves assimétricas RSA.
 * @param aliasPrivk Identificador da chave privada assimétrica
 * @param password Senha de acesso a chave no repositório
 * @param arquivoEntrada arquivo a ser descriptografado
 * @param arquivoSaida nome e caminho de arquivo para armazenar o arquivo descriptografado.
 */
    public void descriptografaRsa(String aliasPrivk, String password, String arquivoEntrada, String arquivoSaida){
		PrivateKey privk = repositorio.getPrivateKey(aliasPrivk, password);
		cripto.descriptografaRsa(privk, arquivoEntrada, arquivoSaida);
	}
    /**
     * Descriptografa arquivo com o algoritmo de chave simétrica DES.
     * @param aliasSecretk Identificador da chave simétrica 
     * @param password Senha de acesso a chave no repositorio
     * @param arquivoEntrada arquivo a ser descriptografado
     * @param arquivoSaida nome e caminho de arquivo para armazenar o arquivo descriptografado
     */
	public void descriptografaDes(String aliasSecretk, String password, String arquivoEntrada, String arquivoSaida){
		Key key = repositorio.getSecretKey(aliasSecretk, password);
		cripto.descriptografaDes(key, arquivoEntrada, arquivoSaida);
	}


}
