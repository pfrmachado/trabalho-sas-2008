package repositorio;



import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStore.SecretKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.FileInputStream;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
/**
 * Reposit�rio de chaves e certificados.
 * Se utiliza do reposit�rio de chaves e certificados
 * criado pela ferramenta keytool. 
 * 
 * Os m�todos respons�veis por alterar dados 
 * do banco,por dependerem muito da tecnologia
 * usada na ferramenta keytool, usada para gerar o banco,
 * est�o como deprecated e n�o ser�o usados neste trabalho.
 * Recomendamos os usu�rios da biblioteca que utilizem o
 * pr�prio keytool para modificar dados do reposit�rio.
 * 
 * Recomendamos tamb�m a utiliza��o do KeyToolGUI, que se encontra em
 * http://yellowcat1.free.fr/keytool_iui.html
 * 
 * @author Leandro Alexandre, S�rgio Daniel, Rafael Duarte, Thiago Rosa 
 * @version 0.6
 */
public class RepositorioImpl implements Repositorio{
	private KeyStore ks = null;	
	private char[] pwd= null;	//password do arquivo keystore
	private String arquivoRepositorio = null; //arquivo keystore

	/**
	 * Este construtor obtem dados necess�rios para acessar o
	 * reposit�rio criado pela ferramenta keytool.
	 * 
	 * @param arquivoRepositorio
	 * @param alias
	 * @param tipoInstancia
	 * @param passwordRepositorio
	 * @throws Exception
	 */
	public RepositorioImpl(String arquivoRepositorio, String alias, String tipoInstancia, String passwordRepositorio) throws Exception{
		ks = KeyStore.getInstance ( tipoInstancia );
		char[] pwd = passwordRepositorio.toCharArray();
		InputStream is = new FileInputStream( arquivoRepositorio );
		ks.load( is, pwd );
		is.close();
		this.pwd = pwd;
		this.arquivoRepositorio = arquivoRepositorio;
	}

	/**
	 * Obt�m uma chave do reposit�rio.
	 * @param alias identificador da chave
	 * @param password senha para acessar a chave
	 * @return a chave
	 */
	private Key getKey (String alias, String password) {
		char[] pwd = password.toCharArray();
		try{
			Key key = ks.getKey( alias, pwd );
			return key;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
	/**
	 * Obt�m o certificado do reposit�rio.
	 * @param alias 
	 * @return Certificate
	 */
	public Certificate getCertificate (String alias) {
		try {
			Certificate c = ks.getCertificate(alias);
			return c;
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}
	/**
	 * Obt�m uma chave privada do reposit�rio.
	 * @param alias
	 * @param password
	 * @return PrivateKey
	 */
	public PrivateKey getPrivateKey (String alias, String password) {
		Key key = getKey(alias, password);
		if( key instanceof PrivateKey )
			return (PrivateKey) key;
		return null;
	}
	
	/**
	 * Obt�m uma chave p�blica do reposit�rio.
	 * @param alias
	 * @return PublicKey
	 */
	public PublicKey getPublicKey (String alias) {
		try {
			Certificate c = getCertificate(alias);
			return c.getPublicKey();
		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;
	}

	/**
	 * Obt�m uma chave sim�trica do reposit�rio.
	 * @param alias
	 * @param password
	 * @return SecretKeySpec
	 */
	public SecretKey getSecretKey (String alias, String password) {
		char[] pass = password.toCharArray();
		try {
			SecretKey s = (SecretKey) ks.getKey(alias, pass);
			return s;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Obt�m o par de chaves assim�tricas do reposit�rio
	 * @param alias
	 * @param password
	 * @return KeyPair
	 */
	public KeyPair getKeyPair(String alias, String password) {
		PublicKey publicKey = getPublicKey(alias);
		PrivateKey privateKey = getPrivateKey(alias, password);
		return new KeyPair(publicKey, privateKey);
	}







	// Os m�todos abaixo, s�o respons�veis por alterar dados 
	// do banco. Por dependerem muito da tecnologia
	// usada na ferramenta keytool, usada para gerar o banco,
	// estes m�todos est�o como deprecated e n�o ser�o usados 
	// neste trabalho.
	// Recomendamos os usu�rios da biblioteca que utilizem o
	// pr�prio keytool para modificar dados do reposit�rio. 

	/**
	 * Remove uma chave sim�trica do reposit�rio
	 * @param alias 
	 * @deprecated
	 */
	public void deleteSecretKey(String alias){
		deleteEntry(alias);
	}

	/**
	 * Remove um certificado e sua chave privada reposit�rio
	 * @param alias
	 * @deprecated 
	 */

	public void deleteCertificateAndPrivateKey(String alias){
		deleteEntry(alias);
	}

	/**
	 * Remove uma entrada do reposit�rio.
	 * @param alias
	 * @deprecated
	 */
	private void deleteEntry(String alias){
		try {
			ks.deleteEntry(alias);
			// Escreve no keystore
			FileOutputStream keyStoreOutputStream =
				new FileOutputStream(arquivoRepositorio);
			ks.store(keyStoreOutputStream, pwd);
			keyStoreOutputStream.close();

		} catch (KeyStoreException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}
	
	/**
	 * Importa um certificado com sua chave privada para o reposit�rio
	 * @param arquivoCertificado no formato x.509
	 * @param arquivoChavePrivada no formato PKCS#8 DER
	 * @param alias nome da nova entrada
	 * @param passwordChavePriv senha da chave privada
	 * @deprecated
	 */
	public void importaCertificadoEChavePrivada(String arquivoCertificado, String arquivoChavePrivada, String alias, String passwordChavePriv ){
		try {
			// carrega certificado (X.509).
			FileInputStream certificateStream =
				new FileInputStream(arquivoCertificado);
			CertificateFactory certificateFactory =
				CertificateFactory.getInstance("X.509");
			java.security.cert.Certificate[] chain = {};
			chain = certificateFactory.generateCertificates(certificateStream).toArray(chain);
			certificateStream.close();

			// carrega chave privada com PKCS#8 DER.
			File keyFile = new File(arquivoChavePrivada);
			byte[] encodedKey = new byte[(int)keyFile.length()];
			FileInputStream keyInputStream = new FileInputStream(keyFile);
			keyInputStream.read(encodedKey);
			keyInputStream.close();
			KeyFactory rSAKeyFactory = KeyFactory.getInstance("RSA");
			PrivateKey privateKey = rSAKeyFactory.generatePrivate(
					new PKCS8EncodedKeySpec(encodedKey));

			ks.setEntry(alias,
					new KeyStore.PrivateKeyEntry(privateKey, chain),
					new KeyStore.PasswordProtection(passwordChavePriv.toCharArray())
			);

			// Escreve no keystore
			FileOutputStream keyStoreOutputStream =
				new FileOutputStream(arquivoRepositorio);

			ks.store(keyStoreOutputStream, pwd);
			keyStoreOutputStream.close();
		}

		catch (Exception e) {
			e.printStackTrace();
			System.exit(1);
		}
	}
	
	
	/**
	 * Cria uma chave privada para o reposit�rio 
	 * @param cert
	 * @param alias
	 * @param passwordChave
	 * @deprecated
	 */
	public void createSecretKey(String cert, String alias, String passwordChave ){
		try {
			char[] pwdchave = passwordChave.toCharArray();
			KeyGenerator kg = KeyGenerator.getInstance("DES");
			kg.init(56); // 56 � o tamanho da chave fixo.
			javax.crypto.SecretKey mySecretKey= kg.generateKey();
			KeyStore.SecretKeyEntry skEntry =
				new KeyStore.SecretKeyEntry(mySecretKey);
			ks.setEntry(alias, skEntry, new KeyStore.PasswordProtection(pwdchave));

			// armazena na keystore
			java.io.FileOutputStream fos =
				new java.io.FileOutputStream(cert);
			ks.store(fos, pwd);
			fos.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
