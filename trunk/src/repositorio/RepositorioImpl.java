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
 * Repositório de chaves e certificados.
 * Se utiliza do repositório de chaves e certificados
 * criado pela ferramenta keytool. 
 * 
 * Os métodos responsáveis por alterar dados 
 * do banco,por dependerem muito da tecnologia
 * usada na ferramenta keytool, usada para gerar o banco,
 * estão como deprecated e não serão usados neste trabalho.
 * Recomendamos os usuários da biblioteca que utilizem o
 * próprio keytool para modificar dados do repositório.
 * 
 * Recomendamos também a utilização do KeyToolGUI, que se encontra em
 * http://yellowcat1.free.fr/keytool_iui.html
 * 
 * @author Leandro Alexandre, Sérgio Daniel, Rafael Duarte, Thiago Rosa 
 * @version 0.6
 */
public class RepositorioImpl implements Repositorio{
	private KeyStore ks = null;	
	private char[] pwd= null;	//password do arquivo keystore
	private String arquivoRepositorio = null; //arquivo keystore

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
	public RepositorioImpl(String arquivoRepositorio, String alias, String tipoInstancia, String passwordRepositorio) throws Exception{
		//		ks = KeyStore.getInstance ( "JCEKS" );
		ks = KeyStore.getInstance ( tipoInstancia );
		char[] pwd = passwordRepositorio.toCharArray();
		InputStream is = new FileInputStream( arquivoRepositorio );
		ks.load( is, pwd );
		is.close();
		this.pwd = pwd;
		this.arquivoRepositorio = arquivoRepositorio;
	}

	/**
	 * Obtém uma chave do repositório.
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
	 * Obtém o certificado do repositório.
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
	 * Obtém uma chave privada do repositório.
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
	 * Obtém uma chave pública do repositório.
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
	 * Obtém uma chave simétrica do repositório.
	 * @param alias
	 * @param password
	 * @return SecretKeySpec
	 */
	public SecretKey getSecretKey (String alias, String password) {
		char[] pass = password.toCharArray();
		try {
//			SecretKeyEntry s = (SecretKeyEntry) ks.getEntry(alias, new KeyStore.PasswordProtection(pass));
//			return (SecretKeySpec) s.getSecretKey();
			SecretKey s = (SecretKey) ks.getKey(alias, pass);
			return s;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
		System.out.println("aaaaaaaaaaaaaaaaaaaaaaaaaaafffffffff");
		return null;
	}

	/**
	 * Obtém o par de chaves assimétricas do repositório
	 * @param alias
	 * @param password
	 * @return KeyPair
	 */
	public KeyPair getKeyPair(String alias, String password) {
		PublicKey publicKey = getPublicKey(alias);
		PrivateKey privateKey = getPrivateKey(alias, password);
		return new KeyPair(publicKey, privateKey);
	}







	// Os métodos abaixo, são responsáveis por alterar dados 
	// do banco. Por dependerem muito da tecnologia
	// usada na ferramenta keytool, usada para gerar o banco,
	// estes métodos estão como deprecated e não serão usados 
	// neste trabalho.
	// Recomendamos os usuários da biblioteca que utilizem o
	// próprio keytool para modificar dados do repositório. 

	/**
	 * Remove uma chave simétrica do repositório
	 * @param alias 
	 * @deprecated
	 */
	public void deleteSecretKey(String alias){
		deleteEntry(alias);
	}

	/**
	 * Remove um certificado e sua chave privada repositório
	 * @param alias
	 * @deprecated 
	 */

	public void deleteCertificateAndPrivateKey(String alias){
		deleteEntry(alias);
	}

	/**
	 * Remove uma entrada do repositório.
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
	 * Importa um certificado com sua chave privada para o repositório
	 * @param arquivoCertificado no formato x.509
	 * @param arquivoChavePrivada no formato PKCS#8 DER
	 * @param alias nome da nova entrada
	 * @param passwordChavePriv senha da chave privada
	 * @deprecated
	 */
	public void importaCertificadoEChavePrivada(String arquivoCertificado, String arquivoChavePrivada, String alias, String passwordChavePriv ){
		try {
			// Load the certificate chain (in X.509 DER encoding).
			FileInputStream certificateStream =
				new FileInputStream(arquivoCertificado);
			CertificateFactory certificateFactory =
				CertificateFactory.getInstance("X.509");
			// Required because Java is STUPID.  You can't just cast the result
			// of toArray to Certificate[].
			java.security.cert.Certificate[] chain = {};
			chain = certificateFactory.generateCertificates(certificateStream).toArray(chain);
			certificateStream.close();

			// Load the private key (in PKCS#8 DER encoding).
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
	 * Cria uma chave privada para o repositório 
	 * @param cert
	 * @param alias
	 * @param passwordChave
	 * @deprecated
	 */
	public void createSecretKey(String cert, String alias, String passwordChave ){
		try {
			char[] pwdchave = passwordChave.toCharArray();
			KeyGenerator kg = KeyGenerator.getInstance("DES");
			kg.init(56); // 56 is the keysize. Fixed for DES
			javax.crypto.SecretKey mySecretKey= kg.generateKey();
			KeyStore.SecretKeyEntry skEntry =
				new KeyStore.SecretKeyEntry(mySecretKey);
			ks.setEntry(alias, skEntry, new KeyStore.PasswordProtection(pwdchave));

			// store away the keystore
			java.io.FileOutputStream fos =
				new java.io.FileOutputStream(cert);
			ks.store(fos, pwd);
			fos.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

}
