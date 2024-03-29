package repositorio;


import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Reposit�rio de chaves e certificados.
 * Se utiliza do reposit�rio de chaves e certificados
 * criado pela ferramenta keytool. 
 * 
 * Recomendamos a utiliza��o do KeyToolGUI, que se encontra em
 * http://yellowcat1.free.fr/keytool_iui.html
 * 
 * @author Leandro Alexandre, S�rgio Daniel, Rafael Duarte, Thiago Rosa 
 * @version 0.6
 */
public interface Repositorio {
	Certificate getCertificate (String alias); 
	PrivateKey getPrivateKey (String alias, String password); 
	PublicKey getPublicKey (String alias); 
	SecretKey getSecretKey (String alias, String password); 
	KeyPair getKeyPair(String alias, String password); 
	void deleteSecretKey(String alias);
	void deleteCertificateAndPrivateKey(String alias);
	void importaCertificadoEChavePrivada(String arquivoCertificado, String arquivoChavePrivada, String alias, String passwordChavePriv );
}
