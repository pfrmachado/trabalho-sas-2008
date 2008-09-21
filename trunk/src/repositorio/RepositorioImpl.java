package repositorio;



import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Signature;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

public class RepositorioImpl {
	  
		
		
		
/*		
		public PublicKey obtemChavePublica(String identificador){
			DadosRepositorio d = new DadosRepositorio();
			File cert = new File(d.arquivobd);
			String pwd = d.senhabd;

			PublicKey publicKey=null;
			try {
				publicKey = getPublicKeyFromFile( cert, identificador, pwd );
			} catch (Exception e) {
				e.printStackTrace();
			}


			System.out.println( publicKey.getEncoded().toString());
			return publicKey;
			
		}
		
		public PrivateKey obtemChavePrivada(String identificador, String passwordChave){
			DadosRepositorio d = new DadosRepositorio();
			File cert = new File(d.arquivobd);
			String pwd = d.senhabd;

			PrivateKey privateKey=null;
			try {
				privateKey = getPrivateKeyFromFile( cert, identificador, pwd, passwordChave );
			} catch (Exception e) {
				e.printStackTrace();
			}


			System.out.println( privateKey.getEncoded().toString());
			return privateKey;
			
		}
		
*/
/*		
		public PrivateKey armazenaChavePrivada(String alias){
			DadosRepositorio d = new DadosRepositorio();
			String password = d.senhabd;

			KeyStore ks;
			try {
				ks = KeyStore.getInstance ( "JKS" );
		        char[] pwd = password.toCharArray();
		        InputStream is = new FileInputStream( d.arquivobd );
		        ks.load( is, pwd );
		        is.close();

			    // save my secret key
			    javax.crypto.SecretKey mySecretKey;
			    KeyStore.SecretKeyEntry skEntry =
			        new KeyStore.SecretKeyEntry(mySecretKey);
			    ks.setEntry("secretKeyAlias", skEntry,new KeyStore.PasswordProtection(pwd));

			    // store away the keystore
			    java.io.FileOutputStream fos =
			        new java.io.FileOutputStream("newKeyStoreName");
			    ks.store(fos, pwd);
			    fos.close();

			} catch (Exception e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		 
		}
		
		
		
*/		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		
		/**
	     * Extrai a chave privada do arquivo.
	     */
	    public static PrivateKey getPrivateKeyFromFile( File cert, String alias, String password, String passwordChave ) throws Exception {
	        KeyStore ks = KeyStore.getInstance ( "JKS" );
	        char[] pwd = password.toCharArray();
	        char[] pwdchave = passwordChave.toCharArray();
	        InputStream is = new FileInputStream( cert );
	        ks.load( is, pwd );
	        is.close();
	        Key key = ks.getKey( alias, pwdchave );
	        if( key instanceof PrivateKey ) {
	            return (PrivateKey) key;
	        }
	        return null;
	    }

		/**
	     * Extrai a chave pública do arquivo.
	     */
	    public static PublicKey getPublicKeyFromFile( File cert, String alias, String password ) throws Exception {
	        KeyStore ks = KeyStore.getInstance ( "JKS" );
	        char[] pwd = password.toCharArray();
	        InputStream is = new FileInputStream( cert );
	        ks.load( is, pwd );
	        Key key = ks.getKey( alias, pwd );
	        Certificate c = ks.getCertificate( alias );
	        PublicKey p = c.getPublicKey();
	        return p;
		}

}
