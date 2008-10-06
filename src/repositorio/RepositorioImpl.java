package repositorio;



import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Signature;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
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

public class RepositorioImpl {
	private KeyStore ks = null;	

	public RepositorioImpl(String arquivoRepositorio, String alias, String tipoInstancia, String passwordRepositorio) throws Exception {
//		ks = KeyStore.getInstance ( "JCEKS" );
		ks = KeyStore.getInstance ( tipoInstancia );
        char[] pwd = passwordRepositorio.toCharArray();
        InputStream is = new FileInputStream( arquivoRepositorio );
        ks.load( is, pwd );
        is.close();
	}
		
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
		
		
		
		
		
		
		
		
		
		
		
		
	public void importaCertificadoEChavePrivada(String cert, String arquivoCertificado, String arquivoChavePrivada, String alias, String password, String passwordChavePriv ){
		try {
		// Load the keystore
		KeyStore keyStore = KeyStore.getInstance("jks");
		FileInputStream keyStoreInputStream =
		new FileInputStream(cert);
		keyStore.load(keyStoreInputStream, password.toCharArray());
		keyStoreInputStream.close();

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


		
		keyStore.setEntry(alias,
		new KeyStore.PrivateKeyEntry(privateKey, chain),
		new KeyStore.PasswordProtection(passwordChavePriv.toCharArray())
		);

		// Write out the keystore
		FileOutputStream keyStoreOutputStream =
		new FileOutputStream(cert);
		keyStore.store(keyStoreOutputStream, password.toCharArray());
		keyStoreOutputStream.close();
		}

		catch (Exception e) {
		e.printStackTrace();
		System.exit(1);
		}
		}
		
		
		
		
		
		
		
		
		public void criaChave(String cert, String alias, String password, String passwordChave ){
	        KeyStore ks;
			try {
				ks = KeyStore.getInstance ( "JCEKS" );
		        char[] pwd = password.toCharArray();
		        char[] pwdchave = passwordChave.toCharArray();
		        InputStream is = new FileInputStream( cert );
		        ks.load( is, pwd );
		        is.close();

		        // get my private key
//			    KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
//			        ks.getEntry(alias, new KeyStore.PasswordProtection(pwdchave));
//			    PrivateKey myPrivateKey = pkEntry.getPrivateKey();

			    // save my secret key
		     // Generate a secret key
		        KeyGenerator kg = KeyGenerator.getInstance("DES");
		        kg.init(56); // 56 is the keysize. Fixed for DES
		        
			    javax.crypto.SecretKey mySecretKey= kg.generateKey();
			    KeyStore.SecretKeyEntry skEntry =
			        new KeyStore.SecretKeyEntry(mySecretKey);
			    ks.setEntry(alias, skEntry, new KeyStore.PasswordProtection(pwdchave));

	/*	        Certificate certif;
		        KeyStore.
		        
		        PrivateKey myPrivateKey;
			    KeyStore.PrivateKeyEntry pkEntry =
			        new KeyStore.PrivateKeyEntry(myPrivateKey);
			    ks.setEntry("secretKeyAlias", pkEntry, new KeyStore.PasswordProtection(pwdchave));
	*/	        
			    // store away the keystore
			    java.io.FileOutputStream fos =
			        new java.io.FileOutputStream(cert);
			    ks.store(fos, pwd);
			    fos.close();

			} catch (Exception e) {
				e.printStackTrace();
			}

		}
		
		
	    public static Key getKeyFromFile( String cert, String alias, String password, String passwordChave ) throws Exception {
	        KeyStore ks = KeyStore.getInstance ( "JCEKS" );
	        char[] pwd = password.toCharArray();
	        char[] pwdchave = passwordChave.toCharArray();
	        InputStream is = new FileInputStream( cert );
	        ks.load( is, pwd );
	        is.close();
	        Key key = ks.getKey( alias, pwdchave );
	        if( key instanceof Key ) {
	            return key;
	        }
	        return null;
	    }

		
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
	    
	    


	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    
	    

		private Key getKey (String alias, String password) {
			char[] psw = password.toCharArray();

			try{
				Key key = ks.getKey( alias, psw );
				return key;
			} catch (Exception e) {
				e.printStackTrace();
			}

			return null;
		}
		
		public Certificate getCertificate (String alias) {
			try {
				Certificate c = ks.getCertificate(alias);
				return c;
			} catch (Exception e) {
				e.printStackTrace();
			}
			
			return null;
		}

		public PrivateKey getPrivateKey (String alias, String password) {
			Key key = getKey(alias, password);
			if( key instanceof PrivateKey )
				return (PrivateKey) key;
			return null;
		}

		public PublicKey getPublicKey (String alias) {
			try {
				Certificate c = getCertificate(alias);
				return c.getPublicKey();
			} catch (Exception e) {
				e.printStackTrace();
			}

			return null;
		}

		public SecretKey getSecretKey (String alias, String password) {
			char[] psw = password.toCharArray();
			try {
				return (SecretKey) ks.getKey(alias, psw);
			} catch (Exception e) {
				e.printStackTrace();
			}

			return null;
		}

		public KeyPair getKeyPair(String alias, String password) {
			PublicKey publicKey = getPublicKey(alias);
			PrivateKey privateKey = getPrivateKey(alias, password);
			return new KeyPair(publicKey, privateKey);
		}



}
