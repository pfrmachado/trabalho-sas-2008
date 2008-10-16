import java.security.Key;
import java.security.KeyStore;
import java.security.Signature;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.cert.Certificate;

import java.io.File;
import java.io.InputStream;
import java.io.FileInputStream;

public class Criptografia {

	private static final String algorithm = "RSA";
	private static final String signatureAlgorithm = "MD5withRSA";

	public static void main(String[] args) {
		String txt = "String a ser encriptada";

		try {
			File cert = new File("/home/rafael/Desktop/guj.jks");
			String alias = "guj";
			String pwd = "guj123";

			PrivateKey privateKey = getPrivateKeyFromFile( cert, alias, pwd );
			PublicKey publicKey = getPublicKeyFromFile( cert, alias, pwd );

			byte[] txtAssinado = createSignature( privateKey, txt.getBytes() );

			System.out.println( txt2Hexa( txtAssinado ) );

			if( verifySignature( publicKey, txt.getBytes(), txtAssinado ) ) {
				System.out.println("Assinatura OK!");
			} else {
				System.out.println("Assinatura NOT OK!");
			}

		} catch( Exception e ) {
			e.printStackTrace();
		}
	}

	/**
     * Extrai a chave privada do arquivo.
     */
    public static PrivateKey getPrivateKeyFromFile( File cert, String alias, String password ) throws Exception {
        KeyStore ks = KeyStore.getInstance ( "JKS" );
        char[] pwd = password.toCharArray();
        InputStream is = new FileInputStream( cert );
        ks.load( is, pwd );
        is.close();
        Key key = ks.getKey( alias, pwd );
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

	/**
     * Retorna a assinatura para o buffer de bytes, usando a chave privada.
     */
	public static byte[] createSignature(PrivateKey key, byte[] buffer) throws Exception {
		Signature sig = Signature.getInstance( signatureAlgorithm );
		sig.initSign(key);
		sig.update(buffer, 0, buffer.length);
		return sig.sign();
	}

	/**
     * Verifica a assinatura para o buffer de bytes, usando a chave pública.
     */
	public static boolean verifySignature( PublicKey key, byte[] buffer, byte[] signed ) throws Exception {
		Signature sig = Signature.getInstance( signatureAlgorithm );
		sig.initVerify(key);
		sig.update(buffer, 0, buffer.length);
		return sig.verify( signed );
	}

	/**
	 * Converte um array de byte em uma representação, em String, de seus hexadecimais.
	 */
	public static String txt2Hexa(byte[] bytes) {
        if( bytes == null ) return null;
		String hexDigits = "0123456789abcdef";
		StringBuffer sbuffer = new StringBuffer();
		for (int i = 0; i < bytes.length; i++) {
			int j = ((int) bytes[i]) & 0xFF;
			sbuffer.append(hexDigits.charAt(j / 16));
			sbuffer.append(hexDigits.charAt(j % 16));
		}
		return sbuffer.toString();
	}
}