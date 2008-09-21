package assinaturas.lixo;


import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.FileInputStream;



public class AssinaturaDigitalImpl2 implements AssinaturaDigital2 {

	private static final String signatureAlgorithm = "MD5withRSA";
	private static File cert = new File("res/sas.jks");
	private static String alias = "sas";
	private static String pwd = "sas123";
	
	
	/**
	 * Retorna a string assinada digitalmente 
	 * @param chavePublica
	 * @param algoritmoChave RSA ou DSA
	 * @param textoAssinado
	 * @param algoritmoAssinatura pode ser MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return
	 */
	public void recuperaArquivoAssinado(byte[] chavePublica,String algoritmoChave, String arquivoAssinado, String arquivoRecuperado, String algoritmoAssinatura){
		KeyFactory kf = null;
		PublicKey pubKey = null;
		
		try {
			kf = java.security.KeyFactory.getInstance(algoritmoChave);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			pubKey = kf.generatePublic(
					new X509EncodedKeySpec(chavePublica));
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

//		byte[] txtAssinado = createSignature( privateKey, txt.getBytes() );

//		System.out.println( txt2Hexa( txtAssinado ) );
		Signature sig=null;
		try {
			sig = Signature.getInstance( algoritmoAssinatura );
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			sig.initVerify(pubKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		FileInputStream fis=null;
	
        byte[] buffer = new byte[4096];
        try {
			fis = new FileInputStream(arquivoAssinado);
	        int bytesLidos = -1;
	        while ((bytesLidos = fis.read(buffer)) != -1) {
	            sig.update(buffer, 0, bytesLidos);
//	        	md.update(buffer, 0, bytesLidos);
	        }

        } catch (Exception e) {
			e.printStackTrace();
		}finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                }
            }
        }
	
		try {
			
			FileOutputStream fos=new FileOutputStream(arquivoRecuperado);
			fos.write(sig.sign());

			System.out.println(sig.sign().toString());
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
	
	
	
	
	
	
	
	
	}
	
	
	

	/**
	 * Retorna a string assinada digitalmente 
	 * @param chavePublica
	 * @param algoritmoChave RSA ou DSA
	 * @param textoAssinado
	 * @param algoritmoAssinatura pode ser MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return
	 */
	public byte[] recuperaStringAssinada(byte[] chavePublica,String algoritmoChave, byte[] textoAssinado, String algoritmoAssinatura){
		KeyFactory kf = null;
		PublicKey pubKey = null;
		
		try {
			kf = java.security.KeyFactory.getInstance(algoritmoChave);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			pubKey = kf.generatePublic(
					new X509EncodedKeySpec(chavePublica));
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

//		byte[] txtAssinado = createSignature( privateKey, txt.getBytes() );

//		System.out.println( txt2Hexa( txtAssinado ) );
		Signature sig=null;
		try {
			sig = Signature.getInstance( algoritmoAssinatura );
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			sig.initVerify(pubKey);
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
//			sig.s
			sig.update(textoAssinado);
			return sig.sign();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;
	}
	
	public Boolean verificaAssinatura(byte[] chavePublica, String algoritmoChave, byte[] textoOriginal, byte[] textoAssinado, String algoritmoAssinatura){

		
		KeyFactory kf = null;
		PublicKey pubKey = null;
		
		try {
			kf = java.security.KeyFactory.getInstance(algoritmoChave);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		try {
			pubKey = kf.generatePublic(
					new X509EncodedKeySpec(chavePublica));
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

//		byte[] txtAssinado = createSignature( privateKey, txt.getBytes() );

//		System.out.println( txt2Hexa( txtAssinado ) );


		Signature sig;
		try {
			sig = Signature.getInstance(algoritmoAssinatura);
			sig.initVerify(pubKey);
			sig.update(textoOriginal, 0, textoOriginal.length);
			return sig.verify( textoAssinado );

		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return null;

	}


	/**
     * Verifica a assinatura para o buffer de bytes, usando a chave pública.
     */
/*	private static boolean verificaAssinatura( PublicKey key, byte[] buffer, byte[] signed ) throws Exception {
		Signature sig = Signature.getInstance( signatureAlgorithm );
		sig.initVerify(key);
		sig.update(buffer, 0, buffer.length);
		return sig.verify( signed );
	}
*/	
	
/*	public static void main(String[] args){
	try {
		String txt = "String a ser encriptada";

		PrivateKey privateKey = getPrivateKeyFromFile( cert, alias, pwd );
		PublicKey publicKey = getPublicKeyFromFile( cert, alias, pwd );

		byte[] txtAssinado = createSignature( privateKey, txt.getBytes() );

		System.out.println( txt2Hexa( txtAssinado ) );

		if( verificaAssinatura( publicKey, txt.getBytes(), txtAssinado ) ) {
			System.out.println("Assinatura OK!");
		} else {
			System.out.println("Assinatura NOT OK!");
		}

	} catch( Exception e ) {
		e.printStackTrace();
	}

	}
	
*/	

	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
	
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
