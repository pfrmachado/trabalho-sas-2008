package assinaturas;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

import java.io.FileOutputStream;
import java.io.FileInputStream;

/**
 * Assina digitalmente um documento (arquivo) ou sequencia de bytes, 
 * verifica a assinatura de um dado documento ou sequencia de bytes e 
 * valida um certificado digital. 
 *
 * @author Leandro Alexandre, Sérgio Daniel, Rafael Duarte, Thiago Roza 
 * @version 0.6
 */

public class AssinaturaDigitalImpl {
	
	/**
	 * Assina digitalmente uma string através da chave privada.
	 * @param privk
	 * @param stringOriginal 
	 * @param algoritmoAssinatura : MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return byte[] com a string assinada
	 */
	public byte[] assinaString(PrivateKey privk, byte[] stringOriginal, String algoritmoAssinatura){
		
		
		Signature sig=null;
		try {
			sig = Signature.getInstance( algoritmoAssinatura );
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			sig.initSign(privk);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		try {
			sig.update(stringOriginal);
			return sig.sign();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		
		return null;

		
	}

	/**
	 * Verifica se através do certificado uma string é possível gerar uma string assinada
	 * @param cert
	 * @param stringAssinada
	 * @param stringOriginal
	 * @param algoritmoAssinatura : MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return verdadeiro caso com a stringOriginal e certificado seja gerada a stringAssinada 
	 */
	public Boolean verificaAssinatura(Certificate cert, byte[] stringAssinada, byte[] stringOriginal, String algoritmoAssinatura){
		return verificaAssinatura(cert.getPublicKey(),  stringAssinada, stringOriginal,  algoritmoAssinatura);
	}


	
	/**
	 * Verifica se através do certificado um arquivo é possível gerar uma assinatura 
	 * @param cert
	 * @param arquivoAssinado
	 * @param arquivoOriginal
	 * @param algoritmoAssinatura : MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return verdadeiro caso com o arquivoOriginal e certificado seja gerado o arquivoAssinado
	 */
	public Boolean verificaAssinatura(Certificate cert, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura){
		return verificaAssinatura(cert.getPublicKey(),  arquivoAssinado,arquivoOriginal, algoritmoAssinatura);
	}
	
	
	/**
	 * Verifica se através da chave pública e uma string é possível gerar uma determinada string assinada
	 * @param pubk
	 * @param stringAssinada
	 * @param stringOriginal
	 * @param algoritmoAssinatura
	 * @return verdadeiro caso com a stringOriginal e a chave pública seja gerada a stringAssinada
	 */
	public Boolean verificaAssinatura(PublicKey pubk, byte[] stringAssinada, byte[] stringOriginal, String algoritmoAssinatura){
		
		
		Signature sig=null;
		try {
			sig = Signature.getInstance( algoritmoAssinatura );
		} catch (NoSuchAlgorithmException e) {
			System.out.println("nao foi possivel iniciar com o algoritmo"+ stringAssinada);
			e.printStackTrace();
		}
		try {
			sig.initVerify(pubk);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		try {
			sig.update(stringOriginal);
			return sig.verify(stringAssinada);
		} catch (SignatureException e) {
			System.out.println("nao foi possivel assinar:\n");
			e.printStackTrace();
		}
		
		return false;

		
	}


	/**
	 * Verifica se através da chave pública e de um arquivo é possível gerar um determinado arquivo assinado.
	 * @param pubk
	 * @param arquivoAssinado
	 * @param arquivoOriginal
	 * @param algoritmoAssinatura : MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 * @return verdadeiro caso com a arquivoOriginal e a chave pública seja gerada a arquivoAssinado
	 */
	public Boolean verificaAssinatura(PublicKey pubk, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura){
		
		Signature sig=null;
		try {
			sig = Signature.getInstance( algoritmoAssinatura );
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			sig.initVerify(pubk);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		
		
		FileInputStream fis=null;
		FileInputStream fis2=null;
	
        byte[] buffer = new byte[4096];
        byte[] buffer2 = new byte[1];
        try {
			fis = new FileInputStream(arquivoOriginal);
	        int bytesLidos = -1;
	        while ((bytesLidos = fis.read(buffer)) != -1) {
	            sig.update(buffer, 0, bytesLidos);
	        }
	        
			fis2 = new FileInputStream(arquivoAssinado);
	        bytesLidos = -1;
        
	        int i=0;
	        while ((bytesLidos = fis2.read(buffer2)) != -1) {
	        	i++;
	        }
	        fis2.close();
	        
			fis2 = new FileInputStream(arquivoAssinado);
        
	        byte[] conteudoAssinado = new byte[i];
	        fis2.read(conteudoAssinado);

	        return (sig.verify(conteudoAssinado));
	        
	        
        } catch (Exception e) {
			e.printStackTrace();
		}finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                }
            }
            if (fis2 != null) {
                try {
                    fis2.close();
                } catch (Exception e) {
                }
            }

        }
	
		
		return false;

	}
	/**
	 * Assina digitalmente um arquivo através da chave privada.
	 * @param chavePrivada
	 * @param arquivoaAssinar
	 * @param arquivoOriginal
	 * @param algoritmoAssinatura  : MD2withRSA, MD5withRSA, SHA1withDSA ou SHA1withRSA
	 */
	public void assinaArquivo(PrivateKey chavePrivada, String arquivoaAssinar, String arquivoOriginal, String algoritmoAssinatura){
		KeyFactory kf = null;
		
		Signature sig=null;
		try {
			sig = Signature.getInstance( algoritmoAssinatura );
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			sig.initSign(chavePrivada);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		
		
		FileInputStream fis=null;
	
        byte[] buffer = new byte[4096];
        String test="";
        try {
			fis = new FileInputStream(arquivoOriginal);
	        int bytesLidos = -1;
	        while ((bytesLidos = fis.read(buffer)) != -1) {
	            sig.update(buffer, 0, bytesLidos);
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
			
			FileOutputStream fos=new FileOutputStream(arquivoaAssinar);
			fos.write(sig.sign());
			fos.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	
	}
	
	


	/**
	 * Valida certificado com a chave pública da autoridade certificadora.
	 * @param certificado certificado a ser validado
	 * @param pubk chave pública da autoridade certificadora
	 * @return true se a autoridade certificadora validou o certificado
	 * false, caso contrário.
	 * 
	 */
	public boolean validaCertificado(Certificate certificado, PublicKey pubk){
        try {
            certificado.verify(pubk);
            return true;
        } catch (SignatureException se) {
            return false;
        } catch (InvalidKeyException e) {
        	System.out.println("Erro em validaCertificado:");
			e.printStackTrace();
		} catch (CertificateException e) {
        	System.out.println("Erro em validaCertificado:");
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
        	System.out.println("Erro em validaCertificado:");
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
        	System.out.println("Erro em validaCertificado:");
			e.printStackTrace();
		}

		return false;
		}

}