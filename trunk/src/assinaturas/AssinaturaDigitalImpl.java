package assinaturas;

import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SignatureException;

import java.io.FileOutputStream;
import java.io.FileInputStream;


public class AssinaturaDigitalImpl {
	

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
		
		return null;

		
	}


	
	public Boolean verificaAssinatura(PublicKey chavePublica, String arquivoAssinado, String arquivoOriginal, String algoritmoAssinatura){
		KeyFactory kf = null;
		
		Signature sig=null;
		try {
			sig = Signature.getInstance( algoritmoAssinatura );
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		try {
			sig.initVerify(chavePublica);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		}
		
		
		FileInputStream fis=null;
		FileInputStream fis2=null;
	
        byte[] buffer = new byte[4096];
        byte[] buffer2 = new byte[4096];
        String assinaturaArquivo = "";

        try {
			fis = new FileInputStream(arquivoOriginal);
	        int bytesLidos = -1;
	        while ((bytesLidos = fis.read(buffer)) != -1) {
	            sig.update(buffer, 0, bytesLidos);
	        }
	        
			fis2 = new FileInputStream(arquivoAssinado);
	        bytesLidos = -1;
	        while ((bytesLidos = fis.read(buffer)) != -1) {
	            assinaturaArquivo = assinaturaArquivo + buffer.toString();
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
			return (sig.verify(assinaturaArquivo.getBytes()));
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		return false;

	}

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

			System.out.println(sig.sign().toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	
	}
	
	
	
	
	
	
}
