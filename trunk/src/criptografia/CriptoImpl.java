package criptografia;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author grupo 
 * @version 0.666
 */
public class CriptoImpl implements Cripto {

    public byte[] criptografaRsa(PublicKey senha, byte[] entrada){
        return getCripto2(senha, entrada, "RSA", false);
    }

    public byte[] criptografaDes(Key senha, byte[] entrada){
        return getCripto(senha, entrada, "DES", false);
    }
    
    public void criptografaRsa(PublicKey senha, String arquivoEntrada, String arquivoSaida){
        getCriptoFile(senha, arquivoEntrada, arquivoSaida, "RSA", false);
    }


    public void criptografaDes(Key senha, String arquivoEntrada, String arquivoSaida){
        getCriptoFile(senha, arquivoEntrada, arquivoSaida, "DES", false);
    }

    public byte[] descriptografaRsa(PrivateKey senha, byte[] entrada){
        return getCripto(senha, entrada, "RSA", true);
    }

    public byte[] descriptografaDes(Key senha, byte[] entrada){
        return getCripto(senha, entrada, "DES", true);
    }
    
    public void descriptografaRsa(PrivateKey senha, String arquivoEntrada, String arquivoSaida){
        getCriptoFile(senha, arquivoEntrada, arquivoSaida, "RSA", true);
    }

    public void descriptografaDes(Key senha, String arquivoEntrada, String arquivoSaida){
        getCriptoFile(senha, arquivoEntrada, arquivoSaida, "DES", true);
    }
    
    
    /**
     * Criptografa/descriptografa sequencia de bytes.
     * 
     * @param senha chave de criptografia/descriptografia
     * @param entrada sequencia de bytes a ser criptografada/descriptografada
     * @param algoritmo algoritmo de critografia/descriptografia
     * @param descriptografa variavel booleana, que se verdadeira
     * executa a descriptografia. Se falsa, criptografa.
     * @return cadeia de bytes criptografada/descriptografada
     */
    private byte[] getCripto(Key senha, byte[] entrada, String algoritmo, boolean descriptografa) {
        
        Cipher cifra;
		try {
			cifra = Cipher.getInstance(algoritmo);
			
			if (descriptografa){
				cifra.init(Cipher.DECRYPT_MODE, senha);
				System.out.println("descript\n");
			} else{
				cifra.init(Cipher.ENCRYPT_MODE, senha);
			}
	        return cifra.doFinal(entrada);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;        
    }

    
    
    
    
    

    
    
    
    
    private byte[] getCripto2(PublicKey senha, byte[] entrada, String algoritmo, boolean descriptografa) {

        Cipher cifra;
    	
    	

    	
		try {
			 cifra = Cipher.getInstance("RSA");
			cifra.init(Cipher.ENCRYPT_MODE, senha);
			System.out.println("asdf");
//			System.out.println(cripto.toHex(cifra.doFinal(mensagem)));
//			System.out.println(cripto.toHex(cripto.criptografaRsa(chaves.getPublic(), mensagem)));

//			cifra = Cipher.getInstance(algoritmo);
			
/*			if (descriptografa){
				cifra.init(Cipher.DECRYPT_MODE, senha);
				System.out.println("descript\n");
			} else{
				cifra.init(Cipher.ENCRYPT_MODE, senha);
			}*/
	        return cifra.doFinal(entrada);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;        
    }
    
    
    
    
    
    
    
    
    
    
    /**
     * Criptografa/descriptografa arquivo
 	 * 
     * @param senha Chave de criptografia/descriptografia
     * @param arquivoEntrada arquivo a ser criptografado/descriptografado
     * @param arquivoSaida resutado da criptografia/descriptografia
     * @param algoritmo algoritmo de criptografia/descriptografia 
     * @param descriptografa se verdadeiro, executa a funcao de descriptografia,
     * caso contrario, criptografa.
     */
    private void getCriptoFile(Key senha, String arquivoEntrada, String arquivoSaida, String algoritmo, Boolean descriptografa){
    
        
        Cipher cifra;
		try {
			cifra = Cipher.getInstance(algoritmo);

			
			FileInputStream fis2=null;

		    byte[] buffer2 = new byte[1];
	        int bytesLidos = -1;

		        
				fis2 = new FileInputStream(arquivoEntrada);
		        bytesLidos = -1;
		    
		        int i=0;
		        while ((bytesLidos = fis2.read(buffer2)) != -1) {
		        	i++;
		        }
		        fis2.close();
		        
				fis2 = new FileInputStream(arquivoEntrada);
		    
		        byte[] conteudoArquivo = new byte[i];
		        fis2.read(conteudoArquivo);

			

			
			
			
				if (descriptografa){
					cifra.init(Cipher.DECRYPT_MODE, senha);
				} else{
					cifra.init(Cipher.ENCRYPT_MODE, senha);
				}
			
			
			
			


			
			FileOutputStream fos=new FileOutputStream(arquivoSaida);
			fos.write(cifra.doFinal(conteudoArquivo));
			fos.close();       
	        
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	
    }    
    
    
    
    
    
    
    
    
    
    public String toHex(byte[] hash) {
        final char[] HEX_CHARS = {'0', '1', '2', '3', '4', '5',
            '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
        };

        char strHash[] = new char[hash.length * 2];
        for (int i = 0, x = 0; i < hash.length; i++) {
            strHash[x++] = HEX_CHARS[(hash[i] >>> 4) & 0xf];
            strHash[x++] = HEX_CHARS[hash[i] & 0xf];
        }
        return new String(strHash);
    }
    
}