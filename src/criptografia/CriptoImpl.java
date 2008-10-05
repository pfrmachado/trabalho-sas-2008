package criptografia;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Key;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author grupo 
 * @version 0.666
 */
public class CriptoImpl implements Cripto {

    public byte[] criptografaRsa(Key senha, byte[] entrada){
        return getCripto(senha, entrada, "RSA");
    }

    public byte[] criptografaDes(Key senha, byte[] entrada){
        return getCripto(senha, entrada, "DES");
    }
    
    public void criptografaRsa(Key senha, String arquivoEntrada, String arquivoSaida){
        getCriptoFile(senha, arquivoEntrada, arquivoSaida, "RSA");
    }

    public void criptografaDes(Key senha, String arquivoEntrada, String arquivoSaida){
        getCriptoFile(senha, arquivoEntrada, arquivoSaida, "DES");
    }

    
    
    /**
     * Obtém o a string criptografada através da string de entrada
     * algoritmo de criptografia e chave.
     * @param entrada Array de bytes cujo valor de hash é desejado.
     * @param hashFunction Método de hash a ser empregado.
     * @return Valor de hash.
     */
    private byte[] getCripto(Key senha, byte[] entrada, String algoritmo) {
        
        Cipher cifra;
		try {
			cifra = Cipher.getInstance(algoritmo);

	        cifra.init(Cipher.ENCRYPT_MODE, senha);
	        return cifra.doFinal(entrada);

		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;        
    }

    
    
    
    
    
    
    
    
    
    
    
    private void getCriptoFile(Key senha, String arquivoEntrada, String arquivoSaida, String algoritmo){
    
        
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

			

			
			
			
			
			
			
			
			cifra.init(Cipher.ENCRYPT_MODE, senha);


			
			FileOutputStream fos=new FileOutputStream(arquivoSaida);
			fos.write(cifra.doFinal(conteudoArquivo));
			fos.close();       
	        
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	
    }    
    
    
    
    
    
    
    
    
    
    
    
}