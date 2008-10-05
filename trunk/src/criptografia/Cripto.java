package criptografia;

import java.security.Key;
        /*
         * Serviços de criptografia da biblioteca.
         *
         * @author Rafael Teixeira Duarte
         * @version 0.666
         *
         *
         * ToDO
         *
         * Implementar interface/classe que criptografa/descriptografa usando RSA/DES
         * um arquivo ou sequencia de bytes      *
         *
         */
public interface Cripto {
	
    //String nomeArquivo des(String );
    void criptografaRsa(Key senha, String nomeArquivoEntrada, String nomeArquivoSaida);
    byte[] criptografaRsa(Key senha, byte[] entrada);
    //byte[] des(byte[] entrada);
    //byte[] rsa(byte[] entrada);
}
