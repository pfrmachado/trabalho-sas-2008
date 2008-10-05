package criptografia;

import java.security.Key;
        /*
         * Criptografia/descriptografia RES e DES.
         *
         * @author Grupo
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
	byte[] criptografaRsa(Key senha, byte[] entrada);
	byte[] criptografaDes(Key senha, byte[] entrada);
	void criptografaRsa(Key senha, String arquivoEntrada, String arquivoSaida);
	void criptografaDes(Key senha, String arquivoEntrada, String arquivoSaida);
	byte[] descriptografaRsa(Key senha, byte[] entrada);
	byte[] descriptografaDes(Key senha, byte[] entrada);
	void descriptografaRsa(Key senha, String arquivoEntrada, String arquivoSaida);
	void descriptografaDes(Key senha, String arquivoEntrada, String arquivoSaida);
}
