package criptografia;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
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
	byte[] criptografaRsa(PublicKey senha, byte[] entrada);
	byte[] criptografaDes(Key senha, byte[] entrada);
	void criptografaRsa(PublicKey senha, String arquivoEntrada, String arquivoSaida);
	void criptografaDes(Key senha, String arquivoEntrada, String arquivoSaida);
	byte[] descriptografaRsa(PrivateKey senha, byte[] entrada);
	byte[] descriptografaDes(Key senha, byte[] entrada);
	void descriptografaRsa(PrivateKey senha, String arquivoEntrada, String arquivoSaida);
	void descriptografaDes(Key senha, String arquivoEntrada, String arquivoSaida);
}
