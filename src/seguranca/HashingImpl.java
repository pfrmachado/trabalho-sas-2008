package br.ufg.inf.seguranca;

import java.io.FileInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 *
 * @author Fábio Nogueira de Lucena
 * @version 0.1
 */
public class HashingImpl implements Hashing {

    public byte[] md5(byte[] entrada) {
        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("MD5");
        } catch (NoSuchAlgorithmException nsae) {
            nsae.printStackTrace();
            return null;
        }
        return md.digest(entrada);
    }

    public byte[] sha1(byte[] entrada) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    /**
     * Obtém os 16 bytes (128 bits) do valor de hash empregando o 
     * algoritmo MD5 para o arquivo cujo nome é fornecido.
     * @param nomeArquivo Nome do arquivo cujo valor de hash é desejado.
     * @return Valor de hash MD5 do arquivo fornecido ou null, caso a operação
     * tenha sido realizada insatisfatoriamente.
     */
    public byte[] md5(String nomeArquivo) {
        MessageDigest md = null;
        FileInputStream fis = null;
        try {
            md = MessageDigest.getInstance("MD5");
            byte[] buffer = new byte[4096];
            fis = new FileInputStream(nomeArquivo);
            int bytesLidos = -1;
            while ((bytesLidos = fis.read(buffer)) != -1) {
                md.update(buffer, 0, bytesLidos);
            }
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (Exception e) {
                }
            }
        }
        return md.digest();
    }

    public byte[] sha1(String nomeArquivo) {
        throw new UnsupportedOperationException("Not supported yet.");
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
