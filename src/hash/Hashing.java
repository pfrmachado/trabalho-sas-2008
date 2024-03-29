package hash;


/**
 * Servi�os de hashing da biblioteca.
 * 
 * @author F�bio Nogueira de Lucena
 * @version 0.1
 */
public interface Hashing {
    byte[] md5(String nomeArquivo);
    byte[] sha1(String nomeArquivo);
    byte[] md5(byte[] entrada);
    byte[] sha1(byte[] entrada);
}
