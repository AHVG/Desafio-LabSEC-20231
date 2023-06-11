package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.*;
import java.security.spec.*;

/**
 * Classe responsável por ler uma chave assimétrica do disco.
 *
 * @see KeyFactory
 * @see KeySpec
 */
public class LeitorDeChaves {

    /**
     * Lê a chave privada do local indicado.
     *
     * @param caminhoChave local do arquivo da chave privada.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave privada.
     */
    public static PrivateKey lerChavePrivadaDoDisco(String caminhoChave,
                                                    String algoritmo) throws IOException,
            NoSuchAlgorithmException, InvalidKeySpecException {
        File arquivo = new File(caminhoChave);
        byte[] keyBytes = Files.readAllBytes(arquivo.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance(algoritmo);

        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(keyBytes);
        return keyFactory.generatePrivate(privateKeySpec);
    }

    /**
     * Lê a chave pública do local indicado.
     *
     * @param caminhoChave local do arquivo da chave pública.
     * @param algoritmo    algoritmo de criptografia assimétrica que a chave
     *                     foi gerada.
     * @return Chave pública.
     */
    public static PublicKey lerChavePublicaDoDisco(String caminhoChave,
                                                   String algoritmo) throws NoSuchAlgorithmException,
            InvalidKeySpecException, IOException {
        File arquivo = new File(caminhoChave);
        byte[] keyBytes = Files.readAllBytes(arquivo.toPath());
        KeyFactory keyFactory = KeyFactory.getInstance(algoritmo);

        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(keyBytes);
        return keyFactory.generatePublic(publicKeySpec);
    }

}
