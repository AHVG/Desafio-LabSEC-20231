package br.ufsc.labsec.pbad.hiring.criptografia.chave;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.Key;

/**
 * Essa classe é responsável por escrever uma chave assimétrica no disco. Note
 * que a chave pode ser tanto uma chave pública quanto uma chave privada.
 *
 * @see Key
 */
public class EscritorDeChaves {

    /**
     * Escreve uma chave no local indicado.
     *
     * @param chave         chave assimétrica a ser escrita em disco.
     * @param nomeDoArquivo nome do local onde será escrita a chave.
     */
    public static void escreveChaveEmDisco(Key chave, String nomeDoArquivo) throws IOException {
        File arquivo = new File(nomeDoArquivo);
        Files.write(arquivo.toPath(), chave.getEncoded());
    }

}
