package br.ufsc.labsec.pbad.hiring.criptografia.certificado;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

/**
 * Classe responsável por escrever um certificado no disco.
 */
public class EscritorDeCertificados {

    /**
     * Escreve o certificado indicado no disco.
     *
     * @param nomeArquivo           caminho que será escrito o certificado.
     * @param certificadoCodificado bytes do certificado.
     */
    public static void escreveCertificado(String nomeArquivo,
                                          byte[] certificadoCodificado) throws IOException {
        File arquivo = new File(nomeArquivo);
        Files.write(arquivo.toPath(), certificadoCodificado);
    }

}
