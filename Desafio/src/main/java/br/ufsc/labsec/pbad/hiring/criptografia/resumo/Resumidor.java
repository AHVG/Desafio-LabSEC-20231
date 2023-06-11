package br.ufsc.labsec.pbad.hiring.criptografia.resumo;


import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static br.ufsc.labsec.pbad.hiring.Constantes.algoritmoResumo;

/**
 * Classe responsável por executar a função de resumo criptográfico.
 *
 * @see MessageDigest
 */
public class Resumidor {

    private MessageDigest md;
    private String algoritmo;

    /**
     * Construtor.
     */
    public Resumidor() throws NoSuchAlgorithmException {
        this.algoritmo = algoritmoResumo;
        this.md = MessageDigest.getInstance(this.algoritmo);
    }

    /**
     * Calcula o resumo criptográfico do arquivo indicado.
     *
     * @param arquivoDeEntrada arquivo a ser processado.
     * @return Bytes do resumo.
     */
    public byte[] resumir(File arquivoDeEntrada) throws IOException {
        byte[] texto = Files.readAllBytes(arquivoDeEntrada.toPath());
        return this.md.digest(texto);
    }

    /**
     * Escreve o resumo criptográfico no local indicado.
     *
     * @param resumo         resumo criptográfico em bytes.
     * @param caminhoArquivo caminho do arquivo.
     */
    public void escreveResumoEmDisco(byte[] resumo, String caminhoArquivo) throws IOException {
        File arquivo = new File(caminhoArquivo);
        Files.write(arquivo.toPath(), resumo);
    }

}
