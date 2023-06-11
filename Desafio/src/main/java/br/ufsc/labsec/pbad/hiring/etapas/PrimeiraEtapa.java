package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.criptografia.resumo.Resumidor;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static br.ufsc.labsec.pbad.hiring.Constantes.caminhoResumoCriptografico;
import static br.ufsc.labsec.pbad.hiring.Constantes.caminhoTextoPlano;

/**
 * <b>Primeira etapa - obter o resumo criptográfico de um documento</b>
 * <p>
 * Basta obter o resumo criptográfico do documento {@code textoPlano.txt}.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * obter o resumo criptográfico do documento, especificado na descrição
 * dessa etapa, usando o algoritmo de resumo criptográfico conhecido por
 * SHA-256;
 * </li>
 * <li>
 * armazenar em disco o arquivo contendo o resultado do resumo criptográfico,
 * em formato hexadecimal.
 * </li>
 * </ul>
 */
public class PrimeiraEtapa {

    public static void executarEtapa() {
        System.out.println("> Iniciando primeira etapa\n");
        try {
            System.out.println("    Resumindo...");
            Resumidor resumidor = new Resumidor();
            byte[] resumo_em_bytes = resumidor.resumir(new File(caminhoTextoPlano));
            System.out.println("    Resumo bem sucedido!\n");

            System.out.println("    Convertendo de bytes para string...");
            StringBuilder sb = new StringBuilder();
            for(byte b : resumo_em_bytes) {
                sb.append(String.format("%02x", b));
            }
            String resumo_em_string = sb.toString();
            System.out.println("    Resumo: " + resumo_em_string);
            System.out.println("    Conversão bem sucedida!\n");

            System.out.println("    Escrevendo em disco...");
            resumidor.escreveResumoEmDisco(resumo_em_bytes, caminhoResumoCriptografico);
            System.out.println("    Escrita bem sucedida!\n");

        } catch (NoSuchAlgorithmException | IOException e) {
            System.out.println("    " + e);
            System.out.println("    Backtrace: " + Arrays.toString(e.getStackTrace()));
        }
        System.out.println("< Primeira etapa finalizada");
    }

}
