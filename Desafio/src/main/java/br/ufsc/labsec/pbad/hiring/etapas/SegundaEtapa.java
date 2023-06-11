package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.criptografia.chave.EscritorDeChaves;
import br.ufsc.labsec.pbad.hiring.criptografia.chave.GeradorDeChaves;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;

/**
 * <b>Segunda etapa - gerar chaves assimétricas</b>
 * <p>
 * A partir dessa etapa, tudo que será feito envolve criptografia assimétrica.
 * A tarefa aqui é parecida com a etapa anterior, pois refere-se apenas a
 * criar e armazenar chaves, mas nesse caso será usado um algoritmo de
 * criptografia assimétrica, o ECDSA.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um par de chaves usando o algoritmo ECDSA com o tamanho de 256 bits;
 * </li>
 * <li>
 * gerar outro par de chaves, mas com o tamanho de 521 bits. Note que esse
 * par de chaves será para a AC-Raiz;
 * </li>
 * <li>
 * armazenar em disco os pares de chaves em formato PEM.
 * </li>
 * </ul>
 */
public class SegundaEtapa {

    public static void executarEtapa() {
        System.out.println("> Iniciando segunda etapa\n");
        try {
            GeradorDeChaves gdc = new GeradorDeChaves(algoritmoChave);

            System.out.println("    Gerando o par de chaves de 256 bits (Usuário)...");
            KeyPair parChaveUsuario = gdc.gerarParDeChaves(256);
            System.out.println("    Geração bem sucedida!\n");

            System.out.println("    Escrevendo em disco o par de 256 bits (Usuário)...");
            EscritorDeChaves.escreveChaveEmDisco(parChaveUsuario.getPrivate(), caminhoChavePrivadaUsuario);
            EscritorDeChaves.escreveChaveEmDisco(parChaveUsuario.getPublic(), caminhoChavePublicaUsuario);
            System.out.println("    Escrita bem sucedida!\n");

            System.out.println("    Gerando o par de chaves de 521 bits (Ac)...");
            KeyPair parChaveAc = gdc.gerarParDeChaves(521);
            System.out.println("    Geração bem sucedida!\n");

            System.out.println("    Escrevendo em disco o par de 521 bits (Ac)...");
            EscritorDeChaves.escreveChaveEmDisco(parChaveAc.getPrivate(), caminhoChavePrivadaAc);
            EscritorDeChaves.escreveChaveEmDisco(parChaveAc.getPublic(), caminhoChavePublicaAc);
            System.out.println("    Escrita bem sucedida!\n");
        }
        catch (NoSuchAlgorithmException | IOException e) {
            System.out.println("    " + e);
            System.out.println("    Backtrace: " + Arrays.toString(e.getStackTrace()));
        }
        System.out.println("< Segundo etapa finalizada");
    }

}
