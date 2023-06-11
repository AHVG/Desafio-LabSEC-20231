package br.ufsc.labsec.pbad.hiring.etapas;

import br.ufsc.labsec.pbad.hiring.criptografia.assinatura.GeradorDeAssinatura;
import br.ufsc.labsec.pbad.hiring.criptografia.repositorio.RepositorioChaves;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.operator.OperatorCreationException;

import javax.sound.midi.SysexMessage;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;

import static br.ufsc.labsec.pbad.hiring.Constantes.*;

/**
 * <b>Quinta etapa - gerar uma assinatura digital</b>
 * <p>
 * Essa etapa é um pouco mais complexa, pois será necessário que
 * implemente um método para gerar assinaturas digitais. O padrão de
 * assinatura digital adotado será o Cryptographic Message Syntax (CMS).
 * Esse padrão usa a linguagem ASN.1, que é uma notação em binário, assim
 * não será possível ler o resultado obtido sem o auxílio de alguma
 * ferramenta. Caso tenha interesse em ver a estrutura da assinatura
 * gerada, recomenda-se o uso da ferramenta {@code dumpasn1}.
 * <p>
 * Os pontos a serem verificados para essa etapa ser considerada concluída
 * são os seguintes:
 * <ul>
 * <li>
 * gerar um assinatura digital usando o algoritmo de resumo criptográfico
 * SHA-256 e o algoritmo de criptografia assimétrica ECDSA;
 * </li>
 * <li>
 * o assinante será você. Então, use o repositório de chaves recém gerado para
 * seu certificado e chave privada;
 * </li>
 * <li>
 * assinar o documento {@code textoPlano.txt}, onde a assinatura deverá ser do
 * tipo "anexada", ou seja, o documento estará embutido no arquivo de
 * assinatura;
 * </li>
 * <li>
 * gravar a assinatura em disco.
 * </li>
 * </ul>
 */
public class QuintaEtapa {

    public static void executarEtapa() {
        System.out.println("> Iniciando quinta etapa\n");
        try{
            System.out.println("    Lendo do disco a chave e o certificado geradas pela Usuárioc...");
            RepositorioChaves repo = new RepositorioChaves(senhaMestre, aliasUsuario);
            repo.abrir(caminhoPkcs12Usuario);
            X509Certificate certificado = repo.pegarCertificado();
            PrivateKey chavePrivada = repo.pegarChavePrivada();
            OutputStream arquivo = new FileOutputStream(caminhoAssinatura);
            System.out.println("    Leitura bem sucedida!\n");

            System.out.println("    Gerando a assinatura...");
            GeradorDeAssinatura geradorDeAssinatura = new GeradorDeAssinatura();
            geradorDeAssinatura.informaAssinante(certificado, chavePrivada);
            CMSSignedData documentoAssinado = geradorDeAssinatura.assinar(caminhoTextoPlano);
            System.out.println("    Geração bem sucedida!\n");

            System.out.println("    Escrevendo assinatura em disco...");
            geradorDeAssinatura.escreveAssinatura(arquivo, documentoAssinado);
            System.out.println("    Escrita bem sucedida!\n");

        } catch (OperatorCreationException | CMSException | IOException | UnrecoverableKeyException |
                 CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
            System.out.println("    " + e);
            System.out.println("    Backtrace: " + Arrays.toString(e.getStackTrace()));
        }
        System.out.println("< Quinta etapa finalizada");
    }

}
