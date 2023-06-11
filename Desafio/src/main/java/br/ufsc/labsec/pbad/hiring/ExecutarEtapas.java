package br.ufsc.labsec.pbad.hiring;

import br.ufsc.labsec.pbad.hiring.etapas.*;

/**
 * Classe principal, responsável por executar todas as etapas.
 */

public class ExecutarEtapas {

    @SuppressWarnings("All")
    public static void main(String[] args) {
        PrimeiraEtapa.executarEtapa();
        SegundaEtapa.executarEtapa();
        TerceiraEtapa.executarEtapa();
        QuartaEtapa.executarEtapa();
        QuintaEtapa.executarEtapa();
        SextaEtapa.executarEtapa();
    }

}
