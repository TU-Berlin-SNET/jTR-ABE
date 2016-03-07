package trabe.lw14.policy;

import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;

public class Lw14TreePreprocessing {
    public ElementPowPreProcessing eppp_f;
    public ElementPowPreProcessing eppp_g;
    public ElementPowPreProcessing eppp_G;
    public ElementPowPreProcessing eppp_H;

    public Lw14TreePreprocessing(ElementPowPreProcessing eppp_f, ElementPowPreProcessing eppp_g, ElementPowPreProcessing eppp_G, ElementPowPreProcessing eppp_H) {
        this.eppp_f = eppp_f;
        this.eppp_g = eppp_g;
        this.eppp_G = eppp_G;
        this.eppp_H = eppp_H;
    }
}
