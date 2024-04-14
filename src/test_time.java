import cn.edu.buaa.crypto.utils.Timer;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;

public class test_time {

    double E_1;
    double E_2;
    double E_3;
    double P;

    PairingParameters typeA1Params;
    private Pairing pairing;
    private Field G1;
    private Field GT;
    private Field Zr;
    public test_time()
    {
        TypeA1CurveGenerator pg = new TypeA1CurveGenerator(3, 256);
        this.typeA1Params = pg.generate();

        this.pairing = PairingFactory.getPairing(typeA1Params);
        this.G1=this.pairing.getG1();
        this.GT=this.pairing.getGT();
        this.Zr=this.pairing.getZr();

        Element g1 = this.G1.newRandomElement().getImmutable();
        Element g2 = this.G1.newRandomElement().getImmutable();
        Element r = this.Zr.newRandomElement().getImmutable();
        Element gt = this.GT.newRandomElement().getImmutable();

        double temperTime;
        Timer timer = new Timer();

        timer.start(0);
        for(int i = 0; i < 100; i++)
        {
            Element tmp = g1.powZn(r);
        }
        temperTime = timer.stop(0);
        this.E_1 = temperTime / 100;
        System.out.println("E_1:" + this.E_1);


        timer.start(0);
        for(int i = 0; i < 100; i++)
        {
            Element tmp = gt.powZn(r);
        }
        temperTime = timer.stop(0);
        this.E_2 = temperTime / 100;
        System.out.println("E_2:" + this.E_2);

        timer.start(0);
        for(int i = 0; i < 100; i++)
        {
            Element tmp = r.powZn(r);
        }
        temperTime = timer.stop(0);
        this.E_3 = temperTime / 100;
        System.out.println("E_3:" + this.E_3);


        timer.start(0);
        for(int i = 0; i < 100; i++)
        {
            Element tmp = this.pairing.pairing(g1, g2);
        }
        temperTime = timer.stop(0);
        this.P = temperTime / 100;
        System.out.println("P:" + this.P);
    }


    public static void main(String[] args){

        double temperTime;
        Timer timer = new Timer();
        timer.start(0);
        try{
            java.lang.Thread.sleep(100);
        }catch(InterruptedException e){
            e.printStackTrace();
        }
        temperTime = timer.stop(0);
        System.out.println("\t" + temperTime);


        test_time instance = new test_time();
    }
}

