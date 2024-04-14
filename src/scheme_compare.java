import cn.edu.buaa.crypto.utils.Timer;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;

public class scheme_compare {

    double E_1;
    double E_2;
    double E_3;
    double P;
    double S1_Size = 10;
    double S2_Size = 10;
    double [] D1_Size = {1,2,3,4,5,6,7,8,9,10};
    double [] D2_Size = {1,2,3,4,5,6,7,8,9,10};
    double [] I_Size = {1,2,3,4,5,6,7,8,9,10};
    double I_prime_Size = 10;

    PairingParameters typeA1Params;
    private Pairing pairing;
    private Field G1;
    private Field GT;
    private Field Zr;

    class scheme31 {
        public double[] InitEncTime(){
            double[] time_cost = new double[10];
            for(int i = 0; i < I_Size.length; i++){
                time_cost[i] = (2 * S1_Size + 2 * I_Size[i] + I_prime_Size + 5) * E_1;
                time_cost[i] += 2 * E_2 + I_prime_Size * E_3 + 3 * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] ReEncTime(){
            double[] time_cost = new double[10];
            for(int i = 0; i < I_Size.length; i++){
                time_cost[i] = (S2_Size - 1) * E_1;
                time_cost[i] += (I_Size[i] + I_prime_Size + 1) * E_2;
                time_cost[i] += (2 * I_Size[i] + 3) * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] InitDecTime(){
            double[] time_cost = new double[10];
            for(int i = 0; i < I_Size.length; i++) {
                time_cost[i] = S1_Size * E_1 + E_2 + 2 * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] ReDecTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < I_Size.length; i++) {
                time_cost[i] = S2_Size * E_1 + E_2 + 3 * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }
    }

    class scheme32 {
        public double[] InitEncTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < I_Size.length; i++){
                time_cost[i] = (4 * I_Size[i] + 7) * E_1 + E_2;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] ReEncTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < I_Size.length; i++){
                time_cost[i] = I_Size[i] * E_2 + (2 * I_Size[i] + 2) * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] InitDecTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < I_Size.length; i++){
                time_cost[i] = I_Size[i] * E_2 + (2 * I_Size[i] + 1) * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] ReDecTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < I_Size.length; i++){
                time_cost[i] = (I_Size[i] + 1) * E_2 + (2 * I_Size[i] + 1) * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }
    }

    class scheme33 {
        public double[] InitEncTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < D1_Size.length; i++){
                time_cost[i] = (3 * S1_Size + 3 * D1_Size[i]) * E_1 + E_2 + P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }
        public double[] ReEncTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < D2_Size.length; i++){

                time_cost[i] = (S2_Size + D2_Size[i]) * E_1;
                time_cost[i] += E_2 + (3 * D2_Size[i] + 1) * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] InitDecTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < D1_Size.length; i++){
                time_cost[i] = S1_Size * E_1 + E_2 + 2 * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] ReDecTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < D1_Size.length; i++){
                time_cost[i] = S2_Size * E_1 + E_2 + 3 * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }
    }

    class scheme_DAC_CSS {
        public double[] InitEncTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < D1_Size.length; i++){
                time_cost[i] = (2 + D1_Size[i]) * E_1 + E_2 + P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }
        public double[] ReEncTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < D1_Size.length; i++){
                time_cost[i] = 3 * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] InitDecTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < D1_Size.length; i++){
                time_cost[i] = P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }

        public double[] ReDecTime(){

            double[] time_cost = new double[10];
            for(int i = 0; i < I_Size.length; i++){
                time_cost[i] = (2 * I_Size[i] + 4) * P;
//                System.out.println(time_cost[i]);
            }

            return time_cost;
        }
    }

    scheme31 scheme1;
    scheme32 scheme2;
    scheme33 scheme3;
    scheme_DAC_CSS scheme4;

    public scheme_compare()
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
//        Element gt = this.pairing.pairing(g1, g2);
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

        scheme1 = new scheme31();
        scheme2 = new scheme32();
        scheme3 = new scheme33();
        scheme4 = new scheme_DAC_CSS();
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


        scheme_compare instance = new scheme_compare();

        double [] time = instance.scheme1.InitEncTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");


        time = instance.scheme1.ReEncTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme1.InitDecTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme1.ReDecTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");




        time = instance.scheme2.InitEncTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme2.ReEncTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme2.InitDecTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme2.ReDecTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");



        time = instance.scheme3.InitEncTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme3.ReEncTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme3.InitDecTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme3.ReDecTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");



        time = instance.scheme4.InitEncTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme4.ReEncTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme4.InitDecTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");

        time = instance.scheme4.ReDecTime();
        for(double element: time){
            System.out.println(element);
        }
        System.out.println("--------------------------");



    }
}
