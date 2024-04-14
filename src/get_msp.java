import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.lsss.LSSSPolicyParameter;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import java.util.Map;

public class get_msp {
    public static void main(String[] args){

        Pairing pairing = PairingFactory.getPairing("params/a_80_256.properties");
        String accessPolicyString = "(0 and 1) or (2 and 3 and 4)";
        String[] satisfiedRhos = new String[] {"0", "1"};
        //Using Lewko-Waters LSSS
        AccessControlEngine accessControlEngine = LSSSLW10Engine.getInstance();
        try {
            //parse access policy
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);

            Element secret = pairing.getZr().newRandomElement().getImmutable();
            Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, secret, accessControlParameter);
//            System.out.println(lambdaElementsMap);

            LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter)accessControlParameter;
            int[][] mspMatrix = lsssPolicyParameter.getLSSSMatrix();
            String[] strRou = lsssPolicyParameter.getRhos();
            int[] rou = new int[strRou.length];

            for(int i = 0; i < mspMatrix.length; i++)
            {
                for(int j = 0; j < mspMatrix[0].length; j++)
                {
                    System.out.print(mspMatrix[i][j] + "\t");
                }
                System.out.println();
            }

            for(int i = 0; i < strRou.length; i++)
            {
                rou[i] = Integer.parseInt(strRou[i]);
                System.out.print(rou[i] + "\t");
            }
        } catch (PolicySyntaxException e) {
            e.printStackTrace();
        }
    }
}
