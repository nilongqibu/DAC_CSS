import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.UnsatisfiedAccessControlException;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;

import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.Element;
import java.util.Map;


public class test_accessPolicy {
    public static void main(String[] args) {

        Pairing pairing = PairingFactory.getPairing("params/a1_3_256.properties");
        String accessPolicyString = "((0 and 1 and 2) and (3 or 4 or 5) and (6 and 7 and (8 or 9 or 10 or 11)))";
        String[] satisfiedRhos = new String[] {"0", "1", "2", "4", "6", "7", "10"};
        //Using Lewko-Waters LSSS
        AccessControlEngine accessControlEngine = LSSSLW10Engine.getInstance();
        try {
            //parse access policy
            int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
            String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
            AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);
            //secret sharing
            Element secret = pairing.getZr().newRandomElement().getImmutable();
            Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, secret, accessControlParameter);

            //Secret reconstruction
            Map<String, Element> omegaElementsMap = accessControlEngine.reconstructOmegas(pairing, satisfiedRhos, accessControlParameter);
            Element reconstructedSecret = pairing.getZr().newZeroElement().getImmutable();
            for (String eachAttribute : satisfiedRhos) {
                if (omegaElementsMap.containsKey(eachAttribute)) {
                    reconstructedSecret = reconstructedSecret.add(lambdaElementsMap.get(eachAttribute).mulZn(omegaElementsMap.get(eachAttribute))).getImmutable();
                }
            }
            System.out.println(secret);
            System.out.println(reconstructedSecret);
            assert(secret == reconstructedSecret);
        } catch (UnsatisfiedAccessControlException e) {
            // throw if the given attribute set does not satisfy the access policy represented by accress tree.
        } catch (PolicySyntaxException e) {
            // throw if invalid access policy representation.
        }

        System.out.println("Hello World!");
    }
}
