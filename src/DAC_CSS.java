import java.util.*;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;

import cn.edu.buaa.crypto.access.AccessControlEngine;
import cn.edu.buaa.crypto.access.AccessControlParameter;
import cn.edu.buaa.crypto.access.lsss.LSSSPolicyParameter;
import cn.edu.buaa.crypto.access.lsss.lw10.LSSSLW10Engine;
import cn.edu.buaa.crypto.access.parser.ParserUtils;
import cn.edu.buaa.crypto.access.parser.PolicySyntaxException;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Field;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.jpbc.PairingParameters;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import it.unisa.dia.gas.plaf.jpbc.pairing.a1.TypeA1CurveGenerator;
import it.unisa.dia.gas.plaf.jpbc.util.ElementUtils;


public class DAC_CSS {
	
	class MasterSecretKey{
		public Element a,b,alpha_1,alpha_2;
		public Element[] t_l;
		public Element[] pi_l;
		public Element[] omega_k;
		public MasterSecretKey(Field Zr, int[] Omiga, int k_max) {
			this.a=Zr.newRandomElement().getImmutable();
			this.b=Zr.newRandomElement().getImmutable();
			this.alpha_1=Zr.newRandomElement().getImmutable();
			this.alpha_2=Zr.newRandomElement().getImmutable();
			this.t_l=new Element[Omiga.length];
			this.pi_l=new Element[Omiga.length];
			for(int l=0; l<Omiga.length; l++) {
				this.t_l[l]=Zr.newRandomElement().getImmutable();
				this.pi_l[l]=pi(l);
			}
			this.omega_k =new Element[k_max];
			for(int k=0; k < k_max; k++) {
				this.omega_k[k]= omega(k);
			}
		}
	}
	class MasterPublicKey{
		public Element g,g_alpha_1,g_alpha_2;
		public Element egg_a_n;
		public Element egg_b_Wmax;
		public Element[] g_a_j;
		public Element[] g_b_w;
		public Element[] T_l;
		public Element[] g_pi_l;
		public Element[] g_omega_k;

		public MasterPublicKey(Field Zr, Element g, MasterSecretKey MSK, int[] J, int[] K) {
			this.g = g.getImmutable();
			this.g_alpha_1=g.powZn(MSK.alpha_1).getImmutable();
			this.g_alpha_2=g.powZn(MSK.alpha_2).getImmutable();

			this.egg_a_n = pairing.pairing(g,g).powZn(MSK.a.powZn(Zr.newElement(n+1))).getImmutable();
			this.egg_b_Wmax = pairing.pairing(g,g).powZn(MSK.b.powZn(Zr.newElement(w_max+1))).getImmutable();

			this.g_a_j=new Element[J.length];
			for(int i=0;i<J.length;i++) {
				this.g_a_j[i]=g.powZn(MSK.a.powZn(Zr.newElement(J[i]))).getImmutable();
			}

			this.g_b_w=new Element[K.length];
			for(int i=0;i<K.length;i++) {
				this.g_b_w[i]=g.powZn(MSK.b.powZn(Zr.newElement(K[i]))).getImmutable();
			}

			this.T_l=new Element[MSK.t_l.length];
			for(int i=0;i<MSK.t_l.length;i++) {
				this.T_l[i]=g.powZn(MSK.t_l[i]).getImmutable();
			}

			this.g_pi_l=new Element[MSK.pi_l.length];
			for(int i=0;i<MSK.pi_l.length;i++) {
				this.g_pi_l[i]=g.powZn(MSK.pi_l[i]).getImmutable();
			}

			this.g_omega_k =new Element[MSK.omega_k.length];
			for(int i = 0; i<MSK.omega_k.length; i++) {
				this.g_omega_k[i]=g.powZn(MSK.omega_k[i]).getImmutable();
			}
		}
	}
	//weight attribute key
	class WeightAttributeKey{
		public ArrayList<ArrayList<Element>> sk_l_w_1;
		public ArrayList<ArrayList<Element>> sk_l_w_2;
		public Element sk_j_3;
		public Element sk_j_4;
	}

	//IBE ciphertext
	class CipherTextIBE{
		public Element C1;
		public Element C2;
		public Element C3;
		public ArrayList<Element> C4;
	}

	//n-ary Tree node
	static class NBinaryTreeNode{
		public int layer;
		public int horizontalPosition;
		public int weightValue;
		public int nodeValue;
		//public Element L;
	}

	class RKIBEToABE{

		public Element rk_1;
		public ArrayList<Element> rk_phi_2;
		public ArrayList<Element[]> rk_phi_eta_3;
		public ArrayList<Element> rk_phi_4;
		public Element rk_5;
		public Element rk_6;
		public Element rk_7;
		public Element[] rk_i_8;
		public Element[] rk_i_9;
		public Element[] rk_i_10;
	}

	//Re-encryption key
	class CipherTextABE{
		public Element C1;
		public Element C2;
		public Element C3;
		public Element C4;
		public Element[] Ci5;
		public Element[] Ci6;
		public Element[] Ci7;
		public Element C8;
	}

	//system user number
	private int n = 10;
	//maximum weight of user attribute
	private int w_max = 128;
	//number of system attributes
	private int attr_num = 10;
	//depth of the n-ary tree
	private int d=8;

	//Maximum columns of MSP matrix
	private int k_max=10;

	// (0 and 1) or (2 and 3 and 4)
	// access policy(M, rou, psi, gamma)
//	private int[][] M = {
//			{1,1,0,0},
//			{0,1,0,0},
//			{1,0,1,1},
//			{0,0,0,1},
//			{0,0,1,0}};
	private int[][] M;

	private Element s; //LSSS secret value, v=[s, v1, v2,...]
	private Element[] lamda; //lamda = Mv
	//rou[i] map to user attribute
	private int[] rou;

	private int[] psi={5, 2, 3, 7, 2}; //weight threshold of rou[i]
	private int[] I = {0, 1}; //row set of satisfied access policy
	// 1 encoding of weight correspond to attribute rou[i]
	private int[] phi={6, 3};
	private int[] gama = {1,1}; //gama*M‘={1，0，0，0}
	//The mapping between a user and an attribute.
	// The row represents the user and the column represents the attribute
	private int[][] R;

	////////////////////////////

	private int[] J;//user*2 set
	private int[] K;//weight*2
	private ArrayList<Integer>[] W_0;
	private ArrayList<Integer>[] W_1;
	private int[] Omiga;//system attributes
	//L sets, representing the weights of different layers
	private Element[] L;

	private int condition_weight;
	//Type A1 curve
	PairingParameters typeA1Params;
	private Pairing pairing;
	private Field G1;
	private Field GT;
	private Field Zr;
	private Element g,g_1,g_3;

	//System master public and private key
	private MasterSecretKey MSK;
	private MasterPublicKey MPK;

	public DAC_CSS(String accessPolicyString) {

		//Initializes the set of users based on the value of n
		this.J=new int[2*this.n-1];
		for(int i=1;i<=this.n;i++) {
			this.J[i-1]=i;
		}
		for(int i=this.n+2;i<=2*this.n;i++) {
			this.J[i-2]=i;
		}
		//Initializes the weight set based on the value of w_max
		this.K=new int[2*this.w_max-1];
		for(int i=1;i<=this.w_max;i++) {
			this.K[i-1]=i;
		}
		for(int i=this.w_max+2;i<=2*this.w_max;i++) {
			this.K[i-2]=i;
		}
		//Initializes the set of system properties based on the value of V
		this.Omiga=new int[attr_num];
		for(int i=0; i < this.attr_num; i++) {
			this.Omiga[i]=i;
		}

		//The mapping between a user and an attribute takes a random value of 0 or 1
		// with a row representing the user and a column representing the attribute
		this.R=new int[this.n][this.attr_num];
		this.R[0][0] = 1;
		this.R[0][1] = 1;

		//Initializes the 0-1 encoding set from 0 to 128
		this.W_0=(ArrayList<Integer>[])new ArrayList[129];
		this.W_1=(ArrayList<Integer>[])new ArrayList[129];

		for(int i=0; i<= 128; i++) {
			this.W_0[i]=zeroCoding(this.d,i);
			this.W_1[i]=oneCoding(this.d,i);
		}


		TypeA1CurveGenerator pg = new TypeA1CurveGenerator(3, 256);
		this.typeA1Params = pg.generate();

		this.pairing = PairingFactory.getPairing(typeA1Params);
		this.G1=this.pairing.getG1();
		this.GT=this.pairing.getGT();
		this.Zr=this.pairing.getZr();

		Element gr = this.G1.newRandomElement().getImmutable();
		this.g=ElementUtils.getGenerator(this.pairing, gr.duplicate(), typeA1Params, 0, 3).getImmutable();
		this.g_1=ElementUtils.randomIn(this.pairing, g).getImmutable();
		this.g_3=ElementUtils.getGenerator(this.pairing, gr.duplicate(), typeA1Params, 2, 3).getImmutable();
		this.MSK=new MasterSecretKey(this.Zr,this.Omiga,this.k_max);
		this.MPK=new MasterPublicKey(this.Zr,this.g,this.MSK,this.J,this.K);

		//The set of weights L for each layer
		this.L=new Element[this.d];
		for(int i=1;i<=this.d;i++) {
			this.L[i-1]=this.g_1.powZn(this.Zr.newElement((int)Math.pow(2,this.d-i))).getImmutable();
		}

		AccessControlEngine accessControlEngine = LSSSLW10Engine.getInstance();
		try{
			int[][] accessPolicy = ParserUtils.GenerateAccessPolicy(accessPolicyString);
			String[] rhos = ParserUtils.GenerateRhos(accessPolicyString);
			AccessControlParameter accessControlParameter = accessControlEngine.generateAccessControl(accessPolicy, rhos);

			LSSSPolicyParameter lsssPolicyParameter = (LSSSPolicyParameter)accessControlParameter;
			this.M = lsssPolicyParameter.getLSSSMatrix();
			String[] strRou = lsssPolicyParameter.getRhos();
			this.rou = new int[strRou.length];
			for(int i = 0; i < strRou.length; i++)
			{
				this.rou[i] = Integer.parseInt(strRou[i]);
			}


			//choose a secret value randomly
			this.s = pairing.getZr().newRandomElement().getImmutable();
			Map<String, Element> lambdaElementsMap = accessControlEngine.secretSharing(pairing, this.s, accessControlParameter);

			this.lamda = new Element[this.M.length];
			for(int i = 0; i < this.M.length; i++)
				this.lamda[i] = lambdaElementsMap.get(strRou[i]);

		}catch (PolicySyntaxException e){
			System.out.println("PolicySyntaxException");
		}

	}

	//Generate the IBE user private key
	public Element KeyGenIBE(MasterSecretKey MSK,int ID) {
		return H1(String.valueOf(ID)).powZn(MSK.alpha_2).getImmutable();
	}

	//Generate the weight attribute key
	public WeightAttributeKey KeyGenABE(MasterSecretKey MSK, MasterPublicKey MPK, int j, int[] A_j, int[] V_j) {


		WeightAttributeKey wak=new WeightAttributeKey();

		ArrayList<ArrayList<Element>> sk_l_w_1 = new ArrayList<ArrayList<Element>>();
		ArrayList<ArrayList<Element>> sk_l_w_2 = new ArrayList<ArrayList<Element>>();

		Element sk_j_3;
		Element sk_j_4;

		Element sigma_j = this.Zr.newRandomElement().getImmutable();

		int index_J = search(J, j);
		//Iterate over each attribute
		for(int i = 0; i < A_j.length; i++) {
			int l=A_j[i];
			int index_Omiga = search(Omiga, l);
			int v_j_l=V_j[i];

			///////////////////
			ArrayList<Integer> W_1_v_j_l=this.W_1[v_j_l];
			ArrayList<Element> array_sk_l_w_1 = new ArrayList<Element>();
			ArrayList<Element> array_sk_l_w_2 = new ArrayList<Element>();

//			System.out.println(W_1_v_j_l);
			if (!W_1_v_j_l.isEmpty()) {
				Iterator<Integer> it=W_1_v_j_l.iterator();

				while(it.hasNext()) {
					Element s_l_w=this.Zr.newRandomElement().getImmutable();
					Element Y_l_w=ElementUtils.randomIn(pairing, g_3).getImmutable();
					Element Q_l_w=ElementUtils.randomIn(pairing, g_3).getImmutable();

					int W_1_value=it.next();
//					System.out.println(W_1_value);
					int index_K = search(K, W_1_value);
					//System.out.println(index_K);

					array_sk_l_w_1.add((((MPK.g_a_j[index_J]).powZn((MSK.t_l[index_Omiga]).div(MSK.alpha_1)))
							.mul((MPK.g_b_w[index_K]).powZn((MSK.pi_l[index_Omiga]).div(MSK.alpha_1)))
							.mul(g.powZn(s_l_w.div(MSK.alpha_1)))
							.mul(Y_l_w)).getImmutable());

					array_sk_l_w_2.add((g.powZn(s_l_w).mul(Q_l_w)).getImmutable());
				}
				sk_l_w_1.add(array_sk_l_w_1);
				sk_l_w_2.add(array_sk_l_w_2);
			}
		}

		sk_j_3=MPK.g_a_j[index_J].powZn(MSK.omega_k[0].div(MSK.alpha_1))
				.mul(g.powZn(sigma_j.div(MSK.alpha_1))).getImmutable();
		sk_j_4=g.powZn(sigma_j).getImmutable();
		wak.sk_l_w_1=sk_l_w_1;
		wak.sk_l_w_2=sk_l_w_2;
		wak.sk_j_3=sk_j_3;
		wak.sk_j_4=sk_j_4;
		return wak;
	}

	//Computes IBE encrypted ciphertext
	public CipherTextIBE Encrypt(char m,MasterPublicKey MPK, int ID, int[] D_1, int[] F_1) throws Exception {
		CipherTextIBE CTIBE=new CipherTextIBE();

		Element r1=this.Zr.newRandomElement().getImmutable();

		Element C1=this.pairing.pairing(H1(String.valueOf(ID)).powZn(r1), MPK.g_alpha_2).mul(m);
		Element C2=this.g.powZn(r1);
		Element C3=this.g_1.powZn(r1);
		ArrayList<Element> C4=new ArrayList<Element>();

		for(int i=0;i<D_1.length;i++) {
			int tao=D_1[i];
			Element product=H5(String.valueOf(tao)).powZn(r1);
			product = product.mul(this.g.powZn(r1.mul(this.Zr.newElement(F_1[i]))));
			C4.add(product.getImmutable());
			this.condition_weight += F_1[i];
		}
		CTIBE.C1=C1.getImmutable();
		CTIBE.C2=C2.getImmutable();
		CTIBE.C3=C3.getImmutable();
		CTIBE.C4=C4;

		return CTIBE;
	}

	//Calculate the re-encryption key
	public RKIBEToABE ConReKeyGen(Element SK_ID, int[] D_2, ArrayList<NBinaryTreeNode> Tc){
		RKIBEToABE rk=new RKIBEToABE();

		Element s_1=this.Zr.newRandomElement().getImmutable();
		Element r_prime=this.GT.newRandomElement().getImmutable();
//		Element r_prime=this.GT.newElement(2).getImmutable();


		rk.rk_1=this.g_1.powZn(s_1).mul(SK_ID).mul(this.H4(r_prime)).getImmutable();

		Iterator<NBinaryTreeNode> it= Tc.iterator();

		ArrayList<Element> al_rk_phi_2=new ArrayList<Element>();
		ArrayList<Element[]> al_rk_phi_eta_3=new ArrayList<Element[]>();
		ArrayList<Element> al_rk_phi_4=new ArrayList<Element>();
		while(it.hasNext()) {
			Element s_phi=this.Zr.newRandomElement().getImmutable();
			NBinaryTreeNode node=it.next();

			//计算al_rk_phi_2
			Element rk_phi_2=this.G1.newOneElement();
			for(int i=1;i<=D_2.length;i++) {
				int tao=D_2[i-1];
				rk_phi_2=rk_phi_2.mul(H5(BigInteger.valueOf(tao).toString()));
			}
			rk_phi_2 = rk_phi_2.mul(this.g.powZn(this.Zr.newElement(this.condition_weight)));
			rk_phi_2=rk_phi_2.powZn(s_phi);
			rk_phi_2=rk_phi_2.mul(this.g.powZn(s_1)).getImmutable();
			al_rk_phi_2.add(rk_phi_2);
			//计算al_rk_phi_eta_3
			Element[] rk_phi_eta_3=new Element[this.d-node.layer];
			for(int i=node.layer+1;i<=this.d;i++) {
				rk_phi_eta_3[i-(node.layer+1)]=this.L[i-1].powZn(s_phi);
			}
			al_rk_phi_eta_3.add(rk_phi_eta_3);

			//计算al_rk_phi_4
			Element rk_phi_4=this.g_1.powZn(s_phi).getImmutable();
			al_rk_phi_4.add(rk_phi_4);
		}
		rk.rk_phi_2=al_rk_phi_2;
		rk.rk_phi_eta_3=al_rk_phi_eta_3;
		rk.rk_phi_4=al_rk_phi_4;



//		Element r_3 = this.Zr.newElement(s).getImmutable();
		rk.rk_5=this.pairing.pairing(this.g, this.g)
				.powZn(this.MSK.a.powZn(this.Zr.newElement(this.n+1)).mul(this.s))
				.mul(this.pairing.pairing(this.g, this.g)
				.powZn(this.MSK.b.powZn(this.Zr.newElement(this.w_max+1)).mul(this.s)))
				.mul(r_prime).getImmutable();
		rk.rk_6=this.g.powZn(this.MSK.alpha_1.mul(this.s)).getImmutable();
		rk.rk_7=this.g.powZn(this.s).getImmutable();

		int n_1 = this.I.length;
		int n_2 = this.M[0].length;
		rk.rk_i_8=new Element[n_1];
		rk.rk_i_9=new Element[n_1];
		rk.rk_i_10=new Element[n_1];


		for(int i=0; i<n_1; i++) {
			//rk_i_8
			rk.rk_i_8[i]=this.g.powZn(this.Zr.newElement(lamda[i])).getImmutable();
			//rk_i_9
			rk.rk_i_9[i]=this.g.powZn(this.MSK.t_l[rou[i]].mul(this.s));
			for(int k=0;k<n_2;k++) {
				rk.rk_i_9[i]=rk.rk_i_9[i]
						       .mul(this.g.powZn(this.MSK.omega_k[k]
						    		            .mul(this.s)
						    		            .mul(this.Zr.newElement(M[i][k]))));
			}
			for(int y=1;y<=this.n;y++) {
				if(this.R[y-1][rou[i]]==1) {
					rk.rk_i_9[i]=rk.rk_i_9[i]
							.mul(this.g.powZn(this.MSK.a.powZn(this.Zr.newElement(this.n+1-y)).mul(this.Zr.newElement(lamda[i]))));
				}
			}
			rk.rk_i_9[i] = rk.rk_i_9[i].getImmutable();
			//rk_i_10
			rk.rk_i_10[i]=this.g.powZn(this.MSK.pi_l[rou[i]].mul(this.s));

			ArrayList<Integer> W_0_psi_i=this.W_0[psi[i]];
			Iterator<Integer> it_W_0= W_0_psi_i.iterator();
			while(it_W_0.hasNext()) {
				int x=it_W_0.next();
				rk.rk_i_10[i]=rk.rk_i_10[i]
						        .mul(this.g.powZn(this.MSK.b.powZn(this.Zr.newElement(this.w_max+1-x))
						        		          .mul(Zr.newElement(lamda[i]))));
			}
			rk.rk_i_10[i] = rk.rk_i_10[i].getImmutable();
		}
		return rk;
	}

	public CipherTextABE ReEnc(RKIBEToABE rk, CipherTextIBE ct_ibe, int[] D_1, int[] F_1, int[] D_2, ArrayList<NBinaryTreeNode> Tc) throws Exception {
		CipherTextABE ct_abe=new CipherTextABE();

		for(int i=0;i<D_1.length;i++) {
			if(search(D_2, D_1[i])<0) {
				return null;
			}
		}

		Element rk_3=rk.rk_phi_2.get(0);

		Element C_tao_4=this.G1.newOneElement();
		for(int i=0;i<D_2.length;i++) {
			int index_D_1=search(D_1,D_2[i]);
			C_tao_4=C_tao_4.mul(ct_ibe.C4.get(index_D_1));
		}

		ct_abe.C1=ct_ibe.C1.mul(this.pairing.pairing(rk_3, ct_ibe.C3))
				.div(this.pairing.pairing(rk.rk_1,ct_ibe.C2)
						.mul(this.pairing.pairing(rk.rk_phi_4.get(0), C_tao_4))).getImmutable();

		ct_abe.C2=rk.rk_5;
		ct_abe.C3=rk.rk_6;
		ct_abe.C4=rk.rk_7;
		ct_abe.Ci5=rk.rk_i_8;
		ct_abe.Ci6=rk.rk_i_9;
		ct_abe.Ci7=rk.rk_i_10;
		ct_abe.C8=ct_ibe.C2;
		return ct_abe;
	}

	//Decrypt the IBE ciphertext
	public char DecIBE(CipherTextIBE ct_ibe,Element sk) {
		return (char)ct_ibe.C1.duplicate().div(this.pairing.pairing(sk.duplicate(), ct_ibe.C2.duplicate())).toBigInteger().byteValue();
	}

	//Decrypt ABE ciphertext
	public char DecABE(CipherTextABE ct_abe, WeightAttributeKey sk_j, int j, int[] A_j, int[] V_j) {

		Element e1,e2,e3,e3_1,e4,e5;
		e1=this.G1.newOneElement();
		e2=this.G1.newOneElement();
		e3=this.GT.newOneElement();

		e4=this.G1.newOneElement();
		e5=this.GT.newOneElement();

		int A_j_index = -1;
//		for(int i=0; i < this.I.length; i++)
		for(int i : I)
		{
			int rou_i = rou[i];
			int phi_i = phi[i];

			e3_1=this.G1.newOneElement();
			A_j_index= search(A_j, rou_i);
//			if(A_j_index==-1)
//				continue;

			int phi_i_pos=-1;

			ArrayList<Integer> weight1Coding= oneCoding(this.d, V_j[A_j_index]);
			for(int k=0;k<weight1Coding.size();k++) {
				if(phi_i==weight1Coding.get(k)) {
					phi_i_pos=k;
					break;
				}
			}
			e1=e1.mul((sk_j.sk_l_w_1.get(rou_i).get(phi_i_pos)).powZn(Zr.newElement(gama[i])));

			e2=e2.mul(ct_abe.Ci6[i].powZn(Zr.newElement(gama[i])));

			//////////////////////////////

			for(int y=1;y<=this.n;y++) {
				if(this.R[y-1][rou_i]==1 && y!=j) {
					e3_1=e3_1
							.mul(this.g.powZn(this.MSK.a.powZn(this.Zr.newElement(this.n+1-y+j))));
				}
			}

			ArrayList<Integer> W_0_psi_i=this.W_0[psi[i]];
			Iterator<Integer> it_W_0= W_0_psi_i.iterator();
			while(it_W_0.hasNext()) {
				int x=it_W_0.next();
				if(x==phi_i) {
					continue;
				}
				e3_1=e3_1.mul(this.g.powZn(this.MSK.b.powZn(this.Zr.newElement(this.w_max+1-x+phi_i))));
			}
			///////////////////////////

			e3=e3.mul(this.pairing.pairing(e3_1, ct_abe.Ci5[i].powZn(Zr.newElement(gama[i]))));

			e4=e4.mul(sk_j.sk_l_w_2.get(rou_i).get(phi_i_pos).powZn(Zr.newElement(gama[i])));

			e5=e5.mul(this.pairing.pairing(this.g.powZn(this.MSK.b.powZn(this.Zr.newElement(phi_i))), ct_abe.Ci7[i].powZn(Zr.newElement(gama[i]))));

		}

		e1 = e1.mul(sk_j.sk_j_3).getImmutable();
		Element r_prime = ct_abe.C2.mul(this.pairing.pairing(e1, ct_abe.C3)).mul(e3)
				.div(pairing.pairing(e2, MPK.g_a_j[j-1]))
				.div(pairing.pairing(ct_abe.C4, e4.mul(sk_j.sk_j_4)))
				.div(e5);

		char rslt = (char)ct_abe.C1.mul(pairing.pairing(this.H4(r_prime), ct_abe.C8)).toBigInteger().intValue();

		return rslt;
	}


    public Element pi(int l){
        return this.Zr.newElement(l).getImmutable();
    }

    public Element omega(int k){
		return this.Zr.newElement(k).getImmutable();
    }

	private byte[] hash(byte[] message) {
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			//Impossible to get this exception
			e.printStackTrace();
		}
		assert (md != null);
		md.update(message);
		return md.digest();
	}

	public Element H1(String str){

		byte[] shaResult = hash(str.getBytes());
		Element a = this.pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
		return this.g.powZn(a).getImmutable();
	}

	public Element H4(Element e){
//    	String str=e.toString();
		String str=e.toBigInteger().toString();
		return H1(str);
	}


	public Element H5(String str){
		byte[] shaResult = hash(str.getBytes());
		Element a = this.pairing.getZr().newElement().setFromHash(shaResult, 0, shaResult.length).getImmutable();
		return this.g.powZn(a).getImmutable();
	}

	public static void main(String[] args) throws Exception {


		//The attribute set and corresponding weight set of user j
		int[] A_j = {0, 1};
		int[] V_j = {3, 6};

		String accessPolicyString = "(0 and 1) or (2 and 3 and 4)";

//		ArrayList<Integer> W_0, W_1;
//		W_0 = zeroCoding(8, 127);
//		W_1 = oneCoding(8, 128);
//		System.out.println(W_0);
//		System.out.println(W_1);

		//user id
		int user_id = 1;

		int[] D_1 = {1,2};
		int[] F_1 = {5,4};

		int[] D_2 = {1,2};


		//1：Initializes the system public parameters and (MSK, MPK)
		DAC_CSS dac_css = new DAC_CSS(accessPolicyString);

		//2:Generate the user key
		Element sk=dac_css.KeyGenIBE(dac_css.MSK,user_id);

		//3：Generate the weight attribute key
		WeightAttributeKey wak = dac_css.KeyGenABE(dac_css.MSK, dac_css.MPK, user_id, A_j, V_j);

		//4：Computes IBE encrypted ciphertext
		CipherTextIBE ct_ibe=dac_css.Encrypt('A', dac_css.MPK, user_id, D_1, F_1);

		//5：Generate the minimum coverage set
		ArrayList<NBinaryTreeNode> Tc=dac_css.getCoverSet(3,3,4,10);
//		for(NBinaryTreeNode item : Tc) {
//			System.out.println(item.layer+":"+item.horizontalPosition);
//		}

		//6：Calculate the reencryption key
		RKIBEToABE rk=dac_css.ConReKeyGen(sk, D_2, Tc);

		//7：Calculate the re-encrypted ciphertext
		CipherTextABE ct_abe=dac_css.ReEnc(rk, ct_ibe, D_1, F_1, D_2, Tc);

		//8：Decrypt the IBE ciphertext
		System.out.println(dac_css.DecIBE(ct_ibe, sk));

		//9：Decrypt ABE ciphertext
		System.out.println(dac_css.DecABE(ct_abe, wak, user_id, A_j, V_j));
	}


	//0 encoding
	public static ArrayList<Integer> zeroCoding(int n, int w){
		ArrayList<Integer> al=new ArrayList();

		int[] w01=new int[n];

		for(int i=n-1;i>=0;i--) {
			w01[i]=w%2;
			w=w/2;
		}
		int sum=0;
		int tempSum=0;
		for(int i=0;i<n;i++) {
			int posValue=w01[i];
			if(posValue==0) {
				tempSum=tempSum+(int)Math.pow(2, n-i-1);
				//System.out.println(tempSum);
				al.add(tempSum);
			}
			sum=sum+posValue*(int)Math.pow(2, n-i-1);
			tempSum=sum;
		}
		return al;
	}

	//1 encoding
	public static ArrayList<Integer> oneCoding(int n, int w){
		ArrayList<Integer> al=new ArrayList();

		int[] w01=new int[n];

		for(int i=n-1;i>=0;i--) {
			w01[i]=w%2;
			w=w/2;
		}
		int sum=0;
		for(int i=0;i<n;i++) {
			int posValue=w01[i];
			sum=sum+posValue*(int)Math.pow(2, n-i-1);
			if(posValue==1) {
				//System.out.println(sum);
				al.add(sum);
			}
		}
		return al;
	}

	public int getCodingValue(int n, String str) {
		int value=0;
		for(int i=0;i<str.length();i++) {
			value+=(str.charAt(i)-'0')*((int) Math.pow(2, n-i-1));
		}
		return value;
	}
	//return -1 if not find
	public static int search(int[] dest, int value) {
		int pos=-1;
		for(int i=0;i<dest.length;i++) {
			if(dest[i]==value) {
				pos=i;
				break;
			}
		}
		return pos;
	}

	public static ArrayList<NBinaryTreeNode> getNBinaryTreePath(int n, int depth, int leafNodeValue) throws Exception{
		if (n <= 1) {
			throw new Exception("n must greater than 1");
		}

		ArrayList<NBinaryTreeNode> nodesArray=new ArrayList<NBinaryTreeNode>();

		Stack<Integer> stack=new Stack<Integer>();
		int length=0;
		while (leafNodeValue != 0) {
			length++;
			stack.push(leafNodeValue%n);
			leafNodeValue /= n;
		}

		if (length > depth) {
			throw new Exception("The weight exceeds the maximum depth range");
		}

		//将上层节点填充0，保持树的深度为depth
		for(int i=1;i<=depth-length;i++) {
			NBinaryTreeNode node=new NBinaryTreeNode();
			node.horizontalPosition=0;
			node.layer=i;
			node.nodeValue=0;
			node.weightValue=(int)Math.round(Math.pow(n, depth-i));
			nodesArray.add(node);
		}

		int layer=depth-length;
		int weightValue=0;
		int uperHorizontalPosition=0;
		while(!stack.isEmpty()) {
			NBinaryTreeNode node=new NBinaryTreeNode();
			layer++;
			//weightValue+=Math.round(Math.pow(n, length-layer));
			weightValue=(int)Math.round(Math.pow(n, depth-layer));

			node.layer=layer;
			node.weightValue=weightValue;
			node.nodeValue=stack.pop().intValue();
			node.horizontalPosition=uperHorizontalPosition*n+node.nodeValue;
			//node.L=this.g_1.powZn(this.Zr.newElement(node.weightValue)).getImmutable();
			uperHorizontalPosition=node.horizontalPosition;
			nodesArray.add(node);
		}
		return nodesArray;
	}


	public static boolean getNBinaryTreeLowerBoundLeafNumOnDepth(int n, int nodeValue, int depth, int lowerBound, Stack<Integer> stack){
		boolean flag=false;

		if (nodeValue>n-1 || depth<=0) {
			return false;
		}

		if(lowerBound<=n-1 && depth==1) {
			stack.push(lowerBound);
			return true;
		}

		flag=getNBinaryTreeLowerBoundLeafNumOnDepth(n,0,depth-1,(int)(lowerBound-Math.pow(2,(depth-1))*nodeValue),stack);
		if(flag) {
			stack.push(nodeValue);
		}else {
			flag=getNBinaryTreeLowerBoundLeafNumOnDepth(n,nodeValue+1,depth,lowerBound,stack);
		}
		return flag;
	}

	public static boolean getNBinaryTreeUpperBoundLeafNumOnDepth(int n, int nodeValue, int depth, int upperBound, Stack<Integer> stack){

		boolean flag=false;

		if (nodeValue<0 || depth<=0) {
			return false;
		}

		if(upperBound<=n-1 && depth==1) {
			stack.push(upperBound);
			return true;
		}

		if(upperBound<Math.pow(2,(depth-1))*nodeValue) {
			flag=getNBinaryTreeUpperBoundLeafNumOnDepth(n,nodeValue-1,depth,upperBound,stack);
		}else{
			flag=getNBinaryTreeUpperBoundLeafNumOnDepth(n,n-1,depth-1,(int)(upperBound-Math.pow(2,(depth-1))*nodeValue),stack);
			if(flag) {
				stack.push(nodeValue);
			}
		}
		return flag;
	}

	public static int getNBinaryLowerLeafNodePositionFromTotalValue(int n, int depth, int totalValue) {
		int lowerBoundNodePos=0;
		int lowerBoundNodeLayer=0;

		Stack<Integer> stackLowerBound=new Stack<Integer>();
		if(getNBinaryTreeLowerBoundLeafNumOnDepth(n,0,depth,totalValue,stackLowerBound)) {
			while(!stackLowerBound.isEmpty()) {
				int i=stackLowerBound.pop();
				lowerBoundNodeLayer++;
				lowerBoundNodePos+=Math.pow(n, depth-lowerBoundNodeLayer)*i;
			}
		}
		return lowerBoundNodePos;
	}

	public static int getNBinaryUpperLeafNodePositionFromTotalValue(int n, int depth, int totalValue) {
		int upperBoundNodePos=0;
		int upperBoundNodeLayer=0;
		Stack<Integer> stackUppererBound=new Stack<Integer>();
		if(getNBinaryTreeUpperBoundLeafNumOnDepth(n,n-1,depth,totalValue,stackUppererBound)) {
			while(!stackUppererBound.isEmpty()) {
				int i=stackUppererBound.pop();
				upperBoundNodeLayer++;
				upperBoundNodePos+=Math.pow(n, depth-upperBoundNodeLayer)*i;
			}
		}
		return upperBoundNodePos;
	}

	public static int getNBinaryTreeNodeTotalValueFromPosition(int n, int depth, int layer, int pos) {
		int totalValue=0;
		for(int i=layer;i>0;i--) {
			totalValue+=(int)Math.pow(2, depth-i)*(pos%n);
			pos=pos/n;
		}
		return totalValue;
	}

	public static NBinaryTreeNode getNBinaryTreeNodeFromPosition(int n, int depth, int layer, int pos) {
		NBinaryTreeNode node = new NBinaryTreeNode();
		node.layer=layer;
		node.horizontalPosition=pos;
		node.nodeValue=pos % n;
		node.weightValue=(int)Math.round(Math.pow(2, depth-layer));
		//node.L=this.g_1.powZn(this.Zr.newElement(node.weightValue)).getImmutable();
		return node;
	}

	public static NBinaryTreeNode getNBinaryTreeUpNodeFromPosition(int n, int depth, int layer, int pos) {
		NBinaryTreeNode node = new NBinaryTreeNode();
		node.layer=layer-1;
		node.horizontalPosition=pos/n;
		node.nodeValue=node.horizontalPosition % n;
		node.weightValue=(int)Math.round(Math.pow(2, depth-node.layer));
		//node.L=this.g_1.powZn(this.Zr.newElement(node.weightValue)).getImmutable();
		return node;
	}

	public static ArrayList<NBinaryTreeNode> getCoverSetFromBoundPos(int n ,int depth, int currentLayer, int lowerBoundNodePos, int upperBoundNodePos) throws Exception{
		ArrayList<NBinaryTreeNode> nBinaryTreeNodeList =new ArrayList<NBinaryTreeNode>();
		if (n <= 1) {
			throw new Exception("n must greater than 1");
		}
		if (depth <= 0) {
			throw new Exception("depth must greater than 0");
		}

		if(currentLayer<=0) {
			return nBinaryTreeNodeList;
		}

		if(currentLayer==1) {
			for(int i=lowerBoundNodePos;i<=upperBoundNodePos;i++) {
				NBinaryTreeNode node=getNBinaryTreeNodeFromPosition(n,depth,currentLayer,i);
				nBinaryTreeNodeList.add(node);
			}
			return nBinaryTreeNodeList;
		}

		if(lowerBoundNodePos==upperBoundNodePos) {
			NBinaryTreeNode node=getNBinaryTreeNodeFromPosition(n,depth,currentLayer,lowerBoundNodePos);
			nBinaryTreeNodeList.add(node);
			return nBinaryTreeNodeList;
		}

		if(lowerBoundNodePos>upperBoundNodePos) {
			return nBinaryTreeNodeList;
		}

		int upLowerBoundNodePos=lowerBoundNodePos/n;
		int upUpperBoundNodePos=upperBoundNodePos/n;

		int tempUpLowerBoundNodePos=0;
		int tempUpUpperBoundNodePos=0;

		if(upLowerBoundNodePos==upUpperBoundNodePos) {
			if(upperBoundNodePos-lowerBoundNodePos==n-1) {
				tempUpLowerBoundNodePos=upLowerBoundNodePos;
				tempUpUpperBoundNodePos=upUpperBoundNodePos;
				ArrayList<NBinaryTreeNode> a= getCoverSetFromBoundPos(n ,depth, currentLayer-1, tempUpLowerBoundNodePos, tempUpUpperBoundNodePos);
				if(a.size()>0) {
					nBinaryTreeNodeList.addAll(a);
				}
			}else {
				for(int i=lowerBoundNodePos;i<=upperBoundNodePos;i++) {
					NBinaryTreeNode node=getNBinaryTreeNodeFromPosition(n,depth,currentLayer,i);
					nBinaryTreeNodeList.add(node);
				}
			}
		}else {
			if (lowerBoundNodePos%n==0) {
				tempUpUpperBoundNodePos=upLowerBoundNodePos;
			}else {
				for(int i=lowerBoundNodePos;i<=((lowerBoundNodePos/n)*n+n-1);i++) {
					NBinaryTreeNode node=getNBinaryTreeNodeFromPosition(n,depth,currentLayer,i);
					nBinaryTreeNodeList.add(node);
				}
				tempUpLowerBoundNodePos=upLowerBoundNodePos+1;
			}
			if(upperBoundNodePos%n==n-1) {
				tempUpUpperBoundNodePos=upUpperBoundNodePos;
			}else {
				tempUpUpperBoundNodePos=upUpperBoundNodePos-1;
			}
			ArrayList<NBinaryTreeNode> a= getCoverSetFromBoundPos(n ,depth, currentLayer-1, tempUpLowerBoundNodePos, tempUpUpperBoundNodePos);
			if(a.size()>0) {
				nBinaryTreeNodeList.addAll(a);
			}
			if(upperBoundNodePos%n != n-1) {
				for(int i=((upperBoundNodePos/n)*n);i<=upperBoundNodePos;i++) {
					NBinaryTreeNode node=getNBinaryTreeNodeFromPosition(n,depth,currentLayer,i);
					nBinaryTreeNodeList.add(node);
				}
			}
		}
		return nBinaryTreeNodeList;
	}

	//Gets the weight minimum coverage set
	public ArrayList<NBinaryTreeNode> getCoverSet(int n, int depth, int lowerBound, int upperBound) throws Exception {
		if (this.condition_weight < lowerBound || this.condition_weight > upperBound) {
			throw new Exception("conditional weight-sum not satisfied");
		}
		int lowerBoundPos=getNBinaryLowerLeafNodePositionFromTotalValue(n,depth,lowerBound);
		int upperBoundPos=getNBinaryUpperLeafNodePositionFromTotalValue(n,depth,upperBound);
//		System.out.println("lowerBoundPos:"+lowerBoundPos);
//		System.out.println("upperBoundPos:"+upperBoundPos);
		return getCoverSetFromBoundPos(n,depth,depth,lowerBoundPos,upperBoundPos);
	}
}