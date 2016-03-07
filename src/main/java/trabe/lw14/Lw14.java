package trabe.lw14;

import it.unisa.dia.gas.jpbc.ElementPowPreProcessing;
import it.unisa.dia.gas.jpbc.PairingPreProcessing;
import trabe.*;
import trabe.lw14.policy.LsssMatrix;
import trabe.lw14.policy.Lw14PolicyAbstractNode;
import trabe.lw14.policy.Lw14TreePreprocessing;
import trabe.matrixElimination.ElementField;
import trabe.matrixElimination.Matrix;
import trabe.policy.PolicyParsing;
import trabe.policyparser.*;

import java.util.*;

import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;

/**
 * <p>Implementation of a CP-ABE scheme with traitor tracing from the paper
 * "Practical Attribute Based Encryption: Traitor Tracing, Revocation, and
 * Large Universe" by Liu and Wong
 * (<a href="https://eprint.iacr.org/2014/616">eprint.iacr.org</a>).</p>
 *
 * <p>The scheme has a limitation due to the traceability feature that the
 * maximum number of users must be set during system setup.</p>
 *
 * <p>It currently supports:</p>
 * <ul>
 *     <li>Boolean formula</li>
 *     <li>Theshold formula</li>
 *     <li>Numerical attributes</li>
 *     <li>Geospatial attributes</li>
 * </ul>
 *
 * <p>It doesn't support:</p>
 * <ul>
 *     <li>Numerical attributes ranges</li>
 * </ul>
 */
public class Lw14 {

    private static final String ATTRIBUTE_NOT_FOUND     = "an attribute was not found in the source private key";
    private static final String ATTRIBUTES_DONT_SATISFY = "decryption failed: attributes in key do not satisfy policy";

    /**
     * Generate a secret master key. The public master key is part of the secret master key.
     * @param users    The number of users that is supported by the system.
     *                 It will be automatically increased to the next power of 2.
     * @return secret master key
     */
    public static AbeSecretMasterKey setup(int users) {
        if (users < 2) {
            throw new IllegalArgumentException("The system must accommodate at least two users.");
        }
        int usersSqrt = (int)(Math.ceil(Math.sqrt(users+1)));

        AbePublicKey pub = new AbePublicKey(AbeSettings.curveParams);
        Pairing p = pub.getPairing();

        Element g = p.getG1().newRandomElement();
        Element h = p.getG1().newRandomElement();
        Element f = p.getG1().newRandomElement();
        Element G = p.getG1().newRandomElement();
        Element H = p.getG1().newRandomElement();

        Element[] f_j = new Element[usersSqrt];
        Element[] alpha_i = new Element[usersSqrt];
        Element[] r_i = new Element[usersSqrt];
        Element[] c_j = new Element[usersSqrt];

        Element[] E_i = new Element[usersSqrt];
        Element[] G_i = new Element[usersSqrt];
        Element[] Z_i = new Element[usersSqrt];
        Element[] H_j = new Element[usersSqrt];

        boolean usePreprocessing = AbeSettings.PREPROCESSING && usersSqrt >= AbeSettings.PREPROCESSING_THRESHOLD/3.0;

        ElementPowPreProcessing eppp_g = null;
        if (usePreprocessing) {
            eppp_g = g.duplicate().getElementPowPreProcessing();
        }
        for(int i = 0; i < usersSqrt; i++){
            f_j[i] = p.getG1().newRandomElement();
            alpha_i[i] = p.getZr().newRandomElement();
            r_i[i] = p.getZr().newRandomElement();
            Element z = p.getZr().newRandomElement();
            c_j[i] = p.getZr().newRandomElement();

            E_i[i] = p.pairing(g, g).powZn(alpha_i[i]);

            if (usePreprocessing) {
                G_i[i] = eppp_g.powZn(r_i[i]);
                Z_i[i] = eppp_g.powZn(z);
                H_j[i] = eppp_g.powZn(c_j[i]);
            } else {
                G_i[i] = g.duplicate().powZn(r_i[i]);
                Z_i[i] = g.duplicate().powZn(z);
                H_j[i] = g.duplicate().powZn(c_j[i]);
            }
        }

        pub.setElements(g, h, f, f_j, G, H, E_i, G_i, Z_i, H_j);
        return new AbeSecretMasterKey(pub, alpha_i, r_i, c_j);
    }

    /**
     * Produces the secret element that ties all user attribute secret components and user secret components together.
     * @param msk    Secret master key
     * @return Secret user element
     */
    public static Pair<Element, Integer> generateUserSecretComponent(AbeSecretMasterKey msk) {
        if (msk == null) {
            throw new IllegalArgumentException("No secret master key passed");
        }
        // advance current position of the master key
        Pair<Element, Integer> p = new Pair<Element, Integer>(msk.getPublicKey().getPairing().getZr().newRandomElement(), msk.counter);

        msk.counter++;
        return p;
    }

    /**
     * Generate a private key with the given set of attributes (internal representation of attributes).
     * @param msk               Secret master key
     * @param sigmaAndPosition  Secret user element to tie all user attributes together and the position of the user in the array
     * @param attributes        Attributes for user
     * @return User private key
     */
    public static AbePrivateKey keygen(AbeSecretMasterKey msk, Pair<Element, Integer> sigmaAndPosition, String[] attributes) {
        AbePublicKey pub = msk.getPublicKey();

        Element sigma = sigmaAndPosition.getFirst();
        AbeUserIndex position = new AbeUserIndex(msk.getSqrtUsers(), sigmaAndPosition.getSecond());

        int m = msk.getSqrtUsers();
        if (position.counter == msk.getMaxUsers()) {
            // last place is reserved so that tracing works
            return null;
        }

        Element k1_ij = pub.g.duplicate().powZn(msk.alpha_i[position.i])
                .mul(pub.G_i[position.i].duplicate().powZn(msk.c_j[position.j]))
                .mul(pub.f.duplicate().mul(pub.f_j[position.j]).powZn(sigma));
        Element k2_ij = pub.g.duplicate().powZn(sigma);
        Element k3_ij = pub.Z_i[position.i].duplicate().powZn(sigma);
        Element[] k_ijj = new Element[m];
        for(int j = 0; j < m; j++){
            if (j != position.j){
                k_ijj[j] = pub.f_j[j].duplicate().powZn(sigma);
            } else {
                // this element should never be used
                k_ijj[j] = null;
            }
        }

        return new AbePrivateKey(position, k1_ij, k2_ij, k3_ij, k_ijj,
                generateAdditionalAttributes(msk, sigma, attributes), pub);
    }

    /**
     * Generates attributes for a given value sigma. The private key needs to
     * have been generated with the same master key as msk and the same sigma.
     * The private key components returned by this method can be added to a
     * private key, thus adding the given attributes to the private key.
     *
     * @param msk           Secret master key
     * @param sigma         Secret user element to tie all user attributes together
     * @param attributes    Attributes for user
     * @return List of private key components (secret attribute keys)
     */
    private static ArrayList<Lw14PrivateKeyComponent> generateAdditionalAttributes(AbeSecretMasterKey msk,
                                                                                    Element sigma, String[] attributes) {
        ArrayList<Lw14PrivateKeyComponent> components = new ArrayList<Lw14PrivateKeyComponent>(attributes.length);
        AbePublicKey pub = msk.getPublicKey();
        Pairing p = pub.getPairing();

        boolean usePreprocessing = AbeSettings.PREPROCESSING && attributes.length >= AbeSettings.PREPROCESSING_THRESHOLD;

        ElementPowPreProcessing eppp_g = null;
        if (usePreprocessing) {
            eppp_g = pub.g.getElementPowPreProcessing();
        }
        Element G_pow_minus_sigma = pub.G.duplicate().powZn(sigma).invert();
        for(String attribute : attributes) {
            Element delta =  p.getZr().newRandomElement();
            Element x = Lw14Util.elementZrFromString(attribute, pub);
            Element k1_ijx;
            if (usePreprocessing) {
                k1_ijx = eppp_g.powZn(delta);
            } else {
                k1_ijx = pub.g.duplicate().powZn(delta);
            }
            Element k2_ijx = pub.H.duplicate().powZn(x).mul(pub.h).powZn(delta)
                    .mul(G_pow_minus_sigma);
            components.add(new Lw14PrivateKeyComponent(attribute, x, k1_ijx, k2_ijx));
        }
        return components;
    }

    /**
     * Pick a random group element and encrypt it under the specified access policy. The resulting ciphertext is returned.
     *
     * After using this function, it is normal to extract the random data in m using the pbc functions element_length_in_bytes and
     * element_to_bytes and use it as a key for hybrid encryption.
     *
     * The policy is specified as a boolean formula without threshold attributes. As an example,
     *
     * "foo and (bar or baz)"
     *
     * Attributes must not have whitespace in them ("_" is possible)
     *
     * @param pub       Public key
     * @param policy    Policy as a boolean formula
     * @param userIndex User index used for tracing (multiple ciphertexts are created with different indexes)
     * @return CipherText and key container object
     * @throws AbeEncryptionException Encryption failed
     */
    public static Pair<CipherText, Element> encrypt(AbePublicKey pub, String policy, int userIndex)
            throws AbeEncryptionException {
        return encrypt(pub, policy, new int[0], userIndex);
    }

    /**
     * Additionally to <code>#encrypt(AbePublicKey, String, int)</code>, this
     * method takes an array of user indexes and creates a ciphertext which
     * those users cannot decrypt even if they possess the necessary attribute
     * secret keys which would satisfy the policy.
     *
     * @param pub       Public key
     * @param policy    Policy as a boolean formula
     * @param revokedUserIndexes    List of revoked users by index
     * @param userIndex Index of the first user that is eligible for the encrypted data
     * @return CipherText and key container object
     * @throws AbeEncryptionException Encryption failed
     */
    public static Pair<CipherText, Element> encrypt(AbePublicKey pub, String policy,
                                                    int[] revokedUserIndexes, int userIndex)
            throws AbeEncryptionException
    {
        Pairing p = pub.getPairing();

        String parsedPolicy = null;
        LsssMatrix accessStructure;
        if (!AbeSettings.USE_TREE) {
            try {
                if (!AbeSettings.USE_THRESHOLD_MATRIX) {
                    accessStructure = LsssMatrix.createMatrixFromBooleanFormula(policy, pub);
                } else {
                    // the threshold formula doesn't work for some reason
                    accessStructure = LsssMatrix.createMatrixFromThresholdFormula(policy, pub);
                }
            } catch (ParseException e) {
                throw new AbeEncryptionException("Couldn't create matrix", e);
            }
        } else {
            try {
                parsedPolicy = PolicyParsing.parsePolicy(policy);
            } catch (ParseException e1) {
                throw new AbeEncryptionException("Policy preparsing failed", e1);
            }
        }

        boolean usePreprocessingPowG = AbeSettings.PREPROCESSING;
        boolean usePreprocessingOnAttributeAmount = AbeSettings.PREPROCESSING && !AbeSettings.USE_TREE && accessStructure.getAttributes() >= AbeSettings.PREPROCESSING_THRESHOLD;

        AbeUserIndex ui = new AbeUserIndex(pub.getSqrtUsers(), userIndex);
        int i_bar = ui.i;
        int j_bar = ui.j;

        Arrays.sort(revokedUserIndexes);


        Element message = p.getGT().newRandomElement();
        Element kappa = p.getZr().newRandomElement();
        Element tau = p.getZr().newRandomElement();
        Element[] s_i = new Element[pub.getSqrtUsers()];
        Element[] t_i = new Element[pub.getSqrtUsers()];
        for(int i = 0; i < s_i.length; i++) {
            s_i[i] = p.getZr().newRandomElement();
            t_i[i] = p.getZr().newRandomElement();
        }

        ElementVector v = new ElementVector(3, p.getZr());
        ElementVector[] w_j = new ElementVector[pub.getSqrtUsers()];
        for(int i = 0; i < s_i.length; i++) {
            w_j[i] = new ElementVector(3, p.getZr());
        }

        Element rx = p.getZr().newRandomElement();
        Element ry = p.getZr().newRandomElement();
        Element rz = p.getZr().newRandomElement();

        ElementVector x1 = new ElementVector( rx, p.getZr().newElement(0), rz );
        ElementVector x2 = new ElementVector( p.getZr().newElement(0), ry, rz );
        ElementVector x3 = new ElementVector( ry.duplicate().mul(rz).negate(),
                rx.duplicate().mul(rz).negate(),
                ry.duplicate().mul(rx) );

        ElementVector[] v_i = new ElementVector[pub.getSqrtUsers()];
        for(int i = 0; i <= i_bar; i++) {
            v_i[i] = new ElementVector(3, p.getZr());
        }
        for(int i = i_bar + 1; i < pub.getSqrtUsers(); i++) {
            // factors for x1 and x2 to create a vector in span{x1, x2}
            Element c1 = p.getZr().newRandomElement();
            Element c2 = p.getZr().newRandomElement();
            v_i[i] = x1.powInBase(c1).add(x2.powInBase(c2));
        }


        Element[] s_hat_i = new Element[pub.getSqrtUsers()];
        ElementVector[] R1_i = new ElementVector[pub.getSqrtUsers()];
        ElementVector[] R2_i = new ElementVector[pub.getSqrtUsers()];
        Element[] Q1_i = new Element[pub.getSqrtUsers()];
        Element[] Q2_i = new Element[pub.getSqrtUsers()];
        Element[] Q3_i = new Element[pub.getSqrtUsers()];
        Element[] T_i = new Element[pub.getSqrtUsers()];
        Element pi = p.getZr().newRandomElement();

        ElementPowPreProcessing eppp_g = null;
        if (usePreprocessingPowG) {
            eppp_g = pub.g.getElementPowPreProcessing();
        }

        Element f_pow_pi = pub.f.duplicate().powZn(pi);

        // iterate over rows
        for(int i = 0; i < pub.getSqrtUsers(); i++) {
            Element f_temp = pub.f.duplicate();
            for(int j = 0; j < pub.getSqrtUsers(); j++) {
                AbeUserIndex tempUserIndex = new AbeUserIndex(i, j, pub.getSqrtUsers());
                if (Arrays.binarySearch(revokedUserIndexes, tempUserIndex.counter) < 0) {
                    f_temp = f_temp.mul(pub.f_j[j]); // assignment is not necessary
                }
            }

            if (i < i_bar) {
                s_hat_i[i] = p.getZr().newRandomElement();

                if (usePreprocessingPowG) {
                    R1_i[i] = v_i[i].powInBase(eppp_g);
                    R2_i[i] = v_i[i].powInBase(eppp_g.powZn(kappa));
                    Q1_i[i] = eppp_g.powZn(s_i[i]);
                } else {
                    R1_i[i] = v_i[i].powInBase(pub.g);
                    R2_i[i] = v_i[i].powInBase(pub.g.duplicate().powZn(kappa));
                    Q1_i[i] = pub.g.duplicate().powZn(s_i[i]);
                }

                Q2_i[i] = f_temp.powZn(s_i[i])
                        .mul(pub.Z_i[i].duplicate().powZn(t_i[i]))
                        .mul(f_pow_pi);

                if (usePreprocessingPowG) {
                    Q3_i[i] = eppp_g.powZn(t_i[i]);
                } else {
                    Q3_i[i] = pub.g.duplicate().powZn(t_i[i]);
                }
                T_i[i] = pub.E_i[i].duplicate().powZn(s_hat_i[i]);
            } else {
                Element t_s_vi_vc = v.duplicate().scalar(v_i[i]).mul(s_i[i]).mul(tau);

                R1_i[i] = v_i[i].powInBase(pub.G_i[i].duplicate().powZn(s_i[i]));
                R2_i[i] = v_i[i].powInBase(pub.G_i[i].duplicate().powZn(s_i[i].duplicate().mul(kappa)));
                if (usePreprocessingPowG) {
                    Q1_i[i] = eppp_g.powZn(t_s_vi_vc);
                } else {
                    Q1_i[i] = pub.g.duplicate().powZn(t_s_vi_vc);
                }

                Q2_i[i] = f_temp.powZn(t_s_vi_vc)
                        .mul(pub.Z_i[i].duplicate().powZn(t_i[i]))
                        .mul(f_pow_pi);

                if (usePreprocessingPowG) {
                    Q3_i[i] = eppp_g.powZn(t_i[i]);
                } else {
                    Q3_i[i] = pub.g.duplicate().powZn(t_i[i]);
                }
                T_i[i] = pub.E_i[i].duplicate().powZn(t_s_vi_vc).mul(message);
            }
        }

        ElementVector[] C1_j = new ElementVector[pub.getSqrtUsers()];
        ElementVector[] C2_j = new ElementVector[pub.getSqrtUsers()];
        // iterate over columns
        for(int j = 0; j < pub.getSqrtUsers(); j++) {
            if (j < j_bar) {
                Element mu = p.getZr().newRandomElement();
                C1_j[j] = x3.duplicate().mul(mu).add(v).powInBase(pub.H_j[j].duplicate().powZn(tau));
            } else {
                C1_j[j] = v.powInBase(pub.H_j[j].duplicate().powZn(tau));
            }
            if (usePreprocessingPowG) {
                C1_j[j] = C1_j[j].mul(w_j[j].powInBase(eppp_g.powZn(kappa)));
                C2_j[j] = w_j[j].powInBase(eppp_g);
            } else {
                C1_j[j] = C1_j[j].mul(w_j[j].powInBase(pub.g.duplicate().powZn(kappa)));
                C2_j[j] = w_j[j].powInBase(pub.g);
            }
        }

        CipherText ct;
        if (!AbeSettings.USE_TREE) {
            int n = accessStructure.getColumns();
            int l = accessStructure.getAttributes();

            ElementVector e = new ElementVector(l, p.getZr());
            ElementVector u = new ElementVector(n, p.getZr());
            u.set(0, pi);

            ElementPowPreProcessing eppp_f = null;
            ElementPowPreProcessing eppp_G = null;
            ElementPowPreProcessing eppp_H = null;
            if (usePreprocessingOnAttributeAmount) {
                eppp_f = pub.f.getElementPowPreProcessing();
                eppp_G = pub.G.getElementPowPreProcessing();
                eppp_H = pub.H.getElementPowPreProcessing();
            }

            Element[] P1_k = new Element[l];
            Element[] P2_k = new Element[l];
            Element[] P3_k = new Element[l];
            // iterate over attributes
            for(int k = 0; k < l; k++) {
                ElementVector A_k = accessStructure.getAttributeRow(k, p.getZr());

                if (usePreprocessingOnAttributeAmount) {
                    P1_k[k] = eppp_f.powZn(A_k.scalar(u))
                            .mul(eppp_G.powZn(e.get(k)));
                    P2_k[k] = eppp_H.powZn(accessStructure.getHashedAttribute(k))
                            .mul(pub.h).powZn(e.get(k).duplicate().negate());
                } else {
                    P1_k[k] = pub.f.duplicate().powZn(A_k.scalar(u))
                            .mul(pub.G.duplicate().powZn(e.get(k)));
                    P2_k[k] = pub.H.duplicate().powZn(accessStructure.getHashedAttribute(k))
                            .mul(pub.h).powZn(e.get(k).duplicate().negate());
                }

                if (usePreprocessingPowG) {
                    P3_k[k] = eppp_g.powZn(e.get(k));
                } else {
                    P3_k[k] = pub.g.duplicate().powZn(e.get(k));
                }
            }

            ct = new CipherText(accessStructure, R1_i, R2_i, Q1_i, Q2_i, Q3_i, T_i,
                    C1_j, C2_j, P1_k, P2_k, P3_k, policy, revokedUserIndexes);
        } else {
            Lw14PolicyAbstractNode policyTree = null;
            try {
                policyTree = Lw14PolicyAbstractNode.parsePolicy(parsedPolicy, pub);
            } catch (ParseException e) {
                throw new AbeEncryptionException("Couldn't build tree", e);
            }

            if (AbeSettings.PREPROCESSING && policyTree.getMinLeaves() >= AbeSettings.PREPROCESSING_THRESHOLD) {
                if (eppp_g == null) {
                    eppp_g = pub.g.getElementPowPreProcessing();
                }
                policyTree.fillPolicy(pub, pi, new Lw14TreePreprocessing(pub.f.getElementPowPreProcessing(), eppp_g,
                        pub.G.getElementPowPreProcessing(), pub.H.getElementPowPreProcessing()));
            } else {
                policyTree.fillPolicy(pub, pi);
            }

            ct = new CipherText(policyTree, R1_i, R2_i, Q1_i, Q2_i, Q3_i, T_i,
                    C1_j, C2_j, null, revokedUserIndexes);
        }

//        System.out.println("encrypted msg: " + message);
        return new Pair<CipherText, Element>(ct, message);
    }

    /**
     * Decrypt the specified ciphertext using the given private key, return the decrypted element m.
     * 
     * Throws an exception if decryption was not possible.
     *
     * @param privateKey    User private key
     * @param cipher        CipherText
     * @return decrypted element which can be used to derive the AES key
     * @throws AbeDecryptionException Decryption failed
     */
    public static Element decrypt(AbePrivateKey privateKey, CipherText cipher) throws AbeDecryptionException {
        Lw14PolicyAbstractNode root = null;
        try {
            if (cipher.accessTree != null) {
                root = cipher.accessTree;
            } else if (cipher.policy != null) {
                throw new AbeDecryptionException("No policy available in order to check satisfiability");
            } else {
                root = Lw14Util.getPolicyTree(cipher.policy, privateKey.getPublicKey());
            }
            if (!Lw14Util.satisfies(root, privateKey)) {
                return null;
            }
        } catch(ParseException e) {
            throw new AbeDecryptionException("Policy could not be parsed", e);
        }

        Pairing p = privateKey.getPublicKey().getPairing();
        int m = privateKey.getPublicKey().getSqrtUsers();
        int my_i = privateKey.position.i;
        int my_j = privateKey.position.j;
//        System.out.println("\nnice matrix:\n" + cipher.accessMatrix.toNiceString());

        Element D_P = p.getGT().newOneElement();
        if (cipher.isAccessMatrix()) {
            int l = cipher.accessMatrix.getAttributes();
            int n = cipher.accessMatrix.getColumns();

            // Create an intersection between ciphertext attributes and private key attributes
            List<String> cipherTextAttributes = cipher.accessMatrix.getAttributeList();
            Set<String> filteredUserAttributes = privateKey.getAttributeSet();
            filteredUserAttributes.retainAll(cipherTextAttributes);

//        System.out.println("filteredUserAttributes " + Arrays.toString(filteredUserAttributes.toArray()));
//        if (filteredUserAttributes.size() < n) {
//            throw new AbeDecryptionException("Not enough attributes to decrypt");
//        }

            int minSize = Math.min(n, filteredUserAttributes.size());
//        System.out.println("minSize " + minSize);

            ElementVector w_k = null;
            List<String> attributeList = new ArrayList<String>(n);
            List<ElementVector> attributeVectorList = new ArrayList<ElementVector>(n);

            /*
             * The intersection of the attribute set used in the ciphertext and the attribute set in the private key are
             * is created. It is then used to create a power set and sorted in ascending order by set size.
             * The reasoning is that the matrix for smaller sets are faster to compute and less error prone:
             * Sometimes it happens that the matrix is not invertible. That is why many potential sets are tried to
             * create a correct LSSS solution.
             * */
            for(Set<String> set : new SortedPowerSet<String>(filteredUserAttributes)) {
                if (!Lw14Util.satisfies(root, set, privateKey.getPublicKey())) {
                    continue;
                }
                minSize = set.size();

                Matrix<Element> mat = new Matrix<Element>(minSize, minSize, new ElementField(p.getZr()));
                attributeList.clear();
                attributeVectorList.clear();
                int i = 0;
                for(String attribute : set) {
                    attributeList.add(attribute);
                    ElementVector row = cipher.accessMatrix.getAttributeRow(attribute, p.getZr());
                    attributeVectorList.add(row);
                    for(int j = 0; j < minSize /*row.getDimension()*/; j++) {
                        mat.set(j, i, row.get(j));
                    }
                    i++;
                }
//            System.out.println("AL: " + Arrays.toString(attributeList.toArray()));
//            System.out.println("AVL: " + Arrays.toString(attributeVectorList.toArray()));

//            System.out.println("mat\n" + mat);
                try {
                    mat.invert();
                } catch(IllegalStateException e) {
                    System.err.println("FAILED TO INVERT");
                    continue;
                }

//            System.out.println("mat inv\n" + mat);

                ElementVector temp_w_k = new ElementVector(minSize);
                for(int row = 0; row < minSize; row++) {
                    temp_w_k.set(row, mat.get(row, 0));
                }

                // check that w_k is indeed a matching solution for the LSSS...
                ElementVector v = new ElementVector(n, p.getZr().newZeroElement());
                for(int k = 0; k < minSize; k++) {
                /*
                 * here k refers to the correct attribute, because attributeVectorList,
                 * mat and temp_w_k where created from the same set
                 * */
                    v.add(attributeVectorList.get(k).duplicate().mul(temp_w_k.get(k)));
                }

//            System.out.println("test v: " + v);

                boolean verified = v.get(0).isOne();
                for(int k = 1; k < minSize; k++) {
                    verified = verified && v.get(k).isZero();
                }
                if (verified) {
                    w_k = temp_w_k;
                    break;
                }
            }
            if (w_k == null) {
                throw new AbeDecryptionException("Solution for LSSS couldn't be found");
            }

//        System.out.println("w_k: " + w_k);

            PairingPreProcessing pp = p.getPairingPreProcessingFromElement(privateKey.k2_ij);

            // step 1
            for(int k = 0; k < minSize; k++) {
                String attribute = attributeList.get(k);
                int attrRow = cipher.accessMatrix.getAttributeRowIndex(attribute);
//            System.out.println("k = " + k + " att = " + attribute + " row = " + attrRow);

                Lw14PrivateKeyComponent component = privateKey.getComponent(attribute);
                if (component == null) {
                    throw new AbeDecryptionException("Attribute '" + attribute +"' not found in private key");
                }

                Element c;
                if (AbeSettings.PREPROCESSING) {
                    c = pp.pairing(cipher.p1[attrRow]);
                } else {
                    c = p.pairing(privateKey.k2_ij, cipher.p1[attrRow]);
                }
                D_P = D_P.mul(c
                        .mul(p.pairing(component.k1_ijx, cipher.p2[attrRow]))
                        .mul(p.pairing(component.k2_ijx, cipher.p3[attrRow])))
                        .powZn(w_k.get(k));
            }
        } else {
            // accessTree

            if (!cipher.accessTree.checkSatisfy(privateKey)) {
                throw new AbeDecryptionException("Private key doesn't satisfy the threshold formula");
            }
            cipher.accessTree.pickSatisfyMinLeaves(privateKey);

            if (AbeSettings.PREPROCESSING && cipher.accessTree.getMinLeaves() >= AbeSettings.PREPROCESSING_THRESHOLD) {
                cipher.accessTree.decFlatten(D_P, privateKey);
            } else {
                cipher.accessTree.decFlatten(D_P, privateKey);
            }
        }

        // Create an int

        // step 2
        Element k_bar_ij = privateKey.k1_ij.duplicate();
        for(int j = 0; j < m; j++) {
            AbeUserIndex tempUserIndex = new AbeUserIndex(my_i, j, m);
            if (j != my_j && Arrays.binarySearch(cipher.revokedUserIndexes, tempUserIndex.counter) < 0) {
                k_bar_ij = k_bar_ij.mul(privateKey.k_ijj[j]); // assignment is not necessary
            }
        }
        Element D_I = p.pairing(k_bar_ij, cipher.q1[my_i]).mul(p.pairing(privateKey.k3_ij, cipher.q3[my_i]))
                .div(p.pairing(privateKey.k2_ij, cipher.q2[my_i]))
                .mul(cipher.r2[my_i].newPair(p, cipher.c2[my_j]))
                .div(cipher.r1[my_i].newPair(p, cipher.c1[my_j]));

        // step 3
        Element M = cipher.t[my_i].duplicate().div(D_P.mul(D_I));

//        System.out.println("decrypted msg: " + M);

        return M;
    }
    
    public static boolean canDecrypt(AbePrivateKey prv, CipherText cph) throws ParseException {
        if (cph.accessTree != null) {
            return cph.accessTree.checkSatisfy(prv);
        } else if (cph.policy != null) {
            return canDecrypt(prv, cph.policy);
        } else {
            throw new ParseException("Unable to check satisfiability through private key, " +
                    "because either policy tree or policy string are missing");
        }
    }

    /**
     * Check if the private key satisfies the policy.
     * @param prv       Private key
     * @param policy    policy
     * @return  Private key Satisfies policy (has the necessary attributes to decrypt)
     * @throws ParseException Policy couldn't be parsed
     */
    public static boolean canDecrypt(AbePrivateKey prv, String policy) throws ParseException {
        String postFixPolicy = PolicyParsing.parsePolicy(policy);
        return Lw14PolicyAbstractNode.parsePolicy(postFixPolicy, prv.getPublicKey()).checkSatisfy(prv);
    }

    public static Element trace(Lw14DecryptionBlackBox blackBox) {
        // TODO: implement
        throw new RuntimeException("Not implemented");
    }
}
