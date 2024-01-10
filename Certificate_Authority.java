package pki;

import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class Certificate_Authority {
    
    //preshared identities declared and initialized
    public static final String ID_CA = "ID-CA";
    public static final String ID_S = "ID-Server";
    
    //declare key variables
    private static PublicKey PK_CA, PK_S;
    private static PrivateKey SK_CA, SK_S;
    private static SecretKey K_TMP;
    
    public static final long TS_2 = System.currentTimeMillis()/1000;
    
    //two variables needed for socket programming
    public static final String SERVER_IP = "localhost";
    public static final int SERVER_PORT = 9001;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    
    public static void main(String args[]) throws IOException{
        //declare variables to place public key in file to be accessible for the rest of the files
        String write_public_key;
        PrintStream public_key_file;
        
        try{
            //initialize public and private keys
            KeyPairGenerator k = KeyPairGenerator.getInstance("RSA");
            k.initialize(1024);
            KeyPair p1 = k.genKeyPair();
            PK_CA = p1.getPublic();
            SK_CA = p1.getPrivate();
            
            //only write public key to file
            write_public_key = Base64.getEncoder().encodeToString(PK_CA.getEncoded());
            public_key_file = new PrintStream(new File("Public_Key.txt"));
            public_key_file.println(write_public_key);
        }catch(NoSuchAlgorithmException e){
            System.out.println(e);
        }catch(Exception e){
            System.out.println(e);
        }
        
        Socket s = new Socket(SERVER_IP, SERVER_PORT); //establish socket connection with the server
        
        //read from Server
        BufferedReader read_AS_response = new BufferedReader(new InputStreamReader(s.getInputStream()));
        String AS_response = read_AS_response.readLine();
        
        //the ciphertext, in hex, must be converted to bytes
        byte[] recvText = DatatypeConverter.parseHexBinary(AS_response);
        
        String plaintext = RSA_Decryption(SK_CA, recvText); //call RSA decryption using private key to get plaintext
        
        //get length of temp key
        Scanner get_key_tmp_len = new Scanner(new File("KEY_TEMP_LEN.txt"));
        int read_key_tmp_len = get_key_tmp_len.nextInt();
        
        //print information from Server
        System.out.println();
        System.out.println("Key Temp (Received) is: " + plaintext.substring(0, read_key_tmp_len));
        System.out.println("Received ciphertext is: " + AS_response);
        
        //to store newly generated public key to string
        String write_public_key_s = "", write_private_key_s = "";
        PrintWriter output = new PrintWriter(s.getOutputStream(), true);
        try{
            //initialize new public and private keys
            KeyPairGenerator k = KeyPairGenerator.getInstance("RSA");
            k.initialize(1024);
            KeyPair p2 = k.genKeyPair();
            PK_S = p2.getPublic();
            SK_S = p2.getPrivate();
            
            //convert keys to string
            write_public_key_s = Base64.getEncoder().encodeToString(PK_S.getEncoded());
            write_private_key_s = Base64.getEncoder().encodeToString(SK_S.getEncoded());
            
            String frstConCat = ID_S.concat(ID_CA.concat(write_public_key_s)); //concatenate IDs and key
            String cert_s = genSignature(SK_CA, frstConCat); //generate RSA signature using private key
        
            //make second concatenation with the (S) certificate
            String secConCat = write_public_key_s.concat(write_private_key_s.concat(cert_s.concat(ID_S).concat(String.valueOf(TS_2))));
        
            byte []key = Base64.getDecoder().decode(plaintext.substring(0, read_key_tmp_len)); //convert string to secret key variable
            K_TMP = new SecretKeySpec(key, 0, key.length, "DES"); //initialize secret key variable
            String sendMsg = DES_Encryption(K_TMP, secConCat); //use DES to encrypt concatenation
            
            //get length of each key within the Key Pair and place it in file
            int key_pair_len = write_public_key_s.length() + write_private_key_s.length();
            PrintStream key_pair_len_file = new PrintStream(new File("KEY_PAIR_LEN.txt"));
            key_pair_len_file.println(write_public_key_s.length());
            key_pair_len_file.println(key_pair_len);
            
            //print out information to verify with Server
            System.out.println();
            //System.out.println("Plaintext is: " + secConCat); //check plaintext
            System.out.println("Ciphertext is: " + sendMsg);
            System.out.println("Key Pair (Generated) is: (" + write_public_key_s + ", " + write_private_key_s + ")");
            System.out.println("(S) Certificate (Generated) is: " + cert_s);
            
            output.println(sendMsg); //send ciphertext to Server
        }catch(NoSuchAlgorithmException e){
            System.out.println(e);
        }catch(Exception e){
            System.out.println(e);
        }
        
        s.close(); //close socket
    }
    
    //RSA Decryption method
    public static String RSA_Decryption(PrivateKey p, byte b[]){
        try{
            decrypt = Cipher.getInstance("RSA"); //have Cipher variable encrypt using DES algorithm
            decrypt.init(Cipher.DECRYPT_MODE, p); //initialized Cipher variable to decrypt mode with secret key as parameter
            byte []deMsg = decrypt.doFinal(b); //derypt text
            return new String(deMsg);
        }catch(BadPaddingException e){
            System.out.println(e);
        }catch(Exception e){
            System.out.println(e);
        }
        return null;
    }
    
    //RSA Generate Signature method
    public static String genSignature(PrivateKey p, String s) {
        byte get_signature[];
        //generate signature using RSA
        try{
            Signature private_sign = Signature.getInstance("SHA256withRSA");
            private_sign.initSign(p);
            private_sign.update(s.getBytes());
            get_signature = private_sign.sign();
            return Base64.getEncoder().encodeToString(get_signature);
        }catch(Exception e){
            System.out.println(e);
        }
        return "";
    }
    
    //DES Encryption method
    public static String DES_Encryption(SecretKey key, String combinedText){        
        try{
            //Ecrypt concatenaetd string using DES
            encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //have Cipher variable encrypt using DES algorithm
            encrypt.init(Cipher.ENCRYPT_MODE, key); //initialized Cipher variable to encrypt mode with secret key as parameter
            byte []text = combinedText.getBytes();
            byte []ciphertext = encrypt.doFinal(text); //ecrypt text
            return DatatypeConverter.printHexBinary(ciphertext);
        }catch(Exception e){
            System.out.println(e);
        }
        return "";
    }
    
}
