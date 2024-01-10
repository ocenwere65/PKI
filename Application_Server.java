package pki;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;


public class Application_Server {
    
    public static final int SERVER_PORT = 9001; //to connect to CA
    
    //preshared identities declared and initialized
    public static final String ID_CA = "ID-CA";
    public static final String ID_S = "ID-Server";
    
    public static String ID_C = ""; //read from client
    
    public static final String data = "take cis3319 class this morning";
    
    private static SecretKey K_TMP; //for DES encryption/decryption
    private static SecretKey K_TMP_2; //for DES encryption/decryption
    private static SecretKey K_SESS; //key session
    
    private static PublicKey PK_CA; //for RSA encryption/decryption
    
    private static PrivateKey SK_CA; //to read from CA
    
    public static final long TS_1 = System.currentTimeMillis()/1000;
    public static final long TS_4 = System.currentTimeMillis()/1000;
    public static final long TS_6 = System.currentTimeMillis()/1000;
    public static final long TS_8 = System.currentTimeMillis()/1000;
    
    //initialize lifetime session and lifetime 4
    public static final long lifetime_sess = 86400;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    
    public static void main(String args[]) throws IOException{
        ServerSocket listener = new ServerSocket(SERVER_PORT, 2); //set up server socket
        
        System.out.println("[CLIENT] Waiting for server connection ...");
        Socket server = listener.accept(); //CA is connected with server
        System.out.println("[CLIENT] Accept new connection from 127.0.0.1");
        
        String write_key_tmp = "";
        int get_key_tmp_len;
        PrintStream key_tmp_file, key_tmp_len_file;
        
        try{
            //initialize temp key using DES
            K_TMP = KeyGenerator.getInstance("DES").generateKey();
            write_key_tmp = Base64.getEncoder().encodeToString(K_TMP.getEncoded());
            key_tmp_file = new PrintStream(new File("KEY_TEMP.txt")); //make new file
            key_tmp_file.println(write_key_tmp); //write to file
            
            get_key_tmp_len = write_key_tmp.length(); //get length of Key string
            key_tmp_len_file = new PrintStream(new File("KEY_TEMP_LEN.txt")); //make new file
            key_tmp_len_file.println(get_key_tmp_len); //write to file
            
            //obtain public key from CA
            Scanner get_pub_key = new Scanner(new File("Public_Key.txt"));
            String read_pub_key = get_pub_key.next();
            
            //convert string to public key variable
            byte []pub_key = Base64.getDecoder().decode(read_pub_key);
            X509EncodedKeySpec ks = new X509EncodedKeySpec(pub_key);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PK_CA = kf.generatePublic(ks);
        }catch(Exception e){
            System.out.println(e);
        }
        
        String frstConCat = write_key_tmp.concat(ID_S.concat(String.valueOf(TS_1))); //concatenate string/int variables and IDs
        String msg = RSA_Encryption(PK_CA, frstConCat); //encrypt concatenation using RSA algorithm
                        
        //print information
        System.out.println();
        System.out.println("Key Temp (Generated) is: " + write_key_tmp);
        System.out.println("Ciphertext is: " + msg);
        PrintWriter output = new PrintWriter(server.getOutputStream(), true);
        output.println(msg); //send ciphertext to CA
        
        String CA_Response = new BufferedReader(new InputStreamReader(server.getInputStream())).readLine();
        System.out.println();
        System.out.println("Received ciphertext is: " + CA_Response); //print ciphertext from CA
        
        //the ciphertext, in hex, must be converted to bytes
        byte[] recvText = DatatypeConverter.parseHexBinary(CA_Response);
        
        String plaintext = DES_Decryption(K_TMP, recvText); //use DES decryption to get plaintext
        
        //get indexes of key pairs i.e. public and private keys of S
        Scanner get_key_pair_len = new Scanner(new File("KEY_PAIR_LEN.txt"));
        int ind_1 = get_key_pair_len.nextInt();
        
        int read_key_pair_len = get_key_pair_len.nextInt();
        int ind_2 = plaintext.indexOf(ID_S); //index to signal cut-off point of certificate
        
        String PK_S = plaintext.substring(0, ind_1);
        String cert_s = plaintext.substring(read_key_pair_len, ind_2);
        String SK_S = plaintext.substring(ind_1, read_key_pair_len);
        //print Key Pair and Certificate
        //System.out.println("Plaintext is: " + plaintext); //check plaintext
        System.out.println("Key Pair (Received) is: (" + PK_S + ", " + SK_S + ")");
        System.out.println("(S) Certificate (Received) is: " + cert_s);
    
        Socket server2 = listener.accept(); //client is connected with server
        
        //read and print plaintext from Client
        String recvClientText = new BufferedReader(new InputStreamReader(server2.getInputStream())).readLine();
        System.out.println();
        System.out.println("Received plaintext is: " + recvClientText);
        
        int pub_key_s_len;
        PrintStream pub_key_s_len_file;
        try{
            //get length of public key and place in file for Client to read from
            pub_key_s_len = PK_S.length();
            pub_key_s_len_file = new PrintStream(new File("pub_key_s_len.txt"));
            pub_key_s_len_file.println(pub_key_s_len);
        }catch(Exception e){
            System.out.println(e);
        }
        
        //make second concatenation
        String scdConCat = PK_S.concat(cert_s.concat(String.valueOf(TS_4)));
        PrintWriter output2 = new PrintWriter(server2.getOutputStream(), true);
        System.out.println("Plaintext is: " + scdConCat);
        output2.println(scdConCat); //send plaintext to Client
        
        //read and print plaintext from Client
        String clientCiphertext = new BufferedReader(new InputStreamReader(server2.getInputStream())).readLine();
        System.out.println();
        System.out.println("Received ciphertext is: " + clientCiphertext);
        
        try{
            //convert string to private key variable
            byte []priv_key = Base64.getDecoder().decode(SK_S);
            PKCS8EncodedKeySpec ks = new PKCS8EncodedKeySpec(priv_key);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            SK_CA = kf.generatePrivate(ks);
        }catch(Exception e){
            System.out.println();
        }
        
        //the ciphertext, in hex, must be converted to bytes
        byte[] recvText2 = DatatypeConverter.parseHexBinary(clientCiphertext);
        String plaintext2 = RSA_Decryption(SK_CA, recvText2);
        
        Scanner get_key_temp_2_len;
        int read_key_temp_2_len;
        String read_key_temp_2;
        
        String write_key_sess = "";
        
        try{
            //read length from shared file to get Key string
            get_key_temp_2_len = new Scanner(new File("KEY_TEMP_2_LEN.txt"));
            read_key_temp_2_len = get_key_temp_2_len.nextInt();
            read_key_temp_2 = plaintext2.substring(0, read_key_temp_2_len);
            
            System.out.println("Temporary Key 2 (Received) is: " + read_key_temp_2); //print Key string
            
            byte []key = Base64.getDecoder().decode(read_key_temp_2); //convert string to secret key variable
            K_TMP_2 = new SecretKeySpec(key, 0, key.length, "DES"); //initialize secret key variable
        
            //initialize key session using DES
            K_SESS = KeyGenerator.getInstance("DES").generateKey();
            write_key_sess = Base64.getEncoder().encodeToString(K_SESS.getEncoded());
            
            //read length from shared file to get ID int
            Scanner get_id_c_len = new Scanner(new File("id_c_len.txt"));
            int read_id_c_len = get_id_c_len.nextInt();
            ID_C = plaintext2.substring(read_key_temp_2_len, read_key_temp_2_len + read_id_c_len);
            
            //make third concatenation
            String thrdConCat = write_key_sess.concat(String.valueOf(lifetime_sess).concat(ID_C.concat(String.valueOf(TS_6))));
            
            //get length of Key Session and place in file for Client to read from
            PrintStream key_sess_len_file = new PrintStream(new File("key_sess_len.txt"));
            key_sess_len_file.println(write_key_sess.length());
            
            String ciphertext2 = DES_Encryption(K_TMP_2, thrdConCat); //encrypt concatenation using DES Encryption
            System.out.println();
            System.out.println("Key Session (Generated) is: " + write_key_sess);
            System.out.println("Ciphertext is: " + ciphertext2);
            output2.println(ciphertext2); //send ciphertext to Client
        }catch(Exception e){
            System.out.println();
        }
        
        //read and print plaintext from Client
        String clientCiphertext2 = new BufferedReader(new InputStreamReader(server2.getInputStream())).readLine();
        System.out.println();
        System.out.println("Received ciphertext is: " + clientCiphertext2);
        
        //the ciphertext, in hex, must be converted to bytes
        byte[] recvText3 = DatatypeConverter.parseHexBinary(clientCiphertext2);
        String plaintext3 = DES_Decryption(K_SESS, recvText3);
       
        //read from shared file to get Reg string
        Scanner get_req_len = new Scanner(new File("req_len.txt"));
        int read_req_len = get_req_len.nextInt();
        System.out.println("Req (Received) is: " + plaintext3.substring(0, read_req_len));
        
        //make fourth concatenation
        String frthConCat = data.concat(String.valueOf(TS_8));
        String ciphertext3 = DES_Encryption(K_SESS, frthConCat); //encryption concatenation using DES Encryption
        
        //get length of Data string and place in file for Client to read from
        int data_len = data.length();
        PrintStream data_len_file = new PrintStream(new File("data_len.txt"));
        data_len_file.println(data_len);
        
        System.out.println();
        //System.out.println("Plaintext is: " + frthConCat); //to check plaintext on Client
        System.out.println("Ciphertext is: " + ciphertext3); //print ciphertext
        output2.println(ciphertext3); //send ciphertext to Client
        
        //close sockets
        server.close();
        server2.close();
        listener.close(); //close ServerSocket
    }
    
    //RSA Encryption method
    public static String RSA_Encryption(PublicKey p, String s){
        try{
            //Ecrypt concatenaetd string using RSA
            encrypt = Cipher.getInstance("RSA"); //have Cipher variable encrypt using DES algorithm
            encrypt.init(Cipher.ENCRYPT_MODE, p); //initialized Cipher variable to encrypt mode with secret key as parameter
            byte []text = s.getBytes();
            byte []ciphertext = encrypt.doFinal(text); //ecrypt text
            return DatatypeConverter.printHexBinary(ciphertext);
        }catch(Exception e){
            System.out.println(e);
        }
        return null;
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
        }catch(InvalidKeyException e){
            System.out.println(e);
        }catch(Exception e){
            System.out.println(e);
        }
        return null;
    }
    
    //DES Decryption method
    public static String DES_Decryption(SecretKey key, byte enMsg[]){
        try{
            decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //have Cipher variable encrypt using DES algorithm
            decrypt.init(Cipher.DECRYPT_MODE, key); //initialized Cipher variable to encrypt mode with secret key as parameter
            byte []deMsg = decrypt.doFinal(enMsg); //ecrypt text
            String oriMsg = new String(deMsg);
            return oriMsg;
        }catch(Exception e){
            System.out.println();
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
