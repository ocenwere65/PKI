package pki;

import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Client {
    
    public static final String ID_C = "ID-Client";
    
    //preshared identities declared and initialized
    public static final String ID_CA = "ID-CA";
    public static final String ID_S = "ID-Server";
    
    public static final String req = "memo";
    
    //two variables needed for socket programming
    public static final String SERVER_IP_C = "localhost";
    public static final int SERVER_PORT_C = 9001;
    
    private static PublicKey PK_S; //for RSA encryption/decryption
    private static SecretKey K_TMP_2;
    private static SecretKey K_SESS;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    
    public static final long TS_3 = System.currentTimeMillis()/1000;
    public static final long TS_5 = System.currentTimeMillis()/1000;
    public static final long TS_7 = System.currentTimeMillis()/1000;
    
    public static void main(String args[]) throws IOException{
        String frtConCat = ID_S.concat(String.valueOf(TS_3));
        
        Socket s = new Socket(SERVER_IP_C, SERVER_PORT_C); //establish socket connection with the server
        PrintWriter output = new PrintWriter(s.getOutputStream(), true);
        System.out.println("Plaintext is: " + frtConCat);
        output.println(frtConCat); //send plaintext to Server
        
        //read and print plaintext from Server
        String recvServerText = new BufferedReader(new InputStreamReader(s.getInputStream())).readLine();
        System.out.println("Received plaintext is: " + recvServerText);
        
        String write_key_tmp_2 = "";
        int get_key_tmp_2_len, get_id_c_len_file;
        PrintStream key_tmp_2_len_file, id_c_len_file;
        
        Scanner get_pub_key_s_len;
        int read_pub_key_s_len;
        String read_pub_key_s;
        
        try{
            //initialize temp key using DES
            K_TMP_2 = KeyGenerator.getInstance("DES").generateKey();
            write_key_tmp_2 = Base64.getEncoder().encodeToString(K_TMP_2.getEncoded());
            
            get_key_tmp_2_len = write_key_tmp_2.length(); //get length of Key string
            key_tmp_2_len_file = new PrintStream(new File("KEY_TEMP_2_LEN.txt")); //make new file
            key_tmp_2_len_file.println(get_key_tmp_2_len); //write to file
            
            //read length from shared file to get Key string
            get_pub_key_s_len = new Scanner(new File("pub_key_s_len.txt"));
            read_pub_key_s_len = get_pub_key_s_len.nextInt();
            read_pub_key_s = recvServerText.substring(0, read_pub_key_s_len);
            
            //read length from shared file to get ID int
            get_id_c_len_file = ID_C.length();
            id_c_len_file = new PrintStream(new File("id_c_len.txt"));
            id_c_len_file.println(get_id_c_len_file);
            
            //convert string to public key variable
            byte []pub_key = Base64.getDecoder().decode(read_pub_key_s);
            X509EncodedKeySpec ks = new X509EncodedKeySpec(pub_key);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PK_S = kf.generatePublic(ks);
        }catch(Exception e){
            System.out.println(e);
        }
        
        //make second concatenation
        String scdConCat = write_key_tmp_2.concat(ID_C.concat(SERVER_IP_C.concat(String.valueOf(SERVER_PORT_C).concat(String.valueOf(TS_5)))));
        String ciphertext = RSA_Encryption(PK_S, scdConCat); //encrypt concatenation using RSA Encryption
        
        System.out.println();
        System.out.println("Temporary Key 2 (Generated) is: " + write_key_tmp_2);
        System.out.println("Ciphertext is: " + ciphertext);
        output.println(ciphertext); //send ciphertext to Server
        
        //read and print second response from Server
        String recvServerText2 = new BufferedReader(new InputStreamReader(s.getInputStream())).readLine();
        System.out.println();
        System.out.println("Received ciphertext is: " + recvServerText2);
        
        //the ciphertext, in hex, must be converted to bytes
        byte[] recvText = DatatypeConverter.parseHexBinary(recvServerText2);
        String plaintext = DES_Decryption(K_TMP_2, recvText); //use DES decryption to get plaintext
        
        //read length from Key Session string and print specified string
        Scanner get_key_sess_len = new Scanner(new File("key_sess_len.txt"));
        int read_key_sess_len = get_key_sess_len.nextInt();
        String sess_key = plaintext.substring(0, read_key_sess_len);
        System.out.println("Key Session (Received) is: " + sess_key);
        
        String thrdConCat = req.concat(String.valueOf(TS_7));
        String ciphertext2;
        
        try{
            byte []key = Base64.getDecoder().decode(sess_key); //convert string to secret key variable
            K_SESS = new SecretKeySpec(key, 0, key.length, "DES"); //initialize secret key variable
            ciphertext2 = DES_Encryption(K_SESS, thrdConCat);
            
            //make file for Server to read lenggth of string
            int req_len = req.length();
            PrintStream req_len_file = new PrintStream(new File("req_len.txt"));
            req_len_file.println(req_len);
            
            System.out.println();
            //System.out.println("Plaintext is: " + thrdConCat);
            System.out.println("Ciphertext is: " + ciphertext2);
            output.println(ciphertext2); //send ciphertext to Server
        }catch(Exception e){
            System.out.println(e);
        }
        
        //read ad print response from Server
        String recvServerText3 = new BufferedReader(new InputStreamReader(s.getInputStream())).readLine();
        System.out.println();
        System.out.println("Received ciphertext is: " + recvServerText3);
        
        //the ciphertext, in hex, must be converted to bytes
        byte[] recvText2 = DatatypeConverter.parseHexBinary(recvServerText3);
        String plaintext3 = DES_Decryption(K_SESS, recvText2); //use DES decryption to get plaintext
        
        //read length of data string variable and print specified string
        Scanner get_data_len = new Scanner(new File("data_len.txt"));
        int read_data_len = get_data_len.nextInt();
        System.out.println("Data (Received) is: " + plaintext3.substring(0, read_data_len)); //print Data string
        
        s.close(); //close socket
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
