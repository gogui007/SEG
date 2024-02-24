/**Fichero: Principal.java
 * Clase para comprobar el funcionamiento de las otras clases del paquete.
 * Asignatura: SEG
 * @author Profesores de la asignatura
 * @version 1.0
 */
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;




public class Principal {

	public static void main (String [ ] args) throws IOException,
	NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
	BadPaddingException, InvalidKeySpecException, InvalidKeyException,
	DataLengthException, IllegalStateException, InvalidCipherTextException {
		int menu1;
		int menu2;
		Scanner sc = new Scanner(System.in);
		Simetrica s = new Simetrica();
		Asimetrica a = new Asimetrica();

		/* completar declaracion de variables e instanciación de objetos */
		
		do {
			System.out.println("¿Qué tipo de criptografía desea utilizar?");
			System.out.println("1. Simétrico.");
			System.out.println("2. Asimétrico.");
			System.out.println("3. Salir.");
			menu1 = sc.nextInt();
			CipherKeyGenerator genClave = new CipherKeyGenerator();
			genClave.init(new KeyGenerationParameters(new SecureRandom(),512));
			byte[] almacenClave = new byte[64];			
			switch(menu1){
				case 1:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA SIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								/*completar acciones*/
								almacenClave = genClave.generateKey();
								Hex.encode(almacenClave);
								FileOutputStream salida= null;
								try {
									salida= new FileOutputStream("datos.bin");
									for (int i=0; i<64 ; i++){
										salida.write(almacenClave[i]);
									}
								} catch (FileNotFoundException e){
									e.printStackTrace();
								} catch (IOException e) {
									e.printStackTrace();
								} finally {
								if (salida!=null)
									try {
										salida.close();
									} catch (IOException e) {
										e.printStackTrace();
								}
								}
							break;
							case 2:
								/*completar acciones*/
								Scanner sc1 = new Scanner(System.in);
								Scanner sc2 = new Scanner(System.in);
								Scanner sc3 = new Scanner(System.in);

								String ficheroClave;
								String fichACifrar;
								String fichCifrado;

								System.out.print("Escriba el nombre del fichero que contiene la clave: ");
								ficheroClave = sc1.next();

								System.out.println("\nFichero a cifrar:");
								fichACifrar = sc2.next();

								System.out.println("\nFichero cifrado:");
								fichCifrado = sc3.next();

								s.cifrar(ficheroClave, fichACifrar, fichCifrado);
							break;
							case 3:
								/*completar acciones*/
								Scanner sc4 = new Scanner(System.in);
								Scanner sc5 = new Scanner(System.in);
								Scanner sc6 = new Scanner(System.in);

								String ficheroK;
								String fichADescifrar;
								String fichDescifrado;

								System.out.print("Escriba el nombre del fichero que contiene la clave: ");
								ficheroK = sc4.next();

								System.out.println("\nFichero a descifrar:");
								fichADescifrar = sc5.next();

								System.out.println("\nFichero descifrado:");
								fichDescifrado = sc6.next();

								s.cifrar(ficheroK, fichADescifrar, fichDescifrado);
							break;
						}
					} while(menu2 != 0);
				break;
				case 2:
					do{
						System.out.println("Elija una opción para CRIPTOGRAFIA ASIMÉTRICA:");
						System.out.println("0. Volver al menú anterior.");
						System.out.println("1. Generar clave.");
						System.out.println("2. Cifrado.");
						System.out.println("3. Descifrado.");
						System.out.println("4. Firmar digitalmente.");
						System.out.println("5. Verificar firma digital.");
						menu2 = sc.nextInt();
				
						switch(menu2){
							case 1:
								/*completar acciones*/
								String fichCPublica;
								String fichCPrivada;
								Scanner sc1 = new Scanner(System.in);
								Scanner sc2 = new Scanner(System.in);

								System.out.print("Escriba el nombre del fichero en el que desea generar la clave pública: ");
								fichCPublica = sc1.next();

								System.out.print("Escriba el nombre del fichero en el que desea generar la clave privada: ");
								fichCPrivada = sc2.next();

								a.generadorParejaClaves(fichCPrivada, fichCPublica);
							break;
							case 2:
								/*completar acciones*/
								String fichACifrar;
								String fichCifrado;
								String fichClave;
								int opcion;
								Scanner sc3 = new Scanner(System.in);
								Scanner sc4 = new Scanner(System.in);
								Scanner sc5 = new Scanner(System.in);
								Scanner sc6 = new Scanner(System.in);

								System.out.print("Escriba el nombre del fichero a cifrar: ");
								fichACifrar = sc3.next();

								System.out.println("Elija el tipo de clave (privada o publica):");
								System.out.println("1. Publica.");
								System.out.println("2. Privada.");
								opcion = sc4.nextInt();

								switch(opcion) {
								    case 1: // CLAVE PUBLICA --> true
								        System.out.println("Escriba el nombre del fichero que contiene la clave pública:");
								        fichClave = sc5.nextLine();
								        System.out.println("Escriba el nombre del fichero cifrado:");
								        fichCifrado = sc6.nextLine();
								        a.cifrar(fichClave, fichACifrar, fichCifrado, "publica");
								        break;
								        
								    case 2: // CLAVE PRIVADA --> false
								        System.out.println("Escriba el nombre del fichero que contiene la clave privada:");
								        fichClave = sc5.nextLine();
								        System.out.println("Escriba el nombre del fichero cifrado:");
								        fichCifrado = sc6.nextLine();
								        a.cifrar(fichClave, fichACifrar, fichCifrado, "privada");
								        break;
								}
							break;
							case 3:
								/*completar acciones*/
								String fichADescifrar;
								String fichDescifrado;
								String fichKey;
								int opcion2;
								Scanner sc7 = new Scanner(System.in);
								Scanner sc8 = new Scanner(System.in);
								Scanner sc9 = new Scanner(System.in);
								Scanner sc10 = new Scanner(System.in);

								System.out.print("Escriba el nombre del fichero a descifrar: ");
								fichADescifrar = sc7.next();

								System.out.println("Elija el tipo de clave (privada o publica):");
								System.out.println("1. Publica.");
								System.out.println("2. Privada.");
								opcion2 = sc8.nextInt();

								switch (opcion2) {
								    case 1: // CLAVE PUBLICA
								        System.out.println("Escriba el nombre del fichero que contiene la clave publica:");
								        fichKey = sc9.nextLine();
								        System.out.println("Escriba el nombre del fichero descifrado:");
								        fichDescifrado = sc10.nextLine();
								        a.descifrar(fichKey, fichADescifrar, fichDescifrado, "publica");
								        break;

								    case 2: // CLAVE PRIVADA
								        System.out.println("Escriba el nombre del fichero que contiene la clave privada:");
								        fichKey = sc9.nextLine();
								        System.out.println("Escriba el nombre del fichero descifrado:");
								        fichDescifrado = sc10.nextLine();
								        a.descifrar(fichKey, fichADescifrar, fichDescifrado, "privada");
								        break;
								}
							break;
							case 4:
								/*completar acciones*/
								String fichClaro;
								String fichFirmado;
								String fichClavPrivada;
								Scanner sc11 = new Scanner(System.in);
								Scanner sc12 = new Scanner(System.in);
								Scanner sc13 = new Scanner(System.in);

								System.out.println("Escriba el nombre del fichero de la clave privada:");
								fichClavPrivada = sc11.nextLine();

								System.out.println("Escriba el nombre del fichero a firmar:");
								fichClaro = sc12.nextLine();

								System.out.println("Escriba el nombre del fichero firmado:");
								fichFirmado = sc13.nextLine();

								a.firmar(fichClavPrivada, fichClaro, fichFirmado);
							break;
							case 5:
								/*completar acciones*/
								String fichEnClaro;
								String fichClavPublica;
								boolean verificado;
								Scanner sc14 = new Scanner(System.in);
								Scanner sc15 = new Scanner(System.in);
								Scanner sc16 = new Scanner(System.in);

								System.out.println("Escriba el nombre del fichero de la clave pública:");
								fichClavPublica = sc14.nextLine();

								System.out.println("Escriba el nombre del fichero original (fichero en claro):");
								fichEnClaro = sc15.nextLine();

								System.out.println("Escriba el nombre del fichero firmado para verificar la firma:");
								fichFirmado = sc16.nextLine();

								verificado = a.verificarFirma(fichClavPublica, fichEnClaro, fichFirmado);

								if (verificado) {
								    System.out.println("La firma se ha verificado correctamente");
								} else {
								    System.out.println("La firma no se ha verificado correctamente");
								}
							break;
						}
					} while(menu2 != 0);
				break;
			}			
		} while(menu1 != 3);
		sc.close();
	}
}