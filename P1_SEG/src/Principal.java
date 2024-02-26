// En la clase Principal.java

import java.io.IOException;
import java.util.Scanner;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;

public class Principal {

    public static void main(String[] args) throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
        int menu1;
        int menu2;
        Scanner sc = new Scanner(System.in);

        String clave;
		String archivo_original;
		String archivo_cifrado;
		String cpublica;
		String cprivada;
		String tipo;
		
        do {
            System.out.println("¿Que tipo de criptografia desea utilizar?");
            System.out.println("1. Simetrico.");
            System.out.println("2. Asimetrico.");
            System.out.println("3. Salir.");
            menu1 = sc.nextInt();

            switch (menu1) {
                case 1:
                    do {
                        System.out.println("Elija una opcion para CRIPTOGRAFIA SIMETRICA:");
                        System.out.println("0. Volver al menu anterior.");
                        System.out.println("1. Generar clave.");
                        System.out.println("2. Cifrado.");
                        System.out.println("3. Descifrado.");
                        menu2 = sc.nextInt();

                        switch (menu2) {
                            case 1:
                            	System.out.print("Escriba el nombre del fichero donde quiere guardar la clave: ");
								String fileName = sc.next();
                                Simetrica.generarClave(fileName);
                                break;
                            case 2:
                            	System.out.print("Indique el nombre del fichero clave: ");
								clave = sc.next();
								System.out.print("Indique el nombre del fichero a cifrar: ");
								archivo_original = sc.next();
								System.out.print("Indique donde dejar el fichero cifrado: ");
								archivo_cifrado = sc.next();
                            	Simetrica.cifrar(clave, archivo_original, archivo_cifrado);
                                break;
                            case 3:
                            	System.out.print("Indique el nombre del fichero clave: ");
								clave = sc.next();
								System.out.print("Indique el nombre del fichero a descifrar: ");
								archivo_cifrado = sc.next();
								System.out.print("Indique donde dejar el fichero descifrado: ");
								archivo_original = sc.next();
                            	Simetrica.descifrar(clave, archivo_cifrado, archivo_original);
                                break;
                        }
                    } while (menu2 != 0);
                    break;
                case 2:
                    do {
                        System.out.println("Elija una opcion para CRIPTOGRAFIA ASIMETRICA:");
                        System.out.println("0. Volver al menu anterior.");
                        System.out.println("1. Generar pareja de claves.");
                        System.out.println("2. Cifrado.");
                        System.out.println("3. Descifrado.");
                        System.out.println("4. Firmar digitalmente.");
                        System.out.println("5. Verificar firma digital.");
                        menu2 = sc.nextInt();

                        switch (menu2) {
                            case 1:
                                /*completar acciones*/
                            	System.out.print("Escriba el nombre del fichero donde quiere guardar la clave privada: ");
                            	cprivada = sc.next();
                            	System.out.print("Escriba el nombre del fichero donde quiere guardar la clave publica: ");
                            	cpublica = sc.next();
                            	Asimetrica.generarClaves(cprivada,cpublica);
                                break;
                            case 2:
                                /*completar acciones*/
                            	System.out.print("Indique el tipo de clave con el que desea cifrar(publica o privada): ");
								tipo = sc.next();
                            	System.out.print("Indique el nombre del fichero clave: ");
								clave = sc.next();
								System.out.print("Indique el nombre del fichero a cifrar: ");
								archivo_original = sc.next();
								System.out.print("Indique donde dejar el fichero cifrado: ");
								archivo_cifrado = sc.next();
                            	Asimetrica.cifrar(tipo, clave, archivo_original, archivo_cifrado);
                                break;
                            case 3:
                                /*completar acciones*/
                            	System.out.print("Indique el tipo de clave con el que desea descifrar(publica o privada): ");
								tipo = sc.next();
                            	System.out.print("Indique el nombre del fichero clave: ");
								clave = sc.next();
								System.out.print("Indique el nombre del fichero a descifrar: ");
								archivo_cifrado = sc.next();
								System.out.print("Indique donde dejar el fichero descifrado: ");
								archivo_original = sc.next();
                            	Asimetrica.descifrar(tipo, clave, archivo_cifrado, archivo_original);
                                break;
                            case 4:
                                /*completar acciones*/
                            	System.out.print("Indique el nombre del fichero de la clave privada: ");
								clave = sc.next();
								System.out.print("Indique el nombre del fichero con el mensaje en claro: ");
								archivo_cifrado = sc.next();
								System.out.print("Indique donde dejar el fichero para dejar la firma: ");
								archivo_original = sc.next();
                            	Asimetrica.firmar(clave, archivo_cifrado, archivo_original);
                                break;
                            case 5:
                                /*completar acciones*/
                            	System.out.print("Indique el nombre del fichero de la clave publica: ");
								clave = sc.next();
								System.out.print("Indique el nombre del fichero con el mensaje en claro: ");
								archivo_cifrado = sc.next();
								System.out.print("Indique el nombre del fichero que contiene la firma: ");
								archivo_original = sc.next();
                            	Asimetrica.comprobarFirmar(clave, archivo_cifrado, archivo_original);
                                break;
                        }
                    } while (menu2 != 0);
                    break;
            }
        } while (menu1 != 3);
        sc.close();
    }
}
