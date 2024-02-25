import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.AsymmetricBlockCipher;


public class Asimetrica {
	public static void generarClaves(String ficheroClavePrivada,String ficheroClavePublica) {
		RSAKeyGenerationParameters parametros =new RSAKeyGenerationParameters(BigInteger.valueOf(17),new SecureRandom(), 2048, 10);
		RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator();
		//Generar par de claves
		generadorClaves.init(parametros);
		AsymmetricCipherKeyPair parClaves = generadorClaves.generateKeyPair();
        RSAKeyParameters cprivada = (RSAKeyParameters) parClaves.getPrivate(); 
        RSAKeyParameters cpublica = (RSAKeyParameters) parClaves.getPublic(); 
		try {
			PrintWriter ficheroPrivada = new PrintWriter(new FileWriter(ficheroClavePrivada));
			ficheroPrivada.println(new String (Hex.encode(cprivada.getModulus().toByteArray())));
			ficheroPrivada.print(new String (Hex.encode(cprivada.getExponent().toByteArray())));
			ficheroPrivada.close();
			System.out.println("Clave asimetrica privada generada y guardada en el archivo: " + ficheroClavePrivada);
			} catch (FileNotFoundException e) {
			e.printStackTrace();
			} catch (IOException e) {
			e.printStackTrace();
			}
		try {
			PrintWriter ficheroPublica = new PrintWriter(new FileWriter(ficheroClavePublica));
			ficheroPublica.println(new String (Hex.encode(cpublica.getModulus().toByteArray())));
			ficheroPublica.print(new String (Hex.encode(cpublica.getExponent().toByteArray())));
			ficheroPublica.close();
			System.out.println("Clave asimetrica publica generada y guardada en el archivo: " + ficheroClavePublica);
			} catch (FileNotFoundException e) {
			e.printStackTrace();
			} catch (IOException e) {
			e.printStackTrace();
			}
	}
	public static void cifrar(String tipo, String clave, String archivo_original, String archivo_cifrado) throws IOException, InvalidCipherTextException {
		// Paso 1: Leer el módulo y el exponente de la clave
		BufferedReader lectorClave = new BufferedReader(new FileReader(clave));
		BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
		BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
		lectorClave.close();
		// Paso 2: Parámetros para el método init del cifrador
		RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente);
		// Paso 3: Instanciar el cifrador
		AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
		cifrador.init(true, parametros);
		 
		
		try (BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(archivo_original));
				BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(archivo_cifrado))) {
			// creamos los arrays de bytes que contendrán los datos leidos y los datos
			// cifrados
			byte[] datosLeidos = new byte[cifrador.getInputBlockSize()]; // el tamaño del array de bytes es el tamaño
																			// del bloque de entrada del cifrador
			int leidos;

			// Leer bloques del archivo de entrada y cifrarlos
			while ((leidos = entrada.read(datosLeidos)) != -1) { // Mientras que haya datos que leer
				byte[] datosCifrados = cifrador.processBlock(datosLeidos, 0, leidos);// Los cifra
				salida.write(datosCifrados);// Los escribe
			}
			salida.close();
			entrada.close();
			System.out.println("Archivo cifrado correctamente.");
		}catch (IOException e) {
            e.printStackTrace();
        }
	}
	public static void descifrar(String tipo, String clave, String archivo_cifrado, String archivo_original) throws IOException, InvalidCipherTextException {
		// Paso 1: Leer el módulo y el exponente de la clave
		try (BufferedReader lectorClave = new BufferedReader(new FileReader(clave))) {
            BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
            BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
            // Paso 2: Parámetros para el método init del cifrador
            RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente);
            // Paso 3: Instanciar el cifrador
            AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
            cifrador.init(false, parametros);

            // Abrimos los flujos de entrada y salida
            try (BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(archivo_cifrado));
                    BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(archivo_original))) {
                // creamos los arrays de bytes que contendrán los datos leídos y los datos descifrados
                byte[] datosCifrados = new byte[cifrador.getInputBlockSize()];
                byte[] datosDescifrados;
                int leidos;

                // Leer bloques del archivo cifrado y descifrarlos
                while ((leidos = entrada.read(datosCifrados)) != -1) { // Mientras que haya datos que leer
                    datosDescifrados = cifrador.processBlock(datosCifrados, 0, leidos); // Los descifra
                    salida.write(datosDescifrados); // Los escribe
                }
                salida.close();
                entrada.close();
                System.out.println("Archivo descifrado correctamente.");
            }catch (IOException e) {
            	e.printStackTrace();
            }
		}
	}
}