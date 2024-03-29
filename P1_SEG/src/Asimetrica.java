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
import java.util.Arrays;

import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;



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
		// Paso 1: Leer el m�dulo y el exponente de la clave
		BufferedReader lectorClave = new BufferedReader(new FileReader(clave));
		BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
		BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
		lectorClave.close();
		// Paso 2: Par�metros para el m�todo init del cifrador
		RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente);
		// Paso 3: Instanciar el cifrador
		AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
		cifrador.init(true, parametros);
		 
		
		try (BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(archivo_original));
				BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(archivo_cifrado))) {
			// creamos los arrays de bytes que contendr�n los datos leidos y los datos
			// cifrados
			byte[] datosLeidos = new byte[cifrador.getInputBlockSize()]; // el tama�o del array de bytes es el tama�o
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
		// Paso 1: Leer el m�dulo y el exponente de la clave
		try (BufferedReader lectorClave = new BufferedReader(new FileReader(clave))) {
            BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
            BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));
            // Paso 2: Par�metros para el m�todo init del cifrador
            RSAKeyParameters parametros = new RSAKeyParameters(tipo.equals("privada"), modulo, exponente);
            // Paso 3: Instanciar el cifrador
            AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
            cifrador.init(false, parametros);

            // Abrimos los flujos de entrada y salida
            try (BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(archivo_cifrado));
                    BufferedOutputStream salida = new BufferedOutputStream(new FileOutputStream(archivo_original))) {
                // creamos los arrays de bytes que contendr�n los datos le�dos y los datos descifrados
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
	public static void firmar(String privada, String mensaje, String firma) throws FileNotFoundException, IOException, InvalidCipherTextException {
		try (BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(mensaje));
	             BufferedOutputStream salidaFirma = new BufferedOutputStream(new FileOutputStream(firma))) {
			Digest resumen = new SHA1Digest();
			resumen.reset(); // reset the digest back to it's initial state

			byte[] datosLeidos = new byte[resumen.getDigestSize()];
			byte[] datosFirmados = new byte[resumen.getDigestSize()];

			BufferedInputStream enClaro = new BufferedInputStream(new FileInputStream(mensaje));
			BufferedOutputStream firmado = new BufferedOutputStream(new FileOutputStream(firma));

			int leidos;
			// bucle de lectura de bloques del fichero con m�todo update
			while ((leidos = enClaro.read(datosLeidos)) != -1) { // Mientras que haya cosas que firmar
				resumen.update(datosLeidos, 0, leidos); // las actualiza, update the message digest with a block of bytes
			}
			// finalizar la operaci�n de resumen y escribirlos en el fichero nombreFirma
			resumen.doFinal(datosFirmados, 0); // close the digest, producing the final digest value
			firmado.write(datosFirmados); // las escribo en el fichero nombreFirma

			// cierro los Input, Output streams
			enClaro.close();
			firmado.close();
			
			cifrar("privada", privada, firma,"resumencifrado_"+firma);
			System.out.println("Se ha guardado la firma cifrada en el archivo 'cifrado_" + firma + "'");
		}
	}
	public static void comprobarFirmar(String publica,String mensaje,String firma) throws InvalidCipherTextException {
		try (BufferedInputStream entrada = new BufferedInputStream(new FileInputStream(mensaje))){
			Digest resumen = new SHA1Digest();
			byte[] datosLeidos = new byte[resumen.getDigestSize()];
			byte[] datosFirmados = new byte[resumen.getDigestSize()]; 
																		
			int leidos;
			while ((leidos = entrada.read(datosLeidos)) != -1) {
				resumen.update(datosLeidos, 0, leidos);
				}
			resumen.doFinal(datosFirmados, 0); 
												
			entrada.close();

			descifrar("publica", publica, firma, "firmaTemporal.txt");

			BufferedInputStream temporal = new BufferedInputStream(new FileInputStream("firmaTemporal.txt"));
			byte[] hash = new byte[temporal.available()];

			temporal.read(hash);
			temporal.close();

			if (Arrays.equals(datosFirmados, hash)) {
				System.out.println("La firma es correcta");
			} else {
				System.out.println("La firma no es correcta");
			}

			} catch (IOException e) {
				e.printStackTrace();
			}
		}
}