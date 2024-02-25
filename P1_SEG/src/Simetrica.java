// En la clase Simetrica.java

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.ThreefishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.paddings.X923Padding;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class Simetrica {
	private static String claveHex;

    public static void setClaveHex(String claveHex) {
        Simetrica.claveHex = claveHex;
    }

    public static String getClaveHex() {
        return claveHex;
    }
    public static void generarClave(String fileName) {
        KeyGenerator generadorClave;
        FileOutputStream salida = null;
        try {
            // Paso 1: Crear objeto generador
            generadorClave = KeyGenerator.getInstance("AES");

            // Paso 2: Inicializar objeto generador
            SecureRandom aleatorio = new SecureRandom();
            generadorClave.init(256, aleatorio);

            // Paso 3: Generar clave
            SecretKey clave = generadorClave.generateKey();

            // Paso 4: Convertir clave a Hexadecimal
            String claveHex = new String(Hex.encode(clave.getEncoded()));

            // Paso 5: Almacenar clave en fichero
            salida = new FileOutputStream(fileName);
            salida.write(claveHex.getBytes());
            System.out.println("Clave simetrica generada y guardada en el archivo: " + fileName);
        } catch (NoSuchAlgorithmException | IOException e) {
            e.printStackTrace();
        } finally {
            if (salida != null) {
                try {
                    salida.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
    public static void cifrar(String clave, String archivo_original, String archivo_cifrado) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        try {
        	String claveHex = Simetrica.leerClave(clave);
            // Paso 1: Decodificar clave de Hex a binario
            byte[] claveBin = Hex.decode(claveHex);
            // Paso 2: Generar parámetros y cargar clave
            KeyParameter  params = new KeyParameter(claveBin);

            // Paso 3: Crear motor de cifrado
            PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new ThreefishEngine(256)), new X923Padding () );

            // Paso 4: Iniciar motor de cifrado con params
            cifrador.init(true, params); // true para cifrar

            // Paso 5: Crear flujos de E/S de ficheros
            BufferedInputStream entrada = new BufferedInputStream(
                new FileInputStream(archivo_original));
            BufferedOutputStream salida = new BufferedOutputStream(
                new FileOutputStream(archivo_cifrado));

            // Paso 6: Crear arrays de bytes para E/S
            byte[] datosLeidos = new byte[cifrador.getBlockSize()];
            byte[] datosCifrados = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];

            // Paso 7: Bucle de lectura, cifrado y escritura
            int bytesLeidos;
            while ((bytesLeidos = entrada.read(datosLeidos)) != -1) {
                int bytesProcesados = cifrador.processBytes(datosLeidos, 0, bytesLeidos, datosCifrados, 0);
                salida.write(datosCifrados, 0, bytesProcesados);
            }
            int bytesProcesados = cifrador.doFinal(datosCifrados, 0);
            salida.write(datosCifrados, 0, bytesProcesados);

            // Paso 8: Cerrar ficheros
            entrada.close();
            salida.close();

            System.out.println("Archivo cifrado correctamente.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static String leerClave(String clave) {
        try {
            BufferedInputStream entrada = new BufferedInputStream(
            new FileInputStream(clave));

            byte[] datosClave = new byte[entrada.available()];
            entrada.read(datosClave);

            entrada.close();

            return new String(datosClave);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }
    public static void descifrar(String clave, String archivo_cifrado, String archivo_original) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        try {
        	String claveHex = Simetrica.leerClave(clave);
            // Paso 1: Decodificar clave de Hex a binario
            byte[] claveBin = Hex.decode(claveHex);
            // Paso 2: Generar parámetros y cargar clave
            KeyParameter  params = new KeyParameter(claveBin);

            // Paso 3: Crear motor de cifrado
            PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new ThreefishEngine(256)), new X923Padding () );

            // Paso 4: Iniciar motor de cifrado con params
            cifrador.init(false, params); // false para descifrar

            // Paso 5: Crear flujos de E/S de ficheros
            BufferedInputStream entrada = new BufferedInputStream(
                new FileInputStream(archivo_cifrado));
            BufferedOutputStream salida = new BufferedOutputStream(
                new FileOutputStream(archivo_original));

            // Paso 6: Crear arrays de bytes para E/S
            byte[] datosLeidos = new byte[cifrador.getBlockSize()];
            byte[] datosCifrados = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];

            // Paso 7: Bucle de lectura, cifrado y escritura
            int bytesLeidos;
            while ((bytesLeidos = entrada.read(datosLeidos)) != -1) {
                int bytesProcesados = cifrador.processBytes(datosLeidos, 0, bytesLeidos, datosCifrados, 0);
                salida.write(datosCifrados, 0, bytesProcesados);
            }
            int bytesProcesados = cifrador.doFinal(datosCifrados, 0);
            salida.write(datosCifrados, 0, bytesProcesados);

            // Paso 8: Cerrar ficheros
            entrada.close();
            salida.close();

            System.out.println("Archivo descifrado correctamente.");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

