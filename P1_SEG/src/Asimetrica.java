import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.File;
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

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.encoders.Hex;


public class Asimetrica {

    public void generadorParejaClaves(String ficheroClavePrivada, String ficheroClavePublica) {
        RSAKeyGenerationParameters parametros = new RSAKeyGenerationParameters(BigInteger.valueOf(3),
                new SecureRandom(), 2048, 10);
        RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator();
        generadorClaves.init(parametros);
        AsymmetricCipherKeyPair clavePareja = generadorClaves.generateKeyPair();

        RSAPrivateCrtKeyParameters cprivada = (RSAPrivateCrtKeyParameters) clavePareja.getPrivate();
        RSAKeyParameters cpublica = (RSAKeyParameters) clavePareja.getPublic();

        try (PrintWriter ficheroPrivada = new PrintWriter(new FileWriter(ficheroClavePrivada));
                PrintWriter ficheroPublica = new PrintWriter(new FileWriter(ficheroClavePublica))) {

            ficheroPrivada.println(new String(Hex.encode(cprivada.getModulus().toByteArray())));
            ficheroPrivada.print(new String(Hex.encode(cprivada.getExponent().toByteArray())));

            ficheroPublica.println(new String(Hex.encode(cpublica.getModulus().toByteArray())));
            ficheroPublica.print(new String(Hex.encode(cpublica.getExponent().toByteArray())));

        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void cifrar(String ficheroClave, String ficheroACifrar, String ficheroCifrado, String tipoClave) {
        RSAKeyParameters parametros;
        AsymmetricBlockCipher cifrador;
        boolean tipo = false;
        try (BufferedInputStream fichACifrar = new BufferedInputStream(new FileInputStream(new File(ficheroACifrar)));
                BufferedOutputStream fichCifrado = new BufferedOutputStream(new FileOutputStream(new File(ficheroCifrado)));
                BufferedReader lectorClave = new BufferedReader(new FileReader(ficheroClave))) {

            BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
            BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));

            if (tipoClave.equals("privada")) {
                tipo = true;
            } else if (tipoClave.equals("publica")) {
                tipo = false;
            }
            parametros = new RSAKeyParameters(tipo, modulo, exponente);
            cifrador = new PKCS1Encoding(new RSAEngine());
            cifrador.init(true, parametros);
            byte[] datosLeidos = new byte[cifrador.getInputBlockSize()];
            int leidos = 0;
            leidos = fichACifrar.read(datosLeidos, 0, cifrador.getInputBlockSize());
            byte[] datosCifrados;
            while (leidos > 0) {
                datosCifrados = cifrador.processBlock(datosLeidos, 0, leidos);
                fichCifrado.write(datosCifrados);
                leidos = fichACifrar.read(datosLeidos, 0, cifrador.getInputBlockSize());
            }
        } catch (IOException | InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }

    public void descifrar(String ficheroClave, String ficheroADescifrar, String ficheroDescifrado, String tipoClave) {
        RSAKeyParameters parametros;
        AsymmetricBlockCipher cifrador;
        boolean tipo = false;
        try (BufferedInputStream fichDescifrar = new BufferedInputStream(
                new FileInputStream(new File(ficheroADescifrar)));
                BufferedOutputStream fichDescifrado = new BufferedOutputStream(
                        new FileOutputStream(new File(ficheroDescifrado)));
                BufferedReader lectorClave = new BufferedReader(new FileReader(ficheroClave))) {

            BigInteger modulo = new BigInteger(Hex.decode(lectorClave.readLine()));
            BigInteger exponente = new BigInteger(Hex.decode(lectorClave.readLine()));

            if (tipoClave.equals("privada")) {
                tipo = true;
            } else if (tipoClave.equals("publica")) {
                tipo = false;
            }
            parametros = new RSAKeyParameters(tipo, modulo, exponente);
            cifrador = new PKCS1Encoding(new RSAEngine());
            cifrador.init(false, parametros);
            byte[] datosLeidos = new byte[cifrador.getInputBlockSize()];
            int leidos = 0;
            leidos = fichDescifrar.read(datosLeidos, 0, cifrador.getInputBlockSize());
            byte[] datosDescifrados;
            while (leidos > 0) {
                datosDescifrados = cifrador.processBlock(datosLeidos, 0, leidos);
                fichDescifrado.write(datosDescifrados);
                leidos = fichDescifrar.read(datosLeidos, 0, cifrador.getInputBlockSize());
            }
        } catch (IOException | InvalidCipherTextException e) {
            e.printStackTrace();
        }
    }

    public void firmar(String ficheroClave, String ficheroClaro, String ficheroConFirma) {
        SHA3Digest resumen;
        try (FileInputStream ficheroEnClaro = new FileInputStream(new File(ficheroClaro));
                BufferedOutputStream ficheroResumen = new BufferedOutputStream(
                        new FileOutputStream(new File("resumen.txt")))) {

            resumen = new SHA3Digest();
            byte[] bloqueLeido = new byte[resumen.getDigestSize()];
            byte[] bloqueFirmado = new byte[resumen.getDigestSize()];
            int leidos = ficheroEnClaro.read(bloqueLeido, 0, bloqueLeido.length);
            while (leidos > 0) {
                resumen.update(bloqueLeido, 0, leidos);
                leidos = ficheroEnClaro.read(bloqueLeido, 0, bloqueLeido.length);
            }
            resumen.doFinal(bloqueFirmado, 0);
            ficheroResumen.write(bloqueFirmado);
            this.cifrar(ficheroClave, "resumen.txt", ficheroConFirma, "privada");
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException | DataLengthException e) {
            e.printStackTrace();
        }
    }

    public boolean verificarFirma(String ficheroClave, String ficheroClaro, String ficheroConFirma) {
        SHA3Digest resumen;
        boolean verificado = false;
        try (FileInputStream leerFicheroEnClaro = new FileInputStream(new File(ficheroClaro));
                BufferedInputStream resumenDes = new BufferedInputStream(
                        new FileInputStream(new File("resumenDescifrado.txt")))) {

            resumen = new SHA3Digest();
            byte[] bloqueLeido = new byte[resumen.getDigestSize()];
            byte[] resumenGenerado = new byte[resumen.getDigestSize()];
            byte[] resumenRecibidoDescifrado = new byte[resumen.getDigestSize()];
            int leidos = leerFicheroEnClaro.read(bloqueLeido);
            while (leidos > 0) {
                resumen.update(bloqueLeido, 0, bloqueLeido.length);
                leidos = leerFicheroEnClaro.read(bloqueLeido);
            }
            resumen.doFinal(resumenGenerado, 0);
            resumenDes.read(resumenRecibidoDescifrado);
            verificado = Arrays.equals(resumenRecibidoDescifrado, resumenGenerado);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return verificado;
    }
}
