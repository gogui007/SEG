import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public class Simetrica {
    public PrivateKey privateKey = null;

    public Simetrica() {
    }

    public void generarClave(String ficheroClave) {
        CipherKeyGenerator genClave = new CipherKeyGenerator();
        genClave.init(new KeyGenerationParameters(new SecureRandom(), 256));
        byte[] claveBin = new byte[32];
        claveBin = genClave.generateKey();
        byte[] claveHex = Hex.encode(claveBin);
        FileOutputStream ficheroKey = null;
        try {
            ficheroKey = new FileOutputStream(ficheroClave);
            ficheroKey.write(claveHex);
        } catch (FileNotFoundException e1) {
            e1.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            if (ficheroKey != null)
                try {
                    System.out.println("La clave se ha generado correctamente");
                    ficheroKey.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        }
    }

    public void cifrar(String ficheroClave, String ficheroACifrar, String ficheroCifrado) throws IOException, DataLengthException, IllegalStateException, InvalidCipherTextException {
        byte[] claveBin;
        byte[] claveHex = new byte[64];
        BufferedOutputStream fichCifrado = null;
        FileInputStream fichK = null;
        BufferedInputStream fichACifrar = null;
        try {
            fichCifrado = new BufferedOutputStream(new FileOutputStream(ficheroCifrado));
            fichK = new FileInputStream(ficheroClave);
            fichACifrar = new BufferedInputStream(new FileInputStream(ficheroACifrar));
            fichK.read(claveHex, 0, 64);
            claveBin = Hex.decode(claveHex);
            KeyParameter params = new KeyParameter(claveBin);
            PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()), new PKCS7Padding());
            cifrador.init(true, params);
            //DATOS LEIDOS
            byte[] bloqueLeido = new byte[cifrador.getBlockSize()]; // Para guardar el fragmento de fichero
            byte[] bloqueCifrado = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];
            int leidos;
            int cifrados = 0;
            leidos = fichACifrar.read(bloqueLeido, 0, cifrador.getBlockSize());
            while (leidos > 0) {
                cifrados = cifrador.processBytes(bloqueLeido, 0, leidos, bloqueCifrado, 0);
                fichCifrado.write(bloqueCifrado, 0, cifrados);
                leidos = fichACifrar.read(bloqueLeido, 0, cifrador.getBlockSize());
            }
            cifrados = cifrador.doFinal(bloqueCifrado, 0);
            //DATOS CIFRADOS
            fichCifrado.write(bloqueCifrado, 0, cifrados);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                fichK.close();
                fichCifrado.close();
                fichACifrar.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void descifrar(String ficheroClave, String ficheroADescifrar, String ficheroDescifrado) throws IOException, DataLengthException, IllegalStateException, InvalidCipherTextException {
        byte[] claveBin;
        byte[] claveHex = new byte[64];
        BufferedOutputStream fichDescifrado = null;
        FileInputStream fichK = null;
        BufferedInputStream fichDescifrar = null;
        try {
            fichDescifrado = new BufferedOutputStream(new FileOutputStream(ficheroDescifrado));
            fichK = new FileInputStream(ficheroClave);
            fichDescifrar = new BufferedInputStream(new FileInputStream(ficheroADescifrar));
            fichK.read(claveHex, 0, 64);
            claveBin = Hex.decode(claveHex);
            KeyParameter params = new KeyParameter(claveBin);
            PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()), new PKCS7Padding());
            cifrador.init(false, params);
            //DATOS LEIDOS
            byte[] bloqueLeido = new byte[cifrador.getBlockSize()]; // Para guardar el fragmento de fichero
            byte[] bloqueCifrado = new byte[cifrador.getOutputSize(cifrador.getBlockSize())];
            int leidos;
            int descifrados = 0;
            leidos = fichDescifrar.read(bloqueLeido, 0, cifrador.getBlockSize());
            while (leidos > 0) {
                descifrados = cifrador.processBytes(bloqueLeido, 0, leidos, bloqueCifrado, 0);
                fichDescifrado.write(bloqueCifrado, 0, descifrados);
                leidos = fichDescifrar.read(bloqueLeido, 0, cifrador.getBlockSize());
            }
            descifrados = cifrador.doFinal(bloqueCifrado, 0);
            //DATOS CIFRADOS
            fichDescifrado.write(bloqueCifrado, 0, descifrados);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            try {
                fichK.close();
                fichDescifrado.close();
                fichDescifrar.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
}
