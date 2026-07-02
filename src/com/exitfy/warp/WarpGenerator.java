package com.exitfy.warp;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URLEncoder;
import java.net.URL;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class WarpGenerator {
    private static final BigInteger P = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19));
    private static final BigInteger A24 = BigInteger.valueOf(121665);
    private static final SecureRandom RNG = new SecureRandom();

    private WarpGenerator() {}

    public static String generate() throws Exception {
        byte[] privateKey = new byte[32];
        RNG.nextBytes(privateKey);
        clamp(privateKey);
        byte[] publicKey = x25519(privateKey, basePoint());
        String publicKeyB64 = b64(publicKey);
        String privateKeyB64 = b64(privateKey);

        String body = "{\"key\":\"" + json(publicKeyB64) + "\",\"install_id\":\"\",\"fcm_token\":\"\",\"tos\":\"" + System.currentTimeMillis() + "\",\"type\":\"Android\",\"model\":\"Android\",\"locale\":\"en_US\"}";
        String response = post("https://api.cloudflareclient.com/v0a4005/reg", body);

        String peerKey = first(response, "\\\"public_key\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
        String endpoint = first(response, "\\\"host\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
        String v4 = first(response, "\\\"v4\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
        String v6 = first(response, "\\\"v6\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");
        String clientId = first(response, "\\\"client_id\\\"\\s*:\\s*\\\"([^\\\"]+)\\\"");

        if (peerKey.length() == 0) {
            peerKey = "bmXOC+F1Q3YH5T4Kv8B3K+t2Bc7qkfjr10T1BG4BhkE=";
        }
        if (endpoint.length() == 0) {
            endpoint = "engage.cloudflareclient.com:2408";
        }
        if (v4.length() == 0) {
            v4 = "172.16.0.2";
        }
        if (v6.length() == 0) {
            v6 = "2606:4700:110:8765:93e4:6b5b:4b3d:1f8e";
        }

        String host = endpoint;
        String port = "2408";
        int idx = endpoint.lastIndexOf(':');
        if (idx > 0 && idx < endpoint.length() - 1) {
            host = endpoint.substring(0, idx);
            port = endpoint.substring(idx + 1);
        }
        String reserved = reservedFromClientId(clientId);
        StringBuilder uri = new StringBuilder();
        uri.append("wireguard://").append(enc(privateKeyB64)).append('@').append(host).append(':').append(port);
        uri.append("?public_key=").append(enc(peerKey));
        uri.append("&address=").append(enc(v4 + "/32"));
        uri.append("&address6=").append(enc(v6 + "/128"));
        uri.append("&mtu=1280");
        if (reserved.length() > 0) {
            uri.append("&reserved=").append(enc(reserved));
        }
        uri.append("#Cloudflare%20WARP");
        return uri.toString();
    }

    private static String post(String url, String body) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("POST");
        c.setConnectTimeout(15000);
        c.setReadTimeout(20000);
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type", "application/json; charset=UTF-8");
        c.setRequestProperty("Accept", "application/json");
        c.setRequestProperty("User-Agent", "okhttp/3.12.1");
        c.setRequestProperty("CF-Client-Version", "a-6.30-3596");
        byte[] bytes = body.getBytes("UTF-8");
        c.setRequestProperty("Content-Length", String.valueOf(bytes.length));
        OutputStream os = c.getOutputStream();
        os.write(bytes);
        os.close();
        int code = c.getResponseCode();
        InputStream is = code >= 200 && code < 300 ? c.getInputStream() : c.getErrorStream();
        String text = readAll(is);
        if (code < 200 || code >= 300) {
            throw new RuntimeException("warp api http " + code + ": " + text);
        }
        return text;
    }

    private static String readAll(InputStream is) throws Exception {
        if (is == null) return "";
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = is.read(buf)) >= 0) out.write(buf, 0, n);
        return new String(out.toByteArray(), "UTF-8");
    }

    private static String first(String text, String regex) {
        Matcher m = Pattern.compile(regex).matcher(text == null ? "" : text);
        return m.find() ? m.group(1) : "";
    }

    private static String reservedFromClientId(String clientId) {
        try {
            if (clientId == null || clientId.length() == 0) return "";
            byte[] raw = Base64.getDecoder().decode(clientId);
            if (raw.length < 3) return "";
            return (raw[0] & 255) + "," + (raw[1] & 255) + "," + (raw[2] & 255);
        } catch (Throwable t) {
            return "";
        }
    }

    private static String enc(String s) throws Exception {
        return URLEncoder.encode(s == null ? "" : s, "UTF-8").replace("+", "%20");
    }

    private static String json(String s) {
        return (s == null ? "" : s).replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String b64(byte[] b) {
        return Base64.getEncoder().encodeToString(b);
    }

    private static byte[] basePoint() {
        byte[] u = new byte[32];
        u[0] = 9;
        return u;
    }

    private static void clamp(byte[] k) {
        k[0] &= 248;
        k[31] &= 127;
        k[31] |= 64;
    }

    private static byte[] x25519(byte[] scalar, byte[] point) {
        BigInteger x1 = leToBig(point);
        BigInteger x2 = BigInteger.ONE;
        BigInteger z2 = BigInteger.ZERO;
        BigInteger x3 = x1;
        BigInteger z3 = BigInteger.ONE;
        int swap = 0;
        for (int t = 254; t >= 0; t--) {
            int kt = (scalar[t >>> 3] >>> (t & 7)) & 1;
            swap ^= kt;
            BigInteger[] a = cswap(swap, x2, x3); x2 = a[0]; x3 = a[1];
            BigInteger[] b = cswap(swap, z2, z3); z2 = b[0]; z3 = b[1];
            swap = kt;

            BigInteger A = x2.add(z2).mod(P);
            BigInteger AA = A.multiply(A).mod(P);
            BigInteger B = x2.subtract(z2).mod(P);
            BigInteger BB = B.multiply(B).mod(P);
            BigInteger E = AA.subtract(BB).mod(P);
            BigInteger C = x3.add(z3).mod(P);
            BigInteger D = x3.subtract(z3).mod(P);
            BigInteger DA = D.multiply(A).mod(P);
            BigInteger CB = C.multiply(B).mod(P);
            BigInteger dapcb = DA.add(CB).mod(P);
            BigInteger damcb = DA.subtract(CB).mod(P);
            x3 = dapcb.multiply(dapcb).mod(P);
            z3 = x1.multiply(damcb.multiply(damcb).mod(P)).mod(P);
            x2 = AA.multiply(BB).mod(P);
            z2 = E.multiply(AA.add(A24.multiply(E)).mod(P)).mod(P);
        }
        BigInteger[] a = cswap(swap, x2, x3); x2 = a[0];
        BigInteger[] b = cswap(swap, z2, z3); z2 = b[0];
        BigInteger out = x2.multiply(z2.modPow(P.subtract(BigInteger.valueOf(2)), P)).mod(P);
        return bigToLe(out);
    }

    private static BigInteger[] cswap(int swap, BigInteger a, BigInteger b) {
        return swap == 0 ? new BigInteger[]{a, b} : new BigInteger[]{b, a};
    }

    private static BigInteger leToBig(byte[] in) {
        byte[] be = new byte[in.length + 1];
        for (int i = 0; i < in.length; i++) be[in.length - i] = in[i];
        return new BigInteger(be);
    }

    private static byte[] bigToLe(BigInteger v) {
        byte[] be = v.mod(P).toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < 32; i++) {
            int src = be.length - 1 - i;
            out[i] = src >= 0 ? be[src] : 0;
        }
        return out;
    }
}
