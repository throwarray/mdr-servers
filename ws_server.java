import java.io.*;
import java.net.*;
import java.security.*;
import java.text.*;
import java.util.*;
import java.util.concurrent.*;

// A unique id to refer to this script.
final String script_id = Long.toHexString(Long.parseLong("[macro_id]")) + "_webSocket";

final int PORT = magicText.evaluateInt("[lv=WS_SERVER_PORT]");
final int wpollrate = 150;
final int wtimeout = 3500;
final int READ_TIMEOUT = 30000;
final int PING_INTERVAL = 20000;

final Thread mainThread = Thread.currentThread();
final ServerSocket server = new ServerSocket();
server.setReuseAddress(true);

final Set clientSet = Collections.synchronizedSet(new HashSet());
final ExecutorService wsPool = Executors.newFixedThreadPool(8);
volatile boolean watching = false;
volatile boolean should_exit = false;

final int OPCODE_CONTINUATION = 0x0;
final int OPCODE_TEXT = 0x1;
final int OPCODE_BINARY = 0x2;
final int OPCODE_CLOSE = 0x8;
final int OPCODE_PING = 0x9;
final int OPCODE_PONG = 0xA;

// CLIENTS
void handleClient(
    Socket sock,
    InputStream in,
    OutputStream out
) throws Exception {
    try {
        while (!server.isClosed() && !sock.isClosed() && !mainThread.isInterrupted() && should_exit == false) {
            Map frame = readWsFrame(in);
            if (frame == null) break;
            int opcode = (Integer) frame.get("opcode");
            byte[] payload = (byte[]) frame.get("payload");

            if (opcode == OPCODE_TEXT) {
                Object parsed = parseJson(new String(payload, "UTF-8"));
                if (!(parsed instanceof Map)) continue;
                Map msg = (Map) parsed;

                Object typeObj = msg.get("type");
                if (typeObj != null && "say".equals(typeObj.toString())) {
                    String name = "anonymous";
                    String text = "";

                    Object nameObj = msg.get("name");
                    if (nameObj != null) name = nameObj.toString();

                    Object textObj = msg.get("text");
                    if (textObj != null) text = textObj.toString();

                    Map responseMap = new HashMap();
                    responseMap.put("type", "said");
                    responseMap.put("name", name);
                    responseMap.put("text", text);

                    String response = jsonEncode(responseMap);
                    sendText(out, response);
                }
            }
            else if (opcode == OPCODE_PING) {
                writeWsFrame(out, OPCODE_PONG, payload);
            }
            else if (opcode == OPCODE_PONG) {
                continue;
            }
            else if (opcode == OPCODE_CLOSE) {
                return;
            }
        }
    } catch (Exception e) {
        // Optional logging
    } finally {
        try { sock.close(); } catch (Exception ignore) {}
    }
}

void sendText(OutputStream out, String msg) throws Exception {
    writeWsFrame(out, OPCODE_TEXT, msg.getBytes("UTF-8"));
}

String parseHandshake(BufferedReader reader) throws Exception {
    String key = null, line;

    // Read headers until blank line
    while ((line = reader.readLine()) != null && line.length() > 0) {
        if (line.startsWith("Sec-WebSocket-Key:")) {
            key = line.substring(19).trim();
        }
    }
    return key;
}

void sendHandshake(PrintWriter writer, String key) throws Exception {
    String accept = base64Encode(
        MessageDigest.getInstance("SHA-1").digest(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").getBytes("UTF-8")
        )
    );

    writer.print("HTTP/1.1 101 Switching Protocols\r\n");
    writer.print("Upgrade: websocket\r\n");
    writer.print("Connection: Upgrade\r\n");
    writer.print("Sec-WebSocket-Accept: " + accept + "\r\n\r\n");
    writer.flush();
}

void doHandshake(Socket client) throws Exception {
    BufferedReader reader = new BufferedReader(
        new InputStreamReader(client.getInputStream(), "UTF-8")
    );

    String key = parseHandshake(reader);

    PrintWriter writer = new PrintWriter(
        new OutputStreamWriter(client.getOutputStream(), "UTF-8"),
        true
    );

    if (key == null) {
        writer.print("HTTP/1.1 400 Bad Request\r\n");
        writer.print("Connection: close\r\n");
        writer.print("Content-Length: 0\r\n\r\n");
        writer.flush();
        throw new IOException("WebSocket key not found");
    }

    sendHandshake(writer, key);
}

Map readWsFrame(InputStream in) throws Exception {
    Map frame = new HashMap();
    int b0 = in.read(); if (b0 == -1) return null;
    int b1 = in.read(); if (b1 == -1) return null;

    int opcode = b0 & 0x0F;
    boolean masked = (b1 & 0x80) != 0;
    int len = b1 & 0x7F;

    if (len == 126) {
        int hi = in.read(); if (hi == -1) throw new IOException("Unexpected end of stream (len hi)");
        int lo = in.read(); if (lo == -1) throw new IOException("Unexpected end of stream (len lo)");
        len = ((hi & 0xFF) << 8) | (lo & 0xFF);
    } else if (len == 127) {
        for (int i = 0; i < 8; i++) {
            if (in.read() == -1) throw new IOException("Unexpected end of stream while skipping long length");
        }
        throw new IOException("Frame too large — unsupported");
    }

    byte[] mask = new byte[4];
    if (masked) {
        int read = 0;
        while (read < 4) {
            int r = in.read(mask, read, 4 - read);
            if (r == -1) throw new IOException("Unexpected end of stream while reading mask");
            read += r;
        }
    }

    byte[] payload = new byte[len];
    for (int i = 0; i < len; i++) {
        int b = in.read();
        if (b == -1) throw new IOException("Unexpected end of stream while reading payload");
        payload[i] = (byte) (b ^ (masked ? mask[i % 4] : 0));
    }

    frame.put("opcode", opcode);
    frame.put("payload", payload);
    return frame;
}

void writeWsFrame(OutputStream out, int opcode, byte[] payload) throws Exception {
    int len = payload.length;
    out.write((byte) (0x80 | opcode)); // FIN + opcode

    if (len <= 125) {
        out.write((byte) len);
    } else if (len < 65536) {
        out.write(126);
        out.write((len >> 8) & 0xFF);
        out.write(len & 0xFF);
    } else {
        out.write(127);
        for (int i = 7; i >= 0; i--) {
            out.write((len >> (8 * i)) & 0xFF);
        }
    }

    out.write(payload);
    out.flush();
}

// UTILS
String jsonEncode(Object obj) throws Exception {
    if (obj == null) return "null";
    if (obj instanceof Boolean || obj instanceof Number) return obj.toString();
    if (obj instanceof String) {
        String s = (String) obj;
        StringBuilder out = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20 || c > 0x7F) {
                        out.append(String.format("\\u%04x", (int)c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append("\"");
        return out.toString();
    }
    if (obj instanceof Map) {
        StringBuilder out = new StringBuilder("{");
        Iterator it = ((Map) obj).entrySet().iterator();
        while (it.hasNext()) {
            Map.Entry e = (Map.Entry) it.next();
            out.append(jsonEncode(e.getKey())).append(":").append(jsonEncode(e.getValue()));
            if (it.hasNext()) out.append(",");
        }
        out.append("}");
        return out.toString();
    }
    if (obj instanceof List) {
        StringBuilder out = new StringBuilder("[");
        Iterator it = ((List) obj).iterator();
        while (it.hasNext()) {
            out.append(jsonEncode(it.next()));
            if (it.hasNext()) out.append(",");
        }
        out.append("]");
        return out.toString();
    }
    throw new Exception("Unsupported type: " + obj.getClass());
}

Object parseJson(String raw) throws Exception {
    String jsonParse_src = raw.trim();
    int[]  jsonParse_i   = { 0 };        // index holder
    return jsonParse_parse(jsonParse_src, jsonParse_i);
}

// skip whitespace
void jsonParse_skipWhitespace(String src, int[] i) {
    while (i[0] < src.length() && Character.isWhitespace(src.charAt(i[0]))) {
        i[0]++;
    }
}

// dispatch based on next token
Object jsonParse_parse(String src, int[] i) throws Exception {
    jsonParse_skipWhitespace(src, i);
    if (i[0] >= src.length()) {
        throw new Exception("Unexpected end of JSON");
    }
    char c = src.charAt(i[0]);
         if (c == '{') return jsonParse_parseObject(src, i);
    else if (c == '[') return jsonParse_parseArray(src, i);
    else if (c == '"') return jsonParse_parseString(src, i);
    else if (c == '-' || Character.isDigit(c)) {
        return jsonParse_parseNumber(src, i);
    }
    else if (src.startsWith("true",  i[0])) { i[0] += 4; return Boolean.TRUE;  }
    else if (src.startsWith("false", i[0])) { i[0] += 5; return Boolean.FALSE; }
    else if (src.startsWith("null",  i[0])) { i[0] += 4; return null;          }
    else {
        throw new Exception("Unexpected character '" + c + "' at pos " + i[0]);
    }
}

// object: { "key": value, … }
Map jsonParse_parseObject(String src, int[] i) throws Exception {
    Map obj = new HashMap();
    i[0]++;
    jsonParse_skipWhitespace(src, i);
    if (src.charAt(i[0]) == '}') {
        i[0]++;
        return obj;
    }
    while (true) {
        jsonParse_skipWhitespace(src, i);
        if (src.charAt(i[0]) != '"') {
            throw new Exception("Expected '\"' at pos " + i[0]);
        }
        String key = jsonParse_parseString(src, i);
        jsonParse_skipWhitespace(src, i);
        if (src.charAt(i[0]) != ':') {
            throw new Exception("Expected ':' after key at pos " + i[0]);
        }
        i[0]++;
        Object val = jsonParse_parse(src, i);
        obj.put(key, val);
        jsonParse_skipWhitespace(src, i);
        char sep = src.charAt(i[0]);
        if (sep == ',') { i[0]++; continue; }
        if (sep == '}') { i[0]++; break;   }
        throw new Exception("Expected ',' or '}' at pos " + i[0]);
    }
    return obj;
}

// array: [ v0, v1, … ]
List jsonParse_parseArray(String src, int[] i) throws Exception {
    List arr = new ArrayList();
    i[0]++;
    jsonParse_skipWhitespace(src, i);
    if (src.charAt(i[0]) == ']') {
        i[0]++;
        return arr;
    }
    while (true) {
        Object elt = jsonParse_parse(src, i);
        arr.add(elt);
        jsonParse_skipWhitespace(src, i);
        char sep = src.charAt(i[0]);
        if (sep == ',') { i[0]++; continue; }
        if (sep == ']') { i[0]++; break;   }
        throw new Exception("Expected ',' or ']' at pos " + i[0]);
    }
    return arr;
}

// string literal, with escapes
String jsonParse_parseString(String src, int[] i) throws Exception {
    StringBuilder sb = new StringBuilder();
    i[0]++;
    while (i[0] < src.length()) {
        char c = src.charAt(i[0]++);
        if (c == '"') return sb.toString();
        if (c == '\\') {
            if (i[0] >= src.length()) {
                throw new Exception("Unfinished escape at end of string");
            }
            char esc = src.charAt(i[0]++);
            switch (esc) {
                case '"' : sb.append('"');  break;
                case '\\': sb.append('\\'); break;
                case '/':  sb.append('/');  break;
                case 'b':  sb.append('\b'); break;
                case 'f':  sb.append('\f'); break;
                case 'n':  sb.append('\n'); break;
                case 'r':  sb.append('\r'); break;
                case 't':  sb.append('\t'); break;
                case 'u':
                    String hex = src.substring(i[0], i[0]+4);
                    i[0] += 4;
                    sb.append((char) Integer.parseInt(hex, 16));
                    break;
                default:
                    throw new Exception("Unknown escape: \\" + esc);
            }
        } else {
            sb.append(c);
        }
    }
    throw new Exception("Unterminated string literal");
}

// number literal (int or float)
Object jsonParse_parseNumber(String src, int[] i) throws Exception {
    int start = i[0];
    boolean hasDot = false, hasExp = false;
    while (i[0] < src.length()) {
        char c = src.charAt(i[0]);
        if (Character.isDigit(c) || c=='+'||c=='-') {
            i[0]++;
        }
        else if (c == '.' && !hasDot) {
            hasDot = true;
            i[0]++;
        }
        else if ((c=='e' || c=='E') && !hasExp) {
            hasExp = true;
            i[0]++;
        }
        else break;
    }
    String num = src.substring(start, i[0]);
    return (hasDot || hasExp) ? Double.valueOf(num) : Long.valueOf(num);
}

String base64Encode(byte[] data) {
    final char[] map = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();
    StringBuilder sb = new StringBuilder();
    int pad = 0;

    for (int i = 0; i < data.length; i += 3) {
        int b = ((data[i] & 0xFF) << 16);
        if (i + 1 < data.length) b |= ((data[i + 1] & 0xFF) << 8);
        else pad++;
        if (i + 2 < data.length) b |= (data[i + 2] & 0xFF);
        else pad++;

        sb.append(map[(b >> 18) & 0x3F]);
        sb.append(map[(b >> 12) & 0x3F]);
        sb.append(pad >= 2 ? '=' : map[(b >> 6) & 0x3F]);
        sb.append(pad >= 1 ? '=' : map[b & 0x3F]);
    }

    return sb.toString();
}

byte[] base64Decode(String s) throws Exception {
    int[] map = new int[256];
    for (int i = 0; i < map.length; i++) map[i] = -1;
    for (int i = 0; i < 64; i++) map["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".charAt(i)] = i;

    ByteArrayOutputStream out = new ByteArrayOutputStream();
    int buffer = 0, bits = 0;

    for (int i = 0; i < s.length(); i++) {
        char c = s.charAt(i);
        if (c == '=') break;
        int val = (c < 256) ? map[c] : -1;
        if (val == -1) continue;

        buffer = (buffer << 6) | val;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.write((buffer >> bits) & 0xFF);
        }
    }

    return out.toByteArray();
}

// INIT

// Handle graceful exit and single instance
Thread watcherThread = new Thread(new Runnable() {
    public void run() {
        try {
          Thread currentThread = Thread.currentThread();
          String exec_id = Long.toHexString(currentThread.getId());
          globals.set(script_id, exec_id);
          watching = true;

          while (!mainThread.isInterrupted() && watching == true && should_exit == false) {
            Thread.sleep(wpollrate);
            if (!exec_id.equals(globals.get(script_id))) return;
          }
        } catch (Exception e) {
          // Optional logging
        } finally {
          watching = false;
          should_exit = true;
        }
    }
});

final Thread pingThread = new Thread(new Runnable() {
    public void run() {
        while (!should_exit && !mainThread.isInterrupted()) {
            try {
                Thread.sleep(PING_INTERVAL);

                synchronized (clientSet) {
                    Iterator it = clientSet.iterator();
                    while (it.hasNext()) {
                        Socket s = (Socket) it.next();
                        try {
                            writeWsFrame(s.getOutputStream(), OPCODE_PING, new byte[0]);
                        } catch (Exception e) {
                            it.remove();
                            try { s.close(); } catch (Exception ignore) {}
                        }
                    }
                }
            } catch (InterruptedException ie) {
                break;
            }
        }
    }
});

void addSocketToPool(Socket sock) {
    wsPool.execute(new Runnable() { public void run() {
        Socket client = sock;
        String client_ip = String.valueOf(client.getInetAddress());
        try {
            doHandshake(client);
            clientSet.add(client);
            handleClient(client, client.getInputStream(), client.getOutputStream());
        } catch (SocketTimeoutException e) {
            // Optional logging
        } catch (Throwable t) {
            // Optional logging
        } finally {
            try { clientSet.remove(client); } catch (Exception ignore) {}
            try { client.close(); } catch (IOException ignore) {}
        }
    }});
}

// Cleanup before exit
void cleanup() {
    try { watcherThread.interrupt(); } catch(Exception ignore) {}
    try { pingThread.interrupt(); } catch(Exception ignore) {}
    try { wsPool.shutdownNow(); } catch(Exception ignore) {}

    synchronized (clientSet) {
        Iterator it = clientSet.iterator();
        while (it.hasNext()) {
            try { ((Socket) it.next()).close(); } catch (IOException ignore) {}
            it.remove();
        }
    }

    try { server.close(); } catch(Exception ignore) {}

    watching = false;
    should_exit = true;
    variableSetter.setBoolean("ws_server_up", false);
}

try {
    watcherThread.setDaemon(true);
    watcherThread.start();

    int wtime = 0; 
    do {
        Thread.sleep(wpollrate * 2);
        wtime = wtime + (wpollrate * 2);
    } while (watching == false && should_exit == false && wtime < wtimeout && !mainThread.isInterrupted());

    server.bind(new InetSocketAddress(PORT));
    server.setSoTimeout(READ_TIMEOUT);

    pingThread.start();
    variableSetter.setBoolean("ws_server_up", true);

    while (!should_exit && !server.isClosed() && !mainThread.isInterrupted()) {
        Socket client = null;
        try {
            if ((client = server.accept()) == null) continue;
            client.setSoTimeout(READ_TIMEOUT);
            addSocketToPool(client);
        } catch (SocketTimeoutException e) {
            // Optional logging
        } catch (Exception e) {
            if (client != null) { 
                try { client.close(); } catch(Exception ignore) {}
            }
        }
    }
} catch (Throwable e) {
    throw e;
} finally {
    cleanup();
}

return true;
