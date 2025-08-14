import java.io.*;
import java.net.*;
import java.security.*;
import java.text.*;
import java.util.*;
import java.util.concurrent.*;

// SETTINGS
final int PORT = magicText.evaluateInt("[lv=HTTP_SERVER_PORT]");
final File ROOT = new File("/sdcard/http");
final Integer HTTP_POOL_SIZE = 8;
final Integer HTTP_TIMEOUT = 5000;

// Watchdog settings
final int wpollrate = 150;
final int wtimeout = 3000;

// An id constant for to refer to this script
final String script_id = Long.toHexString(Long.parseLong("[macro_id]")) + 
    "_httpServer";

// Serves concurrent requests.
// Adjust worker pool type or size as desired.
final Thread currentThread = Thread.currentThread();
final ExecutorService pool = Executors.newFixedThreadPool(HTTP_POOL_SIZE);
final ServerSocket server = new ServerSocket();
volatile boolean watching = false;
volatile boolean should_exit = false;

// SERVER REQUEST HANDLER
void handleRequest(
    Socket sock, BufferedInputStream in, 
    BufferedOutputStream out
) throws Exception {
    // Parse and reject bad requests
    String[] parts = parseRequest(in, out);
    if (parts == null) { 
        sendSimple(out, 400, "Bad Request");
        return;
    }
    
    // Socket ip i.e 192.168.0.1
    String req_ip = sock.getInetAddress().getHostAddress();
    
    // Parse path name
    String rawURI = parts[1];
    int q = rawURI.indexOf('?');
    String path = (q >= 0) ? rawURI.substring(0, q) : rawURI;
    
    // Accepts get / post requests. Rejects other methods.
    String method = parts[0];
    final boolean IS_POST_REQUEST = "post".equalsIgnoreCase(method);
    final boolean IS_GET_REQUEST = "get".equalsIgnoreCase(method);
    if (IS_POST_REQUEST == false && IS_GET_REQUEST == false) {
        sendSimple(out, 405, "Method Not Allowed"); 
        return;
    }
    
    // Parse headers and urlencoded params (query / form body)
    Map headers = parseHeaders(in);
    Map params = parseUrlEncoded(rawURI);
    Map body = parseUrlEncodedBody(in, headers, "post");

    // Optional per request timeout vs the server default (0 == off)
    sock.setSoTimeout(HTTP_TIMEOUT);

    // HANDLE ROUTES
    // A test route to echo back the query / body params. (GET / POST)
    if ("/echo".equals(path)) {
        // Test parsing bodies and serialization to json
        String json = "{\"params\":" + jsonEncode(
            IS_POST_REQUEST ? body : params
        ) + "}";
        
        byte[] data = json.getBytes("UTF-8");
        send200(out, "application/json", data, null);
        return;
    }

    // ROUTES -- GET REQUESTS
    if (IS_GET_REQUEST == false) {
        send404(out);
        return;
    }
    
    // from memory or fn
    else if ("/hello".equals(path)) {
        sendSimple(out, 200, "Hello World");
        return;
    }
    
    // from disk (beta)
    else if ("/".equals(path)) path = "/index.html";

    serveFile(path, out);

    return;
}

// RESPONSE HELPERS
Void sendSimple(OutputStream out, int code, String msg) throws IOException {
    // Void to support typical `return sendSimple(...` pattern
    
    String body = "<h1>" + code + " " + msg + "</h1>";
    String head = "HTTP/1.1 " + code + " " + msg + 
    "\r\nContent-Type: text/html\r\n" +
    "Content-Length: " + body.length() + 
    "\r\nConnection: close\r\n\r\n";
    
    out.write(head.getBytes("UTF-8"));
    out.write(body.getBytes("UTF-8")); out.flush();

    return null;
}

Void send404 (OutputStream out) throws IOException {
    sendSimple(out, 404, "Not Found");

    return null;
}

Void send200(
    OutputStream out, String mime, byte[] body, String etag
) throws IOException {
    StringBuilder sb = new StringBuilder();
    sb.append("HTTP/1.1 200 OK\r\n");
    sb.append("Content-Type: ").append(mime).append("\r\n");
    sb.append("Content-Length: ").append(body.length).append("\r\n");
    sb.append("Last-Modified: ").append(gmtDate(new Date())).append("\r\n");
    if (etag != null) sb.append("ETag: ").append(etag).append("\r\n");
    sb.append("Connection: close\r\n\r\n");
    out.write(sb.toString().getBytes("UTF-8"));
    out.write(body); out.flush();
    
    return null;
}

Void serveFile (String path, BufferedOutputStream out) throws IOException {
    File file = new File(ROOT, path).getCanonicalFile();
    if (!file.getCanonicalPath().startsWith(
        ROOT.getCanonicalPath()) || !file.exists()
    ) { 
        send404(out);
        
    } else {
        byte[] data = readFile(file);
        String mime = mimeType(path);
        String etag; 
        
        //String etag = weakEtag(data);
        
        send200(out, mime, data, etag);
    }
    
    return null;
}

String[] parseRequest (BufferedInputStream in, BufferedOutputStream out) {
    String reqLine = readLine(in);
    if (reqLine == null || reqLine.length() == 0) return null;
    
    String[] parts = reqLine.split(" ");
    if (parts.length < 3) return null;
    
    return parts;
}

// UTILITY FUNCTIONS

// Parse headers
Map parseHeaders(BufferedInputStream in) {
    Map headers = new HashMap();
    String h;
    int headerLimit = 50;
    
    while ((h = readLine(in)).length() > 0 && 
        headers.size() < headerLimit
    ) {
        int i = h.indexOf(':');
        if (i <= 0) continue; 
        // skip malformed
        String key = h.substring(0, i).toLowerCase().trim();
        String val = h.substring(i + 1).trim();
        headers.put(key, val);
    }
    
    return headers;
}

// Simple mime detection inferred by file ext
String mimeType(String path) {
    path = path.toLowerCase();
    return path.endsWith(".html") ? "text/html" :
        path.endsWith(".css")  ? "text/css" :
        path.endsWith(".js")   ? "application/javascript" :
        path.endsWith(".png")  ? "image/png" :
        path.endsWith(".jpg") || path.endsWith(".jpeg") ? "image/jpeg" :
        path.endsWith(".gif")  ? "image/gif" : "application/octet-stream";
}

Map parseUrlEncoded(String rawURI) {
    Map params = new LinkedHashMap();
    int q = rawURI.indexOf('?');
    if (q < 0) return params;
	
    String path = rawURI.substring(0, q);
    String query = rawURI.substring(q + 1);
    String[] pairs = query.split("&");
	
    for (int i = 0; i < pairs.length; i++) {
        String pair = pairs[i];
    		
        if (pair.length() == 0) continue;

        String[] parts = pair.split("=", 2);
        String key = java.net.URLDecoder.decode(parts[0]);
        Object value;
    
        if (parts.length == 1) {
            value = Boolean.TRUE;
        } else {
            value = java.net.URLDecoder.decode(parts[1]);
        }

        if (params.containsKey(key)) {
            Object existing = params.get(key);

            if (existing instanceof List) {
                ((List) existing).add(value);
            } else {
                List list = new ArrayList();
                list.add(existing);
                list.add(value);
                params.put(key, list);
            }
        } else {
            params.put(key, value);
        }
    }

    return params;
}

Map parseUrlEncodedBody (
    BufferedInputStream in,
    Map headers, String method
) {
    Map body = null;
    
    if (method == null || "post".equalsIgnoreCase(method)) {
        String ctype = (String) headers.get("content-type");
        
        int len = parseInt(
            (String) headers.get("content-length"), 0);
            
        if (len > 0 && 
            "application/x-www-form-urlencoded".equalsIgnoreCase(ctype)
        ) {
            byte[] encoded_body = new byte[len];
            readFully(in, encoded_body);
            body = parseUrlEncoded(
                "?" + new String(encoded_body, "UTF-8")
            );
        }
    }
    
    return body;
}

String readLine(InputStream in) throws IOException {
    ByteArrayOutputStream b = new ByteArrayOutputStream();
    int c;
    while ((c = in.read()) != -1) {
        if (c == '\r') { in.read(); break; }
        if (c == '\n') break;
        b.write(c);
    }
    return b.toString("UTF-8");
}

void readFully(InputStream in, byte[] buf) throws IOException {
    int p = 0;
    while (p < buf.length) {
        int n = in.read(buf, p, buf.length - p);
        if (n < 0) break;
        p += n;
    }
}

// Read from disk using shell instead of java methods that didn't work.
// FIXME or recycle shell stdin/out. Otherwise expect ~ pool size count procs.
byte[] readFile(File f) throws Exception {
    final Long timeout = 5000;
    Long start = System.currentTimeMillis();
    
    String filename = f.getCanonicalPath();
    
    filename = filename.replace("\"", "\\\"").replace("$", "\\$");
    
    Process process = null;
    InputStream in = null;
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    
    try {
        process = Runtime.getRuntime().exec(new String[]{
            "sh", "-c", "cat \"" + filename + "\" 2>/dev/null"
        });

        in = process.getInputStream();
        
        byte[] buf = new byte[8192];
    
        int n;
        while ((n = in.read(buf)) != -1) {
            if (System.currentTimeMillis() - start > timeout) {
                throw new IOException("Shell timeout");
            }
            
            out.write(buf, 0, n);
        }
        
    } catch (Throwable e) {
        throw e;
    } finally {
        try { process.destroy(); } catch (Exception ignore) {}
        try { in.close(); } catch (Exception ignore) {}
    }
    
    return out.toByteArray();
}

int parseInt(String s, int d) {
    try { return Integer.parseInt(s); } catch (Exception e) { return d; }
}

String escape(String s) {
    return s.replace("\\", "\\\\").replace("\"", "\\\"");
}

String weakEtag(byte[] data) {
    try {
        // FIXME MessageDigest is null in sandbox?
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(data);
        StringBuilder sb = new StringBuilder("W/\"");
        for (int i = 0; i < digest.length; i++)
            sb.append(String.format("%02x", digest[i]));
        return sb.append('"').toString();
    } catch (Exception e) { return null; }
}

String gmtDate(Date d) {
    SimpleDateFormat fmt = new SimpleDateFormat(
        "EEE, dd MMM yyyy HH:mm:ss z", Locale.US
    );
    
    fmt.setTimeZone(TimeZone.getTimeZone("GMT"));
    return fmt.format(d);
}

// Encode json
String jsonEncode (Object obj) throws Exception {
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
            out.append(jsonEncode(e.getKey())).append(":").append(
                jsonEncode(e.getValue())
            );
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
    int[]  jsonParse_i   = { 0 };
    // index holder
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
    else if (src.startsWith("null",  i[0])) { i[0] += 4; return null; }
    else {
        throw new Exception("Unexpected character '" + c + "' at pos " + i[0]);
    }
}

// object: { "key": value, … }
Map jsonParse_parseObject(String src, int[] i) throws Exception {
    Map obj = new HashMap();
    i[0]++; 
    // skip '{'
    jsonParse_skipWhitespace(src, i);
    if (src.charAt(i[0]) == '}') {
        i[0]++; 
        // empty object
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
        // skip ':'
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
    // skip '['
    jsonParse_skipWhitespace(src, i);
    if (src.charAt(i[0]) == ']') {
        i[0]++;
        // empty array
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
    i[0]++; // skip opening '"'
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
        } else if (c == '.' && !hasDot) {
            hasDot = true;
            i[0]++;
        } else if ((c=='e' || c=='E') && !hasExp) {
            hasExp = true;
            i[0]++;
        } else break;
    }
    String num = src.substring(start, i[0]);
    return (hasDot || hasExp)
         ? Double.valueOf(num)
         : Long.valueOf(num);
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
        int val = map[c];
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

// INITIALIZE
// Thread to trigger graceful exit and watch for this action being ran again;
Thread watcherThread = new Thread(new Runnable() { public void run() { try {
    Thread parrentThread = currentThread;
    Thread currentThread = Thread.currentThread();

    // An id to refer to this latest instance;
    // To ensure that only the latest instance is running.
    String exec_id = Long.toHexString(currentThread.getId());
    globals.set(script_id, exec_id);
    watching = true;

    // If stored id changes, gracefully exit. Set poll rate as desired
    while (
        !parrentThread.isInterrupted() && 
        !currentThread.isInterrupted() && watching == true
    ) {
        Thread.sleep(wpollrate);
        
        if (!exec_id.equals(globals.get(script_id))) { return; }
    }
} catch (Throwable e) {
    e.printStackTrace();
} finally {
    watching = false;
    should_exit = true;
}}});

// Allowing time here for the graceful exit of previous instance' threads,
// and the port to become available again.
watcherThread.setDaemon(true);
watcherThread.start();

int wtime = 0; do {
    Thread.sleep(wpollrate * 2);
    wtime = wtime + (wpollrate * 2);
} while (
    watching == false && 
    should_exit == false &&
    wtime < wtimeout &&
    !currentThread.isInterrupted()
);

// Clients are served from the connection pool 
void addSocketToPool (Socket s) { pool.execute(new Runnable() { 
    public void run() {
        s.setSoTimeout(HTTP_TIMEOUT);
        
        BufferedInputStream in = new BufferedInputStream(s.getInputStream());
        BufferedOutputStream out = new BufferedOutputStream(s.getOutputStream());
        
        try {
            handleRequest(s, in, out);
        } catch (SocketTimeoutException ste) {
            ste.printStackTrace();
        } catch (Throwable e) {
            e.printStackTrace();
        } finally {
            try { s.close(); } catch(IOException ignore) {}
        }
    }
});}

try { 
// Start server and allow rebind / reuse port.
server.setReuseAddress(true);
server.setSoTimeout(HTTP_TIMEOUT);
server.bind(new InetSocketAddress(PORT));
variableSetter.setBoolean("http_server_up", true);

// Enqueue http connections and keep the script running.
while (
    should_exit == false && 
    !currentThread.isInterrupted() && 
    !server.isClosed()
 ) {
    Socket sock = null;
    
    try {
        if ((sock = server.accept()) != null) addSocketToPool(sock);
        
    } catch (SocketTimeoutException ignore) { 
        
        // If the request timeout wasn't handled in the pool
        if (sock != null) {
            try { sock.close(); } catch(Exception ignore) {}
            sock = null;
        }
        
        continue;
    }
    
}} catch (Throwable server_down) {
    // The script ended in error.
    variableSetter.setBoolean("http_server_up", false);
    throw server_down;
    
} finally {
    // Cleanup before exit.
    try { watcherThread.interrupt(); } catch(Exception ignore) {}
    try {
        watching = false;
        should_exit = true;
        pool.shutdown();
    } catch(Exception ignore) {}
    try { server.close(); } catch(Exception ignore) {}
    
}

// The script (gracefully) ended
variableSetter.setBoolean("http_server_up", false);

return true;
