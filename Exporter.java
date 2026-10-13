import jadx.api.*;
import jadx.api.impl.NoOpCodeCache;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.io.*;
import java.util.*;

/** Local JADX exporter with an independently generated class inventory. */
public class Exporter {
    static String q(Object x) {
        if (x == null) return "null";
        StringBuilder b = new StringBuilder("\"");
        for (char c : x.toString().toCharArray()) {
            if (c == '\\' || c == '"') b.append('\\').append(c);
            else if (c < 32) b.append(String.format("\\u%04x", (int)c));
            else b.append(c);
        }
        return b.append('"').toString();
    }
    public static void main(String[] a) throws Exception {
        Path out = Path.of(a[1]).toAbsolutePath().normalize();
        Files.createDirectories(out);
        JadxArgs opts = new JadxArgs();
        opts.setInputFile(Path.of(a[0]).toFile());
        opts.setSkipResources(true);
        opts.setThreadsCount(1);
        opts.setFsCaseSensitive(false);
        opts.setDecompilationMode(DecompilationMode.valueOf(a[2]));
        opts.setCodeCache(NoOpCodeCache.INSTANCE);
        int ok=0, failed=0, markers=0;
        Set<String> paths = new HashSet<>();
        try (JadxDecompiler d = new JadxDecompiler(opts);
             BufferedWriter audit = Files.newBufferedWriter(out.resolve("inventory.jsonl"), StandardCharsets.UTF_8)) {
            d.load();
            List<JavaClass> classes = new ArrayList<>(d.getClasses());
            classes.sort(Comparator.comparing(JavaClass::getRawName));
            for (JavaClass c : classes) {
                String relative=null, hash=null, error=null;
                try {
                    relative=c.getClassNode().getClassInfo().getAliasFullPath().replace('\\','/')+".java";
                    Path target=out.resolve("sources").resolve(relative).normalize();
                    if (!target.startsWith(out.resolve("sources")) || !paths.add(relative.toLowerCase(Locale.ROOT)))
                        throw new IllegalStateException("Unsafe or colliding generated alias");
                    String code=c.getCode();
                    if (code.isEmpty()) throw new IllegalStateException("Empty generated code");
                    if (code.contains("Method not decompiled") || code.contains("JADX ERROR")) markers++;
                    byte[] data=code.getBytes(StandardCharsets.UTF_8);
                    Files.createDirectories(target.getParent());
                    Files.write(target,data,StandardOpenOption.CREATE_NEW);
                    hash=HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(data));
                    ok++;
                } catch (Exception e) { error=e.toString(); failed++; }
                finally { c.unload(); }
                audit.write("{\"class\":"+q(c.getRawName())+",\"dex\":"+q(c.getClassNode().getInputFileName())+",\"mode\":"+q(a[2])+",\"path\":"+q(relative)+",\"sha256\":"+q(hash)+",\"error\":"+q(error)+"}\n");
                audit.flush();
            }
            String summary="{\"classes\":"+classes.size()+",\"generated\":"+ok+",\"failed\":"+failed+",\"jadx_errors\":"+d.getErrorsCount()+",\"files_with_incomplete_markers\":"+markers+"}";
            Files.writeString(out.resolve("summary.json"),summary,StandardCharsets.UTF_8);
        }
        if (failed>0) System.exit(2);
    }
}
