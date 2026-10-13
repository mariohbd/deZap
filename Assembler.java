import java.nio.file.*;
import java.util.*;
import brut.androlib.smali.SmaliBuilder;
import com.android.tools.smali.dexlib2.Opcodes;
import com.android.tools.smali.dexlib2.writer.builder.DexBuilder;
import com.android.tools.smali.dexlib2.writer.io.FileDataStore;

/** Assemble local smali; never modifies input files. */
public class Assembler {
    public static void main(String[] args) throws Exception {
        Path source=Path.of(args[0]), output=Path.of(args[1]);
        int api=Integer.parseInt(args[2]);
        List<Path> files;
        try(var paths=Files.walk(source)) {
            files=paths.filter(p->p.toString().endsWith(".smali")).sorted().toList();
        }
        if(files.isEmpty()) throw new IllegalArgumentException("Empty smali directory");
        var assembler=new SmaliBuilder(api);
        var dex=new DexBuilder(new Opcodes(api));
        for(Path file:files) {
            if(Files.isSymbolicLink(file) || !Files.isRegularFile(file)) throw new IllegalArgumentException("Unsafe smali file");
            if(!assembler.buildFile(file.toFile(),dex)) throw new IllegalStateException("Assembly failed: "+file);
        }
        Files.createDirectories(output.getParent());
        dex.writeTo(new FileDataStore(output.toFile()));
        System.out.println("Assembled "+files.size()+" classes");
    }
}
