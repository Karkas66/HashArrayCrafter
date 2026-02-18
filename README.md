# HashArrayCrafter

![C#](https://img.shields.io/badge/C%23-239120?logo=csharp&logoColor=white)
![Rust](https://img.shields.io/badge/Rust-000000?logo=rust&logoColor=white)
![Windows](https://img.shields.io/badge/Windows-0078D6?logo=windows&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue)

A stealthy shellcode hiding tool that embeds payloads within randomized hash arrays to evade AV/EDR detection.

> ⚠️ **EDUCATIONAL PURPOSES ONLY**  
> This project is strictly for authorized penetration testing and security research in controlled environments. Misuse may violate computer fraud laws and ethical guidelines.

## The Why

- Inspired and developed during my self-study of the malware development course by [Maldev Academy](https://maldevacademy.com)
- Goal: Generate a more or less generic shellcode loader to bypass AVs and less advanced EDR/XDR solutions (**successfully achieved!**)
- The Way: Stupid AVs tend to skip ressource intense function by patching loops and IF statements and analyze what happens after them. You can not skip this logic and preserve functionality, so it looks like a normal program to a stupid scanner
- First iteration used plain C# code, but C# is **very slow** and **easy to reverse engineer** → redesigned to:
  - Make C# loader **optional**
  - Preserve core array-crafting logic while enabling native execution paths
- Parallel development of sister project [**StarShot**](https://github.com/Karkas66/StarShot) (Rust) to fully compensate for C#'s performance and security limitations with a lot of extra functionality

## Workflow

1. The program takes the path to a shellcode file as a plain argument.
2. The payload size is analyzed.
3. The user is prompted to define the final size of the hash array in which the payload will be stored.  
   Recommendations are provided based on payload size.
4. An array with the user-defined size is created and filled with random data.
5. The following hashes are calculated:
   - SHA-512 of the original payload  
   - SHA-512 of the gzip-compressed payload  
6. A random position within the array is selected.
7. The compressed payload bytes are inserted into the array at that position.

### Optional Features

- **Dry Run (C#):**  
  Test restoration of the original payload content without executing it.

- **C# Loader Generation:**  
  Generates a c# loader file capable of restoring and executing the payload  (you have to compile it yourself)
  (includes a fiber-based execution approach).

- **Rust Code Blob Generation:**  
  Produces a Rust-compatible payload blob designed to work seamlessly with the sister project **StarShot**.

---

## Usage

Clone the repository:

```bash
git clone <repo-url>
cd <repo>
```

Compile according to your preferred toolchain, then run the program with your shellcode as argument:

```bash
HashArrayCrafter.exe payload.bin
```

---

## Notes

You can use my own project called **CelestialSpark** to generate shellcode for testing purposes.

---

## Disclaimer

This project was created for educational and research purposes only.  
Use responsibly and only in controlled lab environments.
 "With great power comes great responsibility" — Uncle Ben (and every infosec professional ever)
