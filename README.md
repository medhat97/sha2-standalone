# SHA3 Task - Hash Implementation in C

This project contains an implementation of SHA3 hashing functionality in C that hashes file. The program demonstrates how to perform hashing operations and is split into multiple source files (`main.c` and `hash.c`).


## Project Structure

The project is organized into the following directories and files:

- `src/`: Contains the source code files.
  - `hash.c`: Contains the implementation of the hashing algorithm of SHA3.


- `include/`: Contains header files for public API exposure.
  - `hash.h`: Header file for `hash.c`, containing constants related to SHA3 function prototypes and necessary includes.

- `main.c`: Contains the main function and logic for interacting with the hash functions.

- `Makefile`: Used to build the project.

- `README.md`: Documentation for the project.



## Compilation

To compile the project, navigate to the directory containing the source files and run the following command:

```bash
gcc main.c hash.c -o a.out
```

## Execution

To execute the program, run:

```bash
./a.out <path_to_file>
```

Replace `<path_to_file>` with the path of the file you want to hash.

## Example Usage

```bash
./a.out input.txt
```

This will compute the SHA3 hash of `input.txt` and display it in the console.


## To use the openssl library to perform the same hashing 

openssl dgst -sha3-256 input.txt 
