#include <stdio.h>
#include <stdlib.h>
#include "include/hash.h"
void hash_file(const char filename[]) {
    FILE *file;
    char buffer[7*1024*1024]; // Buffer to read file chunks
    size_t bytesRead;
    char hash[64]={0};

    file = fopen(filename, "rb");
    
  
    sha3 SHA3;

    SHA3_init(&SHA3,SHA3_HASH256);
    

    // Read file and update hash context
    int i =0;
    while ((bytesRead = fread(buffer, 1, 1, file)) > 0) {
        // princle  tf("%c: ", (char)buffer[i]);
        SHA3_process(&SHA3, buffer[i]); 
    }

    // Finalize the hash
    SHA3_hash(&SHA3,hash);
    // Cleanup
    fclose(file);
  

    // Print the hash
    printf("SHA-3 hash of file %s:\n", filename);
    for (unsigned int i = 0; i < 32; i++) {
        printf("%02x", (uint8_t)hash[i]);
    }
    printf("\n");
}

int main() {
    
    char file_to_hash[] = "blank.pdf";

    hash_file(file_to_hash);
    return 0;
}
