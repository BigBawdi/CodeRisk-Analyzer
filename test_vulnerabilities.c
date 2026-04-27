/*
 * test_vulnerabilities.c
 * Sample C file with intentional vulnerabilities for CodeRisk-Analyzer testing.
 * DO NOT use in production.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 1. Buffer Overflow  */
void buffer_overflow_example() {
    char buf[10];
    strcpy(buf, "This string is way too long for the buffer!"); // overflow
}

/* 2. Use of gets() */
void unsafe_input() {
    char input[64];
    gets(input); // no bounds checking whatsoever
    printf("You entered: %s\n", input);
}

/* 3. Format String Vulnerability */
void format_string_bug(char *user_input) {
    printf(user_input); // attacker controls format string
}

/* 4. Memory Leak */
void memory_leak() {
    int *ptr = (int *)malloc(sizeof(int) * 100);
    ptr[0] = 42;
    // forgot to free(ptr)
}

/* 5. Use-After-Free */
void use_after_free() {
    int *ptr = (int *)malloc(sizeof(int));
    *ptr = 7;
    free(ptr);
    printf("Value: %d\n", *ptr); // undefined behavior
}

/* 6. Integer Overflow */
void integer_overflow() {
    int x = 2147483647; // INT_MAX
    int y = x + 1;      // wraps to negative
    printf("Overflow result: %d\n", y);
}

/* 7. Null Pointer Dereference */
void null_deref() {
    int *ptr = NULL;
    *ptr = 99; // crash
}

/* 8. Double Free */
void double_free() {
    char *buf = (char *)malloc(50);
    free(buf);
    free(buf); // undefined behavior
}

/* 9. Stack-based Buffer Overflow via scanf */
void scanf_overflow() {
    char name[8];
    scanf("%s", name); // no width limit
}

/* 10. Uninitialized Variable */
void uninitialized_var() {
    int x;
    printf("x = %d\n", x); // garbage value
}

/* 11. Insecure use of system() */
void command_injection(char *user_input) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ls %s", user_input); // injection risk
    system(cmd);
}

/* 12. Signed/Unsigned Comparison */
void signedness_bug() {
    int len = -1;
    char buf[10];
    if ((unsigned int)len < sizeof(buf)) {
        // -1 as unsigned is a huge number — always true
        buf[0] = 'A';
    }
}

/* Main */

int main() {
    printf("CodeRisk-Analyzer test file.\n");
    printf("This file contains intentional vulnerabilities.\n\n");

    memory_leak();
    integer_overflow();
    uninitialized_var();
    signedness_bug();

    printf("Done. Run static analyzers to detect issues above.\n");
    return 0;
}
