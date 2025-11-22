#include <stdio.h>

static int compute_value(int x) {
    return (x * 2) + 3;
}

int main(void) {
    int v = compute_value(21);
    printf("benign pie value: %d\n", v);
    return 0;
}
