#include <stdio.h>
#include <stdlib.h>

extern void init_alloc_wrapper();




int main(int argc, char **argv) {
  // Initialize mleakdetect

  init_alloc_wrapper();
  // Allocate memory
  int *array = (int*)malloc(100 * sizeof(int));

  // Use the allocated memory
  for (int i = 0; i < 100; i++) {
    array[i] = i;
  }
  int *p_int = new int();
  // Free the memory
  free(array);

  // Dump the memory leaks

  // Exit the program
  return 0;
}
