
#include <stdio.h>
#include <stdlib.h>

// Do NOT touch this function signature
void printMultiplicationTable(int n) {

    printf("X");

    for(int i = 0; i <= n; i++){
        printf("\t%i", i);
    }
    printf("\n");
    for(int j = 0; j <= n; j++){

        printf("%i", j);
        for(int i = 0; i <= n; i++){
            printf("\t%i",(i * j));
        }
        printf("\n");
    }
}

// You have to implement the main function
int main(int argc, char **argv){

    int num = atoi(argv[1]);

    if(num < 8 && num >= 0 ){
        printMultiplicationTable(num);
    }
    else{
        printf("please try again");
    }
  return 0;
}