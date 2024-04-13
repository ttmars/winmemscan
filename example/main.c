#include<stdio.h>
#include <unistd.h>
#include <stdlib.h>

int HP = 99999;

int main(){
    int hp = 88888;

    int *pp = (int *)malloc(8*1024*1024);
    pp[0] = 77777;
    
    for(;HP>0;) {
        HP--;
        hp--;
        pp[0]--;
        printf("HP %d %p %d\n", HP, &HP, sizeof(int));
        printf("hp %d %p\n", hp, &hp);
        printf("hp %d %p\n\n", pp[0], pp);
        sleep(15);
    }
}
