#include <stdio.h>

int getNum(void);
int calc(int a, int b);

int main(void){
    int c = getNum();
    
    if (c > 2)
        return calc(c, 2);
    else
        return 0;
}