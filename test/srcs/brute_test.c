#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char** argv)
{
    const char correct[] = "BRUTINOBRUTONE\0";
    char buffer[64];
    int isCorrect = 1;

    //setvbuf(stdin, NULL, _IONBF, 0);
    //setvbuf(stdout, NULL, _IONBF, 0);


    printf("Write up to 64 chars\n");

    fgets(buffer, 64, stdin);

    for(int i = 0; i< 64; i++)
    {
        if(correct[i] == '\0')
        {
            break;
        }

        if(buffer[i] != correct[i])
        {
            isCorrect = 0;
            break;
        }
    }

    if (isCorrect)
    {
        printf("Giusto!\n");
    }
    else
    {
        printf("Sbagliato!\n");
    }

    return 0;
}
