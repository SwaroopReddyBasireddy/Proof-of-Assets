#include <iostream>
#include <pthread.h>
using namespace std;

char* str = "Child thread";

void* func(void *str)
{
    cout << "Child thread Created: " << (char*)str;
}
// main function
int main()
{
    //double s = ctime(&Time);
    // Step 1: Declaring thread
    pthread_t t;    
    // Step 2: Calling create thread function
    pthread_create(&t, NULL, &func, (void*)str); 
    /*
        Syntax for pthread_create is:
        pthread_create(threadID,attr,start_routine,arg)
        Here,
        threadID = t, arg = (void*)str, atrr = Null, start_routine = func
    */
    cout << "Main thread created" << endl;
    pthread_join(t, NULL);
    //Exiting after completion
    exit(EXIT_SUCCESS); 
    return 0;
}
