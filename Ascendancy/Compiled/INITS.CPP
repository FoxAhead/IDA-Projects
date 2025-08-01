#include <stdio.h>

// This runs before main() due to __InitRtns
class MyClass {
public:
    MyClass() { printf("Constructor!\n"); }
};
MyClass globalObj;  // Constructor called during __InitRtns

void func1(double d1, double d2, double d3)
{
    double d4;
    d4 = (d1 + d2) / d3;
};


void main()
{
    func1(1.23, 4.56, 7.89);
};
