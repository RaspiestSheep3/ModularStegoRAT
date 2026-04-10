// RansomwareModule.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
using namespace std;

//These are the only 2 required functions for the system to run - all other functions will not be called by the module
extern "C" __declspec(dllexport) void SetArguments(int metadata[62])
{
    //This is where all metadata gets passed into the system for processing
    //If a system does not require any metadata this should be left blank
}

extern "C" __declspec(dllexport) void RunModule()
{
    //This is the function that should do the module running 
    cout << "This is test ransomware\n";
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
