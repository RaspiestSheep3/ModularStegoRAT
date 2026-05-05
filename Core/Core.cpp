// Core.cpp : Defines the entry point for the application.
//

#include "Core.h"

using namespace std;

int RunDLL(string DLLPath, string settingDataStringified)
{
	//cout << "DLL Path: " << DLLPath << endl;
	int output = 0;

	int settings[62] = {0};

	string substr;
	for (int i = 0; i < 62; i++) {
		substr = settingDataStringified.substr(i * 3, 3);
		//cout << "Substr: " << substr << endl;
		settings[i] = stoi(substr); //stoi = string to integer
	}

	//Visualising settings
	/*
	for (int j = 0; j < 62; j++) cout << settings[j];
	cout << endl;
	*/

	return output; //If we fail output != 0 => we can work out what the error is
}

int main(int argc, char* argv[])
{
	cout << "Hello CMake." << endl;

	if (argc < 3) { //If less than 3 args are passed - first arg is always the EXE path
		cerr << "Usage: Core.exe <DLLPath> <SettingData>" << endl;
		return 1;
	}

	string dllPath = argv[1];
	string settingDataStringified = argv[2];

	int result = RunDLL(dllPath, settingDataStringified);
	
	return result;
}
