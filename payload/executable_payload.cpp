#include <Windows.h>

/**
* Spawns a MessageBox and then exits.
*
*/
int main(int argc, char* argv[])
{
	MessageBoxA(NULL, "Message from payload", "Injected payload", MB_OK);
	return 0;
}