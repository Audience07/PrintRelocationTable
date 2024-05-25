#include "Head.h"




int main() {

	//typedef (* Func)(int, int);
	//打开dll,获取FileBuffer
	LPVOID DLLFileBuffer = _OpenFile("MyDLL.dll", 0);

	_PrintReloc(DLLFileBuffer);
	
	/*Func Sub = (Func)_GetFunctionAddrByName(DLLFileBuffer, "Sub");

	printf("该函数的FOA为%x", Sub);*/
	
	return 0;





}