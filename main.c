#include "Head.h"




int main() {

	//typedef (* Func)(int, int);
	//��dll,��ȡFileBuffer
	LPVOID DLLFileBuffer = _OpenFile("MyDLL.dll", 0);

	_PrintReloc(DLLFileBuffer);
	
	/*Func Sub = (Func)_GetFunctionAddrByName(DLLFileBuffer, "Sub");

	printf("�ú�����FOAΪ%x", Sub);*/
	
	return 0;





}