#include <iostream>
#include <Windows.h>
#include <string>
#include "hacker.h"
#include<conio.h>
using namespace std;


#define WIDTH		40
#define HEIGHT		15


void init(void) {
	//mode con cols=80 lines=40
	char cmd[128];
	sprintf_s(cmd, "mode con cols=%d lines=%d", WIDTH, HEIGHT);//在新版本中sprintf被sprintf_s所取代
	system(cmd);
}

/*
功能：密码输入的加密
*/
void input_pwd(char pwd[], int max_len) {
	char c;
	int i = 0;

	while (1) {
		c = _getch();
		// getch不从输入缓冲区中读取
		//在getch中，把回车按键输入，识别为回车符'\r'
		//在getchar中，把回车按键输入，识别为换行符'\n'
		if (c == '\r' || i >= max_len) {
			pwd[i] = 0;
			break;
		}
		pwd[i++] = c;
		printf("*", c);
	}
	printf("\n");
}



void printInMiddle(string msg) {
	int space = (WIDTH - msg.length()) / 2;
	for (int i = 0; i<space; i++) {
		cout << " ";
	}
	cout << msg << endl;
}


void login(void) {
	string name;
	//string pwd;
	char pwd[16];
	while (1) {
		system("cls");

		std::cout << "请输入账号：";
		std::cin >> name;

		std::cout << "请输入密码：";
		//std::cin >> pwd;
		input_pwd(pwd, sizeof(pwd));

		if (name == "54hk" && !strcmp(pwd, "123456")) {
			//break;
			return;
		}
		else {
			cout << "用户名或密码错误!" << endl;
			system("pause");
		}
	}
}

void menuShow(void) {
	string menu[] = {
		"1.网站404攻击",
		"2.网站篡改攻击",
		"3.网站攻击修复",
		"4.查看攻击记录",
		"5.退出"
	};

	system("cls");
	printInMiddle("---黑客攻击系统---");

	// 计算菜单最大长度：
	int max = 0;
	int menuCount = sizeof(menu) / sizeof(menu[0]);
	for (int i = 0; i< menuCount; i++) {
		if (menu[i].length() > max) {
			max = menu[i].length();
		}
	}

	int leftSpace = (WIDTH - max) / 2;

	for (int i = 0; i<menuCount; i++) {
		for (int i = 0; i<leftSpace; i++) {
			printf(" ");
		}
		cout << menu[i] << endl;
	}

}

int menuChoise(void) {
	int n = 0;

	while (1) {
		cin >> n;
		if (cin.fail()) {
			cin.clear();
			cin.sync();
			cout << "无效输入. 请重新输入." << endl;
			system("pause");
		}
		else {
			break;
		}
	}

	return n;
}

void attack404(void) {
	char response[MAXSIZE];
	char id[64];

	memset(response, 0, sizeof(response));

	system("cls");
	printInMiddle("---网站404攻击---");
	cout << "请输入准备攻击的网站ID：";
	scanf_s("%s", id, sizeof(id));
	cout << "正在执行404攻击..." << endl;

	hk_404(id, response);

	string retStr = UTF8ToGBK(response);
	cout << retStr << endl;

	system("pause");

}

void siteEdit(void) {
	char response[MAXSIZE];
	char id[16];
	std::string str;
	string attackText;

	system("cls");
	printInMiddle("---网站篡改攻击---");
	cout << "请输入准备攻击的网站ID：";
	scanf_s("%s", id, sizeof(id));
	cout << "请输入嵌入的内容：";
	cin >> attackText;

	GBKToUTF8(attackText);

	hk_tamper(id, (char*)(attackText.c_str()), response);


	string retStr = UTF8ToGBK(response);
	cout << retStr << endl;

	system("pause");

}

void siteRepair(void) {
	char response[MAXSIZE];
	char id[16];
	std::string str;
	string attackText;

	system("cls");
	printInMiddle("---网站攻击修复---");
	cout << "请输入准备查询的网站ID：";
	scanf_s("%s", id, sizeof(id));

	hk_restore(id, response);

	string retStr = UTF8ToGBK(response);
	cout << retStr << endl;

	system("pause");

}

void attckRecord(void) {
	char response[MAXSIZE];
	char id[64];

	system("cls");
	printInMiddle("---攻击记录获取---");
	cout << "请输入准备攻击的网站ID：";
	scanf_s("%s", id, sizeof(id));

	hk_record(id, response);

	string retStr = UTF8ToGBK(response);

	cout << retStr;
	system("pause");

}

int main(void) {
	// 登录
	init();
	login();

	while (1) {
		menuShow();
		int n = menuChoise();
		switch (n) {
		case 1:
			attack404();
			break;
		case 2:
			siteEdit();
			break;
		case 3:
			siteRepair();
			break;
		case 4:
			attckRecord();
			break;
		case 5:
			//break;
			return 0;
		default:
			cout << "无效输入. 请重新输入." << endl;
			system("pause");
			break;
		}
	}

	system("pause");
	return 0;
}
