
// FeedingExDlg.cpp: 实现文件
//

#include "pch.h"
#include "framework.h"
#include "FeedingEx.h"
#include "FeedingExDlg.h"
#include "afxdialogex.h"
#include "windows.h"
#include <TlHelp32.h>
#include <string>
#include <io.h>
#include <fcntl.h>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define PLACE_HOLDER_END 0x12345679

// 获取进程Pid
DWORD GetProcessPid(CString nProcessName);

DWORD GetProcessPid(CString nProcessName)
{
	PROCESSENTRY32 nPT;
	nPT.dwSize = sizeof(nPT);
	HANDLE nSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	BOOL nRet = Process32First(nSnapShot, &nPT);
	while (nRet)
	{
		if (nProcessName.MakeLower() == CString(nPT.szExeFile).MakeLower())
		{
			return nPT.th32ProcessID;
		}
		nRet = Process32Next(nSnapShot, &nPT);
	}
	return 0;
}

// 跳转地址
void HexToDB(DWORD DstAddr, DWORD srcAddr, PBYTE dArry)
{
	//机器码 = 目标地址 - 原地址 - jcc指令长度
	DWORD addr = DstAddr - srcAddr - 0x5;
	dArry[0] = (BYTE)WORD(addr);
	dArry[1] = (BYTE)(WORD(addr) >> 8);
	dArry[2] = (BYTE)(DWORD(addr) >> 16);
	dArry[3] = (BYTE)(DWORD(addr) >> 24);
}

DWORD DBToHEX(DWORD srcAddr, PBYTE dArry)
{
	DWORD addr = 0;
	addr |=  (dArry[3] << 24);
	addr |= (dArry[2] << 16);
	addr |= (dArry[1] << 8);
	addr |= dArry[0];
	return addr + 0x5 + srcAddr;
}

// CFeedingExDlg 对话框



CFeedingExDlg::CFeedingExDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_FEEDINGEX_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CFeedingExDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CFeedingExDlg, CDialogEx)
	ON_WM_CLOSE()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(ICD_SWALLOW, &CFeedingExDlg::OnBnClickedSwallow)
	ON_BN_CLICKED(IDC_INIT_LEFT_99, &CFeedingExDlg::OnBnClickedInitLeft99)
	ON_BN_CLICKED(IDC_LEFT_DECREASE, &CFeedingExDlg::OnBnClickedLeftDecrease)
	ON_BN_CLICKED(IDC_LOCK_LEFT, &CFeedingExDlg::OnBnClickedLockLeft)
END_MESSAGE_MAP()

// CFeedingExDlg 消息处理程序

BOOL CFeedingExDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CFeedingExDlg::OnClose()
{
	CDialogEx::OnOK();
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CFeedingExDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CFeedingExDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

/*  无限吞噬
[ENABLE]
0040E7C7:
  db 75 00 C7 86 18 04 00 00 9A 99 19 3F
[DISABLE]
0040E7C7: 
  db 75 0A C7 86 18 04 00 00 9A 99 19 3F
*/
void CFeedingExDlg::OnBnClickedSwallow()
{
	CButton* b = (CButton*)GetDlgItem(ICD_SWALLOW);
	DWORD nPid = GetProcessPid("feeding.exe");
	if (nPid) {
		HANDLE nHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nPid);
		if (nHandle) {
			BYTE origin[] = { 0x75,0x0A,0xC7,0x86,0x18,0x04,0x00,0x00,0x9A,0x99,0x19,0x3F };
			if (b->GetCheck()) {
				origin[1] = 0x00;
			}
			DWORD baseAddress = 0x40E7C7;
			if (WriteProcessMemory(nHandle, (LPVOID)baseAddress, origin, sizeof(origin), 0)) {
				CloseHandle(nHandle);
				return;
			}
			CloseHandle(nHandle);
		}
	}
	b->SetCheck(FALSE);
}

/*  初始生命99
[ENABLE]
00435150:
  db C7 01 63 00 00 00
00435163:
  db C7 01 63 00 00 00

[DISABLE]
00435150:
  db C7 01 03 00 00 00
00435163:
  db C7 01 03 00 00 00
*/
void CFeedingExDlg::OnBnClickedInitLeft99()
{
	CButton* b = (CButton*)GetDlgItem(IDC_INIT_LEFT_99);
	DWORD nPid = GetProcessPid("feeding.exe");
	if (nPid) {
		HANDLE nHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nPid);
		if (nHandle) {
			BYTE origin[] = { 0xC7,0x01,0x03,0x00,0x00,0x00 };
			if (b->GetCheck()) {
				origin[2] = 0x63;
			}
			DWORD baseAddress1 = 0x00435150;
			DWORD baseAddress2 = 0x00435163;
			if (WriteProcessMemory(nHandle, (LPVOID)baseAddress1, origin, sizeof(origin), 0)
				&& WriteProcessMemory(nHandle, (LPVOID)baseAddress2, origin, sizeof(origin), 0)) {
				CloseHandle(nHandle);
				return;
			}
			CloseHandle(nHandle);
		}
	}
	b->SetCheck(FALSE);
}

/* 生命不减
[ENABLE]
004351B4:
  db EB 02

[DISABLE]
004351B4:
  db 74 02
 */
void CFeedingExDlg::OnBnClickedLeftDecrease()
{
	CButton* b = (CButton*)GetDlgItem(IDC_LEFT_DECREASE);
	DWORD nPid = GetProcessPid("feeding.exe");
	if (nPid) {
		HANDLE nHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nPid);
		if (nHandle) {
			BYTE origin[] = { 0x74,0x02 };
			if (b->GetCheck()) {
				origin[0] = 0xEB;
			}
			DWORD baseAddress = 0x004351B4;
			if (WriteProcessMemory(nHandle, (LPVOID)baseAddress, origin, sizeof(origin), 0)) {
				CloseHandle(nHandle);
				return;
			}
			CloseHandle(nHandle);
		}
	}
	b->SetCheck(FALSE);
}

 __declspec(naked) void  LockLife_start()
{
	__asm
	{
		cmp eax, ecx
		jnz originalcode
		mov[ecx], 0x00000063
		mov eax, [ecx]
		ret
		originalcode:
		mov eax, [ecx]
		ret
	}
}

 __declspec(naked) void LockLife_end() {
	 __asm
	 {
		ret
	 }
 }

/* 锁定生命值99
[ENABLE]

alloc(newmem,2048)
label(returnhere)
label(originalcode)
label(exit)

newmem:
cmp eax,ecx
jnz originalcode
mov [ecx],00000063

originalcode:
mov eax,[ecx]
ret

exit:
jmp returnhere

00435170:
jmp newmem
returnhere:

[DISABLE]
dealloc(newmem)
00435170:
mov eax,[ecx] // 8B 01      
ret           // C3 
fdivr st(0),st(7)    // D8 FF
 */

DWORD OldLockLeftAddress = 0;

void CFeedingExDlg::OnBnClickedLockLeft()
{
	CButton* b = (CButton*)GetDlgItem(IDC_LOCK_LEFT);
	DWORD nPid = GetProcessPid("feeding.exe");
	if (nPid) {
		HANDLE nHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, nPid);
		if (nHandle) {
			BYTE origin[] = { 0x8B,0x01,0xC3,0xCC,0xCC };
			BYTE jmpCode[] = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
			DWORD size = sizeof(origin);
			DWORD hookSize = (DWORD)LockLife_end - (DWORD)LockLife_start;
			DWORD baseAddress = 0x00435170;
			BYTE* read = new BYTE[size];
			memset(read, 0, size * sizeof(BYTE));
			DWORD dwNumberOfBytesRead;
			if (ReadProcessMemory(nHandle, (LPVOID)baseAddress, read, sizeof(origin), &dwNumberOfBytesRead)) {
				if (dwNumberOfBytesRead) {
					if (memcmp(read, origin, sizeof(origin)) == 0) {
						if (b->GetCheck()) {
						enable:
							if (!OldLockLeftAddress
								|| !ReadProcessMemory(nHandle, (LPVOID)OldLockLeftAddress, read, sizeof(origin), &dwNumberOfBytesRead)
								|| read[0] != 0x3B
								|| read[1] != 0xC1) {
								OldLockLeftAddress = (DWORD)VirtualAllocEx(nHandle, NULL, hookSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
							}
							if (OldLockLeftAddress && WriteProcessMemory(nHandle, (LPVOID)OldLockLeftAddress, LockLife_start, hookSize, 0)) {
								HexToDB(OldLockLeftAddress, baseAddress, &jmpCode[1]);
								if (WriteProcessMemory(nHandle, (LPVOID)baseAddress, jmpCode, 5, 0)) {
									CloseHandle(nHandle);
									return;
								}
							}
							CloseHandle(nHandle);
						}
						else {
						disable:
							if (WriteProcessMemory(nHandle, (LPVOID)baseAddress, origin, 5, 0)) {
								CloseHandle(nHandle);
								return;
							}
							CloseHandle(nHandle);
						}
					}
					else if (read[0] == 0xE9) {
						OldLockLeftAddress = DBToHEX(baseAddress, &read[1]);
						if (b->GetCheck()) {
							goto enable;
						}
						else {
							goto disable;
						}
					}

				}
			}
		}
	}
	b->SetCheck(FALSE);
}
