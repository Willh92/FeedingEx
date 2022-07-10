
// FeedingExDlg.h: 头文件
//

#pragma once


// CFeedingExDlg 对话框
class CFeedingExDlg : public CDialogEx
{
// 构造
public:
	CFeedingExDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_FEEDINGEX_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnClose();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedSwallow();
	afx_msg void OnBnClickedInitLeft99();
	afx_msg void OnBnClickedLeftDecrease();
	afx_msg void OnBnClickedLockLeft();
	afx_msg void OnBnClickedGod();
};
