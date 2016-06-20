
// session_regroupDlg.h : 头文件
//

#pragma once
#include "afxeditbrowsectrl.h"
#include "def.h"
#include "afxwin.h"

// Csession_regroupDlg 对话框
class Csession_regroupDlg : public CDialogEx
{
// 构造
public:
	Csession_regroupDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_SESSION_REGROUP_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;
	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedOk2();
	CMFCEditBrowseCtrl input;
	CMFCEditBrowseCtrl output;
	CStatic info;

	u_char pcap_head[24];
	bool analysis;
	bool isTrunk;
	
	u_int16_t ntohs(u_int16_t nshort);
	u_int16_t htons(u_int16_t hshort);
	u_int32_t ntohi(u_int32_t nint);
	int find(u_char * in, const char * tail);
	char * split_file_name(char * path);
	int createfolder(CString path);

	void dispatcher_handler(u_char *, pcap_pkthdr *, u_char *);
	void add_tcp_session(int,bool dir,tcp_session *ts, u_int32_t seq, u_int32_t ack, u_int16_t flag, u_char * pkt_data, int offset, int strl, pcap_pkthdr * cap_header);
	void add_udp_session(udp_session *us, u_char * pkt_data, pcap_pkthdr * cap_header);
	void handle_http(tcp_session * ts, tcp_node *tn,int * tcp_index);
	void add_http_session(http_session *hs, http_node *hn, bool isNew);
};
