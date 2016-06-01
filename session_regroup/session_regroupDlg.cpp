// session_regroupDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "session_regroup.h"
#include "session_regroupDlg.h"
#include "content_decoder.h"
#include "afxdialogex.h"
#include "def.h"
#include <io.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex>
#ifdef _DEBUG
#define new DEBUG_NEW
#endif

int count = 0;
tcp_session * tcp_head = NULL, *tcp_tail = NULL;
udp_session * udp_head = NULL, *udp_tail = NULL;
http_session * http_head = NULL, *http_tail = NULL;
char *method[7] = { "GET", "PUT", "POST", "DELETE", "HEAD","TRACE","CONNETCT" };
char *hver[3] = { "HTTP/1.0", "HTTP/1.1", "HTTP/2" };
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
	enum { IDD = IDD_ABOUTBOX };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(CAboutDlg::IDD)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// Csession_regroupDlg 对话框



Csession_regroupDlg::Csession_regroupDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(Csession_regroupDlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
	analysis = false;
	memset(pcap_head, 0, 24);
	isTrunk = false;
}

void Csession_regroupDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_MFCEDITBROWSE1, input);
	DDX_Control(pDX, IDC_MFCEDITBROWSE2, output);
	DDX_Control(pDX, IDC_LABEL, info);
}

BEGIN_MESSAGE_MAP(Csession_regroupDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &Csession_regroupDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDOK2, &Csession_regroupDlg::OnBnClickedOk2)
END_MESSAGE_MAP()


// Csession_regroupDlg 消息处理程序

BOOL Csession_regroupDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO:  在此添加额外的初始化代码

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void Csession_regroupDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void Csession_regroupDlg::OnPaint()
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
HCURSOR Csession_regroupDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void Csession_regroupDlg::OnBnClickedOk()
{
	FILE *in;
	CString input_path,output_path;
	tcp_head = NULL, tcp_tail = NULL;
	udp_head = NULL, udp_tail = NULL;
	http_head = NULL, http_tail = NULL;
	//input_path = "C:/Users/Administrator/Desktop/TCP[61.135.186.152][80][172.30.217.3][10061].pcap";
	input_path = "F:\\Documents\\Visual Studio 2013\\Projects\\tcpPcap\\tcpPcap/baidu.pcap";
	output_path = "C:/Users/Administrator/Desktop/httpout";
	
	//input.GetWindowTextW(input_path);
	//output.GetWindowTextW(output_path);
	TCHAR* dir = (TCHAR *)malloc(lstrlen(input_path)*sizeof(TCHAR));
	TCHAR drive[5], fname[50], ext[6];
	_wsplitpath(input_path, drive, dir, fname, ext);
	if (wcscmp(ext, _T(".pcap")) != 0){
		info.SetWindowTextW(_T(""));
		MessageBox(_T("输入格式错误"));
		return;
	}
	if (!createfolder(output_path)){
		info.SetWindowTextW(_T(""));
		MessageBox(_T("输出路径错误"));
		return;
	}
	createfolder(output_path);
	createfolder(output_path+_T("/pcap/"));
	createfolder(output_path + _T("/txt/"));
	createfolder(output_path + _T("/_txt/"));
	_wfopen_s(&in, input_path, _T("rb"));
	if (in != NULL){
		info.SetWindowTextW(_T("运行中，读取输入···"));
		fread(pcap_head, sizeof(u_char), 24, in);
		pcap_pkthdr *header = NULL;
		u_char pkt_header[16];
		u_char pkt_data[65535];
		while (!feof(in)){
			memset(pkt_data, 0, 65535);
			memset(pkt_header, 0, 16);
			fread(pkt_header, sizeof(u_char), 16, in);
			header = (pcap_pkthdr *)pkt_header;
			fread(pkt_data, sizeof(u_char), header->caplen, in);
			dispatcher_handler(NULL, header, pkt_data);
		}
		fclose(in);
		tcp_session *cur_ts = tcp_head;
		bool find_http = false;
		while (cur_ts != NULL){
			find_http = false;
			isTrunk = false;
			tcp_node *p = cur_ts->node_head;
			while (p != NULL){
				if (p->content_len > 0){
					for (int i=0; i < 7; i++){
						if (strncmp((char *)(p->pkt_data + p->offset), method[i], strlen(method[i])) == 0){
							find_http = true;
							break;
						}
					}
					if (find_http){
						handle_http(cur_ts, p);
					}
					if (cur_ts->sprot == 5060 || cur_ts->dprot == 5060){

					}
				}
				p = p->next;
			}
			cur_ts = cur_ts->next;
		}
		info.SetWindowTextW(_T("读取成功。"));
		analysis = true;
	}
	else {
		info.SetWindowTextW(_T(""));
		MessageBox(_T("打开文件失败。"));
		return;
	}
	
	return;
}
void Csession_regroupDlg::OnBnClickedOk2()
{
	if (!analysis){
		MessageBox(_T("分析未成功执行。"));
		return;
	}
	CString input_path, output_path;
	output_path = "C:/Users/Administrator/Desktop/httpout";

	FILE *pcap, *txt, *_txt;
	WCHAR filename[1000];
	WCHAR pcapname[1024], txtname[1024], _txtname[1024];
	tcp_session *cur_ts = tcp_head;
	while (cur_ts != NULL){
		memset(filename, 0, sizeof(filename));
		memset(pcapname, 0, sizeof(pcapname));
		memset(txtname, 0, sizeof(txtname));
		memset(_txtname, 0, sizeof(_txtname));

		wsprintf(filename, _T("TCP[%s][%u][%s][%u]"), (CString)(cur_ts->saddr), (cur_ts->sprot), (CString)(cur_ts->daddr), cur_ts->dprot);
		wsprintf(pcapname, _T("%s/pcap/%s.pcap"), output_path, filename);
		wsprintf(txtname, _T("%s/txt/%s.txt"), output_path, filename);
		wsprintf(_txtname, _T("%s/_txt/%s-.txt"), output_path, filename);
		_wfopen_s(&pcap, pcapname, L"wb");
		_wfopen_s(&txt, txtname, L"wb");
		_wfopen_s(&_txt, _txtname, L"wb");
		tcp_node *p = cur_ts->node_head, *tn_prev = NULL;
		int session_index = 0;
		if ((pcap != NULL) && (txt != NULL) && (_txt != NULL)){
			info.SetWindowTextW(_T("运行中，写入输入···"));
			fwrite(pcap_head, sizeof(u_char), 24, pcap);
			int char_len = sizeof(u_char);
			fprintf(_txt, "{[sadd]\t\t:[%s]\r\n", cur_ts->saddr);
			fprintf(_txt, "[dadd]\t\t:[%s]\r\n", cur_ts->daddr);
			fprintf(_txt, "[sport]\t\t:[%u]\r\n", cur_ts->sprot);
			fprintf(_txt, "[dport]\t\t:[%u]\r\n", cur_ts->dprot);
			fprintf(_txt, "[protocol]\t:[tcp]}\r\n\r\n\r\n\r\n", cur_ts->dprot);
			while (p != NULL){
				fwrite(&(p->pkth), sizeof(p->pkth), 1, pcap);
				fwrite(p->pkt_data, p->pkth.caplen, 1, pcap);
				if (p->content_len > 0){
					if (tn_prev != NULL){
						if (tn_prev->dir != p->dir){
							fwrite(&("\r\n\r\n\r\n\r\n"), sizeof(u_char), 8, txt);
						}
					}
					tn_prev = p;
					fwrite(p->pkt_data + p->offset, p->content_len, 1, txt);
				}
				fprintf(_txt, "{[seq]\t\t:[%u]\r\n", p->seq);
				fprintf(_txt, "[ack]\t\t:[%u]\r\n", p->ack);
				fprintf(_txt, "[flag]\t\t:[0x%x]\r\n", p->flag);
				fprintf(_txt, "[dir]\t\t:[%d]\r\n", p->dir);
				fprintf(_txt, "[pkt]\t\t:[0x%x]\r\n", &(p->pkth));
				fprintf(_txt, "[caplen]\t:[%u]\r\n", p->pkth.caplen);
				fprintf(_txt, "[content]\t:[0x%x]\r\n", &(p->pkt_data) + p->offset);
				fprintf(_txt, "[content_len]\t:[%d]}\r\n\r\n\r\n\r\n", p->content_len);
				p = p->next;
			}
		}
		else {
			info.SetWindowTextW(_T(""));
			MessageBox(_T("存储文件失败，路径不存在。tcp保存失败。"));
			return;
		}
		if (pcap != NULL){
			fclose(pcap);
		}
		if (_txt != NULL){
			fclose(_txt);
		}
		if (txt != NULL){
			fclose(txt);
		}
		cur_ts = cur_ts->next;
		session_index++;
	}
	udp_session *cur_us = udp_head;
	while (cur_us != NULL){
		memset(filename, 0, sizeof(filename));
		memset(pcapname, 0, sizeof(pcapname));
		memset(_txtname, 0, sizeof(_txtname));
		wsprintf(filename, _T("UDP[%s][%u][%s][%u]"), (CString)(cur_us->saddr), cur_us->sprot, (CString)(cur_us->daddr), cur_us->dprot);
		wsprintf(pcapname, _T("%s/pcap/%s.pcap"), output_path, filename);
		wsprintf(_txtname, _T("%s/_txt/%s-.txt"), output_path, filename);
		pcap = NULL;
		_txt = NULL;
		_wfopen_s(&pcap, pcapname, L"wb");
		_wfopen_s(&_txt, _txtname, L"wb");
		udp_node *p = cur_us->node_head, *tn_prev = NULL;
		if ((pcap != NULL) && (_txt != NULL)){
			info.SetWindowTextW(_T("运行中，写入输出···"));
			fwrite(pcap_head, sizeof(u_char), 24, pcap);
			int char_len = sizeof(u_char);
			fprintf(_txt, "{[sadd]\t\t:[%s]\r\n", cur_us->saddr);
			fprintf(_txt, "[dadd]\t\t:[%s]\r\n", cur_us->daddr);
			fprintf(_txt, "[sport]\t\t:[%u]\r\n", cur_us->sprot);
			fprintf(_txt, "[dport]\t\t:[%u]\r\n", cur_us->dprot);
			fprintf(_txt, "[protocol]\t:[udp]}\r\n\r\n\r\n\r\n", cur_us->dprot);
			while (p != NULL){
				fwrite(&(p->pkth), sizeof(p->pkth), 1, pcap);
				fwrite(p->pkt_data, p->pkth.caplen, 1, pcap);
				fprintf(_txt, "{[pkt]\t\t:[0x%x]\r\n", &(p->pkth));
				fprintf(_txt, "[caplen]\t:[%u]}\r\n\r\n\r\n\r\n", p->pkth.caplen);
				p = p->next;
			}
		}
		else {
			info.SetWindowTextW(_T(""));
			MessageBox(_T("存储文件失败，路径不存在。udp保存失败。"));
			return;
		}
		if (pcap != NULL){
			fclose(pcap);
		}
		if (_txt != NULL){
			fclose(_txt);
		}
		cur_us = cur_us->next;
	}
	http_session * cur_hs = http_head;
	while (cur_hs != NULL){
		memset(filename, 0, sizeof(filename));
		memset(txtname, 0, sizeof(txtname));
		if (cur_hs->filename != NULL){
			wsprintf(txtname, _T("%s/%s"), output_path, (CString)(cur_hs->filename));
		}
		else {
			wsprintf(filename, _T("%s/http[%s][%u][%s][%u]"), output_path, (CString)(cur_hs->saddr), cur_hs->sprot, (CString)(cur_hs->daddr), cur_hs->dprot);
			wsprintf(txtname, _T("%s.txt"), filename);
		}
		txt = NULL;
		_wfopen_s(&txt, txtname, L"wb");
		http_node *p = cur_hs->node_head, *tn_prev = NULL;
		if (_txt != NULL){
			info.SetWindowTextW(_T("运行中，写入输出···"));
			while (p != NULL){
				if (p->len){
					fwrite(p->content, p->len, sizeof(u_char), txt);
				}
				p = p->next;
			}
		}
		else {
			info.SetWindowTextW(_T(""));
			MessageBox(_T("存储文件失败，路径不存在。udp保存失败。"));
			return;
		}
		if (txt != NULL){
			fclose(txt);
			if (cur_hs->isGzip){
				_wfopen_s(&txt, txtname, _T("rb"));
				fseek(txt, 0, SEEK_END);
				int len = ftell(txt);
				rewind(txt);
				u_char * data = (u_char *)malloc(len);
				fread(data, len, 1, txt);
				fclose(txt);
				if (len > 0){
					std::string out;
					gzip_decoder *tool = new gzip_decoder(len * 4);
					bool res = tool->ungzip(data, len, out);
					if (res){
						_wfopen_s(&txt, txtname, _T("wb"));
						fwrite(out.c_str(), 1, out.size(), txt);
						fclose(txt);
					}
					delete tool;
				}
			}
		}
		cur_hs = cur_hs->next;
	}
	info.SetWindowTextW(_T(""));
	MessageBox(_T("处理完成。"));
	return;
}

u_int16_t Csession_regroupDlg::ntohs(u_int16_t nshort){
	u_int16_t low = nshort & 0x00ff;
	nshort = nshort >> 8;
	nshort = nshort | (low << 8);
	return nshort;
}
u_int16_t Csession_regroupDlg::htons(u_int16_t hshort){
	return ntohs(hshort);
}
u_int32_t Csession_regroupDlg::ntohi(u_int32_t nint){
	u_int byte1 = (nint & 0xff000000) >> 24;
	u_int byte2 = (nint & 0x00ff0000) >> 8;
	u_int byte3 = (nint & 0x0000ff00) << 8;
	u_int byte4 = (nint & 0x000000ff) << 24;
	return byte1 | byte2 | byte3 | byte4;
}
int Csession_regroupDlg::createfolder(CString path){
	if (!PathIsDirectory(path)){
		//_wmkdir(path);
		TCHAR drive[5], dir[1000], fname[50], ext[10];
		_wsplitpath(path,drive,dir, fname, ext);
		if (ext[0] != _T('\0')){
			return 0;
		}
		int len = wcslen(dir);
		while (dir[len-1] == _T('\\') || dir[len-1] == _T('/')){
			dir[len-1] = _T('\0');
		}
		TCHAR temPath[1030];
		temPath[0] = _T('\0');
		lstrcat(temPath, drive);
		lstrcat(temPath, dir);
		if (!createfolder(temPath)){
			return 0;
		}
		lstrcat(temPath, _T("/"));
		lstrcat(temPath, fname);
		!CreateDirectory(temPath, 0);
		
	}
	return 1;
}
void Csession_regroupDlg::add_tcp_session(int count,bool dir,tcp_session * ts, u_int32_t seq, u_int32_t ack, u_int16_t flag, u_char * pkt_data, int offset, int strl, pcap_pkthdr *header){
	tcp_node* tn = (tcp_node *)malloc(sizeof(tcp_node));
	tn->count = count;
	tn->seq = seq;
	tn->ack = ack;
	tn->flag = flag;
	tn->content_len = strl;
	tn->pkt_data = (u_char *)malloc(header->caplen*sizeof(u_char));
	tn->dir = dir;
	for (u_int i = 0; i < header->caplen; i++){
		tn->pkt_data[i] = pkt_data[i];
	}
	
	tn->offset = offset;
	tn->pkth.caplen = header->caplen;
	tn->pkth.len = header->caplen;
	tn->pkth.tv_sec = header->tv_sec;
	tn->pkth.tv_usec = header->tv_usec;
	tn->prev = NULL;
	tn->next = NULL;
	ts->node_head = tn;
	ts->node_tail = tn;
	if (tcp_head == NULL){
		tcp_head = ts;
		tcp_tail = ts;
	}
	else {
		tcp_session* p;
		p = tcp_head;
		while (p != NULL){
			if ((strcmp(p->saddr, ts->saddr) == 0) && (p->sprot == ts->sprot) && (strcmp(p->daddr, ts->daddr) == 0) && (p->dprot == ts->dprot)){
				free(ts);
				tcp_node *q = p->node_tail;
				while (q != NULL){
					if (((q->seq + q->ack) > (tn->seq + tn->ack)) || ((q->seq + q->ack) == (tn->seq + tn->ack)) && q->flag > tn->flag){
						if (q->prev == NULL){
							p->node_head = tn;
							tn->next = q;
							q->prev = tn;
							return;
						}
						else {
							q = q->prev;
						}
					}
					else {
						tn->next = q->next;
						if (q->next == NULL){
							p->node_tail = tn;
						}
						else {
							q->next->prev = tn;
						}
						tn->prev = q;
						q->next = tn;
						return;
					}
				}
			}
			tcp_tail = p;
			p = p->next;
		}
		tcp_tail->next = ts;
		tcp_tail = ts;
		return;
	}
}
void Csession_regroupDlg::add_udp_session(udp_session *us, u_char * pkt_data, pcap_pkthdr * header){
	udp_node* un = (udp_node *)malloc(sizeof(udp_node));
	un->pkt_data = (u_char *)malloc(header->caplen*sizeof(u_char));
	for (u_int i = 0; i < header->caplen; i++){
		un->pkt_data[i] = pkt_data[i];
	}
	un->pkth.caplen = header->caplen;
	un->pkth.len = header->len;
	un->pkth.tv_sec = header->tv_sec;
	un->pkth.tv_usec = header->tv_usec;
	un->next = NULL;
	un->prev = NULL;
	us->node_head = un;
	us->node_tail = un;
	if (udp_head == NULL){
		udp_head = us;
		udp_tail = us;
	}
	else {
		udp_session * p;
		p = udp_head;
		while (p != NULL){
			if ((strcmp(p->saddr, us->saddr) == 0) && (p->sprot == us->sprot) && (strcmp(p->daddr, us->daddr) == 0) && (p->dprot == us->dprot)) {
				free(us);
				udp_node *q = p->node_tail;
				p->node_tail = un;
				q->next = un;
				return;
			}
			udp_tail = p;
			p = p->next;
		}
		udp_tail->next = us;
		udp_tail = us;
		us->node_head = un;
		return;
	}
}
void Csession_regroupDlg::dispatcher_handler(u_char *temp1, pcap_pkthdr *header, u_char *pkt_data)
{
	u_int i = 0;
	ether_header * eheader = (ether_header *)pkt_data;
	count++;
	if (eheader->ether_type == htons(ETHERTYPE_IP)){
		ip_header * ih = (ip_header *)(pkt_data + sizeof(ether_header));
		int ip_len = (int)ntohs(ih->tlen);
		int ver = ih->verl >> 4;
		int ih_len = ih->verl & (0xf);
		ih_len = ih_len * 4;
		if (ih->proto == htons(TCP_PROTOCAL)){
			tcp_header *th = (tcp_header *)(pkt_data + sizeof(ether_header)+ih_len);
			int th_len = (int)(ntohs(th->len_resv_code) >> 12) * 4;
			int tcp_content_len = ip_len - ih_len - th_len;
			tcp_session* ts = (tcp_session *)malloc(sizeof(tcp_session));
			u_int32_t *add1, *add2;
			add1 = (u_int32_t *)(ih->saddr);
			add2 = (u_int32_t *)(ih->daddr);
			bool dir;
			if (ntohi(*add1) <= ntohi(*add2)){
				sprintf_s(ts->saddr, "%d.%d.%d.%d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
				sprintf_s(ts->daddr, "%d.%d.%d.%d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
				ts->sprot = ntohs(th->sport);
				ts->dprot = ntohs(th->dport);
				dir = true;
			}
			else {
				sprintf_s(ts->daddr, "%d.%d.%d.%d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
				sprintf_s(ts->saddr, "%d.%d.%d.%d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
				ts->sprot = ntohs(th->dport);
				ts->dprot = ntohs(th->sport);
				dir = false;
			}
			ts->proto = ih->proto;
			ts->next = NULL;
			ts->node_head = NULL;
			ts->node_tail = NULL;
			int offset = sizeof(ether_header)+ih_len + th_len;
			add_tcp_session(count,dir,ts, ntohi(th->seq), ntohi(th->ack), ntohs(th->len_resv_code&(0x0fff)),
				(u_char*)pkt_data, offset,
				tcp_content_len, header);
		}
		else if (ih->proto == htons(UDP_PROTOCAL)){
			udp_header *uh = (udp_header *)(pkt_data + sizeof(ether_header)+ih_len);
			udp_session* us = (udp_session *)malloc(sizeof(udp_session));
			u_int32_t *add1, *add2;
			add1 = (u_int32_t *)(ih->saddr);
			add2 = (u_int32_t *)(ih->daddr);
			if (ntohi(*add1) < ntohi(*add2)){
				sprintf_s(us->saddr, "%d.%d.%d.%d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
				sprintf_s(us->daddr, "%d.%d.%d.%d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
				us->sprot = ntohs(uh->sport);
				us->dprot = ntohs(uh->dport);
			}
			else {
				sprintf_s(us->daddr, "%d.%d.%d.%d", ih->saddr[0], ih->saddr[1], ih->saddr[2], ih->saddr[3]);
				sprintf_s(us->saddr, "%d.%d.%d.%d", ih->daddr[0], ih->daddr[1], ih->daddr[2], ih->daddr[3]);
				us->dprot = ntohs(uh->sport);
				us->sprot = ntohs(uh->dport);
			}

			us->next = NULL;
			us->node_head = NULL;
			us->node_tail = NULL;
			add_udp_session(us, (u_char*)pkt_data, header);
		}
	}
}

int find(u_char * in, const char * tail){
	for (int i = 0; i < (strlen((char *)in) - strlen(tail))+1; i++){
		if (strncmp((char *)(in + i), tail, strlen(tail)) == 0){
			return i;
		}
	}
	return -1;
}

char * split_file_name(char * path){
	//char *dir = (char*)malloc(sizeof(char)*strlen(path));
	char *file = (char*)malloc(sizeof(char)*strlen(path));
	file[0] = '\0';
	char ext[10];
	errno_t err=_splitpath_s(path, NULL, 0, NULL, 0, file, strlen(path), ext, 10);
	if ( strlen(ext) == 0 || err){
		int offset = find((u_char*)path, "?");
		if (offset >= 0){
			u_char *tem_path = (u_char *)malloc(offset + 1);
			memcpy(tem_path, path, offset);
			tem_path[offset] = '\0';
			errno_t err2 = _splitpath_s((char *)tem_path, NULL, 0, NULL, 0, file, strlen(path), ext, 10);
			if (!err2 && strlen(ext)!=0){
				goto fi;
			}
		}
		return NULL;
	}
	else {
		fi:
		char *filename = (char *)malloc(strlen(file) + strlen(ext) + 1);
		filename[0] = '\0';
		strcat(filename, file);
		strcat(filename, ext);
		return filename;
	}
	
}

void Csession_regroupDlg::handle_http(tcp_session *ts,tcp_node *tn){
	u_char *data = tn->pkt_data + tn->offset;
	http_session * hs = (http_session *)malloc(sizeof(http_session));
	strcpy(hs->saddr, ts->saddr);
	strcpy(hs->daddr, ts->daddr);
	hs->sprot = ts->sprot;
	hs->dprot = ts->dprot;
	hs->filename = NULL;
	hs->method = NULL;
	hs->ver = NULL;
	hs->status = NULL;
	hs->host = NULL;
	hs->total_len = 0;
	hs->path = NULL;
	hs->next = NULL;
	hs->isGzip = false;
	http_node * hn = (http_node *)malloc(sizeof(http_node));
	hn->next = NULL;
	hn->prev = NULL;
	int i = 0;
	int FLAG = 7;
	for (; i < 10; i++){
		if (strncmp((char *)data, method[i], strlen(method[i])) == 0){
			int type = i;
			int len = 0;
			bool isNew = false;
			if (type < FLAG){
				len = strlen(method[type]);
				hs->method = (u_char *)malloc(len + 1);
				memcpy(hs->method, data, len);
				hs->method[len] = '\0';
				isNew = true;
			}
			else {
				hs->method = (u_char *)malloc(1);
				memcpy(hs->method, "\0", 1);
				len = strlen(method[type]);
				hs->ver = (u_char *)malloc(len + 1);
				memcpy(hs->ver, data, len);
				hs->ver[len] = '\0';
				isNew = false;
			}
			data = data + len + SSP;
			len += SSP;
			int offset = find(data, SP);
			if (type < FLAG){
				hs->path = (u_char*)malloc(sizeof(u_char)*(offset + 1));
				memcpy(hs->path, data, offset);
				hs->path[offset] = '\0';
				hs->filename = (u_char *)split_file_name((char *)hs->path);
				printf("wait");
			}
			else {
				hs->status = (u_char*)malloc(sizeof(u_char)*(offset + 1));
				memcpy(hs->status, data, offset);
				hs->status[offset] = '\0';
			}

			data = data + offset + SSP;
			len += offset + SSP;
			offset = find(data, CRLF);
			if (type < FLAG){
				hs->ver = (u_char*)malloc(sizeof(u_char)*(offset + 1));
				memcpy(hs->ver, data, offset);
				hs->ver[offset] = '\0';
			}
			else {

			}
			data = data + offset + SCRLF;
			len += offset + SCRLF;
			offset = find(data, HLEN);
			if (offset != -1){
				u_char * cursor = data + offset + SHLEN + 1;
				offset = find(cursor, CRLF);
				char tem[6];
				memcpy(tem, cursor, offset);
				hn->len = (u_int)atol(tem)< tn->content_len ? (u_int)atol(tem) : tn->content_len;

			}
			else {
				hn->len = 0;
				offset = 0;
			}
			offset = find(data, ENCODE);
			if (offset != -1){
				u_char * cursor = data + offset + SENCODE + 1;
				offset = find(cursor, CRLF);
				u_char *tem = (u_char*)malloc(offset+1);
				memcpy(tem, cursor, offset);
				tem[offset] = '\0';
				offset = find(tem, "gzip");
				if (offset != -1){
					hs->isGzip = true;
				}
				else {
					hs->isGzip = false;
				}
				free(tem);
			}
			else {
				hs->isGzip = false;
			}
			offset = find(data, HOST);
			if (offset != -1){
				u_char * cursor = data + offset + SHOST + 1;
				offset = find(cursor, CRLF);
				hs->host = (u_char*)malloc(offset + 1);
				memcpy(hs->host, cursor, offset);
				hs->host[offset] = '\0';
			}
			offset = find(data, DCRLF);
			if (offset<0){
				isTrunk = true;
			}
			else {
				hn->content = (u_char *)malloc(hn->len);
				hn->content = data + offset + SDCRLF;
				len += offset + SDCRLF;
				u_int tcp_len = tn->content_len - len;
				hn->len = hn->len < tcp_len ? hn->len : tcp_len;
			}

			add_http_session(hs, hn,isNew);
			break;
		}
	}
	if (i >=10){
		if (isTrunk){
			int offset = find(data, DCRLF);
			if (offset<0){
				isTrunk = true;
				return;
			}
			isTrunk = false;
			hn->content = (u_char *)malloc(hn->len);
			hn->content = data + offset + SDCRLF;
			int len = offset + SDCRLF;
			u_int tcp_len = tn->content_len - len;
			hn->len = tn->content_len - len;
		}
		else {
			hn->len = tn->content_len;
			hn->content = data;

		}
		add_http_session(NULL, hn,false);
	}
}
void Csession_regroupDlg::add_http_session(http_session *hs,http_node *hn,bool isNew){
	if (hs != NULL){
		if (!isNew){
			http_tail->isGzip = hs->isGzip;
			http_tail->ver = (u_char *)malloc(strlen((char *)hs->ver));
			memcpy(http_tail->ver,hs->ver,strlen((char *)hs->ver));
			http_tail->status = (u_char *)malloc(4);
			memcpy(http_tail->status, hs->status, 4);
			http_tail->host = (u_char *)malloc(strlen((char *)hs->host));
			memcpy(http_tail->host, hs->host, strlen((char *)hs->host));
			free(hs->ver);
			free(hs->status);
			free(hs->host);
			free(hs);
			goto addnode;
		}
		else {
			hs->node_head = hn;
			hs->node_tail = hn;
			if (http_head == NULL){
				http_head = hs;
				http_tail = hs;
			}
			else {
				http_tail->next = hs;
				http_tail = hs;
			}
		}
		
	}
	else {
		addnode:
		http_session * p;
		p = http_tail;
		if (p != NULL){
			http_node *q = p->node_tail;
			p->node_tail = hn;
			q->next = hn;
		}
	}

}



