function FindProxyForURL(url,host)	
 {

//* Local Loopback return DIRECT *//
 if (shExpMatch(url,"*localhost*") || shExpMatch(url,"*127.0.0.1*")) return "DIRECT";

//* URL Miss return DIRECT *//
 if (!isResolvable(host)) return "DIRECT";

//* VARIABLE 및 필수 사항 *//
 var dip= dnsResolve(host);  //input destination IP Address to "dip"
 var cip = myIpAddress();
 if (shExpMatch(host,"proxy.samsungsds.com")) {return "DIRECT";}  
//* VARIABLE 및 필수 사항 - 끝 *//

// SDSC 전체 임직원 도메인 1 //

 //if (shExpMatch(dip,"109.52.120.*")) return "DIRECT";  //SDSC UREADY IP 250623
 //if (shExpMatch(dip,"109.52.121.*")) return "DIRECT";  //SDSC UREADY IP 250623
 //if (shExpMatch(cip,"109.52.36.60")) return "DIRECT";   // 20251023 temp test
 if (shExpMatch(cip,"109.52.36.223")) return "DIRECT";   // 20251023 temp test
 if (shExpMatch(dip,"182.192.*.*")) return "DIRECT";// vdi 240309
 if (shExpMatch(dip,"109.52.*.*")) return "DIRECT";// sdsc network 240423
 if (shExpMatch(dip,"109.52.164.*")) return "DIRECT";// xian vdi 240423
 if (shExpMatch(dip,"109.52.20.5")) return "DIRECT"; // security 240423
 if (shExpMatch(dip,"109.6.2.9")) return "DIRECT"; // security 241127
 if (shExpMatch(dip,"109.52.21.9")) return "DIRECT"; // SDSC FTP,security 240423
 if (dnsDomainIs(host,"gsrm.samsungsdi.com")) return "DIRECT";    // samsung sdi 240416
 if (shExpMatch(host,"*.singlewindow.cn")) return "DIRECT";    // di.liang 240417
 if (dnsDomainIs(host,"wss.singlewindow.cn")) return "DIRECT";    // di.liang 240417
 if (dnsDomainIs(host,"www.singlewindow.cn")) return "DIRECT";    // di.liang 240417
 if (dnsDomainIs(host,"app.singlewindow.cn")) return "DIRECT";    // di.liang 240417
 if (dnsDomainIs(host,"samsungcic.com")) return "DIRECT";    // samsung video 250703   (必须直通，否则本地不能播放）
 if (dnsDomainIs(host,"platform.samsungcic.com")) return "DIRECT";    // samsung video 250703   (必须直通，否则本地不能播放）
 if (dnsDomainIs(host,"api.samsungcic.com")) return "DIRECT";    // samsung video 250703   (必须直通，否则本地不能播放）
 if (dnsDomainIs(host,"streaming.samsungcic.com")) return "DIRECT";    // samsung video 250703   (必须直通，否则本地不能播放）
 
 //if (dnsDomainIs(host,"protect2.fireeye.com")) return "DIRECT";    // knox mail security 240309
 if (dnsDomainIs(host,"ep.sds.samsung.net")) return "DIRECT";    // sap 240309
 if (dnsDomainIs(host,"openplace-ep.sds.samsung.net")) return "DIRECT";    // sap 250217
 if (dnsDomainIs(host,"xiam.sds.samsung.net")) return "DIRECT";    //sap 250217
 if (shExpMatch(dip,"70.225.50.2")) return "DIRECT";       // sap，openplace3.0 250217
 if (shExpMatch(dip,"70.225.3.2")) return "DIRECT";       // sap openplace3.0 ,250217
 if (dnsDomainIs(host,"beian.cac.gov.cn")) return "DIRECT";    // gov download 240309
 if (shExpMatch(dip,"70.225.5.1")) return "DIRECT";       // fawu system 240423
 //if (dnsDomainIs(host,"tpass.tianjin.chinatax.gov.cn")) return "DIRECT";    // beijing tax, 240423
 //if (dnsDomainIs(host,"tpass.beijing.chinatax.gov.cn")) return "DIRECT";    // beijing tax, 240423
 //if (dnsDomainIs(host,"znhd.beijing.chinatax.gov.cn")) return "DIRECT";    // beijing tax, 250106
 ////////////以上gov.cn已在FW上开通了proxy直接访问。通过代理即可。不必开通PC防火墙。也不必direct。--xu///////////////////////////
 if (shExpMatch(dip,"182.193.17.133")) return "DIRECT";       //  sds gongshi guanli system 240423
 if (dnsDomainIs(host,"devops.sdsdev.co.kr")) return "DIRECT";    // devops.sdsdev.co.kr 240423
 if (dnsDomainIs(host,"code.sdsdev.co.kr")) return "DIRECT";    // code.sdsdev.co.kr 240423
 if (shExpMatch(dip,"70.227.9.9")) return "DIRECT";       // devops.sdsdev.co.kr 240423
 if (shExpMatch(dip,"70.227.98.161")) return "DIRECT";       // stage.hap.samsungsds.com 250312,mg1.cheng 已经申请开通了防火墙PC直连。
 if (shExpMatch(dip,"70.227.73.1")) return "DIRECT";        //https://70.227.73.1/C601000-000/admin/login    (Endpoint Security Suite Login) 20250424
 if (shExpMatch(dip,"42.15.249.78")) return "DIRECT";        //https://42.15.249.78/C601000-000/admin/login    (Endpoint Security Suite Login  20250424
 if (shExpMatch(dip,"70.227.39.65")) return "DIRECT";       // Performance Station 250417,mx1.jin 已经申请开通了防火墙PC和vdi直连，ID:FW20250417000000873921
 if (shExpMatch(dip,"70.225.5.10")) return "DIRECT";       // SR sdsc 240423   8803port
 if (shExpMatch(dip,"70.225.5.12")) return "DIRECT";       // dan.li   7016port
 if (shExpMatch(dip,"70.225.5.2")) return "DIRECT";       // ruihua.xu   7015port
 if (dnsDomainIs(host,"clms.samsung.com.cn")) return "DIRECT";    // 20240426  new
 if (shExpMatch(host,"*.cmbchina.com")) return "DIRECT";    // 20240428 xianghua.piao new
 if (shExpMatch(host,"*.iam.samsung.net")) return "DIRECT";    // 20240428 xianghua.piao new
 //if (dnsDomainIs(host,"wd3.myworkday.com")) return "DIRECT";    // 20250609 GHRP-W
 if (dnsDomainIs(host,"fabrix-in.samsungsds.com")) return "DIRECT";    // 20240430 
 if (shExpMatch(dip,"70.225.5.3")) return "DIRECT";       // guang.li  http://70.225.5.3:2007/ArisamWeb/index.do
 if (shExpMatch(dip,"70.2.140.200")) return "DIRECT";      // xianghua.piao   7011port
 if (shExpMatch(dip,"109.6.1.5")) return "DIRECT";      // hua.liu
 if (shExpMatch(dip,"109.6.103.1")) return "DIRECT";      // sdsc-dev.accessmanager.io (hosts)
 if (dnsDomainIs(host,"hrs-servicedesk.net")) return "DIRECT";  
 if (dnsDomainIs(host,"sdsc-prd.accessmanager.io")) return "DIRECT"; 
 if (dnsDomainIs(host,"sdsc.eams.sdsdev.com")) return "DIRECT";
 if (dnsDomainIs(host,"www.ghrp.samsungsds.com")) return "DIRECT";  //yanan.li 20240507 

 if (dnsDomainIs(host,"hrs-servicedesk.net")) return "DIRECT"; //yanan.li 20240507 new
 if (dnsDomainIs(host,"rs.ssis.samsungsds.com")) return "DIRECT"; //yongcheng.jin 20240508 new
 if (dnsDomainIs(host,"www.startsupport.com")) return "DIRECT"; //yongcheng.jin 20240508 new
 if (dnsDomainIs(host,"113366.com")) return "DIRECT"; //yongcheng.jin 20240508 new
 if (dnsDomainIs(host,"ssmp.samsungsds.com")) return "DIRECT"; //ruihua.xu 20240508 new
 if (shExpMatch(dip,"109.6.11.3")) return "DIRECT";      // jianhui.an new
 if (shExpMatch(dip,"124.251.7.68")) return "DIRECT";      // jing.yu 8655port
 if (shExpMatch(dip,"116.205.88.239")) return "DIRECT";    //jing.yu FW20260522000001077156  http://116.205.88.239:8655/samsungsms/login
 if (shExpMatch(dip,"70.225.5.5")) return "DIRECT";       // yanan.li   9051port
 if (dnsDomainIs(host,"iopsfw.samsungsds.com")) return "DIRECT"; //ruihua.xu 20240514 new
 if (dnsDomainIs(host,"iops.samsungsds.com")) return "DIRECT"; //ruihua.xu 20240514 new
 if (dnsDomainIs(host,"iopswm.samsungsds.com")) return "DIRECT"; //ruihua.xu 20240514 new
 if (dnsDomainIs(host,"iopswmct.samsungsds.com")) return "DIRECT"; //ruihua.xu 20240514 new
 if (dnsDomainIs(host,"iopswmit.samsungsds.com")) return "DIRECT"; //ruihua.xu 20240514 new
 if (dnsDomainIs(host,"iopscomm.samsungsds.com")) return "DIRECT"; //ruihua.xu 20240514 new

 if (shExpMatch(dip,"70.121.*.*")) return "DIRECT";  // SDSK VDI접속 20240516
 if (shExpMatch(dip,"70.122.*.*")) return "DIRECT";  // SDSK VDI접속 20240516
 if (shExpMatch(dip,"70.123.*.*")) return "DIRECT";  // SDSK VDI접속 20240516
 if (dnsDomainIs(host,"fabrix-in.samsungsds.com")) return "DIRECT"; //fabrix 20240517 new
 if (dnsDomainIs(host,"fabrix-s.samsungsds.com")) return "DIRECT"; //fabrix ai chat 20240517 new
 if (dnsDomainIs(host,"sdssfa.my.salesforce.com")) return "DIRECT"; //ruihua.xu 20240520 new
 if (shExpMatch(dip,"182.195.83.117")) return "DIRECT";           // SDS APPLICATION MONITORING SYSTEM,xiaohua.quan_20240524//
 if (dnsDomainIs(host,"mspplus.samsungsds.com")) return "DIRECT"; //SDS MSP+ SYSTEM,xiaohua.quan_20240524
 if (dnsDomainIs(host,"mp.samsungsdscloud.com")) return "DIRECT"; //SDS SYSTEM: mp.samsungsdscloud.com,jinghui.xu_20240524
 if (shExpMatch(dip,"109.6.3.2")) return "DIRECT";           // SDSC COMMONSDSC 20240524
 if (dnsDomainIs(host,"sdsc.projectview.sdsdev.co.kr")) return "DIRECT"; //SDS SYSTEM xiumei.jin_20240527
 if (dnsDomainIs(host,"abroad.cloud.nmsplus.net")) return "DIRECT"; //MNS site yongzhu.an_20240531
 if (shExpMatch(dip,"182.195.85.51")) return "DIRECT";  //MNS site yongzhu.an_20240531 
 if (shExpMatch(dip,"182.195.85.12")) return "DIRECT";  //MNS site yongzhu.an_20240531 
 if (dnsDomainIs(host,"asharp.sdsdev.co.kr")) return "DIRECT"; //meixiang.jin_20240531
 if (dnsDomainIs(host,"aipro.sdsdev.co.kr")) return "DIRECT"; //meixiang.jin_20240531
 if (shExpMatch(dip,"70.227.9.12")) return "DIRECT";    //meixiang.jin_20240531
 if (shExpMatch(dip,"70.227.9.1")) return "DIRECT";      //meixiang.jin_20240531
 if (dnsDomainIs(host,"tx360.sdsdev.co.kr")) return "DIRECT"; //meixiang.jin_20240531
 if (shExpMatch(dip,"109.6.54.1")) return "DIRECT";           // SAMSUNG SDS LEGO 20240531
 if (dnsDomainIs(host,"efss.samsung.net")) return "DIRECT"; //haeyong yang 20240604
 if (shExpMatch(dip,"109.6.1.7")) return "DIRECT";           // xiang.jin 20240606
 if (shExpMatch(dip,"109.52.64.14")) return "DIRECT";           // yiwan.ge 20240607
 if (shExpMatch(dip,"182.193.21.166")) return "DIRECT";           // ning.cheng 20240607
 if (shExpMatch(dip,"109.10.87.57")) return "DIRECT";           // yongjie.jin 20240612
 if (shExpMatch(dip,"70.225.3.10")) return "DIRECT";           //[SCI] http://70.225.3.10:7082/htmlOsci/IndexSingle.jsp,ruihua.xu 20240617
 if (shExpMatch(dip,"70.225.0.12")) return "DIRECT";           // ruihua.xu 20240617
 if (shExpMatch(dip,"70.225.0.13")) return "DIRECT";           // ruihua.xu 20240617
 if (shExpMatch(dip,"70.220.30.226")) return "DIRECT";           // https://stagemspitsm.samsungsds.com 241021
 if (shExpMatch(dip,"70.220.30.229")) return "DIRECT";           // https://stgmspplus.samsungsds.com 241021
 if (shExpMatch(dip,"70.220.49.225")) return "DIRECT";           // https://stgmspplus.samsungsds.com 241021
 
 if (shExpMatch(dip,"70.222.5.3")) return "DIRECT";           // 250313
 if (shExpMatch(dip,"70.222.0.60")) return "DIRECT";           // lookin.samsungsds.com_250313
 if (shExpMatch(dip,"70.222.63.4")) return "DIRECT";           // shan.xu firewall request 20260318
 if (shExpMatch(dip,"109.6.2.2")) return "DIRECT";             // sdsc scp ftp server 241120
 if (shExpMatch(dip,"109.6.2.10")) return "DIRECT";             // sdsc scp EMASSDC server 241225
 if (shExpMatch(dip,"109.6.2.9")) return "DIRECT";             // sdsc scp ESCORT server 241225
 if (shExpMatch(dip,"109.6.1.2")) return "DIRECT";             // sdsc scp EPP server 241225
 if (shExpMatch(dip,"109.6.1.13")) return "DIRECT";             // sdsc scp EDR server 251203
 if (shExpMatch(dip,"109.5.51.4")) return "DIRECT";             //  20250221
 if (shExpMatch(dip,"109.5.51.5")) return "DIRECT";             // 20250221
 if (shExpMatch(dip,"109.6.7.66")) return "DIRECT";             // 20250604 Zabbix guangze.jin
 if (shExpMatch(dip,"109.6.7.77")) return "DIRECT";             // 20250604 ipam guangze.jin 20260116
 if (shExpMatch(dip,"109.6.7.70")) return "DIRECT";             // 20260707 Ftp（serv-U） guangze.jin  FW20260616000001090831
 if (shExpMatch(dip,"109.6.7.71")) return "DIRECT";             // 20260707 PRTG guangze.jin  FW20260616000001090831
 if (shExpMatch(dip,"109.5.1.*")) return "DIRECT";              // http://109.5.1.26:7004/bmrs/sslmain.do
 if (shExpMatch(dip,"109.5.1.25")) return "DIRECT";              // https://109.5.1.25 
 if (shExpMatch(dip,"109.5.101.4")) return "DIRECT";              // https://109.5.101.4:8080 //金成范MCS项目 申请了防火墙直通
 if (shExpMatch(dip,"109.5.101.6")) return "DIRECT";              // https://109.5.101.6:8070 //金星 申请了防火墙直通
 if (shExpMatch(dip,"109.5.68.34")) return "DIRECT";              // https://109.5.68.34:8080 //金成范MCS项目 申请了防火墙直通
 if (shExpMatch(dip,"109.5.72.2")) return "DIRECT";              // https://109.5.72.2:9595 //RMS测试服务器，金星申请了防火墙，改为直通 20251014
 if (shExpMatch(dip,"109.133.25.10")) return "DIRECT";              // https://109.133.25.10 //李明星SESY-FW, 申请了防火墙直通
 if (shExpMatch(dip,"109.5.74.226")) return "DIRECT";              // http://109.5.74.226    //金星申请了防火墙直通 20251106
 if (shExpMatch(dip,"52.83.236.168")) return "DIRECT";              //haocheng.li申请了防火墙直通 20260420
 if (shExpMatch(dip,"52.83.110.138")) return "DIRECT";              //haocheng.li申请了防火墙直通 20260420
 if (shExpMatch(dip,"109.5.90.35")) return "DIRECT";              //zhirong.zhao申请了防火墙直通 20260720
 
 if (dnsDomainIs(host,"lookin.samsungsds.com")) return "DIRECT";    //20250221
 if (dnsDomainIs(host,"mspitsm.samsungsds.com")) return "DIRECT";   //20250221
 if (dnsDomainIs(host,"scloud.singleid.samsung.net")) return "DIRECT";   //20251107 从vdi访问需直通
 //if (dnsDomainIs(host,"confluence.secext.samsung.net")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY";   //20250424
 if (dnsDomainIs(host,"ifas.samsung.net")) return "DIRECT";   //20253228 knox mail大附件下载。
 if (dnsDomainIs(host,"mspitsm.samsungsds.com")) return "DIRECT";   //20250221
 if (dnsDomainIs(host,"ai-poc.samsungsds.com.cn")) return "DIRECT";   //20250510 zhirong.zhao 申请了防火墙20250508-20260807
 if (dnsDomainIs(host,"s-nova.samsungsds.com.cn")) return "DIRECT";   //https://s-nova.samsungsds.com.cn:3000,20251113 zhirong.zhao 申请了防火墙20250508-20260807
 if (dnsDomainIs(host,"s-nova2.samsungsds.com.cn")) return "DIRECT";   //https://s-nova2.samsungsds.com.cn:3000,20251113 zhirong.zhao 申请了防火墙2026-06-25 ~ 2027-06-24
 if (dnsDomainIs(host,"s-nova2-admin.samsungsds.com.cn")) return "DIRECT";   //https://s-nova2-admin.samsungsds.com.cn:4000 zhirong.zhao 申请了防火墙2026-06-25 ~ 2027-06-24 
 if (shExpMatch(dip,"182.193.5.61")) return "DIRECT";    //20250226(vdi上无法打开，吕林让加）
 if (shExpMatch(dip,"182.193.4.225")) return "DIRECT";       //  sds gongshi guanli system 240423
 //if (dnsDomainIs(host,"mail-training.co.kr")) return "DIRECT";   //20250317 wy.jiang 钓鱼邮件网址
 //if (shExpMatch(dip,"114.204.162.124")) return "DIRECT";   //20250317 wy.jiang 钓鱼邮件网址
 if (shExpMatch(cip,"109.52.124.116")) return "DIRECT";      //hui1.quan test 20250220
 if (shExpMatch(dip,"10.40.20.184")) return "DIRECT";      //haojie.ye 在vdi里面访问10.40.20.184：8088，防火墙审批完成。20250320
 if (shExpMatch(dip,"10.40.20.201")) return "DIRECT";      //haojie.ye 在vdi里面访问10.40.20.184：8088，防火墙审批完成。20250320
 if (shExpMatch(dip,"182.195.86.250")) return "DIRECT";      //ycheng.jin 已经申请防火墙 20250401
 if (shExpMatch(dip,"182.195.86.252")) return "DIRECT";      //ycheng.jin 已经申请防火墙 20250401
 if (dnsDomainIs(host,"rs.ssis.samsungsds.com")) return "DIRECT";    //ycheng.jin 已经申请防火墙 20250401
 if (dnsDomainIs(host,"galaxy.local.opentide.com")) return "DIRECT";    //yj01.jin 已经申请防火墙 202504010-20260409
 if (dnsDomainIs(host,"wcmsgc3.local.opentide.com.cn")) return "DIRECT";    //yj01.jin 已经申请防火墙 202504010-20260409
 if (dnsDomainIs(host,"wcmsgc.local.opentide.com.cn")) return "DIRECT";    //yj01.jin 已经申请防火墙 202504010-20260409
 if (dnsDomainIs(host,"wcmsgc2.local.opentide.com.cn")) return "DIRECT";    //yj01.jin 已经申请防火墙 202504010-20260409
 if (dnsDomainIs(host,"wcmsgc.local.opentide.com.cn")) return "DIRECT";    //yj01.jin 已经申请防火墙 202504010-20260409
 if (dnsDomainIs(host,"galaxy.local.opentide.com.cn")) return "DIRECT";    //yj01.jin 已经申请防火墙 202504010-20260409
 //if (shExpMatch(dip,"203.254.247.145")) return "DIRECT";      //juan.guo 已经申请防火墙 20251013
 //if (dnsDomainIs(host,"wsstage.samsung.net")) return "DIRECT";  //juan.guo 已经申请防火墙 20251013
 if (shExpMatch(dip,"109.254.2.208")) return "DIRECT"; //yj01.jin 已经申请防火墙 202504010-20260409
 if (shExpMatch(dip,"109.254.2.218")) return "DIRECT"; //yj01.jin 已经申请防火墙 202504010-20260409
 if (shExpMatch(dip,"182.195.128.109")) return "DIRECT"; //dejun.yang 已经申请防火墙 20250430-20251029
 if (shExpMatch(dip,"109.5.0.35")) return "DIRECT"; //金成范已经申请防火墙 20250930-260130
 if (shExpMatch(dip,"109.5.0.36")) return "DIRECT"; //金成范已经申请防火墙 20250930-260130
 if (shExpMatch(dip,"109.5.0.37")) return "DIRECT"; //金成范已经申请防火墙 20250930-260130
 if (shExpMatch(dip,"109.5.31.150")) return "DIRECT"; //金成范已经申请防火墙 20250930-260630
 if (shExpMatch(dip,"109.6.52.13")) return "DIRECT"; //郭娟邀请给法务内部测试地址设置为直通
 if (dnsDomainIs(host,"premcs.samsungmcs.com")) return "DIRECT"; //金成范已经申请防火墙 20250930-260130
 if (dnsDomainIs(host,"sds.drive.samsung.net")) return "DIRECT";    //本社人员要下载samsung drive 临时开通了防火墙
 if (dnsDomainIs(host,"knox.efss.samsung.net")) return "DIRECT"; // ruihua.xu 20240617
 if (shExpMatch(dip,"109.6.54.2")) return "DIRECT";           //SDSCPortal(Stage),20240618
 if (shExpMatch(dip,"109.6.54.3")) return "DIRECT";           //  http://109.6.54.3:3101  SDSC AI HR 招聘系统
 if (shExpMatch(dip,"109.6.54.5")) return "DIRECT";           //  http://109.6.54.5:3101 ,SDSC 银行金额日报Agent系统
 if (shExpMatch(dip,"109.6.3.3")) return "DIRECT";           //SDSCPortal(zhengshi),20240618 (no f/w)
 if (dnsDomainIs(host,"recruit.grh.samsung.net")) return "DIRECT"; // ruihua.xu 20240617
 //if (dnsDomainIs(host,"www.smart-together.com")) return "DIRECT"; // ruihua.xu 20240620sdsc
 if (dnsDomainIs(host,"portal.samsungsds.com.cn")) return "DIRECT"; // sdscportal.samsungsds.com.cn,ruihua.xu 20240624 (no f/w)
 if (dnsDomainIs(host,"scsvisitor.samsung.com.cn")) return "DIRECT"; // 协商网址https://scsvisitor.samsung.com.cn:8090/
 if (shExpMatch(dip,"203.86.53.176")) return "DIRECT";           // 朝阳区重点产业政策信息管理平台) 方兰（自己申请FW)  http://203.86.53.176:6060/cyzc_ent/#/
 if (shExpMatch(dip,"70.220.51.65")) return "DIRECT";         		//三星内部系统，A# https://asharp.sdsdev.co.kr
 if (shExpMatch(dip,"70.220.145.1")) return "DIRECT";         		//三星内部系统，https://gppm.samsungappservice.com
 if (shExpMatch(dip,"70.220.98.33")) return "DIRECT";   //chengfan.jin SOI Promotion项目 FW20260828000001132105
 if (shExpMatch(dip,"70.121.224.52")) return "DIRECT";   //chengfan.jin SOI Promotion项目 FW20260828000001132105
 
 
 if (dnsDomainIs(host,"asharp.sdsdev.co.kr")) return "DIRECT";		//三星内部系统，A# https://asharp.sdsdev.co.kr
 if (shExpMatch(dip,"109.6.2.7")) return "DIRECT";           // SDSC SecuPrint7@SCP 240725
 //if (shExpMatch(dip,"10.227.103.50")) return "DIRECT";           // host,"stsds.secsso.net,内部IP，需要修改电脑上的hosts
 //if (shExpMatch(dip,"103.83.46.173")) return "DIRECT";      //税务直报系统 20240801 chy.piao only //取消直通，防火墙开通了proxy IP直接访问https://103.83.46.173:8099
 if (dnsDomainIs(host,"itrm.sec.samsung.net")) return "DIRECT";		//三星电子内部系统IRP，https://itrm.sec.samsung.net,yinji.zhao 20240809
 if (dnsDomainIs(host,"nirp-qa.sec.samsung.net")) return "DIRECT";		//三星电子内部系统N-IRP, https://nirp-qa.sec.samsung.net,yinji.zhao_20240809
 if (dnsDomainIs(host,"nirp.sec.samsung.net")) return "DIRECT";		//三星电子内部系统N-IRP, https://nirp.sec.samsung.net,yinji.zhao_20240809
 if ((shExpMatch(cip,"109.52.36.226"))&&(dnsDomainIs(host,"stsds.secsso.net"))) return "DIRECT";		//三星电子内部系统N-IRP认证网站secsso, APP.IT.Group申请了直接访问。2608
 //if ((shExpMatch(cip,"182.192.89.15")) && (dnsDomainIs(host,"youtube.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (dnsDomainIs(host,"sts.secsso.net")) return "DIRECT";		//三星电子内部系统N-IRP认证网站secsso, https://sts.secsso.net
 if (dnsDomainIs(host,"vkghrap.sec.samsung.net")) return "DIRECT";	// https://vkghrap.sec.samsung.net:5999/cis/portal/sdpMain.do
 if (dnsDomainIs(host,"ndedidap.sec.samsung.net")) return "DIRECT";	//https://ndedidap.sec.samsung.net:8443/,shunji.cui,FW20260720000001109107
 if (dnsDomainIs(host,"ndedipap.sec.samsung.net")) return "DIRECT";	//https://ndedipap.sec.samsung.net:8443/,shunji.cui,FW20260720000001109107
 if (dnsDomainIs(host,"nsedidap.sec.samsung.net")) return "DIRECT";	//https://nsedidap.sec.samsung.net:8443/,shunji.cui,FW20260720000001109107
 if (dnsDomainIs(host,"nsedipap.sec.samsung.net")) return "DIRECT";	//https://nsedipap.sec.samsung.net:8443/,shunji.cui,FW20260720000001109107
  
 if (dnsDomainIs(host,"mfa.secsso.net")) return "DIRECT";		//三星电子内部系统N-IRP认证网站secsso, https://mfa.secsso.net,yinji.zhao_20240809
 //if (dnsDomainIs(host,"corpadpss.secsso.net")) return "DIRECT";		//三星电子内部系统N-IRP认证网站secsso, https://corpadpss.secsso.net,yinji.zhao_20240809     //20250414取消了direct，因为vdi里面无法访问by xu
 if (dnsDomainIs(host,"scop.sec.samsung.net")) return "DIRECT";		//三星电子内部系统SCOP, https://scop.sec.samsung.net,yuanlin.jin 20240914 (no f/w)
 if (dnsDomainIs(host,"code.sdsdev.co.kr")) return "DIRECT";        // 三星github企业版地址 yuanlin.jin
 if (dnsDomainIs(host,"backend.cop-prd.click")) return "DIRECT";	 //三星电子内部系统SCOP, https://scop.sec.samsung.net,yuanlin.jin 20240914 (no f/w)
 if (dnsDomainIs(host,"scop-dev-cn-tfstate.s3.cn-north-1.amazonaws.com.cn")) return "DIRECT";//三星电子内部系统SCOP yuanlin.jin 20240914 (no f/w)
 if (dnsDomainIs(host,"sdsdev.co.kr")) return "DIRECT";		 //三星电子内部系统  成明刚
 if (dnsDomainIs(host,"stagemspitsm.samsungsds.com")) return "DIRECT";	//三星SDS内部系统测试 yue.liu 241021 自己申请了防火墙
 if (dnsDomainIs(host,"stgmspplus.samsungsds.com")) return "DIRECT";	//三星SDS内部系统 yue.liu 241021 自己申请了防火墙
 if (dnsDomainIs(host,"sreplus3-stg.sdsdev.co.kr")) return "DIRECT";	//三星SDS内部系统 yue.liu 241021 自己申请了防火墙
 if (dnsDomainIs(host,"scloud.samsungsds.com")) return "DIRECT";
 if (shExpMatch(dip,"119.180.26.88")) return "DIRECT";                  //yanping.guan vpn支援天津申请了防火墙
 if (shExpMatch(dip,"122.5.3.88")) return "DIRECT";                     //yanping.guan vpn支援天津申请了防火墙
 if (shExpMatch(dip,"72.2.2.235")) return "DIRECT";       //http://72.2.2.235:8020/agent/identity/anoymous/ssoLogin.do? layout=NO   机票担当王春杏申请了防火墙，只有他的有线IP109.52.36.14能访问。
 if (shExpMatch(dip,"123.37.41.184")) return "DIRECT";    //neil.kang 20260724-0824 firewall
 //if (dnsDomainIs(host,"oiems.samsung.com.cn")) return "DIRECT";	//三星SDS内部系统oiems.samsung.com.cn,109.5.23.225,yiwan.zhang 自己申请了防火墙 FW20260731000001115901  
 if (shExpMatch(dip,"109.5.23.225")) return "DIRECT";             //三星SDS内部系统oiems.samsung.com.cn,yiwan.zhang 自己申请了防火墙 FW20260731000001115901
 

 if (dnsDomainIs(host,"nsrm.sec.samsung.net")) return "DIRECT";	
 if (dnsDomainIs(host,"dsnsrm.sec.samsung.net")) return "DIRECT";	
  if (dnsDomainIs(host,"nerpsr.sec.samsung.net")) return "DIRECT";    //haojie.ye  FW 20260828申请了防火墙
 if (dnsDomainIs(host,"nerpd-mf.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"nerps-mf.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"nerpd-bh.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"nerps-bi.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"nerpd-bi.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"nerpdr-ac.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"gppm.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"segam.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"bqms.sec.samsung.net")) return "DIRECT";
 //if (dnsDomainIs(host,"dsbqms.samsungds.net")) return "DIRECT";
 if (dnsDomainIs(host,"nerpd-ac.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"nerps-ac.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"nerpd-voc.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"nerps-voc.sec.samsung.net")) return "DIRECT";
 if (dnsDomainIs(host,"samsung.csod.com")) return "DIRECT";
 //if (dnsDomainIs(host,"www.imarketchina.net")) return "DIRECT";

 
 if (dnsDomainIs(host,"hrs-servicedesk.net")) return "DIRECT";	//三星SDS内部系统GHRP（S）的SR平台
 if (dnsDomainIs(host,"bigdata.samsung.com")) return "DIRECT";	//三星SDS内部系统 songquan.ma 241209 自己申请了防火墙
 if (dnsDomainIs(host,"wd3-impl.workday.com")) return "DIRECT";		//三星SDS内部系统GHRP(W)测试网站，zhenhua.jin_241220
 if (dnsDomainIs(host,"fossid.devops.sec.samsung.net")) return "DIRECT"; //三星内部系统 songquan.ma 250114 (no f/w)
 if (dnsDomainIs(host,"sscboard.net")) return "DIRECT"; //20250319 bosun8.kim 用户自己申请了fw
 if (shExpMatch(dip,"42.15.243.2")) return "DIRECT"; //20250319 bosun8.kim 用户自己申请了fw
 if (shExpMatch(dip,"10.40.20.184")) return "DIRECT"; //20250320 叶豪杰  用户自己申请了fw
 if (dnsDomainIs(host,"meta-llama-3-70b-instruct.serving.70-220-152-1.sslip.io")) return "DIRECT"; //20250507 yiwan.zhang 用户自己申请了fw
 if (dnsDomainIs(host,"portal.azure.cn")) return "DIRECT"; //250523 协助越南测试
 if (dnsDomainIs(host,"management.chinacloudapi.cn")) return "DIRECT"; //250523 协助越南测试
 if (shExpMatch(dip,"109.5.68.66")) return "DIRECT"; //20250529 金成范  用户自己申请了fw
 if (dnsDomainIs(host,"confluence.secext.samsung.net")) return "DIRECT"; //250605  ds.quan 三星内網全員申請防火墻完成                                                                                                                                                                                                                                                                     
 if (dnsDomainIs(host,"jira.secext.samsung.net")) return "DIRECT"; //250605  ds.quan 三星内網全員申請防火墻完成
 if (dnsDomainIs(host,"mfa.secsso.net")) return "DIRECT"; //250605  ds.quan 三星内網全員申請防火墻完成
 if (dnsDomainIs(host,"bizaccount-ciam.samsung.com")) return "DIRECT"; //250605  ds.quan 三星内網全員申請防火墻完成
 if (dnsDomainIs(host,"sts.secsso.net")) return "DIRECT"; //250605  ds.quan 三星内網全員申請防火墻完成 
 if (dnsDomainIs(host,"fidm.au1.gigya.com")) return "DIRECT"; //250605  ds.quan 三星内網全員申請防火墻完成  
 if (dnsDomainIs(host,"nexus.sdsdev.co.kr")) return "DIRECT"; //250605  ds.quan 三星内網全員申請防火墻完成  
 if (dnsDomainIs(host,"bart.sec.samsung.net")) return "DIRECT"; //250605  ds.quan 三星内網全員申請防火墻完成  
 //if (dnsDomainIs(host,"ridibooks.com")) return "DIRECT"; //250630 bosun8.kim test
 if (dnsDomainIs(host,"lc.multicampus.com")) return "DIRECT"; //250701 proxy模式无法访问。直通可以。
 if (dnsDomainIs(host,"api.multicampus.com")) return "DIRECT"; //250701 proxy模式无法访问。直通可以。
 if (shExpMatch(dip,"119.196.101.176")) return "DIRECT"; //20250016 bosun8.kim  用户自己申请了fw 119.196.101.176:8443
 if (shExpMatch(dip,"70.225.5.19")) return "DIRECT";       // mybi.sds.samsung.net 20250723
// if (dnsDomainIs(host,"partner.samsungsemi.com")) return "DIRECT"; //250730 yanhua.h 申请了防火墙 端口：7777
 if (dnsDomainIs(host,"n8ndev.samsungsds.com.cn")) return "DIRECT"; //250728-20260727 ds.quan 申请了防火墙 
 if (dnsDomainIs(host,"n8n-scp-scic-stg.samsungsds.com.cn")) return "DIRECT"; //白良银申请防火墙
 if (dnsDomainIs(host,"n8n-scp-scic-prd.samsungsds.com.cn")) return "DIRECT"; //白良银申请防火墙
 if (dnsDomainIs(host,"n8n-scp-sdsc-poc.samsungsds.com.cn")) return "DIRECT"; //白良银申请防火墙
 if (dnsDomainIs(host,"difydev.samsungsds.com.cn")) return "DIRECT"; //250728-20260727 ds.quan 申请了防火墙
 if (shExpMatch(dip,"109.6.22.5")) return "DIRECT";  //250728-20260727 ds.quan 申请了防火墙
 if (shExpMatch(dip,"42.15.248.183")) return "DIRECT"; //20250815 dongping.hu 用户自己申请了fw
 if (dnsDomainIs(host,"adportal.sec.samsung.net")) return "DIRECT"; //250815   三星内網全員申請防火墻完成  
 if (shExpMatch(dip,"10.40.200.75")) return "DIRECT"; //金美香 FW20250210000000840224-- hy03.cheng访问http://10.40.200.75:35080/emm/admin/login.do
 if (shExpMatch(dip,"112.107.222.96")) return "DIRECT"; //20250916 hy01.cheng visit mobileKnox http://112.107.222.96/
 if (shExpMatch(host,"*.sso-portal.us-east-1.amazonaws.com")) return "DIRECT"; //到26年十月，藏东聚申请了防火墙
 if (shExpMatch(host,"*.aws.dev")) return "DIRECT"; //到26年十月，藏东聚申请了防火墙
 if (dnsDomainIs(host,"*.awsstatic.com")) return "DIRECT"; //到26年十月，藏东聚申请了防火墙
 if (dnsDomainIs(host,"*.console.aws.a2z.com")) return "DIRECT"; //到26年十月，藏东聚申请了防火墙
 //if (dnsDomainIs(host,"*.sso-portal.us-east-1.amazonaws.com")) return "DIRECT"; //到26年十月，藏东聚申请了防火墙
 if (dnsDomainIs(host,"*.sso.amazonaws.com")) return "DIRECT"; //到26年十月，藏东聚申请了防火墙
 if (dnsDomainIs(host,"*.awsapp.com")) return "DIRECT"; //到26年十月，藏东聚申请了防火墙
 if (dnsDomainIs(host,"oidc.us-east-1.amazonaws.com")) return "DIRECT"; //到26年十月，藏东聚申请了防火墙
 if (dnsDomainIs(host,"*.sso.us-east-1.amazonaws.com")) return "DIRECT"; //到26年十月，藏东聚申请了防火墙
 if (shExpMatch(dip,"109.5.78.225")) return "DIRECT"; //20251024 金星申请了防火墙
 if (shExpMatch(dip,"12.30.96.73")) return "DIRECT"; //金星申请了防火墙270420
 if (shExpMatch(dip,"140.179.157.27")) return "DIRECT"; //20251028-20260427 韩超申请了proxy例外
 if (shExpMatch(dip,"52.80.44.228")) return "DIRECT"; //20251028-20260427 韩超申请了proxy例外
 if (shExpMatch(dip,"43.196.8.109")) return "DIRECT"; //20251028-20260427 韩超申请了proxy例外
 if (shExpMatch(dip,"54.223.51.61")) return "DIRECT"; //20251028-20260427 韩超申请了proxy例外
 if (shExpMatch(dip,"109.52.64.101")) return "DIRECT"; //20251028-20260427 金美香申请了防火墙例外，261028到期
 if (shExpMatch(dip,"182.198.194.203")) return "DIRECT"; //20260106-20270105 物流yizhen1.li申请了防火墙例外
 if ((shExpMatch(cip,"109.52.36.66")) && (shExpMatch(host,"sopenapi.singleid.samsung.net"))) return "DIRECT"; // 于京
 if ((shExpMatch(cip,"109.52.36.66")) && (shExpMatch(host,"signin.aws.amazon.com"))) return "DIRECT"; // 于京
 if (shExpMatch(dip,"112.107.222.122")) return "DIRECT"; // knox portal260112   haley.lee申请了防火墙tcp80
 if (shExpMatch(dip,"182.198.246.158")) return "DIRECT"; // knox portal260112      haley.lee申请了防火墙tcp80
 if (shExpMatch(dip,"109.6.1.12")) return "DIRECT"; // xiang1.jin261207  申请了防火墙tcp8080
 if (shExpMatch(dip,"109.5.1.24")) return "DIRECT"; // 社内系统 申请了防火墙
 if (shExpMatch(dip,"139.224.214.166")) return "DIRECT"; // 韩超 申请了防火墙 
 if (shExpMatch(dip,"151.101.192.223")) return "DIRECT"; // 韩超 申请了防火墙 到27年3月5
 
 if (shExpMatch(dip,"109.6.3.1")) return "DIRECT"; // 申请了防火墙 到27年3月5 AI课题测试
 if (shExpMatch(dip,"109.5.101.3")) return "DIRECT";   // 金星 申请了防火墙直通到270106
 if (shExpMatch(dip,"109.6.10.3")) return "DIRECT";   // sdscdify.samsungsds.com.cn
 if (shExpMatch(dip,"109.6.10.5")) return "DIRECT";   // AI_Workflow FW20260603000001083084
 if (shExpMatch(dip,"109.6.111.34")) return "DIRECT";   // AI_Work  FW20260828000001132216，c.baily
 if (shExpMatch(dip,"109.6.111.66")) return "DIRECT";   // AI_Work  FW20260828000001132216, c.baily
 if (shExpMatch(dip,"109.6.111.3")) return "DIRECT";   // AI_Work  FW20260828000001132216, c.baily
  
 if (dnsDomainIs(host,"dashscope.aliyuncs.com")) return "DIRECT"; //xianghui.huang申请了防火墙 270426
 if (dnsDomainIs(host,"dkms.bigdata.samsung.com.cn")) return "DIRECT"; //chengfan.jin申请了防火墙
 if (dnsDomainIs(host,"failover-dkms.bigdata.samsung.com.cn")) return "DIRECT"; //cengfan.jin申请了防火墙
 if (shExpMatch(dip,"39.106.10.89")) return "DIRECT";   // c.baily 申请了防火墙 260831 FW20260826000001130116
 if (shExpMatch(dip,"47.95.112.50")) return "DIRECT";   // c.baily 申请了防火墙 260831FW20260826000001130116
 if (shExpMatch(dip,"82.156.255.71")) return "DIRECT";   // juan.guo FW20260721000001109920
 if (dnsDomainIs(host,"ai.samsung.com.cn")) return "DIRECT"; //zhirong.zhao申请了防火墙
 if (dnsDomainIs(host,"ai-admin.samsung.com.cn")) return "DIRECT"; //zhirong.zhao申请了防火墙   
  if (dnsDomainIs(host,"qai.samsung.com.cn")) return "DIRECT"; //zhirong.zhao申请了防火墙
 if (dnsDomainIs(host,"qai-admin.samsung.com.cn")) return "DIRECT"; //zhirong.zhao申请了防火墙   
	 
 
//VDI (182.192 *.*)必须使用越南Vietnam的gdc-Proxy 才能访问的网站  //多条件语句，注意括号配对                      //20250225 by xu

 //if (dnsDomainIs(host,"chatgpt.com")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (dnsDomainIs(host,"openai.com")) return "PROXY 182.192.254.44:8080"; // wy.jiang SDS-GDC PROXY
 //if (dnsDomainIs(host,"namu.wiki")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (dnsDomainIs(host,"www.google.com")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (dnsDomainIs(host,"naver.*")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (dnsDomainIs(host,"pstatic.net")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (shExpMatch(url,"*.naver.com")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (dnsDomainIs(host,"www.naver.com")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (dnsDomainIs(host,"news.naver.com")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (dnsDomainIs(host,"www.youtube.com")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if (dnsDomainIs(host,"youtu.be")) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"notepad-plus-plus.org"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"www.naver.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"chatgpt.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"namu.wiki"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"google.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.89.45")) && (dnsDomainIs(host,"naver.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.89.45")) && (dnsDomainIs(host,"pstatic.net"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 if ((shExpMatch(cip,"182.192.89.15")) && (dnsDomainIs(host,"youtube.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 if ((shExpMatch(cip,"182.192.89.15")) && (dnsDomainIs(host,"google.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 if ((shExpMatch(cip,"182.192.89.124")) && (dnsDomainIs(host,"google.com.vn"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 if ((shExpMatch(cip,"182.192.89.124")) && (dnsDomainIs(host,"youtube.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 if ((shExpMatch(cip,"182.192.89.124")) && (dnsDomainIs(host,"google.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 if ((shExpMatch(cip,"182.192.89.124")) && (dnsDomainIs(host,"google.com.vn"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 if ((shExpMatch(cip,"182.192.89.13")) && (dnsDomainIs(host,"naver.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 if ((shExpMatch(cip,"182.192.89.13")) && (dnsDomainIs(host,"pstatic.net"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 
 if ((shExpMatch(cip,"182.192.89.142")) && (shExpMatch(host,"*.openai.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.69")) && (shExpMatch(host,"*.openai.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.19")) && (shExpMatch(host,"*.openai.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.138")) && (shExpMatch(host,"*.openai.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.134")) && (shExpMatch(host,"*.openai.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.133")) && (shExpMatch(host,"*.openai.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.14")) && (shExpMatch(host,"*.openai.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.142")) && (shExpMatch(host,"www.chatgpt.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.69")) && (shExpMatch(host,"www.chatgpt.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.19")) && (shExpMatch(host,"www.chatgpt.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.138")) && (shExpMatch(host,"www.chatgpt.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.134")) && (shExpMatch(host,"www.chatgpt.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.133")) && (shExpMatch(host,"www.chatgpt.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 if ((shExpMatch(cip,"182.192.89.14")) && (shExpMatch(host,"www.chatgpt.com"))) return "PROXY 182.192.254.44:8080"; // 金弗宣申请到25.12.31
 
 //if ((shExpMatch(cip,"182.192.*.*")) && (shExpMatch(host,"*.openai.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"www.naver.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"news.naver.com"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"*.samsung.internal"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"*grafana.ecp.samsung.internal"))) return "DIRECT"; // ruihua.xu SDS-GDC PROXY
 //if ((shExpMatch(cip,"182.192.*.*")) && (dnsDomainIs(host,"sds.drive.samsung.net"))) return "PROXY 182.192.254.44:8080"; // ruihua.xu SDS-GDC PROXY
 
 

// SDSC 전체 임직원 도메인 1 - 끝 //	 

//人事部招聘网站使用proxy特别慢，改为直通//FW临时开通测试ID2647
//if (dnsDomainIs(host,"z.zhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"www.zhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"t.zhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"ws.zhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"c-res.zhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"logapi.zhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"res.zhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"static.zhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"t.kanzhun.com")) return "DIRECT";
//if (dnsDomainIs(host,"www.kanzhun.com")) return "DIRECT";
//if (dnsDomainIs(host,"www.bosszhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"apm-fe-qa.weizhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"img.bosszhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"imgaz.bosszhipin.com")) return "DIRECT";
//if (dnsDomainIs(host,"amap-proxy.zpurl.cn")) return "DIRECT";
//if (dnsDomainIs(host,"apm-fe.zhipin.com")) return "DIRECT";
//人事部招聘网站使用proxy特别慢，改为直通//FW临时开通测试ID2647


//xingyu.jin 20240828-20241129开始//
if (dnsDomainIs(host,"eh774r2.impervadns.net")) return "DIRECT";
if (dnsDomainIs(host,"backend.cop-prd.click")) return "DIRECT";
if (dnsDomainIs(host,"keycloak.cop-prd.click")) return "DIRECT"; //使用proxy，在vdi里面不能访问，不能跳转。longhai.ren-20250703
if (dnsDomainIs(host,"ram.cop-prd.click")) return "DIRECT";
if (shExpMatch(dip,"10.40.68.241")) return "DIRECT";
if (shExpMatch(dip,"112.106.189.146")) return "DIRECT";
if (shExpMatch(dip,"10.40.68.51")) return "DIRECT";
//if (shExpMatch(dip,"112.106.189.213")) return "DIRECT";     //20250414取消了direct，因为vdi里面无法访问by xu
//xingyu.jin 20240828-20241129结束//

//bosun8 kim 요청 사내시스템 20240507//
if (dnsDomainIs(host,"kor1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kor2.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kor3.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kor4.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kor5.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"smartoffice-in.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"smartoffice.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"pds.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"misap.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"apdms.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"edvs.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"ota.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"relay.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"mpush.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"sso.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"eurelay.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"eumpush.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"usrelay.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"usmpush.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"mobile.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"mobilepush.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"mobilesso.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"mobile.w1.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"mobilepush.w1.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"mobile.w2.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"mobilepush.w2.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"sqaproxy.stage.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"ktgld.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"ktaproxy.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"teams.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"ktmproxy.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"pad.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"www.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"secpartner.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"selcpartner.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"gamma.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"hdc.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"ilmofashion.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"sdcpartner.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"semespartner.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"sescpartner.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"svcpartner.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kvmpartner.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"epsso.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"ssdrm.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kr5.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"survey.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"sms.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"image.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"video.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"blog.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"community.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"support.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"push1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"push2.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"push3.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"push4.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"push5.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"v70.dr.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"epsso.dr.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"ssdrm.dr6.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kr1.dr.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kr2.dr.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kr3.dr.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kr4.dr.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kr5.dr.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"ws.dr6.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"www.samsungforever.com")) return "DIRECT";
if (dnsDomainIs(host,"forever.britymail.com")) return "DIRECT";
if (dnsDomainIs(host,"portal.samsungsquare.com")) return "DIRECT";
if (dnsDomainIs(host,"ocsp.digicert.com")) return "DIRECT";
if (dnsDomainIs(host,"crl3.digicert.com")) return "DIRECT";
if (dnsDomainIs(host,"crl4.digicert.com")) return "DIRECT";
if (dnsDomainIs(host,"m.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"m.stage.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"push.secmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"relay.secmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"attach.secmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"relay.mobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"push.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"attach.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"eupush.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"euattach.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"uspush.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"usattach.samsungmobiledesk.co.kr")) return "DIRECT";
if (dnsDomainIs(host,"stream.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"stream.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"media.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"media.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"www.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kr1.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"analytics.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"image.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"video.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"sms.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"survey.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"blog.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"community.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"support.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"search.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"dav.stage1.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"kteproxy.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"ktbproxy.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"smtp.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"v7pop3.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"smtp.w1.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"pop3.w1.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"smtp.w2.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"pop3.w2.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"v7smtp.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"pop3plus.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"pop3plus.w1.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"pop3plus.w2.samsung.com")) return "DIRECT";
if (dnsDomainIs(host,"sqipush4.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"sqipush5.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"sqepush5.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"sqipush2.stage.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"sqadmin.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"dn.gam.kr")) return "DIRECT";
if (dnsDomainIs(host,"*.meeting.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"meeting.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"sqadmin.stage.samsung.net")) return "DIRECT";
if (dnsDomainIs(host,"scdownload.meeting.samsung.net")) return "DIRECT";
if (shExpMatch(dip,"182.195.52.*")) return "DIRECT";
if (shExpMatch(dip,"182.195.98.*")) return "DIRECT";
if (shExpMatch(dip,"182.195.83.*")) return "DIRECT";
if (shExpMatch(dip,"182.197.58.*")) return "DIRECT";
if (shExpMatch(dip,"112.107.90.*")) return "DIRECT";
if (shExpMatch(dip,"112.107.99.*")) return "DIRECT";
if (shExpMatch(dip,"112.106.134.*")) return "DIRECT";
if (shExpMatch(dip,"203.254.227.10")) return "DIRECT";
if (shExpMatch(dip,"203.254.225.38")) return "DIRECT";
if (shExpMatch(dip,"211.45.27.198")) return "DIRECT";
if (shExpMatch(dip,"203.254.227.18")) return "DIRECT";
if (shExpMatch(dip,"112.107.221.*")) return "DIRECT";
if (shExpMatch(dip,"203.254.245.23")) return "DIRECT";
if (shExpMatch(dip,"203.254.227.19")) return "DIRECT";


// bosun8 kim 요청 사내시스템 - 끝 //


// SDSC ECC //
if (shExpMatch(dip,"70.2.170.151")) return "DIRECT"; // ECC ASCS eccascs-vip eccascs-vip.sds.samsung.net ECC HA
if (shExpMatch(dip,"70.2.170.15")) return "DIRECT"; // ECC AP ieph1105  ieph1105.sds.samsung.net   ECC PRD AP1
if (shExpMatch(dip,"70.2.170.16")) return "DIRECT"; // ECC AP ieph1106  ieph1106.sds.samsung.net   ECC PRD AP2
if (shExpMatch(dip,"70.2.170.17")) return "DIRECT"; // ECC AP ieph1107  ieph1107.sds.samsung.net   ECC PRD AP3
if (shExpMatch(dip,"70.2.170.18")) return "DIRECT"; // ECC AP ieph1108  ieph1108.sds.samsung.net   ECC PRD AP4
if (shExpMatch(dip,"70.2.170.171")) return "DIRECT"; // ECC L7 ecc  ecc.sds.samsung.net
if (shExpMatch(dip,"70.2.170.152")) return "DIRECT"; // EP SCS epscs-vip epscs-vip.sds.samsung.net  EP HA
if (shExpMatch(dip,"70.2.170.172")) return "DIRECT"; // ep.sds.samsung.net   EP L7
if (shExpMatch(dip,"70.2.170.154")) return "DIRECT"; // MDG AP mdgascs-vip mdgascs-vip.sds.samsung.net MDG HA
if (shExpMatch(dip,"70.2.170.41")) return "DIRECT"; // MDG AP ieph1401.sds.samsung.net MDG PRD AP1
if (shExpMatch(dip,"70.2.170.42")) return "DIRECT"; // MDG AP ieph1402.sds.samsung.net MDG PRD AP2
if (shExpMatch(dip,"70.2.170.174")) return "DIRECT"; // MDG L7 mdg  mdg.sds.samsung.net 
if (shExpMatch(dip,"70.2.170.43")) return "DIRECT"; // iepw1403  iepw1403.sds.samsung.net DQM PRD
if (shExpMatch(dip,"70.2.170.44")) return "DIRECT"; // iepw1404  iepw1404.sds.samsung.net  TREX PRD
if (shExpMatch(dip,"70.2.170.156")) return "DIRECT"; // bwascs-vip bwascs-vip.sds.samsung.net BW HA BW ASCS/AP
if (shExpMatch(dip,"70.2.170.53")) return "DIRECT"; // ieph1503  ieph1503.sds.samsung.net  BW PRD AP1 BW ASCS/AP
if (shExpMatch(dip,"70.2.170.54")) return "DIRECT"; // iepw1404   ieph1504  ieph1504.sds.samsung.net  BW PRD AP2 BW ASCS/AP
if (shExpMatch(dip,"70.2.170.175")) return "DIRECT"; // bw  bw.sds.samsung.net  BW L7
if (shExpMatch(dip,"70.2.170.157")) return "DIRECT"; // boscs-vip boscs-vip.sds.samsung.net BO HA
if (shExpMatch(dip,"70.2.170.61")) return "DIRECT"; // bw  iepw1601  iepw1601.sds.samsung.net BO PRD AP1
if (shExpMatch(dip,"70.2.170.62")) return "DIRECT"; // bw  iepw1602  iepw1602.sds.samsung.net BO PRD AP2
if (shExpMatch(dip,"70.2.170.176")) return "DIRECT"; // bo  bo.sds.samsung.net  BO L7
if (shExpMatch(dip,"70.2.170.158")) return "DIRECT"; // solascs-vip solascs-vip.sds.samsung.net SOLMAN HA
if (shExpMatch(dip,"70.2.170.71")) return "DIRECT"; // ieph1701  ieph1701.sds.samsung.net  SOLMAN PRD AP1
if (shExpMatch(dip,"70.2.170.72")) return "DIRECT"; // ieph1702  ieph1702.sds.samsung.net  SOLMAN PRD AP2
if (shExpMatch(dip,"70.2.170.177")) return "DIRECT"; // sol  sol.sds.samsung.net  SOLMAN L7
if (shExpMatch(dip,"70.2.170.159")) return "DIRECT"; // crmascs-vip crmascs-vip.sds.samsung.net CRM HA
if (shExpMatch(dip,"70.2.170.85")) return "DIRECT"; // ieph1805  ieph1805.sds.samsung.net  CRM PRD AP1
if (shExpMatch(dip,"70.2.170.86")) return "DIRECT"; // ieph1806.sds.samsung.net  CRM PRD AP2
if (shExpMatch(dip,"70.2.170.178")) return "DIRECT"; // crm  crm.sds.samsung.net CRM L7 
if (shExpMatch(dip,"70.2.170.91")) return "DIRECT"; //  iepw1901  iepw1901.sds.samsung.net  ARIS PRD
if (shExpMatch(dip,"70.2.170.144")) return "DIRECT"; // cicfmascs-vip.sds.samsung.net cicfmascs-vip CI/CFM PRD HA
if (shExpMatch(dip,"70.2.170.115")) return "DIRECT"; // iepl2105.sds.samsung.net iepl2105 CI/CFM PRD AP1
if (shExpMatch(dip,"70.2.170.116")) return "DIRECT"; // iepl2106.sds.samsung.net iepl2106 CI/CFM PRD AP2
if (shExpMatch(dip,"70.2.170.179")) return "DIRECT"; // cicfm.sds.samsung.net cicfm CI/CFM PRD L7
if (shExpMatch(dip,"70.2.170.119")) return "DIRECT"; // iepl2203.sds.samsung.net    iepl2203 CC PRD AP 1
if (shExpMatch(dip,"70.2.170.145")) return "DIRECT"; // sscscs-vip.sds.samsung.net sscscs-vip SSC PRD HA
if (shExpMatch(dip,"70.2.170.124")) return "DIRECT"; // iepl2305.sds.samsung.net iepl2305 SSC PRD AP1
if (shExpMatch(dip,"70.2.170.125")) return "DIRECT"; // iepl2306.sds.samsung.net iepl2306 SSC PRD AP2
if (shExpMatch(dip,"70.2.170.180")) return "DIRECT"; // ssc.sds.samsung.net SSC L7
if (shExpMatch(dip,"70.2.170.184")) return "DIRECT"; // grc.sds.samsung.net
if (shExpMatch(dip,"70.2.170.57")) return "DIRECT"; // iepl1507.sds.samsung.net
if (shExpMatch(dip,"70.2.170.58")) return "DIRECT"; // iepl1508.sds.samsung.net
if (shExpMatch(dip,"70.2.180.53")) return "DIRECT"; // ieql1101 ieql1101.sds.samsung.net HANA ECC QAS SDS 차세대 품질
if (shExpMatch(dip,"70.2.170.54")) return "DIRECT"; // ieqh1102 ieqh1102.sds.samsung.net ECC QAS SDS 차세대 품질
if (shExpMatch(dip,"70.2.170.56")) return "DIRECT"; // ieqh1201 ieqh1201.sds.samsung.net EP QAS SDS 차세대 품질
if (shExpMatch(dip,"70.2.140.140")) return "DIRECT"; // samsungsdsmss.com ADDED BY F5 NETWORKS SSL TUNNEL - ORIGINAL RECORD



// SDSC ECC - 끝 //	


// 전체 임직원 도메인 1 //
// if (dnsDomainIs(host,"mail-training.co.kr")) {return "PROXY 109.52.26.14:9090";}  // 23 0719

 if (dnsDomainIs(host,"seller.samsungapps.com")) {return "PROXY 109.52.26.14:9090";}  // 23 0714
 if (dnsDomainIs(host,"samsungapps.com")) {return "PROXY 109.52.26.14:9090";}  // 23 0714
 if (dnsDomainIs(host,"img.samsungapps.com")) {return "PROXY 109.52.26.14:9090";}  // 23 0714  
 if (dnsDomainIs(host,"pad.samsung.net")) return "DIRECT";    // 23 0712
 if (dnsDomainIs(host,"englist.co.kr")) {return "PROXY 109.52.26.14:9090";}  // 23 0614  secu2 
 if (dnsDomainIs(host,"mozilla.org")) {return "PROXY 109.52.26.14:9090";}  // 23 0608  secu2  
 //if (dnsDomainIs(host,"teams.microsoft.com")) {return "PROXY 109.52.26.14:9090";}	// 22 0210  secu1
 //if (dnsDomainIs(host,"activity.windows.com")) {return "PROXY 109.52.26.14:9090";}	// 220330  secu2
 if (dnsDomainIs(host,"console.aws.amazon.com")) {return "PROXY 109.52.26.14:9090";}   // 22 0824 secu1 secu2
 if (dnsDomainIs(host,"amazonaws.com")) {return "PROXY 109.52.26.14:9090";}   // 221007 secu2
 if (dnsDomainIs(host,"awsstatic.com")) {return "PROXY 109.52.26.14:9090";}   // 221007 secu2
 if (dnsDomainIs(host,"aws.amazon.com")) {return "PROXY 109.52.26.14:9090";}	// 211125 secu2
 if (shExpMatch(host,"player.sericeo.org")) {return "PROXY 109.52.26.14:9090";}  // secu 2   (rks201112)
 if (shExpMatch(host,"*.player.sericeo.org")) {return "PROXY 109.52.26.14:9090";}  // secu 2   (rks201112)
 if (shExpMatch(host,"player-hls.sericeo.org")) {return "PROXY 109.52.26.14:9090";}  // secu 2   (rks201112)
 if (shExpMatch(host,"*.player-hls.sericeo.org")) {return "PROXY 109.52.26.14:9090";}  // secu 2   (rks201112)
 //if (shExpMatch(host, "streaming.samsungcic.com")) return "DIRECT";    //secu 21 0510
 //if (shExpMatch(host, "*.streaming.samsungcic.com")) return "DIRECT";    //secu 21 0510
 if (shExpMatch(host, "samsung.jp10.sapanalytics.cloud")) return "DIRECT";    //secu 3수석 영구 181106
 if (shExpMatch(host, "samsung-test.jp10.sapanalytics.cloud")) return "DIRECT";    //김구 영구 181108
 if (shExpMatch(host,"standards.ieee.org")) {return "PROXY 109.52.26.14:9090";}  // (rks210312)
 if (shExpMatch(host,"*.standards.ieee.org")) {return "PROXY 109.52.26.14:9090";}  // (rks210312)
 if (dnsDomainIs(host,"sds.s-bluevery.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"sso.s-bluevery.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"static23.samsungcard.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"samsungcard.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"samsungcard.sc.omtrdc.net")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"safebrowsing.googleapis.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"assets.adobedtm.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"gartner.webex.com")) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"webex.com")) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"enterprisedb.com")) {return "PROXY 109.52.26.14:9090";}  // 23 0419  secu2 
 if (dnsDomainIs(host,"welfare.comwel.or.kr")) {return "PROXY 109.52.26.14:9090";}  // 23 0706 박윤구
 if (dnsDomainIs(host,"help.scourt.go.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"mcst.go.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"hikorea.go.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"nts.go.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"hometax.go.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"daum.net")) return "PROXY 109.52.26.14:9090";
 //if (dnsDomainIs(host,"google.com")) return "PROXY 182.192.254.44:8080";
 if (dnsDomainIs(host,"gov.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"dart.fss.or.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"fss.or.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"ftc.go.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"g2b.go.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"nanet.go.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"dl.nanet.go.kr")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"nonghyupmall.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"chat.openai.com")) return "PROXY 109.52.26.14:9090";   // secu2
 //if (dnsDomainIs(host,"bard.google.com")) return "PROXY 109.52.26.14:9090";   // secu2
 //if (dnsDomainIs(host,"translate.google.com")) {return "PROXY 109.52.26.14:9090";} // 23 0516  secu2
 //if (dnsDomainIs(host,"translate.google.co.kr")) {return "PROXY 109.52.26.14:9090";} // 23 0516  secu2
 if (dnsDomainIs(host,"deepl.com")) {return "PROXY 109.52.26.14:9090";} // 23 0516  secu2
 if (dnsDomainIs(host,"papago.naver.com")) {return "PROXY 109.52.26.14:9090";} // 23 0516  secu2
 if (dnsDomainIs(host,"albamon.com")) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"jobkorea.co.kr")) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"alb-amon.kr")) {return "PROXY 109.52.26.14:9090";}
// 전체 임직원 도메인 1 - 끝 //

// 전체 임직원 도메인 2 //
 //if ((shExpMatch(cip,"70.117.*.*")) & (dnsDomainIs(host,"cloud.zoom.us"))) {return "PROXY 109.52.26.14:9090";} 
 //if ((shExpMatch(cip,"70.118.*.*")) & (dnsDomainIs(host,"cloud.zoom.us"))) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"cloud.zoom.us")) {return "PROXY 109.52.26.14:9090";}
 //if (shExpMatch(cip,"109.52.35.10"))  {return "PROXY 109.52.26.14:9090";} 
 //if ((shExpMatch(cip,"70.118.*.*")) & (dnsDomainIs(host,"adobe.com"))) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"adobe.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"firefly.adobe.com")) return "PROXY 109.52.26.14:9090"; // 임시 240123 ~ 
 //if ((shExpMatch(cip,"70.117.*.*")) & (dnsDomainIs(host,"clova-x.naver.com"))) {return "PROXY 109.52.26.14:9090";}
 //if ((shExpMatch(cip,"70.118.*.*")) & (dnsDomainIs(host,"clova-x.naver.com"))) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"clova-x.naver.com")) return "PROXY 109.52.26.14:9090";
 //if ((shExpMatch(cip,"70.117.*.*")) & (dnsDomainIs(host,"midjourney.com"))) {return "PROXY 109.52.26.14:9090";}
 //if ((shExpMatch(cip,"70.118.*.*")) & (dnsDomainIs(host,"midjourney.com"))) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"midjourney.com")) return "PROXY 109.52.26.14:9090";
 //if ((shExpMatch(cip,"70.117.*.*")) & (dnsDomainIs(host,"protect2.fireeye.com"))) {return "PROXY 109.52.26.14:9090";}
 //if ((shExpMatch(cip,"70.118.*.*")) & (dnsDomainIs(host,"protect2.fireeye.com"))) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"protect2.fireeye.com")) return "PROXY 109.52.26.14:9090";
 //if ((shExpMatch(cip,"70.117.*.*")) & (dnsDomainIs(host,"ipaddress.com"))) {return "PROXY 109.52.26.14:9090";}
 //if ((shExpMatch(cip,"70.118.*.*")) & (dnsDomainIs(host,"ipaddress.com"))) {return "PROXY 109.52.26.14:9090";}
 if (dnsDomainIs(host,"ipaddress.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"sites.ipaddress.com")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"ad-m.asia")) return "PROXY 109.52.26.14:9090";
 if (dnsDomainIs(host,"sync-dsp.ad-m.asia")) return "PROXY 109.52.26.14:9090";
// 전체 임직원 도메인 2 - 끝 //

// // 정보전략 secu 3 프로 박진명 프로 2020 6월~7월 요청 Knox Portal 서비스 IP 및 도메인 // //
// 그룹망 //
 if (shExpMatch(host,"stg.connect.samsung.net")) {return "PROXY 109.52.26.14:9090";}	// 210928 노준호
 if (shExpMatch(host,"*.wf.samsung.net")) {return "PROXY 109.52.26.14:9090";}  // secu2   21 0901
 if (shExpMatch(host,"wf.samsung.net")) {return "PROXY 109.52.26.14:9090";}  // secu2   21 0901
 //if (shExpMatch(host, "*.ap-chuncheon-1.oraclecloud.com")) return "DIRECT";   // 양현준 영구  21 0901 신청
 //if (shExpMatch(host, "ap-chuncheon-1.oraclecloud.com")) return "DIRECT";   // 양현준 영구  21 0901 신청
 if (shExpMatch(host,"watcher.samsungnoc.com")) {return "PROXY 109.52.26.14:9090";} // 김종화 210727
 if (shExpMatch(host,"prod.impartner.live")) {return "PROXY 109.52.26.14:9090";}  // 김영훈  to 220328 (rks210330)
 if (shExpMatch(host,"*.prod.impartner.live")) {return "PROXY 109.52.26.14:9090";}  // 김영훈  to 220328 (rks210330)
 if (shExpMatch(host,"vensim.com")) {return "PROXY 109.52.26.14:9090";}  // secu 2   (rks210323)
 if (shExpMatch(host,"*.vensim.com")) {return "PROXY 109.52.26.14:9090";}  // secu 2   (rks210323)
 //if (shExpMatch(host,"singleid.samsung.net")) {return "PROXY 109.52.26.14:9090";} // 김지원 210506
 //if (shExpMatch(host,"*.singleid.samsung.net")) {return "PROXY 109.52.26.14:9090";} // 김지원 210506
 if (shExpMatch(host,"niffler.samsungsre.com")) {return "PROXY 109.52.26.14:9090";}  // 김종화   (rks210312)
 if (shExpMatch(host,"*.niffler.samsungsre.com")) {return "PROXY 109.52.26.14:9090";}  // 김종화   (rks210312)
 if (shExpMatch(host,"s-connect.samsung.net")) {return "PROXY 109.52.26.14:9090";}  // 모승환   (rks210223)
 if (shExpMatch(host,"*.s-connect.samsung.net")) {return "PROXY 109.52.26.14:9090";}  // 모승환   (rks210223)
 if (shExpMatch(host, "pcdownload.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "pcdownload.w1.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "pcdownload.w2.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "ktgld.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "ktaproxy.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "teams.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "ktmproxy.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "kr5.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "survey.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "sms.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "image.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "video.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "blog.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "community.samsung.net")) return "DIRECT"; 
 //if (shExpMatch(host, "sds.drive.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "support.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "push1.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "push2.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "push3.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "push4.samsung.net")) return "DIRECT"; 
 if (shExpMatch(host, "push5.samsung.net")) return "DIRECT"; 
 if (shExpMatch(dip,"112.107.220.46")) {return "DIRECT";}
 if (shExpMatch(dip,"112.107.220.86")) {return "DIRECT";}
 if (shExpMatch(dip,"112.107.220.136")) {return "DIRECT";}
 if (shExpMatch(dip,"112.107.220.137")) {return "DIRECT";}  // 임혁신   (rks200730)
 if (shExpMatch(dip,"203.254.199.139")) {return "DIRECT";}
 if (shExpMatch(dip,"203.254.195.139")) {return "DIRECT";}
 if (shExpMatch(dip,"112.107.221.211")) {return "DIRECT";}
 if (shExpMatch(dip,"112.107.221.212")) {return "DIRECT";}
 if (shExpMatch(dip,"112.107.221.214")) {return "DIRECT";}
 if (shExpMatch(dip,"112.107.221.217")) {return "DIRECT";}
 if (shExpMatch(dip,"109.10.97.238")) {return "DIRECT";}
 if (shExpMatch(dip,"109.10.97.239")) {return "DIRECT";}

// 인터넷망 공인망 //
 if (shExpMatch(host,"*.chime.aws")) {return "PROXY 109.52.26.14:9090";} // secu secu 2 20 1028
 if (shExpMatch(host,"chime.aws")) {return "PROXY 109.52.26.14:9090";} // secu secu 2 20 1028
 if (shExpMatch(host,"datanet.co.kr")) {return "PROXY 109.52.26.14:9090";}  // secu 2   (rks210317)
 if (shExpMatch(host,"*.datanet.co.kr")) {return "PROXY 109.52.26.14:9090";}  // secu 2   (rks210317)
 if (shExpMatch(host,"ota.samsungmobiledesk.co.kr")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(host,"relay.samsungmobiledesk.co.kr")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(host,"mpush.samsungmobiledesk.co.kr")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(host,"eurelay.samsungmobiledesk.co.kr")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(host,"eumpush.samsungmobiledesk.co.kr")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(host,"usrelay.samsungmobiledesk.co.kr")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(host,"usmpush.samsungmobiledesk.co.kr")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(host,"samsungforever.com")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"112.106.134.87")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"112.106.134.70")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"112.106.134.14")) {return "PROXY 109.52.26.14:9090";}
//  정보전략 secu 3 프로 박진명 프로 2020 6월~7월 요청 Knox Portal 서비스 IP 및 도메인  - 끝 - //

//  samsungsvc.co.kr  //
 if (dnsDomainIs(host,"samsungsvc.co.kr")) return "PROXY 109.52.26.14:9090";
// samsungsvc.co.kr 끝   //

//* SDS 사업장 대역 *//
 if (shExpMatch(dip,"70.191.151.180")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.191.151.183")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.32.127.*")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.34.32.43")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.34.35.183")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.35.200.95")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.35.58.60")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.162.148")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.72.39")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.127.110")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.127.174")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.100.19")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.102.106")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.65.14")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.71.239")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.89.14")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.90.82")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.37.95.165")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.38.38.210")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.38.116.65")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.38.54.242")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.39.148.159")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.39.150.205")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.39.151.60")) {return "PROXY 109.52.26.14:9090";}  // secu 2  vensim.com (rks210323)
 if (shExpMatch(dip,"70.40.217.66")) {return "PROXY 109.52.26.14:9090";}  // secu 1   (rks210122)
 if (shExpMatch(dip,"70.42.13.100")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.185.*")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.227.135")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.227.144")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.227.171")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.23.121")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.230.22")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.241.134")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.242.50")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.33.241")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.33.242")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.42.6.250")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"70.47.199.221")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"71.21.1.*")) {return "DIRECT";}	// 물산리조트 남경훈 220412
 if (shExpMatch(dip,"71.21.2.*")) {return "DIRECT";}	// 물산리조트 남경훈 220412
 if (shExpMatch(dip,"71.26.1.*")) {return "DIRECT";}	// 220418 남경훈
 if (shExpMatch(dip,"71.26.2.*")) {return "DIRECT";}	// 220418 남경훈
 if (shExpMatch(dip,"71.26.37.*")) {return "DIRECT";}	// 220418 남경훈
 if (shExpMatch(dip,"71.51.1.100")) {return "DIRECT";}
 if (shExpMatch(dip,"71.51.1.11")) {return "DIRECT";}
 if (shExpMatch(dip,"71.51.1.12")) {return "DIRECT";}
 if (shExpMatch(dip,"71.51.10.*")) {return "DIRECT";}	// 220421 박수진
 if (shExpMatch(dip,"71.51.2.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.51.20.*")) {return "DIRECT";}	// 220421 박수진
 if (shExpMatch(dip,"71.52.2.157")) {return "DIRECT";}	// 220518 김근영
 if (shExpMatch(dip,"71.52.2.38")) {return "DIRECT";}
 if (shExpMatch(dip,"71.52.3.*")) {return "DIRECT";}	// 220421 박수진
 if (shExpMatch(dip,"71.100.103.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.100.105.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.100.106.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.100.107.7")) {return "DIRECT";}
 if (shExpMatch(dip,"71.100.111.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.100.112.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.2.101.5")) {return "DIRECT";}
 if (shExpMatch(dip,"71.2.101.6")) {return "DIRECT";}
 if (shExpMatch(dip,"71.2.200.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.2.5.151")) {return "DIRECT";}
 
 if (shExpMatch(dip,"71.31.1.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.31.10.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.31.2.*")) {return "DIRECT";}
 if (shExpMatch(dip,"71.55.0.100")) {return "DIRECT";}
 if (shExpMatch(dip,"71.55.0.101")) {return "DIRECT";}
 if (shExpMatch(dip,"71.65.2.101")) {return "DIRECT";}
 if (shExpMatch(dip,"71.65.2.102")) {return "DIRECT";}
 if (shExpMatch(dip,"72.10.180.143")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.10.193.107")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.10.32.148")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.10.33.20")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.10.37.212")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.10.39.146")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.10.53.219")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.18.195.184")) {return "DIRECT";}
 if (shExpMatch(dip,"72.2.113.199")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.2.114.72")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.2.119.192")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"72.2.*.*")) {return "DIRECT";}
 if (shExpMatch(dip,"72.50.*.*")) {return "DIRECT";}
 if (shExpMatch(dip,"72.52.146.60")) {return "DIRECT";}
 if (shExpMatch(dip,"72.70.1.*")) {return "DIRECT";}
 if (shExpMatch(dip,"74.208.164.166")) {return "DIRECT";}
 if (shExpMatch(dip,"74.42.253.166")) {return "DIRECT";}
 if (shExpMatch(dip,"74.86.103.114")) {return "DIRECT";}
 if (shExpMatch(dip,"75.1.14.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.1.240.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.1.50.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.1.55.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.1.56.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.1.70.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.10.10.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.10.11.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.10.20.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.10.21.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.100.*.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.102.11.135")) {return "PROXY 109.52.26.14:9090";}  //secu 2 190321
 if (shExpMatch(dip,"75.11.100.166")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.11.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.12.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.13.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.14.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.15.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.16.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.21.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.23.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.24.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.25.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.26.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.27.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.29.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.30.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.11.61.*")) {return "DIRECT";} 
 if (shExpMatch(dip,"75.200.*.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.4.100.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.4.101.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.4.102.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.4.105.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.4.110.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.2.104.*")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"75.5.105.*")) {return "PROXY 109.52.26.14:9090";}
 if (shExpMatch(dip,"75.5.*.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.5.115.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.5.117.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.5.119.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.5.129.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.5.141.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.5.147.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.5.155.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.5.157.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.5.213.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.10.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.11.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.12.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.13.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.14.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.15.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.16.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.18.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.20.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.31.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.32.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.41.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.42.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.43.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.44.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.51.*")) {return "DIRECT";}
 if (shExpMatch(dip,"75.7.52.*")) {return "DIRECT";}
 if (shExpMatch(dip,"76.1.1.*")) {return "DIRECT";}
 if (shExpMatch(dip,"76.100.100.*")) {return "DIRECT";}
 if (shExpMatch(dip,"76.2.*.*")) {return "DIRECT";}
 if (shExpMatch(dip,"76.3.*.*")) {return "DIRECT";}
 if (shExpMatch(dip,"76.73.124.10")) {return "DIRECT";}
 if (shExpMatch(dip,"77.2.50.230")) {return "DIRECT";}
 if (shExpMatch(dip,"77.2.50.240")) {return "DIRECT";}
 if (shExpMatch(dip,"77.2.70.240")) {return "DIRECT";}
 if (shExpMatch(dip,"77.241.93.160")) {return "DIRECT";}
 if (shExpMatch(dip,"77.79.10.70")) {return "DIRECT";}
 if (shExpMatch(dip,"77.79.10.71")) {return "DIRECT";}
 if (shExpMatch(dip,"77.91.227.248")) {return "DIRECT";}
 if (shExpMatch(dip,"78.39.222.97")) {return "DIRECT";}
 if (shExpMatch(dip,"8.37.192.188")) {return "DIRECT";}
 if (shExpMatch(dip,"8.37.192.120")) {return "DIRECT";}
 if (shExpMatch(dip,"80.239.177.4")) {return "DIRECT";}
 if (shExpMatch(dip,"81.100.122.25")) {return "DIRECT";} // secu 2 (rks200619)
 if (shExpMatch(dip,"81.100.21.*")) {return "DIRECT";}	// 220414 이명진
 if (shExpMatch(dip,"81.100.3.*")) {return "DIRECT";}
 if (shExpMatch(dip,"81.100.7.*")) {return "DIRECT";}
 if (shExpMatch(dip,"81.100.30.50")) {return "DIRECT";}    //  2023.07.27 ~ 영구 박소영
 if (shExpMatch(dip,"81.100.31.51")) {return "DIRECT";}    //  2023.07.27 ~ 영구 박소영
 if (shExpMatch(dip,"81.100.31.52")) {return "DIRECT";}    //  2023.07.27 ~ 영구 박소영
 if (shExpMatch(dip,"81.100.141.51")) {return "DIRECT";}    //  2023.07.27 ~ 영구 박소영
 if (shExpMatch(dip,"81.100.142.51")) {return "DIRECT";}    //  2023.07.27 ~ 영구 박소영
 if (shExpMatch(dip,"81.100.73.*")) {return "DIRECT";}
 if (shExpMatch(dip,"81.102.7.*")) {return "DIRECT";}
 if (shExpMatch(dip,"81.173.113.120")) {return "DIRECT";}  // 최명균 180917
 if (shExpMatch(dip,"81.177.26.27")) {return "DIRECT";}
 if (shExpMatch(dip,"81.177.3.169")) {return "DIRECT";}
 if (shExpMatch(dip,"81.2.101.155")) {return "DIRECT";}
 if (shExpMatch(dip,"81.2.16.120")) {return "DIRECT";}
 if (shExpMatch(dip,"81.2.3.*")) {return "DIRECT";}
 if (shExpMatch(dip,"81.2.4.*")) {return "DIRECT";}
 if (shExpMatch(dip,"81.2.5.*")) {return "DIRECT";}
 if (shExpMatch(dip,"81.2.6.*")) {return "DIRECT";}
 if (shExpMatch(dip,"81.2.7.*")) {return "DIRECT";}

//Client IP Direct //
//if (cip == "109.2.0.16") {return "DIRECT";}   //zhmeng.zhang //
//if (cip == "109.2.0.60") {return "DIRECT";}   //ZHENG JIE //
//if (cip == "109.2.11.22") {return "DIRECT";}   // songjie.han //
//URL r to Proxy //
if (shExpMatch(host, "*.umeng.com")) {return "PROXY 109.52.26.14:9090";} //account.umeng.com Go to Proxy //
if (dnsDomainIs(host, ".account.umeng.com")) {return "PROXY 109.52.26.14:9090";} //account.umeng.com Go to Proxy //
if (shExpMatch(host, "*.sycm.taobao.com")) {return "PROXY 109.52.26.14:9090";} //sycm.taobao.com Go to Proxy //
if (dnsDomainIs(host, ".sycm.taobao.com")) {return "PROXY 109.52.26.14:9090";} //sycm.taobao.com Go to Proxy //
 
// V2 //
 if (shExpMatch(dip,"109.10.1.244")) {return "DIRECT";}            // V2 WAS/ESB Server //
 if (shExpMatch(dip,"101.78.2.35")) {return "DIRECT";}            // V2 Group Picture Server //
 if (shExpMatch(dip,"109.10.1.249")) {return "DIRECT";}            // V2 Socket Server //

// V3 Update //
 if (dnsDomainIs(host, "astweb.ahnlab.co.kr")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "auth.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "gms.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "ispt.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "psu1.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "psu2.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "su.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "su2.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "su3.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "su4.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "su5.ahnlab.com")) {return "DIRECT";}            // V3 Update //
 if (dnsDomainIs(host, "update.ahnlab.com")) {return "DIRECT";}            // V3 Update //

// MS Update //
 //if (dnsDomainIs(host, "Download.microsoft.com")) {return "DIRECT";}            // MS Update //
 //if (dnsDomainIs(host, "Download.windowsupdate.com")) {return "DIRECT";}            // MS Update //
 //if (dnsDomainIs(host, "windowsupdate.microsoft.com")) {return "DIRECT";}            // MS Update //
 //if (dnsDomainIs(host, "update.microsoft.com")) {return "DIRECT";}            // MS Update //
 //if (dnsDomainIs(host, "ntservicepack.microsoft.com")) {return "DIRECT";}            // MS Update //
 //if (dnsDomainIs(host, "stats.update.microsoft.com")) {return "DIRECT";}            // MS Update //

// Knox //
 if (shExpMatch(dip,"117.18.237.29")) {return "DIRECT";}            // Knox - DigiCert ??? CRL?? - crl3.digicert.com //
 if (shExpMatch(dip,"123.32.14.25")) {return "DIRECT";}            // Knox - DigiCert ??? CRL?? - crl3.digicert.com //
 if (shExpMatch(dip,"66.225.197.197")) {return "DIRECT";}            // Knox - DigiCert ??? CRL?? - crl4.digicert.com //
 if (shExpMatch(dip,"107.10.109.172")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"107.10.109.173")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"107.10.109.174")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"107.10.109.175")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"107.10.109.238")) {return "DIRECT";}            // Knox Meeting //
 
 if (shExpMatch(dip,"107.10.109.239")) {return "DIRECT";}            // Knox Meeting //
 
 if (shExpMatch(dip,"109.10.97.238")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"109.10.97.239")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.203")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.204")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.204")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.225")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.226")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.227")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.228")) {return "DIRECT";}            // Knox Meeting //
 
 if (shExpMatch(dip,"112.106.134.231")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.232")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.233")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.236")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.237")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.238")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.239")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.240")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.241")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.242")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.243")) {return "DIRECT";}            // Knox Meeting //
  
  
 if (shExpMatch(dip,"123.32.14.26")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.41")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.42")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.43")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.44")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.45")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.46")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.47")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.48")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.49")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.50")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.91")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.92")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.93")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.94")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.95")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.96")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.97")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.98")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.99")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.100")) {return "DIRECT";}            // Knox Meeting //
  
 
 
 
 
 
 
 
 
 
 if (shExpMatch(dip,"182.195.52.141")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.143")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.144")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.145")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.146")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.147")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.148")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.149")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.150")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.151")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.152")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.153")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.154")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.155")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.156")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.157")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.158")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.159")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.160")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.161")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.162")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.163")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.164")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.165")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.166")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.167")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.168")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.169")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.170")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.171")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.172")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.173")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.174")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.175")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.176")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.177")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.178")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.179")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.180")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.181")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.182")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.183")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.184")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.185")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.186")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.187")) {return "DIRECT";}            // Knox Meeting //
 

 
 
 if (shExpMatch(dip,"182.195.52.151")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.245.203")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.245.204")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.245.219")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.246.168")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.246.169")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.248.248")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.248.249")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.248.250")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.248.251")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.248.252")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.248.253")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.198.248.254")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.236.37")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.236.38")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.236.39")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.236.40")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.236.41")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.236.44")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.236.45")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.237.37")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.237.38")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.237.39")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.237.40")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.237.41")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.237.59")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.237.60")) {return "DIRECT";}            // Knox Meeting //
 
 
 if (shExpMatch(dip,"203.254.241.37")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.241.39")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.241.40")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.241.45")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.241.46")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.241.57")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.241.58")) {return "DIRECT";}            // Knox Meeting //
 
 if (shExpMatch(dip,"203.254.249.181")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.249.182")) {return "DIRECT";}            // Knox Meeting //
 
 
 if (shExpMatch(dip,"203.254.255.24")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.255.25")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.255.26")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.255.27")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.255.28")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.255.29")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"203.254.255.30")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"211.189.100.45")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"211.189.100.58")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"211.189.100.59")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"211.189.100.60")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"211.189.100.61")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"211.189.100.62")) {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"182.195.52.*"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.31"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.32"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.33"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.34"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.35"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.36"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.37"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.38"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.39"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.40"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.41"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.42"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.43"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.44"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.45"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.46"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.47"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.48"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.49"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.50"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.51"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.52"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.53"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.54"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.55"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.56"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.57"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.58"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.59"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.60"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.61"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.107.90.62"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.*"))   {return "DIRECT";}            // Knox Meeting //
 if (shExpMatch(dip,"112.106.134.220")) {return "DIRECT";}            // Knox Meeting Web //
 if (shExpMatch(dip,"112.106.134.231")) {return "DIRECT";}            // Knox Meeting Web //
 if (shExpMatch(dip,"112.107.221.204")) {return "DIRECT";}            // Knox Meeting Web //
 if (shExpMatch(dip,"112.106.196.100")) {return "DIRECT";}            // KNOX Messenger - sqmproxy.samsung.net //
 if (shExpMatch(dip,"112.106.196.111")) {return "DIRECT";}            // KNOX Messenger - sqipush1.samsung.net //
 if (shExpMatch(dip,"112.106.196.112")) {return "DIRECT";}            // KNOX Messenger - sqipush2.samsung.net //
 if (shExpMatch(dip,"112.106.196.113")) {return "DIRECT";}            // KNOX Messenger - sqipush3.samsung.net //
 if (shExpMatch(dip,"112.106.196.114")) {return "DIRECT";}            // KNOX Messenger - sqipush4.samsung.net //
 if (shExpMatch(dip,"112.106.196.115")) {return "DIRECT";}            // KNOX Messenger - sqipush5.samsung.net //
 if (shExpMatch(dip,"112.106.196.68")) {return "DIRECT";}            // KNOX Messenger - sqrproxy.samsung.net //
 if (shExpMatch(dip,"112.106.196.69")) {return "DIRECT";}            // KNOX Messenger - sqaproxy.samsung.net //
 if (shExpMatch(dip,"112.106.196.70")) {return "DIRECT";}            // KNOX Messenger - sqadmin.samsung.net //
 if (shExpMatch(dip,"112.106.196.80")) {return "DIRECT";}            // KNOX Messenger - sqgld.samsung.net //
 if (shExpMatch(dip,"112.106.197.184")) {return "DIRECT";}            // KNOX Messenger - sqgld.stage.samsung.net //
 if (shExpMatch(dip,"112.106.197.187")) {return "DIRECT";}            // KNOX Messenger - sqaproxy.stage.samsung.net //
 if (shExpMatch(dip,"112.106.197.188")) {return "DIRECT";}            // KNOX Messenger - sqadmin.stage.samsung.net //
 if (shExpMatch(dip,"112.106.197.191")) {return "DIRECT";}            // KNOX Messenger - sqmproxy.stage.samsung.net //
 if (shExpMatch(dip,"112.106.197.194")) {return "DIRECT";}            // KNOX Messenger - sqipush1.stage.samsung.net //
 if (shExpMatch(dip,"112.106.197.195")) {return "DIRECT";}            // KNOX Messenger - sqipush2.stage.samsung.net //
 if (shExpMatch(dip,"112.106.197.240")) {return "DIRECT";}            // KNOX Messenger - sqrproxy.stage.samsung.net //
 if (shExpMatch(dip,"112.106.240.39")) {return "DIRECT";}            // KNOX Messenger - sqepush1.samsung.net //
 if (shExpMatch(dip,"112.106.240.40")) {return "DIRECT";}            // KNOX Messenger - sqepush2.samsung.net //
 if (shExpMatch(dip,"112.106.240.41")) {return "DIRECT";}            // KNOX Messenger - sqepush3.samsung.net //
 if (shExpMatch(dip,"112.106.240.42")) {return "DIRECT";}            // KNOX Messenger - sqepush4.samsung.net //
 if (shExpMatch(dip,"112.106.240.43")) {return "DIRECT";}            // KNOX Messenger - sqepush5.samsung.net //
 if (shExpMatch(dip,"112.107.218.250")) {return "DIRECT";}            // KNOX Messenger - sqepush5.samsung.net //
 if (shExpMatch(dip,"203.254.224.146")) {return "DIRECT";}            // KNOX Messenger - sqepush1.stage.samsung.net //
 if (shExpMatch(dip,"203.254.224.147")) {return "DIRECT";}            // KNOX Messenger - sqepush2.stage.samsung.net //
 if (shExpMatch(dip,"112.106.196.135")) {return "DIRECT";}            // Knox Portal - ??? ?? //
 if (shExpMatch(dip,"112.107.220.101")) {return "DIRECT";}            // Knox Portal - kr1.samsung.net //
 if (shExpMatch(dip,"112.107.220.102")) {return "DIRECT";}            // Knox Portal - kr1.samsung.net //
 if (shExpMatch(dip,"112.107.220.103")) {return "DIRECT";}            // Knox Portal - kr1.samsung.net //
 if (shExpMatch(dip,"112.107.220.104")) {return "DIRECT";}            // Knox Portal - kr1.samsung.net //
 if (shExpMatch(dip,"112.107.220.105")) {return "DIRECT";}            // Knox Portal - kr1.samsung.net //
 if (shExpMatch(dip,"112.107.220.106")) {return "DIRECT";}            // Knox Portal - kr1.samsung.net //
 if (shExpMatch(dip,"112.107.220.115")) {return "DIRECT";}            // Knox Portal - kr1.samsung.net //
 if (shExpMatch(dip,"112.107.220.133")) {return "DIRECT";}            // Knox Portal - desktop.samsung.net //
 if (shExpMatch(dip,"112.107.220.134")) {return "DIRECT";}            // Knox Portal - openapi.samsung.net //
 if (shExpMatch(dip,"112.107.220.135")) {return "DIRECT";}            // Knox Portal - flip.samsung.net //
 if (shExpMatch(dip,"112.107.220.15")) {return "DIRECT";}            // Knox Portal - flip.samsung.net //
 if (shExpMatch(dip,"112.107.220.150")) {return "DIRECT";}            // Knox Portal - imap.samsung.com //
 if (shExpMatch(dip,"112.107.220.160")) {return "DIRECT";}            // Knox Portal - dav.samsung.net //
 if (shExpMatch(dip,"112.107.220.2")) {return "DIRECT";}            // Knox Portal - dav.samsung.net //
 if (shExpMatch(dip,"112.107.220.3")) {return "DIRECT";}            // Knox Portal - kr2.samsung.net //
 if (shExpMatch(dip,"112.107.220.32")) {return "DIRECT";}            // Knox Portal - kr3.samsung.net //
 if (shExpMatch(dip,"112.107.220.72")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.33")) {return "DIRECT";}            // Knox Portal - analytics.samsung.net //
 if (shExpMatch(dip,"112.107.220.34")) {return "DIRECT";}            // Knox Portal - epsso.samsung.net //
 if (shExpMatch(dip,"112.107.220.35")) {return "DIRECT";}            // Knox Portal - ssdrm.samsung.net //
 if (shExpMatch(dip,"112.107.220.36")) {return "DIRECT";}            // Knox Portal - developers.samsung.net //
 if (shExpMatch(dip,"112.107.220.76")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.37")) {return "DIRECT";}            // Knox Portal - blog.samsung.net //
 if (shExpMatch(dip,"112.107.220.77")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.38")) {return "DIRECT";}            // Knox Portal - community.samsung.net //
 if (shExpMatch(dip,"112.107.220.78")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.39")) {return "DIRECT";}            // Knox Portal - support.samsung.net //
 if (shExpMatch(dip,"112.107.220.4")) {return "DIRECT";}            // Knox Portal - survey.samsung.net //
 if (shExpMatch(dip,"112.107.220.40")) {return "DIRECT";}            // Knox Portal - kr4.samsung.net //
 if (shExpMatch(dip,"112.107.220.41")) {return "DIRECT";}            // Knox Portal - sms.samsung.net //
 if (shExpMatch(dip,"112.107.220.42")) {return "DIRECT";}            // Knox Portal - media.samsung.net //
 if (shExpMatch(dip,"112.107.220.43")) {return "DIRECT";}            // Knox Portal - image.samsung.net //
 if (shExpMatch(dip,"112.107.220.44")) {return "DIRECT";}            // Knox Portal - video.samsung.net //
 if (shExpMatch(dip,"112.107.220.45")) {return "DIRECT";}            // Knox Portal - service.samsung.net //
 if (shExpMatch(dip,"112.107.220.85")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.5")) {return "DIRECT";}            // Knox Portal - search.samsung.net //
 if (shExpMatch(dip,"112.107.220.6")) {return "DIRECT";}            // Knox Portal - kr5.samsung.net //
 if (shExpMatch(dip,"112.107.220.73")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.74")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.75")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.79")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.80")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.81")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.82")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.83")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.220.84")) {return "DIRECT";}            // Knox Portal - kr6.samsung.net //
 if (shExpMatch(dip,"112.107.221.230")) {return "DIRECT";}            // Knox Portal - lfas.samsung.net //
 if (shExpMatch(dip,"112.107.222.151")) {return "DIRECT";}            // Knox Portal - mm101.samsung.net //
 if (shExpMatch(dip,"112.107.222.152")) {return "DIRECT";}            // Knox Portal - mm102.samsung.net //
 if (shExpMatch(dip,"112.107.222.153")) {return "DIRECT";}            // Knox Portal - mm103.samsung.net //
 if (shExpMatch(dip,"112.107.222.154")) {return "DIRECT";}            // Knox Portal - mm104.samsung.net //
 if (shExpMatch(dip,"112.107.222.155")) {return "DIRECT";}            // Knox Portal - mm105.samsung.net //
 if (shExpMatch(dip,"112.107.222.156")) {return "DIRECT";}            // Knox Portal - mm106.samsung.net //
 if (shExpMatch(dip,"182.195.51.187")) {return "DIRECT";}            // Knox Portal - imap.stage1.samsung.com //
 if (shExpMatch(dip,"182.195.51.188")) {return "DIRECT";}            // Knox Portal - mm101.stage1.samsung.net //
 if (shExpMatch(dip,"182.195.51.197")) {return "DIRECT";}            // Knox Portal - desktop.stage1.samsung.net //
 if (shExpMatch(dip,"182.195.51.237")) {return "DIRECT";}            // Knox Portal - media.stage.samsung.net //
 if (shExpMatch(dip,"182.195.52.141")) {return "DIRECT";}            // Knox Portal - media.stage.samsung.net //
 if (shExpMatch(dip,"203.254.195.140")) {return "DIRECT";}            // Knox Portal - w2.samsung.net //
 if (shExpMatch(dip,"203.254.195.143")) {return "DIRECT";}            // Knox Portal - epsso.w2.samsung.net //
 if (shExpMatch(dip,"203.254.195.151")) {return "DIRECT";}            // Knox Portal - image.w2.samsung.net //
 if (shExpMatch(dip,"203.254.195.152")) {return "DIRECT";}            // Knox Portal - video.w2.samsung.net //
 if (shExpMatch(dip,"203.254.195.153")) {return "DIRECT";}            // Knox Portal - survey.w2.samsung.net //
 if (shExpMatch(dip,"203.254.195.154")) {return "DIRECT";}            // Knox Portal - sms.w2.samsung.net //
 if (shExpMatch(dip,"203.254.195.171")) {return "DIRECT";}            // Knox Portal - openapi.w2.samsung.net //
 if (shExpMatch(dip,"203.254.195.79")) {return "DIRECT";}            // Knox Portal - smtp.w2.samsung.net //
 if (shExpMatch(dip,"203.254.195.80")) {return "DIRECT";}            // Knox Portal - pop3.w2.samsung.net //
 if (shExpMatch(dip,"203.254.195.85")) {return "DIRECT";}            // Knox Portal - pop3plus.w2.samsung.com //
 if (shExpMatch(dip,"203.254.195.86")) {return "DIRECT";}            // Knox Portal - mm301.samsung.net //
 if (shExpMatch(dip,"203.254.195.87")) {return "DIRECT";}            // Knox Portal - imap.w2.samsung.com //
 if (shExpMatch(dip,"203.254.195.90")) {return "DIRECT";}            // Knox Portal - desktop.w2.samsung.net //
 if (shExpMatch(dip,"203.254.199.140")) {return "DIRECT";}            // Knox Portal - w1.samsung.net //
 if (shExpMatch(dip,"203.254.199.148")) {return "DIRECT";}            // Knox Portal - epsso.w1.samsung.net //
 if (shExpMatch(dip,"203.254.199.151")) {return "DIRECT";}            // Knox Portal - image.w1.samsung.net //
 if (shExpMatch(dip,"203.254.199.152")) {return "DIRECT";}            // Knox Portal - video.w1.samsung.net //
 if (shExpMatch(dip,"203.254.199.153")) {return "DIRECT";}            // Knox Portal - survey.w1.samsung.net //
 if (shExpMatch(dip,"203.254.199.154")) {return "DIRECT";}            // Knox Portal - sms.w1.samsung.net //
 if (shExpMatch(dip,"203.254.199.171")) {return "DIRECT";}            // Knox Portal - openapi.w1.samsung.net //
 if (shExpMatch(dip,"203.254.199.200")) {return "DIRECT";}            // Knox Portal - pop3.w1.samsung.net //
 if (shExpMatch(dip,"203.254.199.205")) {return "DIRECT";}            // Knox Portal - desktop.w1.samsung.net //
 if (shExpMatch(dip,"203.254.199.210")) {return "DIRECT";}            // Knox Portal - pop3plus.w1.samsung.com //
 if (shExpMatch(dip,"203.254.199.218")) {return "DIRECT";}            // Knox Portal - mm201.samsung.net //
 if (shExpMatch(dip,"203.254.199.219")) {return "DIRECT";}            // Knox Portal - imap.w1.samsung.com //
 if (shExpMatch(dip,"203.254.199.220")) {return "DIRECT";}            // Knox Portal - smtp.w1.samsung.net //
 if (shExpMatch(dip,"203.254.214.131")) {return "DIRECT";}            // Knox Portal - openapi.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.143")) {return "DIRECT";}            // Knox Portal - www.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.152")) {return "DIRECT";}            // Knox Portal - kr1.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.157")) {return "DIRECT";}            // Knox Portal - analytics.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.187")) {return "DIRECT";}            // Knox Portal - dav.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.188")) {return "DIRECT";}            // Knox Portal - blog.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.189")) {return "DIRECT";}            // Knox Portal - community.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.190")) {return "DIRECT";}            // Knox Portal - image.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.191")) {return "DIRECT";}            // Knox Portal - video.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.192")) {return "DIRECT";}            // Knox Portal - sms.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.193")) {return "DIRECT";}            // Knox Portal - survey.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.194")) {return "DIRECT";}            // Knox Portal - support.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.195")) {return "DIRECT";}            // Knox Portal - search.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.203")) {return "DIRECT";}            // Knox Portal - lfas1.stage.samsung.net //
 if (shExpMatch(dip,"203.254.214.67")) {return "DIRECT";}            // Knox Portal - ??? //
 if (shExpMatch(dip,"203.254.224.61")) {return "DIRECT";}            // Knox Portal - ext.samsung.net //
 if (shExpMatch(dip,"203.254.227.15")) {return "DIRECT";}            // Knox Portal - smtp.samsung.com //
 if (shExpMatch(dip,"203.254.227.30")) {return "DIRECT";}            // Knox Portal - pop3plus.samsung.com //
 if (shExpMatch(dip,"203.254.241.39")) {return "DIRECT";}            // Knox Portal - pop3plus.samsung.com //
 if (shExpMatch(dip,"203.254.247.109")) {return "DIRECT";}            // Knox Portal - ??? //
 if (shExpMatch(dip,"203.254.247.110")) {return "DIRECT";}            // Knox Portal - ??? //
 if (shExpMatch(dip,"203.254.247.149")) {return "DIRECT";}            // Knox Portal - ssdrm.stage.samsung.net //
 if (shExpMatch(dip,"203.254.247.150")) {return "DIRECT";}            // Knox Portal - epsso.stage.samsung.net //
 if (shExpMatch(dip,"203.254.247.46")) {return "DIRECT";}            // Knox Portal - push1.samsung.net //
 if (shExpMatch(dip,"203.254.247.47")) {return "DIRECT";}            // Knox Portal - push2.samsung.net //
 if (shExpMatch(dip,"203.254.247.48")) {return "DIRECT";}            // Knox Portal - push3.samsung.net //
 if (shExpMatch(dip,"203.254.247.49")) {return "DIRECT";}            // Knox Portal - push4.samsung.net //
 if (shExpMatch(dip,"203.254.247.57")) {return "DIRECT";}            // Knox Portal - push5.samsung.net //
 if (shExpMatch(dip,"203.254.255.24")) {return "DIRECT";}            // Knox Portal - push5.samsung.net //
 if (shExpMatch(dip,"210.118.77.20")) {return "DIRECT";}            // Knox Portal - ssdrm.w1.samsung.net //
 if (shExpMatch(dip,"210.118.77.30")) {return "DIRECT";}            // Knox Portal - ext.w1.samsung.net //
 if (shExpMatch(dip,"210.118.77.101")) {return "DIRECT";}            // Knox meeting //
 if (shExpMatch(dip,"210.118.77.102")) {return "DIRECT";}            // Knox meeting //
 
 
 
 
 
 
 if (shExpMatch(dip,"210.118.77.8")) {return "DIRECT";}            // Knox Portal - dav.w1.samsung.net //
 if (shExpMatch(dip,"211.189.100.23")) {return "DIRECT";}            // Knox Portal - ssdrm.w2.samsung.net //
 if (shExpMatch(dip,"211.189.100.30")) {return "DIRECT";}            // Knox Portal - ext.w2.samsung.net //
 if (shExpMatch(dip,"211.189.100.44")) {return "DIRECT";}            // Knox Portal - ext.w2.samsung.net //
 if (shExpMatch(dip,"211.189.100.8")) {return "DIRECT";}            // Knox Portal - dav.w2.samsung.net //
 if (dnsDomainIs(host, "vod.samsung.net")) {return "DIRECT";}            // Knox Portal - vod.samsung.net //
 if (shExpMatch(dip,"203.254.227.19")) {return "DIRECT";}            // Knox Portal - ??/??(OUTLOOK) //
 if (shExpMatch(dip,"112.106.134.14")) {return "DIRECT";}            // Knox Portal Mobile - mpush.samsungmobiledesk.co.kr //
 if (shExpMatch(dip,"112.106.134.70")) {return "DIRECT";}            // Knox Portal Mobile - relay.samsungmobiledesk.co.kr //
 if (shExpMatch(dip,"112.106.134.87")) {return "DIRECT";}            // Knox Portal Mobile - ota.samsungmobiledesk.co.kr //
 if (shExpMatch(dip,"112.107.220.1")) {return "DIRECT";}            // Knox Teams - ktbproxy.samsung.net //
 if (shExpMatch(dip,"112.107.221.211")) {return "DIRECT";}            // Knox Teams - ktgld.samsung.net //
 if (shExpMatch(dip,"112.107.221.212")) {return "DIRECT";}            // Knox Teams - ktaproxy.samsung.net //
 if (shExpMatch(dip,"112.107.221.213")) {return "DIRECT";}            // Knox Teams - kteproxy.samsung.net //
 if (shExpMatch(dip,"112.107.221.214")) {return "DIRECT";}            // Knox Teams - teams.samsung.net //
 if (shExpMatch(dip,"112.107.221.217")) {return "DIRECT";}            // Knox Teams - ktmproxy.samsung.net //
 if (shExpMatch(dip,"112.107.220.135")) {return "DIRECT";}            // Knox Portal - flip.samsung.net_2019.12.26 //
 if (shExpMatch(dip,"112.107.220.137")) {return "DIRECT";}            // Knox Portal - download.samsung.net_2020.11.24 //

// GERP //
 if (shExpMatch(dip,"10.34.11.234")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.235")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.34")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.41")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.42")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.43")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.44")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.45")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.46")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.47")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.48")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.49")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.50")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.51")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.52")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.53")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.54")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.55")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.56")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.57")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.58")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.59")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.11.60")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.103")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.111")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.112")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.113")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.114")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.115")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.116")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.117")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.118")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.119")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.120")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.203")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"10.34.12.204")) {return "DIRECT";}            // GERP - GMP_GFP //
 if (shExpMatch(dip,"165.213.246.193")) {return "DIRECT";}            // GERP - GMS //
 if (shExpMatch(dip,"165.213.246.235")) {return "DIRECT";}            // GERP - GMS //
 if (shExpMatch(dip,"165.213.246.237")) {return "DIRECT";}            // GERP - GMQ_GFQ //
 if (shExpMatch(dip,"165.213.246.240")) {return "DIRECT";}            // GERP - GMQ_GFQ //
 if (shExpMatch(dip,"165.213.246.246")) {return "DIRECT";}            // GERP - GMQ_GFQ //
 if (shExpMatch(dip,"165.213.246.252")) {return "DIRECT";}            // GERP - GMQ_GFQ //
 if (shExpMatch(dip,"165.213.246.38")) {return "DIRECT";}            // GERP - GMQ_GFQ //
 if (shExpMatch(dip,"10.47.11.234")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.235")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.34")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.36")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.37")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.38")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.39")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.40")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.41")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.42")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.43")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.44")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.45")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.46")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.47")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.48")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.49")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.50")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.51")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.52")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.53")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.54")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.11.55")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.12.211")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.12.212")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.12.83")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.12.85")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.12.86")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.12.87")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.12.88")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.47.12.89")) {return "DIRECT";}            // GERP - GMR_GFR //
 if (shExpMatch(dip,"10.34.16.151")) {return "DIRECT";}            // GERP - GIP //
 if (shExpMatch(dip,"10.34.16.189")) {return "DIRECT";}            // GERP - GIP //
 if (shExpMatch(dip,"10.34.16.190")) {return "DIRECT";}            // GERP - GIP //
 if (shExpMatch(dip,"10.34.16.224")) {return "DIRECT";}            // GERP - GIP //
 if (shExpMatch(dip,"10.34.16.225")) {return "DIRECT";}            // GERP - GIP //
 if (shExpMatch(dip,"10.34.16.156")) {return "DIRECT";}            // GERP - GSP //
 if (shExpMatch(dip,"10.47.14.163")) {return "DIRECT";}            // GERP - GBS_GBQ //
 if (shExpMatch(dip,"10.47.14.173")) {return "DIRECT";}            // GERP - GBS_GBQ //
 if (shExpMatch(dip,"10.47.14.174")) {return "DIRECT";}            // GERP - GBS_GBQ //
 if (shExpMatch(dip,"10.48.10.21")) {return "DIRECT";}            // NERP 270720//
 if (shExpMatch(dip,"10.48.11.21")) {return "DIRECT";}            // NERP 270720
 if (shExpMatch(dip,"10.34.14.163")) {return "DIRECT";}            // GERP - GBP //
 if (shExpMatch(dip,"10.34.14.165")) {return "DIRECT";}            // GERP - GBP //
 if (shExpMatch(dip,"10.34.14.166")) {return "DIRECT";}            // GERP - GBP //
 if (shExpMatch(dip,"10.34.14.167")) {return "DIRECT";}            // GERP - GBP //
 if (shExpMatch(dip,"10.34.14.168")) {return "DIRECT";}            // GERP - GBP //
 if (shExpMatch(dip,"10.34.14.170")) {return "DIRECT";}            // GERP - GBP //
 if (shExpMatch(dip,"10.34.14.253")) {return "DIRECT";}            // GERP - GBP //
 if (shExpMatch(dip,"10.34.14.254")) {return "DIRECT";}            // GERP - GBP //
 if (shExpMatch(dip,"10.34.15.10")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.15.11")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.15.12")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.52")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.54")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.55")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.56")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.57")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.58")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.59")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.60")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.61")) {return "DIRECT";}            // GERP - EPI_1 //
 if (shExpMatch(dip,"10.34.25.51")) {return "DIRECT";}            // GERP - EPI_2 //

// Site //
 if (shExpMatch(dip,"70.2.170.151")) {return "DIRECT";}            // ID 1107  - [SDSC] ??SAP?????? //
 if (shExpMatch(dip,"70.2.170.16")) {return "DIRECT";}            // ID 1107  - [SDSC] ??SAP?????? //
 if (shExpMatch(dip,"70.2.170.18")) {return "DIRECT";}            // ID 1107  - [SDSC] ??SAP?????? //
 if (shExpMatch(dip,"70.20.10.171")) {return "DIRECT";}            // ID 1109  - [SDSC] ITRM???? //
 if (shExpMatch(dip,"39.106.119.195")) {return "DIRECT";}            // ID 815  - [SDSC] GCDM???????????????? //
 if (shExpMatch(dip,"39.105.137.110")) {return "DIRECT";}            // ID 828  - [SDSC] GCDM????????????????SAP??QA????? //
 if (shExpMatch(dip,"39.106.166.153")) {return "DIRECT";}            // ID 828  - [SDSC] GCDM????????????????SAP??QA????? //
 if (shExpMatch(dip,"39.105.125.38")) {return "DIRECT";}            // ID 820  - [SDSC] GCDM???????????????? //
 if (shExpMatch(dip,"39.105.37.8")) {return "DIRECT";}            // ID 820  - [SDSC] GCDM???????????????? //
 if (shExpMatch(dip,"39.105.98.105")) {return "DIRECT";}            // ID 820  - [SDSC] GCDM???????????????? //
 if (shExpMatch(dip,"109.10.1.224")) {return "DIRECT";}            // ID 1016  - [SDSC] 106????IP??ChinaPortal????? //
 if (shExpMatch(dip,"109.10.1.89")) {return "DIRECT";}            // ID 1016  - [SDSC] 106????IP??ChinaPortal????? //
 
 if (shExpMatch(dip,"109.10.100.82")) {return "DIRECT";} // ID 1069  - [SDSC] 106????IP??MCS???WAS???,??JEUS???ADMIN/HTTP/AJP??,?????? //
 if (shExpMatch(dip,"109.10.100.83")) {return "DIRECT";} // ID 1069  - [SDSC] 106????IP??MCS???WAS???,??JEUS???ADMIN/HTTP/AJP??,?????? //
 if (shExpMatch(dip,"109.10.100.84")) {return "DIRECT";} // ID 1069  - [SDSC] 106????IP??MCS???WAS???,??JEUS???ADMIN/HTTP/AJP??,?????? //
 if (shExpMatch(dip,"109.10.13.121")) {return "DIRECT";} // ID 1069  - [SDSC] 106????IP??MCS???WAS???,??JEUS???ADMIN/HTTP/AJP??,?????? //
 if (shExpMatch(dip,"109.10.13.122")) {return "DIRECT";} // ID 1069  - [SDSC] 106????IP??MCS???WAS???,??JEUS???ADMIN/HTTP/AJP??,?????? //
 if (shExpMatch(dip,"109.10.13.123")) {return "DIRECT";} // ID 1069  - [SDSC] 106????IP??MCS???WAS???,??JEUS???ADMIN/HTTP/AJP??,?????? //
 if (shExpMatch(dip,"109.10.13.124")) {return "DIRECT";} // ID 1069  - [SDSC] 106????IP??MCS???WAS???,??JEUS???ADMIN/HTTP/AJP??,?????? //
 if (shExpMatch(dip,"109.10.13.125")) {return "DIRECT";} // ID 1069  - [SDSC] 106????IP??MCS???WAS???,??JEUS???ADMIN/HTTP/AJP??,?????? //
 if (shExpMatch(dip,"109.10.13.101")) {return "DIRECT";}            // ID 1017  - [SDSC] 106????IP??MCS/chinportal cloud ??? //
 if (shExpMatch(dip,"109.10.13.110")) {return "DIRECT";}            // ID 1017  - [SDSC] 106????IP??MCS/chinportal cloud ??? //
 if (shExpMatch(dip,"70.20.10.180")) {return "DIRECT";}            // ID 1017  - [SDSC] 106????IP??MCS/chinportal cloud ??? //
 if (shExpMatch(dip,"109.10.1.*")) {return "DIRECT";}            // ID 1017  - [SDSC] 106????IP??MCS/chinportal cloud ??? //
 if (shExpMatch(dip,"182.195.81.243")) {return "DIRECT";}            // ID 871  - [SDSC] IPA:Intelligent Process Automation ???? //
 if (shExpMatch(dip,"11.4.14.179")) {return "DIRECT";}            // ID 1100  - [SDSC] AMS???? //
 if (shExpMatch(dip,"101.103.2.42")) {return "DIRECT";}            // ID 1101  - Knox meeting ???????(???/???) //
 if (shExpMatch(dip,"182.195.83.41")) {return "DIRECT";}            // ID 937  - [SDSC] BrityWorks server ?? //
 if (shExpMatch(dip,"39.105.135.4")) {return "DIRECT";}            // ID 928  - [SDSC] GCDM??? //
 if (shExpMatch(dip,"112.106.141.11")) {return "DIRECT";}            // ID 988  - SAP?????? //
 if (dnsDomainIs(host, "gerplo.sec.samsung.net")) {return "DIRECT";}            // ID 989  - [SDSC]  ERP RMS ????? //
 if (shExpMatch(dip,"10.34.11.34")) {return "DIRECT";}            // ID 989  - [SDSC]  ERP RMS ????? //
 if (shExpMatch(dip,"109.10.1.47")) {return "DIRECT";}            // ID 989  - [SDSC]  ERP RMS ????? //
 if (shExpMatch(dip,"165.213.246.252")) {return "DIRECT";}            // ID 989  - [SDSC]  ERP RMS ????? //
 if (shExpMatch(dip,"203.241.132.34")) {return "DIRECT";}            // ID 989  - [SDSC]  ERP RMS ????? //
 if (shExpMatch(dip,"10.34.11.*")) {return "DIRECT";}            // ID 989  - [SDSC]  ERP RMS ????? //
 if (shExpMatch(dip,"10.34.12.*")) {return "DIRECT";}            // ID 989  - [SDSC]  ERP RMS ????? //
 if (shExpMatch(dip,"183.136.184.141")) {return "DIRECT";}            // ID 1049  - [SDSC] War Room???CCTV????_??? //
 if (shExpMatch(dip,"47.95.85.*")) {return "DIRECT";}            // ID 1081  - [SDSC] ??OSS Browser?????????Jar?_can.jin //
 if (shExpMatch(dip,"70.2.170.172")) {return "DIRECT";}            // ID 1095  - [SDSC] ep.sds.samsung.net?? //
 if (shExpMatch(dip,"70.20.10.140")) {return "DIRECT";}            // ID 1094  - [SDSC] OpenITSM?? //
 if (shExpMatch(dip,"70.2.140.170")) {return "DIRECT";}            // ID 1093  - [SDSC] Openplace?? //
 if (shExpMatch(dip,"70.2.170.171")) {return "DIRECT";}            // ID 1096  - [SDSC] ecc.sds.samsung.net?? //
 if (shExpMatch(dip,"70.2.140.190")) {return "DIRECT";}            // ID 1092  - [SDSC] GHRP???? //
 if (shExpMatch(dip,"70.20.1.240")) {return "DIRECT";}            // ID 1092  - [SDSC] GHRP???? //
 if (shExpMatch(dip,"107.10.120.129")) {return "DIRECT";}            // ID 415  - ??GHRP???? //
 if (shExpMatch(dip,"39.105.132.195")) {return "DIRECT";}            // ID 996  - [SDSC] GCDM??? //
 if (shExpMatch(dip,"39.105.142.138")) {return "DIRECT";}            // ID 996  - [SDSC] GCDM??? //
 if (shExpMatch(dip,"107.10.109.*")) {return "DIRECT";}            // ID 1561  - [Knox connect] //
 if (shExpMatch(dip,"109.10.97.*")) {return "DIRECT";}            // ID 1563  - [Knox connect] //
 if (shExpMatch(dip,"112.106.156.217")) {return "DIRECT";}            // ID 49  - SPLM????_xiyue.cui splm.sec.samsung.net //
 if (shExpMatch(dip,"112.106.156.218")) {return "DIRECT";}            // ID 49  - SPLM????_xiyue.cui splm.sec.samsung.net //
 if (shExpMatch(dip,"112.106.156.219")) {return "DIRECT";}            // ID 49  - SPLM????_xiyue.cui splm.sec.samsung.net //
 //if (dnsDomainIs(host, "alibabacloud.com")) {return "DIRECT";}            // ID 1111  - [SDSC] console.aliyun.com??_can.jin //
 //if (dnsDomainIs(host, "cms-intl.console.aliyun.com")) {return "DIRECT";}            // ID 1111  - [SDSC] console.aliyun.com??_can.jin //
 // if (dnsDomainIs(host, "kvstorenext.console.aliyun.com")) {return "DIRECT";}            // ID 1111  - [SDSC] console.aliyun.com??_can.jin //
 //if (dnsDomainIs(host, "mns.console.aliyun.com")) {return "DIRECT";}            // ID 1111  - [SDSC] console.aliyun.com??_can.jin //
 //if (dnsDomainIs(host, "oss.console.aliyun.com")) {return "DIRECT";}            // ID 1111  - [SDSC] console.aliyun.com??_can.jin //
 //if (dnsDomainIs(host, "rdsnew.console.aliyun.com")) {return "DIRECT";}            // ID 1111  - [SDSC] console.aliyun.com??_can.jin //
 //if (dnsDomainIs(host, "sls.console.aliyun.com")) {return "DIRECT";}            // ID 1111  - [SDSC] console.aliyun.com??_can.jin //
 //if (shExpMatch(dip,"47.94.255.148")) {return "DIRECT";}            // ID 1067  - [SDSC] api.weixin.qq.com??_can.jin //
 //if (shExpMatch(dip,"203.244.224.138")) {return "DIRECT";}            // ID 1201  -In house HR //
 //if (dnsDomainIs(host, "aegis.aligames.com")) {return "DIRECT";}            //aegis.aligames.com //
 //if (shExpMatch(host, "aegis.aligames.com")) {return "DIRECT";}            //aegis.aligames.com //
 if (shExpMatch(host, "admin.samsungvpn.com")) {return "DIRECT";}       //ID : 1212 admin.samsungvpn.com//
 if (shExpMatch(dip,"112.106.187.177")) {return "DIRECT";}   //ID:1217 pvi.samsung.com //
 if (dnsDomainIs(host, "pvi.samsung.com")) {return "DIRECT";} //ID:1217 pvi.samsung.com //
 if (shExpMatch(dip,"70.2.140.140")) {return "DIRECT";}   //ID:1227 [SDSC] ARISAM_20191219 //
 if (shExpMatch(dip,"70.2.90.100")) {return "DIRECT";}   //ID:1228 [SDSC] DevOps_20191219 //
 if (dnsDomainIs(host, "cpdm.sec.samsung.net")) {return "DIRECT";}            // ID : 1262 cpdm.sec.samsung.net _CPCex SYSTEM //
 if (shExpMatch(dip,"27.106.204.249")) {return "DIRECT";}   //ID:1334 Retail War Room_20200313 //
 if (shExpMatch(dip,"27.106.204.149")) {return "DIRECT";}   //ID:1330 N-ERP EDI Monitoring //
 if (shExpMatch(dip,"27.106.204.164")) {return "DIRECT";}   //ID:1330 N-ERP EDI Monitoring //
 if (shExpMatch(dip,"182.195.83.121")) {return "DIRECT";}   //ID:1348 IPA 1.6 //
 if (shExpMatch(dip,"182.195.85.206")) {return "DIRECT";}   //ID:1348 IPA 1.6 //
 if (shExpMatch(dip,"182.195.83.143")) {return "DIRECT";}   //ID:1482 IPA  //
 if (shExpMatch(dip,"182.198.195.203")) {return "DIRECT";}   //ID:1358 shengzhen.piao //
 if (shExpMatch(dip,"27.106.207.66")) {return "DIRECT";}   //ID:1357 xuefeng.piao //
 //if (shExpMatch(dip,"112.106.161.145")) {return "DIRECT";}   //ID:1384 qasgsrm.secbuy.com //
 if (shExpMatch(dip,"70.2.90.114")) {return "DIRECT";}   //ID:1381 code.sdsdev.co.kr //
 if (dnsDomainIs(host, "sec.s-bluevery.com")) {return "DIRECT";}         // ID:1472 //
 if (shExpMatch(dip,"107.10.120.24")) {return "DIRECT";}   //ID:1476 //
 if (shExpMatch(dip,"182.195.129.76")) {return "DIRECT";}            // ID 1533 - prfx.samsung.net//
 if (shExpMatch(dip,"182.195.86.240")) {return "DIRECT";}            //lego.sdsdev.co.kr//
 if (dnsDomainIs(host, "www.cdr-adr.org.cn")) {return "DIRECT";}         // ID:1632 //
 if (shExpMatch(dip,"182.195.83.149")) {return "DIRECT";}            // ID 1636//
 if (dnsDomainIs(host, "concursolutions.com")) {return "DIRECT";}         // ID:1548 //
 if (dnsDomainIs(host, "consent.trustarc.com")) {return "DIRECT";}         // ID:1548 //
 if (dnsDomainIs(host, "www.concursolutions.com")) {return "DIRECT";}         // ID:1548 //
 if (dnsDomainIs(host, "*.concursolutions.com")) {return "DIRECT";}         // ID:1548 //
 if (dnsDomainIs(host, "cdn.walkme.com")) {return "DIRECT";} 
 if (dnsDomainIs(host, "cloudportal.samsungsds.com")) {return "DIRECT";}         // ID:1636 //
 if (dnsDomainIs(host, "grip.net")) {return "DIRECT";}         // ID:1698 //
 if (dnsDomainIs(host, "stream.rnduc.com")) {return "DIRECT";}         // Knox Streaming //
 //if (dnsDomainIs(host, "samsungu.csod.com")) {return "DIRECT";}         // ID:1403 // // 
 //if (shExpMatch(host, "*.samsungu.csod.com")) {return "DIRECT";}         // ID:1403 // //


//gdc//
if (shExpMatch(host, "*.samsunggdms.com")) return "DIRECT"; 
if (shExpMatch(host, "samsunggdms.com")) return "DIRECT";
if (shExpMatch(host, "mena.samsunggdms.com")) return "DIRECT";
if (shExpMatch(host, "nahq.samsunggdms.com")) return "DIRECT";
if (shExpMatch(host, "afhq.samsunggdms.com")) return "DIRECT";
if (shExpMatch(host, "euhq.samsunggdms.com")) return "DIRECT";
if (shExpMatch(host, "gov-cloud.samsungsds.com")) return "DIRECT";
if (shExpMatch(host, "gov-admin.comm.samsungsdscloud.com")) return "DIRECT";
if (shExpMatch(host, "stage-samjob.samsung.com.sg")) return "DIRECT";
if (shExpMatch(host, "mlops-dev2.sdspass.io")) return "DIRECT";
if (shExpMatch(host, "*.mlops-dev2.sdspass.io")) return "DIRECT";
if (dnsDomainIs(host,"mcc.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"iam.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"horizon.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"cloudformation.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"masakari.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"neutron.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"barbican.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"designate.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"octavia.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"aodh.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"cinder.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"placement.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"gnocchi.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"ironic.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"nova.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"heat.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"rgw-store.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"keystone.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"glance.mvp.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"horizon.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"cloudformation.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"masakari.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"neutron.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"barbican.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"designate.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"octavia.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"aodh.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"cinder.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"placement.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"gnocchi.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"ironic.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"nova.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"heat.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"rgw-store.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"keystone.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"glance.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"aodh.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"barbican.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"cinder.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"cloudformation.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"designate.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"glance.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"gnocchi.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"heat.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"ironic.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"keystone.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"masakari.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"metadata.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"neutron.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"nova.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"octavia.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"placement.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"rgw-store.admin.mvp-dev.sdscloud.com"))return "DIRECT";
if (dnsDomainIs(host,"qa-madmin.evldin.com"))return "DIRECT";
if (shExpMatch(host, "samsung.jp10.sapanalytics.cloud")) return "DIRECT";
if (shExpMatch(host, "samsung-test.jp10.sapanalytics.cloud")) return "DIRECT";
if (shExpMatch(host, "s-mp.samsungsdscloud.com")) return "DIRECT";
if (shExpMatch(host, "hometax.go.kr")) return "DIRECT";
if (shExpMatch(host, "*.hometax.go.kr")) return "DIRECT";
if (shExpMatch(host, "mysingle.wyz070.com")) return "DIRECT";
if (shExpMatch(host, "*.samsung.net")) return "DIRECT";
if (shExpMatch(host, "samsung.net")) return "DIRECT";
if (shExpMatch(host, "*.smart-office.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.sbc-cloud.com")) return "DIRECT";
if (shExpMatch(host, "admin.studitok.com")) return "DIRECT";
if (shExpMatch(host, "fabrix-in.samsungsds.com")) return "DIRECT";
if (shExpMatch(host, "*.fabrix-in.samsungsds.com")) return "DIRECT";
if (shExpMatch(host, "samsungglp.com")) return "DIRECT";
if (shExpMatch(host, "*.samsungglp.com")) return "DIRECT";
if (shExpMatch(host, "daum.net")) return "DIRECT";
if (shExpMatch(host, "*.nexplant-mes-cloud.com")) return "DIRECT";
//if (shExpMatch(host, "*.samsungcic.com")) return "DIRECT";
if (shExpMatch(host, "onadmin.e-campus.co.kr")) return "DIRECT";
if (shExpMatch(host, "sr.e-campus.co.kr")) return "DIRECT";
if (shExpMatch(host, "smartsbc.samsungpop.com")) return "DIRECT";
if (shExpMatch(host, "smartss.samsungpop.com")) return "DIRECT";
if (shExpMatch(host, "adaptiveoffice.com")) return "DIRECT";
if (shExpMatch(host, "*.adaptiveoffice.com")) return "DIRECT";
if (shExpMatch(host, "sdswomen.com")) return "DIRECT";
if (shExpMatch(host, "*.sdswomen.com")) return "DIRECT";
if (shExpMatch(host, "securewh.tesco.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.securewh.tesco.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.mil.kr")) return "DIRECT";
if (shExpMatch(host, "sdscpms.net")) return "DIRECT";
if (shExpMatch(host, "*.sdscpms.net")) return "DIRECT";
if (shExpMatch(host, "fustat.samsungdm.com")) return "DIRECT";
if (shExpMatch(host, "*.fustat.samsungdm.com")) return "DIRECT";
if (shExpMatch(host, "elec.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "abroad.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "life.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "fire.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "card.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "stock.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "trans.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "core.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "indy.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "uni.nmsplus.net")) return "DIRECT";
if (shExpMatch(host, "uni.nmsplus.co.kr")) return "DIRECT";
if (shExpMatch(host, "iuse.sdscloud.co.kr")) return "DIRECT";
if (dnsDomainIs(host, "nprotect.net")) return "DIRECT";
if (dnsDomainIs(host, "nprotect2.net")) return "DIRECT";
if (dnsDomainIs(host, "nprotect.com")) return "DIRECT";
if (shExpMatch(host, "*.nprotect.net")) return "DIRECT";
if (shExpMatch(host, "*.nprotect2.net")) return "DIRECT";
if (shExpMatch(host, "*.nprotect.com")) return "DIRECT";
if (shExpMatch(host, "keytoken.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.keytoken.co.kr")) return "DIRECT";
if (shExpMatch(host, "samsungsdsbiz.com")) return "DIRECT";
if (shExpMatch(host, "*.samsungsdsbiz.com")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot-arch.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot-arch.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot-arch1.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot-arch1.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot-arch2.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot-arch2.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot1.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot1.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot2.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot2.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot3.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot3.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot4.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot4.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot5.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot5.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.biot6.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.biot6.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "stage.cloudplatform.io")) return "DIRECT";
if (shExpMatch(host, "stage.cmp.io")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator1.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator1.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator3.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator3.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator4.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator4.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator5.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator5.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator9.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator9.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator10.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator10.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator11.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator11.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator13.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator13.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator14.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator14.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator15.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator15.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator16.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator16.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator17.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator17.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator18.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator18.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "*.dev.insator19.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "dev.insator19.sdsdev.co.kr")) return "DIRECT";
if (shExpMatch(host, "ssl2.samsungvpn.com")) return "DIRECT";
if (shExpMatch(host, "scloud.samsungsds.com")) return "DIRECT";
if (shExpMatch(host, "obj1.sap-east-1.samsungsdscloud.com")) return "DIRECT";
if (shExpMatch(host, "obj1.kr-west-1.samsungsdscloud.com")) return "DIRECT";
//gdc//




// A Class //
//if (shExpMatch(dip,"10.*.*.*")) {return "DIRECT";}            // 10.*.*.*  //
//if (shExpMatch(dip,"109.*.*.*")) {return "DIRECT";}            // 109.*.*.*  //
//if (shExpMatch(dip,"70.*.*.*")) {return "DIRECT";}             //* SDS 사업장 대역 *//

//* SDS 사업장 대역 * B Class //
if (shExpMatch(dip,"70.32.*.*")) {return "DIRECT";}
if (shExpMatch(dip,"71.28.*.*")) {return "DIRECT";}	// 220418 남경훈
if (shExpMatch(dip,"71.2.*.*")) {return "DIRECT";}	// 220418 남경훈
if (shExpMatch(dip,"72.10.*.*")) {return "DIRECT";}
if (shExpMatch(dip,"71.26.*.*")) {return "DIRECT";} 
if (shExpMatch(dip,"72.100.*.*")) {return "DIRECT";}
if (shExpMatch(dip,"72.152.*.*")) {return "DIRECT";}
if (shExpMatch(dip,"75.2.*.*")) {return "DIRECT";}
if (shExpMatch(dip,"75.3.*.*")) {return "DIRECT";}
if (shExpMatch(dip,"75.20.*.*")) {return "DIRECT";}
if (shExpMatch(dip,"70.225.*.*")) {return "DIRECT";}
if (shExpMatch(dip,"109.10.5.*")) {return "DIRECT";}

 //   else {                                                 //260831注销掉else，此语句存在逻辑错误
        return "PROXY 109.52.26.14:9090";
  //  }
}
