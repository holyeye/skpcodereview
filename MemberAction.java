
import icasApi.common.Cipher;
import it.sauronsoftware.base64.Base64;

import java.io.PrintWriter;
import java.net.InetAddress;
import java.net.URLEncoder;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Random;
import java.util.SimpleTimeZone;
import java.util.Vector;
import java.util.StringTokenizer;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import jwork.sso.agent.SSOManager;

import org.apache.log4j.Logger;
import org.json.JSONObject;

public class MemberAction extends BaseAction {
	private String tMsg;

	public String getTMsg() {
		return tMsg;
	}

	public void setTMsg(String msg) {
		tMsg = msg;
	}

	private String sp_list;

	public String getSp_list() {
		return sp_list;
	}

	public void setSp_list(String sp_list) {
		this.sp_list = sp_list;
	}

	private String tppw;

	public String getTppw() {
		return tppw;
	}

	public void setTppw(String tppw) {
		this.tppw = tppw;
	}

	private MemberService memberService;
	private MemberHpService memberHpService;
	private ConsumerService consumerService;
	private MultiService multiService;
	private RingBellService ringBellService;
	private Member member;
	private MemberPunish memberPunish;
	private TopService topService;
	private RepresentPhone representPhone;
	private final static Logger log = Logger.getLogger(MemberAction.class);
	private IDPReceiverM idpReceiverM;
	private IDPReceiverM idpReceiverMoIDAuth;
	private IDPReceiverM idpReceiverMoList;

	private ImIDPReceiverM imIdpReceiverM;
	private SignService signService;

	/*
	 * EMAIL 선언
	 */
	private String SENDER = "admin@tstore.co.kr"; // 송신자
	private String RECEIVER;

	private String header;
	private String contents;
	private String RESULT = "FAIL";

	private String loginId;
	private String password;
	private String prePhoneNumber;
	private String phone_01;
	private String phone_02;
	private int loginResult;

	private String loginResultMsg;

	private String mobileLoginResult;

	// IDP MDN 인증시 필요한 값
	private String user_code;
	private String mobile_sign;

	// IDP에서 받아오는 PARAMETER
	private String resp_url;
	private String resp_type;
	private String result_text;
	private String user_id;
	private String result;
	private String sp_auth_key;
	private String cmd;
	private String resp_flow;
	private String sp_id;
	private String sp_url;
	private String user_auth_key;
	private String user_key;

	// MDN 인증시 IDP에서 받아오는 PARAMETER

	private String user_mdn;
	private String sign_data;
	private String user_mdn1;
	private String user_mdn2;
	private String user_mdn3;
	private String phone_auth_code;
	private String svc_mng_num;
	private String model_id;

	private String redirectActionURL;
	private String redirectActionParam;
	private String loginRedirectURL; // logout 후 다시 return할 URL
	private String gnbLoginRedirectURL;

	private String checkMdnAuth; // MDN 회원여부 check Y:회원OK N:MDN 회원아님
	private String v4SprtYn; // V4 지원 유무 (PD005201:지원 PD005200:미지원)
	private String hpNo;
	private String email;
	private List<Member> emailList;
	private String anotherJoinCk;
	private String useStatsYn; // 앱 이용통계 정보 활용
	private String marketingYn; // 정보광고 수신동의
	private String user_mdn_type;

	private List telecomList = null;

	// 통합아이디 연동 정보
	private String im_int_svc_no;
	private String join_sst_list;
	private String join_site; // 전환시 사용중 사이트 정보
	private String imSvcNo; // 이용동의시 회원조회 필요
	private String change_type; // 전환시 Tstore/Idp

	// 아이디 잠금 상태일경우
	private String imgSign;
	private String signData;
	private String resultText;
	private String imgUrl;

	private String loginFailURL;
	private String stActionPositionNm;// 신규통계로그-이전 액션
	private String stPrePageNm;// 신규통계로그-이전 페이지
	private String strCurrPageNm;// 신규통계로그-현재페이지

	public String getMarketingYn() {
		return marketingYn;
	}

	public void setMarketingYn(String marketingYn) {
		this.marketingYn = marketingYn;
	}

	public String getUseStatsYn() {
		return useStatsYn;
	}

	public void setUseStatsYn(String useStatsYn) {
		this.useStatsYn = useStatsYn;
	}

	public String getAnotherJoinCk() {
		return anotherJoinCk;
	}

	public void setAnotherJoinCk(String anotherJoinCk) {
		this.anotherJoinCk = anotherJoinCk;
	}

	public String getResult() {
		return result;
	}

	public String gotoEtc() {
		this.searchV4SprtYn();
		return SUCCESS;
	}

	private void searchV4SprtYn() {
		HttpServletRequest request = getRequest();
		Member member = (Member) SessionUtil.getMemberSession(request);

		if (member != null) {
			RepresentPhone repPhone = topService.getRepresentPhone(member.getMbrNo());
			if (repPhone != null) {
				hpNo = repPhone.getHpNo();
				if (hpNo != null) {
					v4SprtYn = memberService.searchV4SprtYn(hpNo);
					if (v4SprtYn == null || v4SprtYn.equals("")) {
						v4SprtYn = "PD005200";
					}
				}
			}
		}
	}

	public void setResult(String result) {
		this.result = result;
	}

	public MemberAction() {
		memberService = new MemberServiceImpl();
		memberHpService = new MemberHpServiceImpl();
		member = new Member();
		topService = new TopServiceImpl();
		multiService = new MultiServiceImpl();
		memberPunish = new MemberPunish();
		ringBellService = new RingBellServiceImpl();
		consumerService = new ConsumerServiceImpl();
		signService = new SignServiceImpl();
	}

	public MemberService getMemberService() {
		return memberService;
	}

	public void setMemberService(MemberService memberService) {
		this.memberService = memberService;
	}

	public MemberHpService getMemberHpService() {
		return memberHpService;
	}

	public void setMemberHpService(MemberHpService memberHpService) {
		this.memberHpService = memberHpService;
	}

	public TopService getTopService() {
		return topService;
	}

	public void setTopService(TopService topService) {
		this.topService = topService;
	}

	public Member getMember() {
		return member;
	}

	public void setMember(Member member) {
		this.member = member;
	}

	public List getTelecomList() {
		return telecomList;
	}

	public void setTelecomList(List telecomList) {
		this.telecomList = telecomList;
	}

	/** TIME CHECK TEMP METHOD **/
	public String getCurrentTime() {
		String s1 = "";
		s1 = "yyyyMMdd HH:MM:SS";
		SimpleDateFormat simpledateformat = new SimpleDateFormat(s1);
		SimpleTimeZone simpletimezone = new SimpleTimeZone(0x1ee6280, "KST");
		simpledateformat.setTimeZone(simpletimezone);
		long l = System.currentTimeMillis();
		Date date = new Date(l);
		return simpledateformat.format(date);
	}

	public String getCookie(HttpServletRequest request, String CookieName) throws Exception {
		Cookie[] cookies = request.getCookies();
		if (cookies == null)
			return null;
		String value = "";
		for (int i = 0; i < cookies.length; i++) {
			if (CookieName.equals(cookies[i].getName())) {
				value = cookies[i].getValue();
				break;
			}
		}
		return value;
	}

	/**
	 * 회원 로그인
	 * <P/>
	 * id,pwd / mdn을 입력 받아 로그인 처리 한다.
	 * 
	 * @return
	 */
	public String getLogin() {
		log.info(" ===================== getLogin start time == [" + DateUtil.getShortTimeStampString()
				+ "] ===================== ");
		log.info(" getLogin_loginId : " + loginId);
		String returnResult = "fail";
		try {
			telecomList = CacheCommCode.getCommCode(CommCodeGroupDefinitions.GRP_CD_US_TELECOM);
			if (gnbLoginRedirectURL != null && !gnbLoginRedirectURL.equals("")) {
				loginRedirectURL = gnbLoginRedirectURL;
			}

			if (loginId != null && (loginResultMsg == null || "".equals(loginResultMsg))) {
				idpReceiverM = IDPManager.getInstance().userAuthForId(loginId, password);
				result = idpReceiverM.getResponseHeader().getResult();

				loginResult = -1;
				if (result != null) {
					loginResult = Integer.parseInt(result);
				}

				Enumeration enums = null;
				enums = getRequest().getParameterNames();
				String requestName = "";
				log.info("========== IDP LOGIN Reqest Variable Names START ==============================");
				while (enums.hasMoreElements()) {
					requestName = (String) enums.nextElement();
					log.info("names :" + requestName + ", value : " + getRequest().getParameter(requestName));
				}
				log.info("========== IDP LOGIN Reqest Variable Names END==============================");

				// 결과가 성공일 경우
				if (loginResult == 1000) {
					user_key = idpReceiverM.getResponseBody().getUser_key();
					user_auth_key = idpReceiverM.getResponseBody().getUser_auth_key();

					// member = memberService.selectMember(user_id, null);
					member = memberService.selectMemberByMbrNo(user_key);
					// TODO 원래대로 user_key로 조회하게 적용해야 함~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~!!!!!!!
					log.info("[param] member 조회 member.getMbrCatCd() ="
							+ (member == null ? "null" : member.getMbrCatCd()));

					if (member == null) {
						/**   DB에 회원 데이터가 없는경우 **/
						log.info("IDP :: 가입상태,    :: 데이터 존재하지 않음");
						returnResult = "fail";
						loginResultMsg = "NO_MEMBER_ ";
					} else if (member.getMbrStatCd().equals("US000502")) {
						/** EAMIL 인증후에도   DB에는 가입완료처리되지 않은경우 **/

						log.info("IDP :: 가입완료,    :: 가가입상태");
						returnResult = "fail";
						loginResultMsg = "NOT_C LETE_ ";
					} else if (!member.getMbrCatCd().equals("US000202") && !member.getMbrCatCd().equals("US000203")
							&& !member.getMbrCatCd().equals("US000204") && !member.getMbrCatCd().equals("US000207")) {
						/** 개발자 ID로 로그인 하는 경우 **/
						log.info("개발자 ID ==> 일반사용자 권한 없음");
						returnResult = "fail";
						loginResultMsg = "NO_AUTH_USER_POC";
					} else if (member.getMbrStatCd().equals("US000505")) { // DB만 탈퇴 처리되어 로그인 되는 경우 막음 2012.02.10
						log.info("IDP 정상, DB 탈퇴 회원 ");
						returnResult = "fail";
						loginResultMsg = "NO_MEMBER_ ";
					} else {
						log.info("[param] 로그인 성공 ");

						// 이용 중지상태인 경우 로그인 성공시 상태 정상으로 변경
						if ("US000504".equals(member.getMbrStatCd())) {
							Member updateStat = new Member();
							updateStat.setMbrNo(user_key);
							updateStat.setMbrStatCd("US000503");
							consumerService.updateConsumer(updateStat);
						}

						member.setUser_auth_key(user_auth_key);
						member.setUser_key(user_key);
						memberService.insertLoginInfo(member.getMbrNo(), getRequest());

						List<MemberHp> myHpList = memberHpService.selectHpByMbrNo(user_key);
						if (myHpList != null) {
							if (member.getMobileCnt() != myHpList.size()) {
								Member updateStat = new Member();
								updateStat.setMbrNo(user_key);
								updateStat.setMobileCnt(myHpList.size());
								consumerService.updateConsumer(updateStat);
								member.setMobileCnt(myHpList.size());
							}
						}

						// 세션을 생성한다.
						SessionUtil.setMemberSession(getRequest(), member);
						// 통계를 위한 쿠키 생성
						SessionCheckFilter.setLID(getRequest(), getResponse(), CipherAES.encrypt(member.getMbrNo()));

						representPhone = topService.getRepresentPhone(member.getMbrNo());
						if (representPhone != null) {
							if (multiService.getPhoneCheck(representPhone.getPhoneModelCd())) {
								representPhone.setMultiPhoneYn("Y");
							} else {
								representPhone.setMultiPhoneYn("N");
							}
							SessionUtil.setAnySession(getRequest(), "REP_HP_SESSION", representPhone);
						} else {
							SessionUtil.removeAnySession(getRequest(), "REP_HP_SESSION");
						}

						if (representPhone != null) {
							// if(representPhone.getPhoneModelCd().indexOf("미지원") == 0){ 대체. 20100222 soohee
							if (!CommonUtil.isSupportPhone(representPhone.getPhoneModelCd())) {
								SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
							} else {
								SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "MYPHONE");
							}
						} else {
							SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
						}
						SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION");
						if (loginRedirectURL != null && !loginRedirectURL.equals("")
								&& loginRedirectURL.indexOf("main. ") == -1) {
							redirectActionURL = loginRedirectURL;
							if (redirectActionParam != null && !redirectActionParam.equals("")) {
								redirectActionURL += redirectActionParam;
							}
							returnResult = "loginRedirect";
						} else {
							returnResult = "success";
							anotherJoinCk = "6";
						}
						// is_email_auth_yn 체크 해서 N인 경우 팝업
						idpReceiverM = IDPManager.getInstance().searchUserCommonInfo4SPServer(
								IDPManager.IDP_PARAM_KEY_TYPE_USERKEY, user_key);
						if (IDPManager.IDP_RES_CODE_OK.equals(idpReceiverM.getResponseHeader().getResult())) {
							if ("N".equals(idpReceiverM.getResponseBody().getIs_email_approved())) {
								SessionUtil.setAnySession(getRequest(), "is_email_approved", "N");
							}
						}
					}
				}
				// 성공인 경우를 제외하고 모두 chkJoinFamilySiteAjax에서 체크(성공일 경우만 진입)
			}

			if ("fail".equals(returnResult))
				loginFailURL = "/user/loginImF. ?loginResultMsg=" + loginResultMsg + "&loginResult=" + loginResult;
			if (null != loginRedirectURL && !loginRedirectURL.equals(""))
				loginFailURL = loginFailURL + "&loginRedirectURL=" + URLEncoder.encode(loginRedirectURL);
			CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
			if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
				checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
			}

			if ("PRE_ USE_STOP".equals(loginResultMsg)) { // 기존 IDP회원 잠금상태일경우 인증코드 넣고 로그인
				idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
				imgSign = idpReceiverM.getResponseBody().getImage_sign();
				signData = idpReceiverM.getResponseBody().getSign_data();
				resultText = idpReceiverM.getResponseHeader().getResult_text();
				imgUrl = idpReceiverM.getResponseBody().getImage_url();

				checkPwdInfo.setUserId(user_id);
				checkPwdInfo.setErrorCount(6);
				SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo); // 세션이 없어진 이후에도 로그인시 자동가입방지
																							// 받도록
			}

			if (checkPwdInfo.getErrorCount() > 5) {
				loginFailURL = loginFailURL + "&imgSign=" + URLEncoder.encode(imgSign) + "&signData="
						+ URLEncoder.encode(signData) + "&imgUrl=" + URLEncoder.encode(imgUrl);
			}
			log.info(" ===================== loginFailURL : " + loginFailURL);
			log.info(" ===================== getLogin end time == [" + DateUtil.getShortTimeStampString()
					+ "] ==============");
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			StatisticsLogUtil.writeLog(getRequest());
		}

		return returnResult;
	}

	/**
	 * 통합 회원 로그인
	 * <P/>
	 * id,pwd / mdn을 입력 받아 로그인 처리 한다.
	 * 
	 * @return
	 */
	public String getOneIdLogin() {
		log.info(" ===================== getOneIdLogin start time == [" + DateUtil.getShortTimeStampString()
				+ "] ===================== ");
		String returnResult = "fail";
		try {
			if (gnbLoginRedirectURL != null && !gnbLoginRedirectURL.equals("")) {
				loginRedirectURL = gnbLoginRedirectURL;
			}

			if (user_id != null) {
				if (null == getRequest().getParameter("imsso") || "".equals(getRequest().getParameter("imsso"))) {
					imIdpReceiverM = ImIDPManager.getInstance().authForId(user_id, password);
				} else {
					imIdpReceiverM = ImIDPManager.getInstance().authForSvcNo(im_int_svc_no);
				}
				result = imIdpReceiverM.getResponseHeader().getResult();

				Enumeration enums = null;
				enums = getRequest().getParameterNames();
				String requestName = "";
				log.info("========== IDP LOGIN Reqest Variable Names START ==============================");
				while (enums.hasMoreElements()) {
					requestName = (String) enums.nextElement();
					log.info("names :" + requestName + ", value : " + getRequest().getParameter(requestName));
				}
				log.info("========== IDP LOGIN Reqest Variable Names END==============================");
				log.info("========== IM IDP LOGIN RESUT : " + result);
				// 결과가 성공일 경우
				if (ImIDPConstants.IDP_RES_CODE_OK.equals(result)) {
					user_id = imIdpReceiverM.getResponseBody().getUser_id();
					im_int_svc_no = imIdpReceiverM.getResponseBody().getIm_int_svc_no();
					user_auth_key = imIdpReceiverM.getResponseBody().getUser_auth_key();
					user_key = imIdpReceiverM.getResponseBody().getUser_key();

					String login_status_code = getRequest().getParameter("login_status_code") == null ? "" : getRequest()
							.getParameter("login_status_code");
					String login_limit_sst_code = getRequest().getParameter("login_limit_sst_code") == null ? "" : getRequest()
							.getParameter("login_limit_sst_code");
					if (Constants.SSO_SST_CD_ WEB.equals(login_limit_sst_code) && "20".equals(login_status_code)) {
						// returnResult = "fail";
						// loginResultMsg = "IM_ USE_STOP";
						//
						// CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
						// if(SessionUtil.getAnySession(getRequest(),"CHECK_PWD_SESSION") != null){
						// checkPwdInfo = (CheckPwdInfo)SessionUtil.getAnySession(getRequest(),"CHECK_PWD_SESSION");
						//
						// }
						//
						// if("IM_ USE_STOP".equals(loginResultMsg)){ //통합 회원 잠금상태일경우 인증코드 넣고 로그인
						// try{
						// idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
						// imgSign = idpReceiverM.getResponseBody().getImage_sign();
						// signData = idpReceiverM.getResponseBody().getSign_data();
						// resultText = idpReceiverM.getResponseHeader().getResult_text();
						// imgUrl = idpReceiverM.getResponseBody().getImage_url();
						// }catch(Exception e){
						// idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
						// imgSign = idpReceiverM.getResponseBody().getImage_sign();
						// signData = idpReceiverM.getResponseBody().getSign_data();
						// resultText = idpReceiverM.getResponseHeader().getResult_text();
						// imgUrl = idpReceiverM.getResponseBody().getImage_url();
						// }
						//
						// if(SessionUtil.getAnySession(getRequest(),"CHECK_PWD_SESSION") == null){
						// checkPwdInfo.setUserId(user_id);
						// checkPwdInfo.setErrorCount(6);
						// SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo); //세션이 없어진 이후에도
						// 로그인시 자동가입방지 받도록
						// }
						// }
						// 없어도 되는것인지 확인 필요
					} else {

						imIdpReceiverM = ImIDPManager.getInstance().userInfoIdpSearchServer(im_int_svc_no);
						log.info("imIdpReceiverM.getResponseHeader().getResult() ::: userInfoSearchServer "
								+ imIdpReceiverM.getResponseHeader().getResult());
						if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())
								&& user_id.equals(imIdpReceiverM.getResponseBody().getUser_id()) // 20120830 변조 방지 처리
								&& user_key.equals(imIdpReceiverM.getResponseBody().getUser_key())
								&& im_int_svc_no.equals(imIdpReceiverM.getResponseBody().getIm_int_svc_no())) {

							// member = memberService.selectMemberByMbrNo(user_key);
							member = memberService.selectMemberByImSvcNo(im_int_svc_no);
							if (member == null) {
								/**   DB에 회원 데이터가 없는경우 **/
								log.info("IDP :: 가입상태,    :: 데이터 존재하지 않음");
								returnResult = "fail";
								loginResultMsg = "NO_MEMBER_ ";
							} else if (member.getMbrStatCd().equals("US000502")) {
								/** EAMIL 인증후에도   DB에는 가입완료처리되지 않은경우 **/
								log.info("IDP :: 가입완료,    :: 가가입상태");
								returnResult = "fail";
								loginResultMsg = "NOT_C LETE_ ";
							} else if (member.getMbrStatCd().equals("US000505")) { // DB만 탈퇴 처리되어 로그인 되는 경우 막음
																				   // 2012.02.10
								log.info("IDP 정상, DB 탈퇴 회원 ");
								returnResult = "fail";
								loginResultMsg = "NO_MEMBER_ ";
							} else {
								member.setIm_int_svc_no(im_int_svc_no);
								member.setUser_auth_key(user_auth_key);
								member.setUser_key(user_key);
								member.setUser_tn(member.getMdnNo());

								String tn_auth = imIdpReceiverM.getResponseBody().getIs_user_tn_auth();
								if (null == tn_auth || "".equals(tn_auth))
									tn_auth = "N";
								member.setIs_user_tn_auth(tn_auth);

								String tn_own = imIdpReceiverM.getResponseBody().getIs_user_tn_own();
								if (null == tn_own || "".equals(tn_own))
									tn_own = "N";
								member.setIs_user_tn_own(tn_own);

								member.setUser_tn_type(imIdpReceiverM.getResponseBody().getUser_tn_type());
								member.setUser_tn_nation_cd(imIdpReceiverM.getResponseBody().getUser_tn_nation_cd());

								String email_auth = imIdpReceiverM.getResponseBody().getIs_email_auth();
								if (null == email_auth || "".equals(email_auth))
									email_auth = "N";
								member.setIs_email_auth(email_auth); // 회원정보 수정시 필요

								String rname_auth = imIdpReceiverM.getResponseBody().getIs_rname_auth();
								if (null == rname_auth || "".equals(rname_auth))
									rname_auth = "N";
								member.setIm_realNmAuthYn(rname_auth);

								memberService.insertLoginInfo(member.getMbrNo(), getRequest());

								// 임시 비번인 경우 alert처리
								if ("2".equals(imIdpReceiverM.getResponseBody().getUser_passwd_type()))
									SessionUtil.setAnySession(getRequest(), "tempPwd", "Y");

								List<MemberHp> myHpList = memberHpService.selectHpByMbrNo(user_key);
								if (myHpList != null) {
									if (member.getMobileCnt() != myHpList.size()) {
										Member updateStat = new Member();
										updateStat.setMbrNo(user_key);
										updateStat.setMobileCnt(myHpList.size());
										consumerService.updateConsumer(updateStat);
										member.setMobileCnt(myHpList.size());
									}
								}

								// 세션을 생성한다.
								SessionUtil.setMemberSession(getRequest(), member);
								// 통계를 위한 쿠키 생성
								SessionCheckFilter.setLID(getRequest(), getResponse(),
										CipherAES.encrypt(member.getMbrNo()));

								representPhone = topService.getRepresentPhone(member.getMbrNo());
								if (representPhone != null) {
									if (multiService.getPhoneCheck(representPhone.getPhoneModelCd())) {
										representPhone.setMultiPhoneYn("Y");
									} else {
										representPhone.setMultiPhoneYn("N");
									}
									SessionUtil.setAnySession(getRequest(), "REP_HP_SESSION", representPhone);
								} else {
									SessionUtil.removeAnySession(getRequest(), "REP_HP_SESSION");
								}

								if (representPhone != null) {
									if (!CommonUtil.isSupportPhone(representPhone.getPhoneModelCd())) {
										SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
									} else {
										SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "MYPHONE");
									}
								} else {
									SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
								}
								SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION");
								if (loginRedirectURL != null && !loginRedirectURL.equals("")) {
									redirectActionURL = loginRedirectURL;
									if (redirectActionParam != null && !redirectActionParam.equals("")) {
										redirectActionURL += redirectActionParam;
									}
									returnResult = "loginRedirect";
								} else {
									returnResult = "success";
									if ("Y".equals(getRequest().getParameter("imsso")))
										returnResult = "ssoSuccess";
									anotherJoinCk = "6";
								}
							}
						}
					}

				} else if (ImIDPConstants.IDP_RES_CODE_WRONG_PASSWD.equals(result)) { // 비밀번호 5, 10회 입력 오류 체크

					int pwdErrorCount = 0;

					CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
					if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
						checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
					}

					if (checkPwdInfo.getUserId() != null) {
						if (checkPwdInfo.getUserId().equals(user_id)) {
							pwdErrorCount = checkPwdInfo.getErrorCount();
						}
					}
					pwdErrorCount = pwdErrorCount + 1;
					checkPwdInfo.setUserId(user_id);
					checkPwdInfo.setErrorCount(pwdErrorCount);
					SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo);
					if (pwdErrorCount > 5) {
						loginResultMsg = "IM_ USE_STOP";
						try {
							idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
							imgSign = idpReceiverM.getResponseBody().getImage_sign();
							signData = idpReceiverM.getResponseBody().getSign_data();
							resultText = idpReceiverM.getResponseHeader().getResult_text();
							imgUrl = idpReceiverM.getResponseBody().getImage_url();
						} catch (Exception e) {
							idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
							imgSign = idpReceiverM.getResponseBody().getImage_sign();
							signData = idpReceiverM.getResponseBody().getSign_data();
							resultText = idpReceiverM.getResponseHeader().getResult_text();
							imgUrl = idpReceiverM.getResponseBody().getImage_url();
						}
					}

					if (pwdErrorCount == 6) {
						imIdpReceiverM = ImIDPManager.getInstance().setLoginStatus(user_id, "20");
						if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
							log.info("user loginStatus stop");
						}
					} else if (pwdErrorCount == 11) {
						String imSvcNo = signService.getImSvcNo(user_id);
						log.info("imSvcNo : " + imSvcNo);

						if (null != imSvcNo && !"".equals(imSvcNo)) {// 통합아이디 사용자인 경우
							imIdpReceiverM = ImIDPManager.getInstance().userInfoIdpSearchServer(imSvcNo);
							if (ImIDPConstants.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
								HashMap hm = new HashMap();
								hm.put("key", imSvcNo);
								hm.put("user_tn", imIdpReceiverM.getResponseBody().getUser_tn());

								String tn_auth = imIdpReceiverM.getResponseBody().getIs_user_tn_auth();
								if (null == tn_auth || "".equals(tn_auth))
									tn_auth = "N";
								hm.put("user_tn_auth", tn_auth);

								hm.put("user_email", imIdpReceiverM.getResponseBody().getUser_email());

								String email_auth = imIdpReceiverM.getResponseBody().getIs_email_auth();
								if (null == email_auth || "".equals(email_auth))
									email_auth = "N";
								hm.put("is_email_auth", email_auth);
								imIdpReceiverM = ImIDPManager.getInstance().resetPwd(hm);// 임시 비번 발급처리
								if (ImIDPConstants.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader()
										.getResult())) {
									log.info("reset password Imserver send mail or sms");
								}
							}
						}
					} else { // 나머지 비번 틀린경우
						loginResultMsg = "PASSWORD_WRONG";
					}
					returnResult = "fail";
				} else if (ImIDPConstants.IDP_RES_CODE_INVALID_USER_INFO.equals(result)) { // 가가입 상태일 때
					StringBuffer sb = new StringBuffer();
					sb.append("");
					StringTokenizer st = null;
					String spList = join_sst_list;
					if (null != spList) {
						st = new StringTokenizer(spList, ",");
						sb.append(st.nextToken());
					}
					log.info("가가입한 사이트 : " + sb.toString()); // 가가입시 처리 할 팝업 두가지( 용, 타사이트용) SB p53

					if (sb.toString().indexOf(Constants.SSO_SST_CD_ WEB) == -1
							&& sb.toString().indexOf("90000") == -1) {
						loginResultMsg = "OTHER_WAIT_MEMBER";
						if (Constants.SSO_SST_CD_11ST_WEB.equals(sb.toString().trim())) {
							sp_id = Constants.SSO_SST_11ST;
							sp_url = "http://www.11st.co.kr";
						} else if (Constants.SSO_SST_CD_CYWORLD_WEB.equals(sb.toString().trim())) {
							sp_id = Constants.SSO_SST_CYWORLD;
							sp_url = "http://www.nate.com";
						} else if (Constants.SSO_SST_CD_MELON_WEB.equals(sb.toString().trim())) {
							sp_id = Constants.SSO_SST_MELON;
							sp_url = "http://www.melon.com";
						} else if (Constants.SSO_SST_CD_NATE_WEB.equals(sb.toString().trim())) {
							sp_id = Constants.SSO_SST_NATE;
							sp_url = "http://www.nate.com";
						} else if (Constants.SSO_SST_CD_TCLOUD_WEB.equals(sb.toString().trim())) {
							sp_id = Constants.SSO_SST_TCLOUD;
							sp_url = "http://www.tcloud.co.kr";
						} else if (Constants.SSO_SST_CD_TMAP_WEB.equals(sb.toString().trim())) {
							sp_id = Constants.SSO_SST_TMAP;
							sp_url = "http://tmap.tworld.co.kr";
						} else if (Constants.SSO_SST_CD_ WEB.equals(sb.toString().trim())) {
							sp_id = Constants.SSO_SST_TSTORE;
							sp_url = "http://www.tstore.co.kr";
						} else if (Constants.SSO_SST_CD_IM_DEV_CENTER.equals(sb.toString().trim())) {
							sp_id = Constants.sSO_SST_DEVCENTER;
							sp_url = "http://developers.skplanetx.com";
						} else if (Constants.SSO_SST_CD_CONTEXT_PORTAL.equals(sb.toString().trim())) {
							sp_id = Constants.SSO_SST_C_PORTAL;
							sp_url = "";
						} else if (Constants.SSO_SST_CD_NOP.equals(sb.toString().trim())) {
							sp_id = Constants.SSO_SST_NOP;
							sp_url = "http://platform.smarttouch.com";
						}
						returnResult = "failToMain";
					} else {
						loginResultMsg = " WAIT_MEMBER";
						returnResult = "failToMain";
					}

				} else if (ImIDPConstants.IDP_RES_CODE_UNAUTHORIZED_USER.equals(result)) { // 미등록 사용자
					returnResult = "fail";
					loginResultMsg = "FAIL";
				} else if (ImIDPConstants.IDP_RES_CODE_LOGIN_RESTRICT.equals(result)) { // 로그인 제한 상태
					returnResult = "fail";
					loginResultMsg = "IM_ USE_STOP";

					CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
					if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
						checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");

					}

					if ("IM_ USE_STOP".equals(loginResultMsg)) { // 통합 회원 잠금상태일경우 인증코드 넣고 로그인
						try {
							idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
							imgSign = idpReceiverM.getResponseBody().getImage_sign();
							signData = idpReceiverM.getResponseBody().getSign_data();
							resultText = idpReceiverM.getResponseHeader().getResult_text();
							imgUrl = idpReceiverM.getResponseBody().getImage_url();
						} catch (Exception e) {
							idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
							imgSign = idpReceiverM.getResponseBody().getImage_sign();
							signData = idpReceiverM.getResponseBody().getSign_data();
							resultText = idpReceiverM.getResponseHeader().getResult_text();
							imgUrl = idpReceiverM.getResponseBody().getImage_url();
						}

						checkPwdInfo.setUserId(user_id);
						checkPwdInfo.setErrorCount(6);
						SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo); // 세션이 없어진 이후에도 로그인시
																									// 자동가입방지 받도록
					}
				} else {
					returnResult = "fail";
					loginResultMsg = "FAIL";
				}

				// 5회이상 실패시 자동가입방지 처리
				if ("fail".equals(returnResult))
					loginFailURL = "/user/loginImF. ?loginResultMsg=" + loginResultMsg + "&loginResult="
							+ loginResult;
				if (null != loginRedirectURL && !loginRedirectURL.equals(""))
					loginFailURL = loginFailURL + "&loginRedirectURL=" + URLEncoder.encode(loginRedirectURL);
				CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
				if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
					checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
					if (checkPwdInfo.getErrorCount() > 5) {
						loginResultMsg = "IM_ USE_STOP";
						loginFailURL = loginFailURL + "&imgSign=" + URLEncoder.encode(imgSign) + "&signData="
								+ URLEncoder.encode(signData) + "&imgUrl=" + URLEncoder.encode(imgUrl);
					}
				}
				log.info(" ===================== loginFailURL : " + loginFailURL);
			}

			// 타사이트 LOCK 경우 처리
			String otherLock = getRequest().getParameter("otherLock");
			if (null != otherLock && !"".equals(otherLock)) {
				CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
				checkPwdInfo.setUserId(user_id);
				checkPwdInfo.setErrorCount(6);
				SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo); // 세션이 없어진 이후에도 로그인시 자동가입방지
																							// 받도록

				if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
					checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
					if (checkPwdInfo.getErrorCount() > 5) {
						try {
							idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
							imgSign = idpReceiverM.getResponseBody().getImage_sign();
							signData = idpReceiverM.getResponseBody().getSign_data();
							resultText = idpReceiverM.getResponseHeader().getResult_text();
							imgUrl = idpReceiverM.getResponseBody().getImage_url();
						} catch (Exception e) {
							idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
							imgSign = idpReceiverM.getResponseBody().getImage_sign();
							signData = idpReceiverM.getResponseBody().getSign_data();
							resultText = idpReceiverM.getResponseHeader().getResult_text();
							imgUrl = idpReceiverM.getResponseBody().getImage_url();
						}

						loginResultMsg = "";
						loginFailURL = "/user/loginImF. ?loginResultMsg=IM_ USE_STOP&loginResult=0&imgSign="
								+ URLEncoder.encode(imgSign) + "&signData=" + URLEncoder.encode(signData) + "&imgUrl="
								+ URLEncoder.encode(imgUrl);
					}
				}
				log.info(" ===================== loginFailURL : " + loginFailURL);
			}

			log.info(" ===================== getOneIdLogin end time == [" + DateUtil.getShortTimeStampString()
					+ "] ==============");
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			StatisticsLogUtil.writeLog(getRequest());
		}
		return returnResult;
	}

	public String idpHiddenSubmit() {
		HttpServletRequest request = getRequest();
		member = (Member) SessionUtil.getMemberSession(getRequest());
		String cmd = request.getParameter("cmd") == null ? "" : request.getParameter("cmd");

		if (cmd.equals("TXUpdateUserPwdIDP")) { // 패스워드 변경(통합회원)
			if (member == null || (member != null && !member.getIm_int_svc_no().equals(request.getParameter("key")))) {
				result = "fail";
			} else {
				redirectActionURL = com. .commons.idp.im.ImIDPManager.IDP_REQUEST_URL_HTTPS + "/web/IMModify.api";
			}

		} else if (cmd.equals("modifyAuthInfo")) { // 패스워드/이메일 변경(기존회원)
			user_id = request.getParameter("user_id") == null ? "" : request.getParameter("user_id"); // 패스워드
			if ("".equals(user_id))
				user_id = request.getParameter("mbrId") == null ? "" : request.getParameter("mbrId"); // 이메일

			if (member == null || (member != null && !member.getMbrId().equals(user_id))) {
				result = "fail";
			} else {
				redirectActionURL = "https://" + com. .commons.util.config.Constants. _IDP_HOSTNAME
						+ "/web/Modify.api";
			}

		} else if (cmd.equals("authForPasswd")) { // 패스워드 인증 후 이동(기존IDP 마이페이지 진입시:MypageIdentification.jsp)
			if (member == null || (member != null && !member.getMbrId().equals(request.getParameter("user_id")))) {
				result = "fail";
			} else {
				redirectActionURL = "https://" + com. .commons.util.config.Constants. _IDP_HOSTNAME
						+ "/web/Auth.api";
			}
		} else if (cmd.equals("authIntegratedSPPW")) { // 패스워드 인증 후 이동(통합IDP:MypageIdentification.jsp)
			if (member == null || (member != null && !member.getMbrId().equals(request.getParameter("user_id")))) {
				result = "fail";
			} else {
				redirectActionURL = com. .commons.idp.im.ImIDPManager.IDP_REQUEST_URL_HTTPS
						+ "/web/IntegrationAuth.api";
			}
		} else if (cmd.equals("TXUpdateUserInfoIDP")) { // 이메일 변경(통합회원)
			if (member == null || (member != null && !member.getMbrId().equals(request.getParameter("mbrId")))) {
				result = "fail";
			} else {
				redirectActionURL = com. .commons.idp.im.ImIDPManager.IDP_REQUEST_URL_HTTPS + "/web/IMModify.api";
			}
		}

		return SUCCESS;
	}

	public String ssoLoginCheckAjax() {
		log.info("ssoLoginCheckAjax start()");
		PrintWriter writer = null;

		try {
			JSONObject jsonObject = new JSONObject();
			HttpServletRequest request = getRequest();
			HttpServletResponse response = getResponse();
			jsonObject.put("resultCode", "N");

			// Member member = (Member)SessionUtil.getMemberSession(getRequest());
			// if(null == member){ //세션이 없는 경우에만 SSO처리
			String j_sso_q = request.getParameter("j_sso_q") == null ? "" : request.getParameter("j_sso_q");
			log.info("####################### get j_sso_q : " + j_sso_q);
			String responseMessage = SSOManager.getSSOMemberInfoByKey(j_sso_q);
			log.info("####################### get responseMessage : " + responseMessage);
			if (SSOManager.isSuccess(responseMessage)) {
				log.info("####################### success responseMessage");
				// 통합회원 서비스 번호
				String im_int_svc_no = SSOManager.getResponseData(responseMessage);
				log.info("####################### get im_int_svc_no : " + im_int_svc_no);
				if (null != im_int_svc_no && !"".equals(im_int_svc_no)) { // 조회 된 경우
					imIdpReceiverM = ImIDPManager.getInstance().authForSvcNo(im_int_svc_no); // IDP SSO 로그인
					log.info("imIdpReceiverM.getResponseHeader().getResult() ::: userInfoSearchServer "
							+ imIdpReceiverM.getResponseHeader().getResult());
					if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) { // 성공인 경우
																											   // DB
																											   // 데이터를
																											   // 이용 멤버
																											   // 세션 생성
						member = memberService.selectMemberByImSvcNo(im_int_svc_no);
						// member = memberService.selectMember(imIdpReceiverM.getResponseBody().getUser_id(), null);
						// 가능하면 통합서비스 관리 번호로 가져오도록 수정
						// member = memberService.selectMemberByMbrNo(imIdpReceiverM.getResponseBody().getUser_key());
						if (null != member) { // 회원정보가 있는 경우만 처리
							member.setIm_int_svc_no(im_int_svc_no);
							member.setUser_auth_key(imIdpReceiverM.getResponseBody().getUser_auth_key());
							member.setUser_key(imIdpReceiverM.getResponseBody().getUser_key());
							member.setUser_tn(member.getMdnNo());

							String tn_auth = imIdpReceiverM.getResponseBody().getIs_user_tn_auth();
							if (null == tn_auth || "".equals(tn_auth))
								tn_auth = "N";
							member.setIs_user_tn_auth(tn_auth);

							String tn_own = imIdpReceiverM.getResponseBody().getIs_user_tn_own();
							if (null == tn_own || "".equals(tn_own))
								tn_own = "N";
							member.setIs_user_tn_own(tn_own);

							member.setUser_tn_type(imIdpReceiverM.getResponseBody().getUser_tn_type());
							member.setUser_tn_nation_cd(imIdpReceiverM.getResponseBody().getUser_tn_nation_cd());

							String email_auth = imIdpReceiverM.getResponseBody().getIs_email_auth();
							if (null == email_auth || "".equals(email_auth))
								email_auth = "N";
							member.setIs_email_auth(email_auth); // 회원정보 수정시 필요

							String rname_auth = imIdpReceiverM.getResponseBody().getIs_rname_auth();
							if (null == rname_auth || "".equals(rname_auth))
								rname_auth = "N";
							member.setIm_realNmAuthYn(rname_auth);

							memberService.insertLoginInfo(member.getMbrNo(), getRequest());

							List<MemberHp> myHpList = memberHpService.selectHpByMbrNo(member.getUser_key());
							if (myHpList != null) {
								if (member.getMobileCnt() != myHpList.size()) {
									Member updateStat = new Member();
									updateStat.setMbrNo(member.getUser_key());
									updateStat.setMobileCnt(myHpList.size());
									consumerService.updateConsumer(updateStat);
									member.setMobileCnt(myHpList.size());
								}
							}

							// 세션을 생성한다.
							SessionUtil.setMemberSession(getRequest(), member);
							// 통계를 위한 쿠키 생성
							SessionCheckFilter
									.setLID(getRequest(), getResponse(), CipherAES.encrypt(member.getMbrNo()));

							representPhone = topService.getRepresentPhone(member.getMbrNo());
							if (representPhone != null) {
								if (multiService.getPhoneCheck(representPhone.getPhoneModelCd())) {
									representPhone.setMultiPhoneYn("Y");
								} else {
									representPhone.setMultiPhoneYn("N");
								}
								SessionUtil.setAnySession(getRequest(), "REP_HP_SESSION", representPhone);
							} else {
								SessionUtil.removeAnySession(getRequest(), "REP_HP_SESSION");
							}

							if (representPhone != null) {
								if (!CommonUtil.isSupportPhone(representPhone.getPhoneModelCd())) {
									SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
								} else {
									SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "MYPHONE");
								}
							} else {
								SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
							}
							SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION");

							jsonObject.put("resultCode", "Y");
						}
					}
				} else {
					log.info("####################### get im_int_svc_no fail ");
				}
			} else {
				log.info("####################### fail responseMessage");
			}
			// }

			writer = response.getWriter();
			writer.write(jsonObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
		return SUCCESS;
	}

	public String ssoLoginGetImSvcNo() {
		log.info("ssoLoginGetImSvcNo start()");
		PrintWriter writer = null;

		try {
			JSONObject jsonObject = new JSONObject();
			HttpServletRequest request = getRequest();
			HttpServletResponse response = getResponse();
			jsonObject.put("resultCode", "N");

			String j_sso_q = request.getParameter("j_sso_q") == null ? "" : request.getParameter("j_sso_q");
			log.info("####################### get j_sso_q : " + j_sso_q);
			String responseMessage = SSOManager.getSSOMemberInfoByKey(j_sso_q);
			log.info("####################### get responseMessage : " + responseMessage);
			if (SSOManager.isSuccess(responseMessage)) {
				log.info("####################### success responseMessage");
				// 통합회원 서비스 번호
				String im_int_svc_no = SSOManager.getResponseData(responseMessage);
				log.info("####################### get im_int_svc_no : " + im_int_svc_no);
				jsonObject.put("im_int_svc_no", im_int_svc_no);
				jsonObject.put("resultCode", "Y");
			}
			writer = response.getWriter();
			writer.write(jsonObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
		return SUCCESS;
	}

	public String chkJoinFamilySiteAjax() {

		log.debug("chkJoinFamilySiteAjax start()");
		PrintWriter writer = null;
		String resultCode = "";

		try {
			JSONObject jsonObject = new JSONObject();
			HttpServletRequest request = getRequest();
			HttpServletResponse response = getResponse();

			String userId = getRequest().getParameter("rep_hp") == null ? "" : Base64.decode(getRequest().getParameter(
					"rep_hp"));
			String userPwd = getRequest().getParameter("biz_nm") == null ? "" : Base64.decode(getRequest()
					.getParameter("biz_nm"));

			idpReceiverM = IDPManager.getInstance().authPwd(userId, userPwd);

			String result = idpReceiverM.getResponseHeader().getResult();
			String familyName = "";

			int chMeb = -1;
			if (result != null) {
				chMeb = Integer.parseInt(result);
			}

			if (chMeb == 1000) { // 정상인 경우 메인 팝업 비로그인
				resultCode = "NODATA";
				member = memberService.selectMember(userId, null);
				if (member != null) {
					if ("US000502".equals(member.getMbrStatCd())) { // authPwd로 가가입 상태 체크 불가 성공인 경우 DB 상태로 체크 - 가가입자 체크
						// 계정 인증 후 이메일재발송 팝업에서는 인증절차 생략 무조건 재발송 처리
						idpReceiverM = IDPManager.getInstance().userAuthForId(userId, userPwd);
						if (IDPManager.IDP_RES_CODE_INVALID_USER_INFO.equals(idpReceiverM.getResponseHeader()
								.getResult())
								|| IDPManager.IDP_RES_CODE_OK.equals(idpReceiverM.getResponseHeader().getResult())) {
							if (!"US000202".equals(member.getMbrCatCd())) {
								loginResultMsg = "DEV_POC_WAIT_MEMBER";
							}
							resultCode = "PRE_ MEMBER";
						}

					} else if ("US000503".equals(member.getMbrStatCd())) {
						if (!"US000202".equals(member.getMbrCatCd())) {
							resultCode = "DEV_POC_MEMBER";
						} else {
							resultCode = "JOIN_ MEMBER";
						}
					} else if ("US000504".equals(member.getMbrStatCd())) {
						resultCode = "PRE_ USE_STOP";
					}
				}
			} else if (chMeb == 2201) {// 로그인 처리 비번 틀림
				resultCode = "INVAID_PASSWD";

				user_id = userId;
				int pwdErrorCount = 0;

				CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
				if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
					checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
				}

				if (checkPwdInfo.getUserId() != null) {
					if (checkPwdInfo.getUserId().equals(user_id)) {
						pwdErrorCount = checkPwdInfo.getErrorCount();
					}
				}
				pwdErrorCount = pwdErrorCount + 1;
				checkPwdInfo.setUserId(user_id);
				checkPwdInfo.setErrorCount(pwdErrorCount);
				SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo);

				member = memberService.selectMember(user_id, null);
				if (member != null) {
					if ("US000504".equals(member.getMbrStatCd())) { // 일시 정지 상태 (로그인 5회이상 실패로 잠김시 로그인시 인증코드 추가처리
						log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>PRE_ USE_STOP");
						resultCode = "PRE_ USE_STOP";
					}
				}

				if (pwdErrorCount > 5) {
					idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
					imgSign = idpReceiverM.getResponseBody().getImage_sign();
					signData = idpReceiverM.getResponseBody().getSign_data();
					resultText = idpReceiverM.getResponseHeader().getResult_text();
					imgUrl = idpReceiverM.getResponseBody().getImage_url();
				}

				if (pwdErrorCount == 6) { // 5회 이상 실패시 자체 일시 정지 상태로 변경
					Member updateStat = new Member();
					updateStat.setMbrNo(member.getMbrNo());
					updateStat.setMbrStatCd("US000504");
					consumerService.updateConsumer(updateStat);
					resultCode = "PRE_ USE_STOP";
				} else if (pwdErrorCount == 11) {
					HashMap pwdResultMap = new HashMap();

					String newPwd = null;
					idpReceiverM = IDPManager.getInstance().findPwd(IDPManager.IDP_PARAM_KEY_QUERY_PWD_KEY_TYPE_ID,
							user_id);
					if (IDPManager.IDP_RES_CODE_OK.equals(idpReceiverM.getResponseHeader().getResult())) {
						newPwd = idpReceiverM.getResponseBody().getTemp_passwd();
					}

					String receiverName = "";
					if (member.getMbrNm() != null && !member.getMbrNm().equals("")) {
						receiverName = member.getMbrId();
					} else {
						receiverName = member.getMbrId();
					}

					// ///////// 임시 비밀번호 발급 이메일 발송 ///////////////
					// 수신자 EMAIL
					RECEIVER = member.getEmailAddr();

					// eamil /비밀번호/이름 /가입일/현재날짜(yyyy.mm.dd)
					header = "http://" + Constants.USER_POC_IP + "/userpoc/images/mail" // 이미지 URL 경로.
							+ "," + "http://" + Constants.USER_POC_IP + "/userpoc" // linkPath
							+ "," + newPwd // 임시 비밀번호
							+ "," + user_id // 아이디
							+ "," + DateUtil.getAddDay(0, "yyyy-MM-dd"); // 현재날짜(yyyy.mm.dd)

					// ROWNUM,비밀번호
					contents = "";
					/*
					 * Email 발송..
					 */
					RESULT = sendPasswordMail(SENDER, RECEIVER, header, contents);
					// //////////// 임시 비밀번호 발송 끝 //////////////////////
				}
			} else {

				idpReceiverMoIDAuth = IDPManager.getInstance().otherChannelIdAuth(userId, userPwd);
				String oChResult = idpReceiverMoIDAuth.getResponseHeader().getResult();
				if (IDPManager.IDP_RES_CODE_OK.equals(oChResult)) {

					idpReceiverMoList = IDPManager.getInstance().otherChannelList("1", userId);
					String oChResult1 = idpReceiverMoList.getResponseHeader().getResult();
					if (IDPManager.IDP_RES_CODE_OK.equals(oChResult1)) {
						familyName = idpReceiverMoList.getResponseBody().getSp_list();
						StringBuffer sb = new StringBuffer();
						sb.append("");
						int i = 0;
						if (familyName != null) {
							StringTokenizer st = new StringTokenizer(familyName, "|");
							while (st.hasMoreTokens()) {
								String temp = st.nextToken().trim();
								StringTokenizer st1 = new StringTokenizer(temp, ",");
								if (st1.hasMoreTokens()) {
									String site = st1.nextToken();
									if (site.indexOf("GTP_") < 0) {
										if (i > 0) {
											sb.append(", ");
										}
										sb.append(site);
									}
								}
								i++;
							}
						}

						resultCode = sb.toString(); // 패밀리 사이트 가입자
						if ("".equals(resultCode))
							resultCode = "NODATA";
					} else {

						resultCode = "NODATA"; // 가입 가능
					}
				} else {

					resultCode = "NODATA"; // 가입 가능
				}
			}

			long cDate = Long.parseLong(DateUtil.getCurrentDate());

			//  기존 회원인 경우 탈퇴 처리를 위해 userAuthKey 생성
			if ("JOIN_MEMBER".equals(resultCode)) {
				idpReceiverM = IDPManager.getInstance().userAuthForId(userId, userPwd);
				SessionUtil.setAnySession(getRequest(), "id_auth_key", idpReceiverM.getResponseBody()
						.getUser_auth_key());
			}

			jsonObject.put("resultCode", resultCode);

			writer = response.getWriter();
			writer.write(jsonObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
			log.error("타 서비스 가입 체크중 에러가 발생하였습니다. " + e);
			// throw e;
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
		return SUCCESS;
	}

	/*
	 * 기존  회원 체크(이용동의 가입시 기존회원 통합 체크)
	 */
	public String chkJoinTstoreAjax() {

		log.info("chkJoinTstoreAjax start()");
		PrintWriter writer = null;
		String resultCode = "";

		try {
			JSONObject jsonObject = new JSONObject();
			HttpServletRequest request = getRequest();
			HttpServletResponse response = getResponse();

			String userId = getRequest().getParameter("user_id") == null ? "" : getRequest().getParameter("user_id");
			String userPwd = getRequest().getParameter("user_passwd") == null ? "" : getRequest().getParameter(
					"user_passwd");

			idpReceiverM = IDPManager.getInstance().authPwd(userId, userPwd);

			String result = idpReceiverM.getResponseHeader().getResult();

			int chMeb = -1;
			if (result != null) {
				chMeb = Integer.parseInt(result);
			}

			if (chMeb == 1000) { // 정상인 경우 메인 팝업 비로그인
				resultCode = "JOIN_MEMBER";
				member = memberService.selectMember(userId, null);
				if (member != null) {
					if ("US000502".equals(member.getMbrStatCd())) { // authPwd로 가가입 상태 체크 불가 성공인 경우 DB 상태로 체크 - 가가입자 체크
						// 계정 인증 후 이메일재발송 팝업에서는 인증절차 생략 무조건 재발송 처리
						idpReceiverM = IDPManager.getInstance().userAuthForId(userId, userPwd);
						if (IDPManager.IDP_RES_CODE_INVALID_USER_INFO.equals(idpReceiverM.getResponseHeader()
								.getResult())
								|| IDPManager.IDP_RES_CODE_OK.equals(idpReceiverM.getResponseHeader().getResult())) {
							if (!"US000202".equals(member.getMbrCatCd())) {
								loginResultMsg = "DEV_POC_WAIT_MEMBER";
							}
							resultCode = "PRE_ MEMBER";
						}

					} else if ("US000503".equals(member.getMbrStatCd())) {
						if ("US000504".equals(member.getMbrStatCd())) { // 일시 정지 상태 (로그인 5회이상 실패로 잠김시 로그인시 인증코드 추가처리
							resultCode = "PRE_ USE_STOP";
						}
						if (!"US000202".equals(member.getMbrCatCd())) {
							resultCode = "DEV_POC_MEMBER";
						}
					}
				}
			} else if (chMeb == 2201) {// 로그인 처리 비번 틀림
				resultCode = "INVAID_PASSWD";
				member = memberService.selectMember(user_id, null);
				if (member != null) {
					if ("US000504".equals(member.getMbrStatCd())) { // 일시 정지 상태 (로그인 5회이상 실패로 잠김시 로그인시 인증코드 추가처리
						log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>PRE_ USE_STOP");
						resultCode = "PRE_ USE_STOP";
					}
				}
			}

			//   기존 회원인 경우 탈퇴 처리를 위해 userAuthKey 생성
			if ("JOIN_ MEMBER".equals(resultCode)) {
				idpReceiverM = IDPManager.getInstance().userAuthForId(userId, userPwd);
				SessionUtil.setAnySession(getRequest(), " id_auth_key", idpReceiverM.getResponseBody()
						.getUser_auth_key());
			}
			jsonObject.put("resultCode", resultCode);
			writer = response.getWriter();
			writer.write(jsonObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
		return SUCCESS;
	}

	public String newLogin() {
		log.info("newLogin start()");
		String resultCode = "IDP";
		String doubleChk = "N";
		String tId = "N";
		try {
			if (user_id.indexOf("@nate.com") > -1)
				user_id = user_id.substring(0, user_id.indexOf("@"));

			// 통합 아이디 가입자 확인
			imIdpReceiverM = ImIDPManager.getInstance().findJoinServiceList(user_id);
			if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
				String imSvcNo = imIdpReceiverM.getResponseBody().getIm_int_svc_no();
				String spList = imIdpReceiverM.getResponseBody().getSp_list();

				if (spList.indexOf(Constants.SSO_SST_CD_ WEB) == -1 && spList.indexOf(",") > -1) {// 리턴 리스트 중에 T
																										// Store가 없고
																										// 타사이트 정보가 있으면
																										// 이용동의 가입

					// 미동의 가입자 동일인확인 절차 : 아이디 패스워드 인증 IM 연동
					String imResult = jwork.sso.agent.SSOManager.authDisagreeMember(user_id,
							CipherAES.getSHA256(password));
					log.info(imResult);
					String imValue[] = imResult.split("\\|");
					String imCode = imValue[0];

					// 이용동의 가입자 세션 정보
					int pwdErrorCount = 0;
					CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
					if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
						checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
					}

					if ("S001".equals(imCode)) { // IM 연동 성공시
						if (null != checkPwdInfo)
							SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION"); // 세션 초기화

						String imLoginStatus = jwork.cipher.client.JworkCrypto.decrypt(imValue[2].getBytes());
						log.info("imLoginStatus : " + imLoginStatus);
						if ("null".equals(imLoginStatus) || "10".equals(imLoginStatus)) {// 정상
							resultCode = "NA";
							// imSvcNo; //전환시 이용동의가입자 체크후 이용동의 가입시
							// 필요-----------------------------------------------------------------------------------
						} else { // 로그인 제한상태
							resultCode = "NA_LU";
						}
					} else { // 비번 틀린경우나 연동 실패(미동의 사용자 5회 실패시 LOCK 설정)
						resultCode = "NAF";

						if (checkPwdInfo.getUserId() != null) {
							if (checkPwdInfo.getUserId().equals(user_id)) {
								pwdErrorCount = checkPwdInfo.getErrorCount();
							}
						}
						if ("N".equals(doubleChk)) {
							pwdErrorCount = pwdErrorCount + 1;
							checkPwdInfo.setUserId(user_id);
							checkPwdInfo.setErrorCount(pwdErrorCount);
							SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo);
							doubleChk = "Y";
						}

						if (pwdErrorCount == 6) {
							imIdpReceiverM = ImIDPManager.getInstance().setLoginStatus(user_id, "20");
							if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
								log.info("미동의 가입자 loginStatus stop");
							}
						}
						if (pwdErrorCount > 5)
							resultCode = "NA_LU";
					}

				} else if (spList.indexOf(Constants.SSO_SST_CD_ WEB) > -1) { //   가입된 아이디인 경우(DB체크 대신 사용)
					resultCode = "IM";
					tId = "Y";
				} else {
					resultCode = "IDP";
					tId = "Y";
				}
			}

			if ("N".equals(tId)) { //   계정이 아닌 경우에만 처리
				imIdpReceiverM = ImIDPManager.getInstance().checkIdStatusIdpIm(user_id);// 타사이트 가가입 체크
				if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
					Object im_user_status_cd = imIdpReceiverM.getResponseBody().getIm_user_status_cd();
					if (null != im_user_status_cd && !"".equals(im_user_status_cd)) {
						if ("11".equals(im_user_status_cd)) {
							// 계정 정보가 동일한 경우만 가가입 팝업
							String imResult = jwork.sso.agent.SSOManager.authDisagreeMember(user_id,
									CipherAES.getSHA256(password));
							log.info(imResult);
							String imValue[] = imResult.split("\\|");
							String imCode = imValue[0];

							// 가가입자 로그인 세션정보
							int pwdErrorCount = 0;
							CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
							if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
								checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(),
										"CHECK_PWD_SESSION");
							}

							if ("S001".equals(imCode)) { // IM 연동 성공시
								if (null != checkPwdInfo)
									SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION"); // 세션 초기화

								String imLoginStatus = jwork.cipher.client.JworkCrypto.decrypt(imValue[2].getBytes());
								log.info("imLoginStatus : " + imLoginStatus);
								if ("null".equals(imLoginStatus) || "10".equals(imLoginStatus)) {// 정상
									resultCode = "OT";
								} else { // 로그인 제한상태
									resultCode = "OT_LU";
								}
							} else { // 비번 틀린경우나 연동 실패(가승인자 5회 실패시 LOCK 설정)
								resultCode = "OTF";

								if (checkPwdInfo.getUserId() != null) {
									if (checkPwdInfo.getUserId().equals(user_id)) {
										pwdErrorCount = checkPwdInfo.getErrorCount();
									}
								}

								if ("N".equals(doubleChk)) {
									pwdErrorCount = pwdErrorCount + 1;
									checkPwdInfo.setUserId(user_id);
									checkPwdInfo.setErrorCount(pwdErrorCount);
									SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo);
									doubleChk = "Y";
								}

								if (pwdErrorCount == 6) {
									imIdpReceiverM = ImIDPManager.getInstance().setLoginStatus(user_id, "20");
									if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader()
											.getResult())) {
										log.info("가승인 가입자 loginStatus stop");
									}
								}
								if (pwdErrorCount > 5)
									resultCode = "OT_LU";
							}
						}
					}
				}
			}

			// 기존 IDP 계정인 경우 체크
			if ("IDP".equals(resultCode)) {
				log.info(" ===================== oldIdp new getLogin start time == ["
						+ DateUtil.getShortTimeStampString() + "] ===================== ");
				log.info("oldIdp new  getLogin_loginId : " + loginId);
				String returnResult = "fail";
				String familyName = "";
				if (gnbLoginRedirectURL != null && !gnbLoginRedirectURL.equals("")) {
					loginRedirectURL = gnbLoginRedirectURL;
				}

				if (loginId != null && (loginResultMsg == null || "".equals(loginResultMsg))) {
					idpReceiverM = IDPManager.getInstance().userAuthForId(loginId, password);
					result = idpReceiverM.getResponseHeader().getResult();

					loginResult = -1;
					if (result != null) {
						loginResult = Integer.parseInt(result);
					}

					Enumeration enums = null;
					enums = getRequest().getParameterNames();
					String requestName = "";
					log.info("========== IDP LOGIN Reqest Variable Names START ==============================");
					while (enums.hasMoreElements()) {
						requestName = (String) enums.nextElement();
						log.info("names :" + requestName + ", value : " + getRequest().getParameter(requestName));
					}
					log.info("========== IDP LOGIN Reqest Variable Names END==============================");

					// 결과가 성공일 경우
					if (loginResult == 1000) {
						user_key = idpReceiverM.getResponseBody().getUser_key();
						user_auth_key = idpReceiverM.getResponseBody().getUser_auth_key();

						member = memberService.selectMemberByMbrNo(user_key);
						// TODO 원래대로 user_key로 조회하게 적용해야 함~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~!!!!!!!
						log.info("[param] member 조회 member.getMbrCatCd() ="
								+ (member == null ? "null" : member.getMbrCatCd()));

						if (member == null) {
							/**   DB에 회원 데이터가 없는경우 **/
							log.info("IDP :: 가입상태,    :: 데이터 존재하지 않음");
							returnResult = "fail";
							loginResultMsg = "NO_MEMBER_ ";
						} else if (member.getMbrStatCd().equals("US000502")) {
							/** EAMIL 인증후에도   DB에는 가입완료처리되지 않은경우 **/

							log.info("IDP :: 가입완료,    :: 가가입상태");
							returnResult = "fail";
							loginResultMsg = "NOT_C LETE_ ";
						} else if (!member.getMbrCatCd().equals("US000202") && !member.getMbrCatCd().equals("US000203")
								&& !member.getMbrCatCd().equals("US000204") && !member.getMbrCatCd().equals("US000207")) {
							/** 개발자 ID로 로그인 하는 경우 **/
							log.info("개발자 ID ==> 일반사용자 권한 없음");
							returnResult = "fail";
							loginResultMsg = "NO_AUTH_USER_POC";
						} else if (member.getMbrStatCd().equals("US000504")) { // 일시 정지 상태
							log.info("일시 정지 ");
							resultCode = "PRE_ USE_STOP";
						} else if (member.getMbrStatCd().equals("US000505")) { // DB만 탈퇴 처리되어 로그인 되는 경우 막음 2012.02.10
							log.info("IDP 정상, DB 탈퇴 회원 ");
							returnResult = "fail";
							loginResultMsg = "NO_MEMBER_ ";
						} else {
							log.info("[param] 로그인 성공 ");
							//   기존 회원인 경우 탈퇴 처리를 위해 userAuthKey 생성
							SessionUtil.setAnySession(getRequest(), " id_auth_key", idpReceiverM
									.getResponseBody().getUser_auth_key());

							// 이용 중지상태인 경우 로그인 성공시 상태 정상으로 변경
							if ("US000504".equals(member.getMbrStatCd())) {
								Member updateStat = new Member();
								updateStat.setMbrNo(user_key);
								updateStat.setMbrStatCd("US000503");
								consumerService.updateConsumer(updateStat);
							}

							member.setUser_auth_key(user_auth_key);
							member.setUser_key(user_key);
							memberService.insertLoginInfo(member.getMbrNo(), getRequest());

							List<MemberHp> myHpList = memberHpService.selectHpByMbrNo(user_key);
							if (myHpList != null) {
								if (member.getMobileCnt() != myHpList.size()) {
									Member updateStat = new Member();
									updateStat.setMbrNo(user_key);
									updateStat.setMobileCnt(myHpList.size());
									consumerService.updateConsumer(updateStat);
									member.setMobileCnt(myHpList.size());
								}
							}

							// 세션을 생성한다.
							SessionUtil.setMemberSession(getRequest(), member);
							// 통계를 위한 쿠키 생성
							SessionCheckFilter
									.setLID(getRequest(), getResponse(), CipherAES.encrypt(member.getMbrNo()));

							representPhone = topService.getRepresentPhone(member.getMbrNo());
							if (representPhone != null) {
								if (multiService.getPhoneCheck(representPhone.getPhoneModelCd())) {
									representPhone.setMultiPhoneYn("Y");
								} else {
									representPhone.setMultiPhoneYn("N");
								}
								SessionUtil.setAnySession(getRequest(), "REP_HP_SESSION", representPhone);
							} else {
								SessionUtil.removeAnySession(getRequest(), "REP_HP_SESSION");
							}

							if (representPhone != null) {
								// if(representPhone.getPhoneModelCd().indexOf("미지원") == 0){ 대체. 20100222 soohee
								if (!CommonUtil.isSupportPhone(representPhone.getPhoneModelCd())) {
									SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
								} else {
									SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "MYPHONE");
								}
							} else {
								SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
							}
							SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION");
							if (loginRedirectURL != null && !loginRedirectURL.equals("")
									&& loginRedirectURL.indexOf("main. ") == -1) {
								redirectActionURL = loginRedirectURL;
								if (redirectActionParam != null && !redirectActionParam.equals("")) {
									redirectActionURL += redirectActionParam;
								}
								returnResult = "loginRedirect";
							} else {
								returnResult = "success";
								anotherJoinCk = "6";
							}
							// is_email_auth_yn 체크 해서 N인 경우 팝업
							idpReceiverM = IDPManager.getInstance().searchUserCommonInfo4SPServer(
									IDPManager.IDP_PARAM_KEY_TYPE_USERKEY, user_key);
							if (IDPManager.IDP_RES_CODE_OK.equals(idpReceiverM.getResponseHeader().getResult())) {
								if ("N".equals(idpReceiverM.getResponseBody().getIs_email_approved())) {
									SessionUtil.setAnySession(getRequest(), "is_email_approved", "N");
								}
							}
						}
					} else if (loginResult == 2201) {// 로그인 처리 비번 틀림
						resultCode = "INVAID_PASSWD";

						int pwdErrorCount = 0;

						CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
						if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
							checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
						}

						if (checkPwdInfo.getUserId() != null) {
							if (checkPwdInfo.getUserId().equals(user_id)) {
								pwdErrorCount = checkPwdInfo.getErrorCount();
							}
						}
						pwdErrorCount = pwdErrorCount + 1;
						checkPwdInfo.setUserId(user_id);
						checkPwdInfo.setErrorCount(pwdErrorCount);
						SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo);

						member = memberService.selectMember(user_id, null);
						if (member != null) {
							if ("US000504".equals(member.getMbrStatCd())) { // 일시 정지 상태 (로그인 5회이상 실패로 잠김시 로그인시 인증코드 추가처리
								log.info(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>PRE_ USE_STOP");
								resultCode = "PRE_ USE_STOP";
							}
						}

						if (pwdErrorCount > 5) {
							idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
							imgSign = idpReceiverM.getResponseBody().getImage_sign();
							signData = idpReceiverM.getResponseBody().getSign_data();
							resultText = idpReceiverM.getResponseHeader().getResult_text();
							imgUrl = idpReceiverM.getResponseBody().getImage_url();
						}

						if (pwdErrorCount == 6) { // 5회 이상 실패시 자체 일시 정지 상태로 변경
							Member updateStat = new Member();
							updateStat.setMbrNo(member.getMbrNo());
							updateStat.setMbrStatCd("US000504");
							consumerService.updateConsumer(updateStat);
							resultCode = "PRE_ USE_STOP";
						} else if (pwdErrorCount == 11) {
							HashMap pwdResultMap = new HashMap();

							String newPwd = null;
							idpReceiverM = IDPManager.getInstance().findPwd(
									IDPManager.IDP_PARAM_KEY_QUERY_PWD_KEY_TYPE_ID, user_id);
							if (IDPManager.IDP_RES_CODE_OK.equals(idpReceiverM.getResponseHeader().getResult())) {
								newPwd = idpReceiverM.getResponseBody().getTemp_passwd();
							}

							String receiverName = "";
							if (member.getMbrNm() != null && !member.getMbrNm().equals("")) {
								receiverName = member.getMbrId();
							} else {
								receiverName = member.getMbrId();
							}

							// ///////// 임시 비밀번호 발급 이메일 발송 ///////////////
							// 수신자 EMAIL
							RECEIVER = member.getEmailAddr();

							// eamil /비밀번호/이름 /가입일/현재날짜(yyyy.mm.dd)
							header = "http://" + Constants.USER_POC_IP + "/userpoc/images/mail" // 이미지 URL 경로.
									+ "," + "http://" + Constants.USER_POC_IP + "/userpoc" // linkPath
									+ "," + newPwd // 임시 비밀번호
									+ "," + user_id // 아이디
									+ "," + DateUtil.getAddDay(0, "yyyy-MM-dd"); // 현재날짜(yyyy.mm.dd)

							// ROWNUM,비밀번호
							contents = "";
							/*
							 * Email 발송..
							 */
							RESULT = sendPasswordMail(SENDER, RECEIVER, header, contents);
							// //////////// 임시 비밀번호 발송 끝 //////////////////////
						}
					} else if (loginResult == 2215) { // 가가입 상태
						member = memberService.selectMember(user_id, null);
						if (member != null) {
							if (!"US000202".equals(member.getMbrCatCd())) {
								loginResultMsg = "DEV_POC_WAIT_MEMBER";
							}
							resultCode = "PRE_ MEMBER";
						}
					} else {

						idpReceiverMoIDAuth = IDPManager.getInstance().otherChannelIdAuth(user_id, password);
						String oChResult = idpReceiverMoIDAuth.getResponseHeader().getResult();
						if (IDPManager.IDP_RES_CODE_OK.equals(oChResult)) {

							idpReceiverMoList = IDPManager.getInstance().otherChannelList("1", user_id);
							String oChResult1 = idpReceiverMoList.getResponseHeader().getResult();
							if (IDPManager.IDP_RES_CODE_OK.equals(oChResult1)) {
								familyName = idpReceiverMoList.getResponseBody().getSp_list();
								StringBuffer sb = new StringBuffer();
								sb.append("");
								int i = 0;
								if (familyName != null) {
									StringTokenizer st = new StringTokenizer(familyName, "|");
									while (st.hasMoreTokens()) {
										String temp = st.nextToken().trim();
										StringTokenizer st1 = new StringTokenizer(temp, ",");
										if (st1.hasMoreTokens()) {
											String site = st1.nextToken();
											if (site.indexOf("GTP_") < 0) {
												if (i > 0) {
													sb.append(", ");
												}
												sb.append(site);
											}
										}
										i++;
									}
								}

								resultCode = sb.toString(); // 패밀리 사이트 가입자
								if ("".equals(resultCode))
									resultCode = "NODATA";
							} else {

								resultCode = "NODATA"; // 가입 가능
							}
						} else {

							resultCode = "NODATA"; // 가입 가능
						}
					}

				}

				if ("fail".equals(returnResult))
					loginFailURL = "/user/loginImF. ?loginResultMsg=" + loginResultMsg + "&loginResult="
							+ loginResult;
				if (null != loginRedirectURL && !loginRedirectURL.equals(""))
					loginFailURL = loginFailURL + "&loginRedirectURL=" + URLEncoder.encode(loginRedirectURL);
				CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
				if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
					checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
				}

				if ("PRE_ USE_STOP".equals(loginResultMsg)) { // 기존 IDP회원 잠금상태일경우 인증코드 넣고 로그인
					idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
					imgSign = idpReceiverM.getResponseBody().getImage_sign();
					signData = idpReceiverM.getResponseBody().getSign_data();
					resultText = idpReceiverM.getResponseHeader().getResult_text();
					imgUrl = idpReceiverM.getResponseBody().getImage_url();

					checkPwdInfo.setUserId(user_id);
					checkPwdInfo.setErrorCount(6);
					SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo); // 세션이 없어진 이후에도 로그인시
																								// 자동가입방지 받도록
				}

				if (checkPwdInfo.getErrorCount() > 5) {
					loginFailURL = loginFailURL + "&imgSign=" + URLEncoder.encode(imgSign) + "&signData="
							+ URLEncoder.encode(signData) + "&imgUrl=" + URLEncoder.encode(imgUrl);
				}
				log.info(" ===================== loginFailURL : " + loginFailURL);
				log.info(" ===================== oldidp new getLogin end time == ["
						+ DateUtil.getShortTimeStampString() + "] ==============");
			}

			// 통합아이디 가가입자, 사용자 로그인 처리
			if ("OT".equals(resultCode) || "IM".equals(resultCode)) { // 통합아이디 로그인 처리
				String returnResult = "fail";
				if (gnbLoginRedirectURL != null && !gnbLoginRedirectURL.equals("")) {
					loginRedirectURL = gnbLoginRedirectURL;
				}

				if (user_id != null) {
					if (null == getRequest().getParameter("imsso") || "".equals(getRequest().getParameter("imsso"))) {
						imIdpReceiverM = ImIDPManager.getInstance().authForId(user_id, password);
					} else {
						imIdpReceiverM = ImIDPManager.getInstance().authForSvcNo(im_int_svc_no);
					}
					result = imIdpReceiverM.getResponseHeader().getResult();

					Enumeration enums = null;
					enums = getRequest().getParameterNames();
					String requestName = "";
					log.info("========== IDP LOGIN Reqest Variable Names START ==============================");
					while (enums.hasMoreElements()) {
						requestName = (String) enums.nextElement();
						log.info("names :" + requestName + ", value : " + getRequest().getParameter(requestName));
					}
					log.info("========== IDP LOGIN Reqest Variable Names END==============================");
					log.info("========== IM IDP LOGIN RESUT : " + result);
					// 결과가 성공일 경우
					if (ImIDPConstants.IDP_RES_CODE_OK.equals(result)) {
						user_id = imIdpReceiverM.getResponseBody().getUser_id();
						im_int_svc_no = imIdpReceiverM.getResponseBody().getIm_int_svc_no();
						user_auth_key = imIdpReceiverM.getResponseBody().getUser_auth_key();
						user_key = imIdpReceiverM.getResponseBody().getUser_key();

						String login_status_code = getRequest().getParameter("login_status_code") == null ? "" : getRequest()
								.getParameter("login_status_code");
						String login_limit_sst_code = getRequest().getParameter("login_limit_sst_code") == null ? "" : getRequest()
								.getParameter("login_limit_sst_code");
						if (Constants.SSO_SST_CD_ WEB.equals(login_limit_sst_code)
								&& "20".equals(login_status_code)) {
						} else {
							imIdpReceiverM = ImIDPManager.getInstance().userInfoIdpSearchServer(im_int_svc_no);
							log.info("imIdpReceiverM.getResponseHeader().getResult() ::: userInfoSearchServer "
									+ imIdpReceiverM.getResponseHeader().getResult());
							if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())
									&& user_id.equals(imIdpReceiverM.getResponseBody().getUser_id()) // 20120830 변조 방지
																									 // 처리
									&& user_key.equals(imIdpReceiverM.getResponseBody().getUser_key())
									&& im_int_svc_no.equals(imIdpReceiverM.getResponseBody().getIm_int_svc_no())) {

								member = memberService.selectMemberByImSvcNo(im_int_svc_no);
								if (member == null) {
									/**   DB에 회원 데이터가 없는경우 **/
									log.info("IDP :: 가입상태,    :: 데이터 존재하지 않음");
									returnResult = "fail";
									loginResultMsg = "NO_MEMBER_ ";
								} else if (member.getMbrStatCd().equals("US000502")) {
									/** EAMIL 인증후에도   DB에는 가입완료처리되지 않은경우 **/
									log.info("IDP :: 가입완료,    :: 가가입상태");
									returnResult = "fail";
									loginResultMsg = "NOT_C LETE_ ";
								} else if (member.getMbrStatCd().equals("US000505")) { // DB만 탈퇴 처리되어 로그인 되는 경우 막음
																					   // 2012.02.10
									log.info("IDP 정상, DB 탈퇴 회원 ");
									returnResult = "fail";
									loginResultMsg = "NO_MEMBER_ ";
								} else {
									member.setIm_int_svc_no(im_int_svc_no);
									member.setUser_auth_key(user_auth_key);
									member.setUser_key(user_key);
									member.setUser_tn(member.getMdnNo());

									String tn_auth = imIdpReceiverM.getResponseBody().getIs_user_tn_auth();
									if (null == tn_auth || "".equals(tn_auth))
										tn_auth = "N";
									member.setIs_user_tn_auth(tn_auth);

									String tn_own = imIdpReceiverM.getResponseBody().getIs_user_tn_own();
									if (null == tn_own || "".equals(tn_own))
										tn_own = "N";
									member.setIs_user_tn_own(tn_own);

									member.setUser_tn_type(imIdpReceiverM.getResponseBody().getUser_tn_type());
									member.setUser_tn_nation_cd(imIdpReceiverM.getResponseBody().getUser_tn_nation_cd());

									String email_auth = imIdpReceiverM.getResponseBody().getIs_email_auth();
									if (null == email_auth || "".equals(email_auth))
										email_auth = "N";
									member.setIs_email_auth(email_auth); // 회원정보 수정시 필요

									String rname_auth = imIdpReceiverM.getResponseBody().getIs_rname_auth();
									if (null == rname_auth || "".equals(rname_auth))
										rname_auth = "N";
									member.setIm_realNmAuthYn(rname_auth);

									memberService.insertLoginInfo(member.getMbrNo(), getRequest());

									// 임시 비번인 경우 alert처리
									if ("2".equals(imIdpReceiverM.getResponseBody().getUser_passwd_type()))
										SessionUtil.setAnySession(getRequest(), "tempPwd", "Y");

									List<MemberHp> myHpList = memberHpService.selectHpByMbrNo(user_key);
									if (myHpList != null) {
										if (member.getMobileCnt() != myHpList.size()) {
											Member updateStat = new Member();
											updateStat.setMbrNo(user_key);
											updateStat.setMobileCnt(myHpList.size());
											consumerService.updateConsumer(updateStat);
											member.setMobileCnt(myHpList.size());
										}
									}

									// 세션을 생성한다.
									SessionUtil.setMemberSession(getRequest(), member);
									// 통계를 위한 쿠키 생성
									SessionCheckFilter.setLID(getRequest(), getResponse(),
											CipherAES.encrypt(member.getMbrNo()));

									representPhone = topService.getRepresentPhone(member.getMbrNo());
									if (representPhone != null) {
										if (multiService.getPhoneCheck(representPhone.getPhoneModelCd())) {
											representPhone.setMultiPhoneYn("Y");
										} else {
											representPhone.setMultiPhoneYn("N");
										}
										SessionUtil.setAnySession(getRequest(), "REP_HP_SESSION", representPhone);
									} else {
										SessionUtil.removeAnySession(getRequest(), "REP_HP_SESSION");
									}

									if (representPhone != null) {
										if (!CommonUtil.isSupportPhone(representPhone.getPhoneModelCd())) {
											SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
										} else {
											SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "MYPHONE");
										}
									} else {
										SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
									}
									SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION");
									if (loginRedirectURL != null && !loginRedirectURL.equals("")) {
										redirectActionURL = loginRedirectURL;
										if (redirectActionParam != null && !redirectActionParam.equals("")) {
											redirectActionURL += redirectActionParam;
										}
										returnResult = "loginRedirect";
									} else {
										returnResult = "success";
										if ("Y".equals(getRequest().getParameter("imsso")))
											returnResult = "ssoSuccess";
										anotherJoinCk = "6";
									}
								}
							}
						}

					} else if (ImIDPConstants.IDP_RES_CODE_WRONG_PASSWD.equals(result)) { // 비밀번호 5, 10회 입력 오류 체크

						int pwdErrorCount = 0;

						CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
						if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
							checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
						}

						if (checkPwdInfo.getUserId() != null) {
							if (checkPwdInfo.getUserId().equals(user_id)) {
								pwdErrorCount = checkPwdInfo.getErrorCount();
							}
						}
						pwdErrorCount = pwdErrorCount + 1;
						checkPwdInfo.setUserId(user_id);
						checkPwdInfo.setErrorCount(pwdErrorCount);
						SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo);
						if (pwdErrorCount > 5) {
							loginResultMsg = "IM_ USE_STOP";
							try {
								idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
								imgSign = idpReceiverM.getResponseBody().getImage_sign();
								signData = idpReceiverM.getResponseBody().getSign_data();
								resultText = idpReceiverM.getResponseHeader().getResult_text();
								imgUrl = idpReceiverM.getResponseBody().getImage_url();
							} catch (Exception e) {
								idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
								imgSign = idpReceiverM.getResponseBody().getImage_sign();
								signData = idpReceiverM.getResponseBody().getSign_data();
								resultText = idpReceiverM.getResponseHeader().getResult_text();
								imgUrl = idpReceiverM.getResponseBody().getImage_url();
							}
						}

						if (pwdErrorCount == 6) {
							imIdpReceiverM = ImIDPManager.getInstance().setLoginStatus(user_id, "20");
							if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
								log.info("user loginStatus stop");
							}
						} else if (pwdErrorCount == 11) {
							String imSvcNo = signService.getImSvcNo(user_id);
							log.info("imSvcNo : " + imSvcNo);

							if (null != imSvcNo && !"".equals(imSvcNo)) {// 통합아이디 사용자인 경우
								imIdpReceiverM = ImIDPManager.getInstance().userInfoIdpSearchServer(imSvcNo);
								if (ImIDPConstants.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader()
										.getResult())) {
									HashMap hm = new HashMap();
									hm.put("key", imSvcNo);
									hm.put("user_tn", imIdpReceiverM.getResponseBody().getUser_tn());

									String tn_auth = imIdpReceiverM.getResponseBody().getIs_user_tn_auth();
									if (null == tn_auth || "".equals(tn_auth))
										tn_auth = "N";
									hm.put("user_tn_auth", tn_auth);

									hm.put("user_email", imIdpReceiverM.getResponseBody().getUser_email());

									String email_auth = imIdpReceiverM.getResponseBody().getIs_email_auth();
									if (null == email_auth || "".equals(email_auth))
										email_auth = "N";
									hm.put("is_email_auth", email_auth);
									imIdpReceiverM = ImIDPManager.getInstance().resetPwd(hm);// 임시 비번 발급처리
									if (ImIDPConstants.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader()
											.getResult())) {
										log.info("reset password Imserver send mail or sms");
									}
								}
							}
						} else { // 나머지 비번 틀린경우
							loginResultMsg = "PASSWORD_WRONG";
						}
						returnResult = "fail";
					} else if (ImIDPConstants.IDP_RES_CODE_INVALID_USER_INFO.equals(result)) { // 가가입 상태일 때
						StringBuffer sb = new StringBuffer();
						sb.append("");
						StringTokenizer st = null;
						String spList = join_sst_list;
						if (null != spList) {
							st = new StringTokenizer(spList, ",");
							sb.append(st.nextToken());
						}
						log.info("가가입한 사이트 : " + sb.toString()); // 가가입시 처리 할 팝업 두가지( 용, 타사이트용) SB p53

						if (sb.toString().indexOf(Constants.SSO_SST_CD_ WEB) == -1
								&& sb.toString().indexOf("90000") == -1) {
							loginResultMsg = "OTHER_WAIT_MEMBER";
							if (Constants.SSO_SST_CD_11ST_WEB.equals(sb.toString().trim())) {
								sp_id = Constants.SSO_SST_11ST;
								sp_url = "http://www.11st.co.kr";
							} else if (Constants.SSO_SST_CD_CYWORLD_WEB.equals(sb.toString().trim())) {
								sp_id = Constants.SSO_SST_CYWORLD;
								sp_url = "http://www.nate.com";
							} else if (Constants.SSO_SST_CD_MELON_WEB.equals(sb.toString().trim())) {
								sp_id = Constants.SSO_SST_MELON;
								sp_url = "http://www.melon.com";
							} else if (Constants.SSO_SST_CD_NATE_WEB.equals(sb.toString().trim())) {
								sp_id = Constants.SSO_SST_NATE;
								sp_url = "http://www.nate.com";
							} else if (Constants.SSO_SST_CD_TCLOUD_WEB.equals(sb.toString().trim())) {
								sp_id = Constants.SSO_SST_TCLOUD;
								sp_url = "http://www.tcloud.co.kr";
							} else if (Constants.SSO_SST_CD_TMAP_WEB.equals(sb.toString().trim())) {
								sp_id = Constants.SSO_SST_TMAP;
								sp_url = "http://tmap.tworld.co.kr";
							} else if (Constants.SSO_SST_CD_ WEB.equals(sb.toString().trim())) {
								sp_id = Constants.SSO_SST_TSTORE;
								sp_url = "http://www.tstore.co.kr";
							} else if (Constants.SSO_SST_CD_IM_DEV_CENTER.equals(sb.toString().trim())) {
								sp_id = Constants.sSO_SST_DEVCENTER;
								sp_url = "http://developers.skplanetx.com";
							} else if (Constants.SSO_SST_CD_CONTEXT_PORTAL.equals(sb.toString().trim())) {
								sp_id = Constants.SSO_SST_C_PORTAL;
								sp_url = "";
							} else if (Constants.SSO_SST_CD_NOP.equals(sb.toString().trim())) {
								sp_id = Constants.SSO_SST_NOP;
								sp_url = "http://platform.smarttouch.com";
							}
							returnResult = "failToMain";
						} else {
							loginResultMsg = " WAIT_MEMBER";
							returnResult = "failToMain";
						}

					} else if (ImIDPConstants.IDP_RES_CODE_UNAUTHORIZED_USER.equals(result)) { // 미등록 사용자
						returnResult = "fail";
						loginResultMsg = "FAIL";
					} else if (ImIDPConstants.IDP_RES_CODE_LOGIN_RESTRICT.equals(result)) { // 로그인 제한 상태
						returnResult = "fail";
						loginResultMsg = "IM_ USE_STOP";

						CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
						if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
							checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");

						}

						if ("IM_ USE_STOP".equals(loginResultMsg)) { // 통합 회원 잠금상태일경우 인증코드 넣고 로그인
							try {
								idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
								imgSign = idpReceiverM.getResponseBody().getImage_sign();
								signData = idpReceiverM.getResponseBody().getSign_data();
								resultText = idpReceiverM.getResponseHeader().getResult_text();
								imgUrl = idpReceiverM.getResponseBody().getImage_url();
							} catch (Exception e) {
								idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
								imgSign = idpReceiverM.getResponseBody().getImage_sign();
								signData = idpReceiverM.getResponseBody().getSign_data();
								resultText = idpReceiverM.getResponseHeader().getResult_text();
								imgUrl = idpReceiverM.getResponseBody().getImage_url();
							}

							checkPwdInfo.setUserId(user_id);
							checkPwdInfo.setErrorCount(6);
							SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo); // 세션이 없어진 이후에도
																										// 로그인시 자동가입방지
																										// 받도록
						}
					} else {
						returnResult = "fail";
						loginResultMsg = "FAIL";
					}

					// 5회이상 실패시 자동가입방지 처리
					if ("fail".equals(returnResult))
						loginFailURL = "/user/loginImF. ?loginResultMsg=" + loginResultMsg + "&loginResult="
								+ loginResult;
					if (null != loginRedirectURL && !loginRedirectURL.equals(""))
						loginFailURL = loginFailURL + "&loginRedirectURL=" + URLEncoder.encode(loginRedirectURL);
					CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
					if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
						checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
						if (checkPwdInfo.getErrorCount() > 5) {
							loginResultMsg = "IM_ USE_STOP";
							loginFailURL = loginFailURL + "&imgSign=" + URLEncoder.encode(imgSign) + "&signData="
									+ URLEncoder.encode(signData) + "&imgUrl=" + URLEncoder.encode(imgUrl);
						}
					}
					log.info(" ===================== loginFailURL : " + loginFailURL);
				}

				// 타사이트 LOCK 경우 처리
				String otherLock = getRequest().getParameter("otherLock");
				if (null != otherLock && !"".equals(otherLock)) {
					CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
					checkPwdInfo.setUserId(user_id);
					checkPwdInfo.setErrorCount(6);
					SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo); // 세션이 없어진 이후에도 로그인시
																								// 자동가입방지 받도록

					if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
						checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
						if (checkPwdInfo.getErrorCount() > 5) {
							try {
								idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
								imgSign = idpReceiverM.getResponseBody().getImage_sign();
								signData = idpReceiverM.getResponseBody().getSign_data();
								resultText = idpReceiverM.getResponseHeader().getResult_text();
								imgUrl = idpReceiverM.getResponseBody().getImage_url();
							} catch (Exception e) {
								idpReceiverM = IDPManager.getInstance().warterMarkImageUrl();
								imgSign = idpReceiverM.getResponseBody().getImage_sign();
								signData = idpReceiverM.getResponseBody().getSign_data();
								resultText = idpReceiverM.getResponseHeader().getResult_text();
								imgUrl = idpReceiverM.getResponseBody().getImage_url();
							}

							loginResultMsg = "";
							loginFailURL = "/user/loginImF. ?loginResultMsg=IM_ USE_STOP&loginResult=0&imgSign="
									+ URLEncoder.encode(imgSign)
									+ "&signData="
									+ URLEncoder.encode(signData)
									+ "&imgUrl=" + URLEncoder.encode(imgUrl);
						}
					}
					log.info(" ===================== loginFailURL : " + loginFailURL);
				}

				log.info(" ===================== getOneIdLogin end time == [" + DateUtil.getShortTimeStampString()
						+ "] ==============");
			}

			if ("NA".equals(resultCode)) { // 이용동의 가입자 팝업

			} else if ("NAF".equals(resultCode) || "OTF".equals(resultCode)) { //   미동의 통합아이디이나 비번 틀림 , 타사이트 통합아이디
																			   // 가가입 상태나 비번 틀림 안내 alert

			} else if ("NA_LU".equals(resultCode)) { // 미동의 가입자 로그인제한 상태 안내 (One ID 안내 사이트에서 PW초기화 유도)

			} else if ("OT_LU".equals(resultCode)) { // 가승인 사용자 로그인 제한 상태 안내 (One ID 안내 사이트에서 컨펌 URL제공하여 가입완료 상태로 전환,
													 // PW초기화 유도)

			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return SUCCESS;
	}

	/**
	 * 통합아이디 기존/통합 회원확인
	 * */
	public String chkIdpImIdpCheckAjax() {

		log.info("chkIdpImIdpCheckAjax start()");
		PrintWriter writer = null;
		String resultCode = "IDP";
		String doubleChk = "N";
		String tId = "N";
		try {

			JSONObject jsonObject = new JSONObject();
			HttpServletResponse response = getResponse();

			String userId = getRequest().getParameter("rep_hp") == null ? "" : Base64.decode(getRequest().getParameter(
					"rep_hp"));
			String user_passwd = getRequest().getParameter("biz_nm") == null ? "" : Base64.decode(getRequest()
					.getParameter("biz_nm"));

			// boolean chk = memberService.isImMemberCheck(userId);
			// if(chk)resultCode="IM";
			// //네이트 아이디 체크
			// if(userId.indexOf("@nate.com") > -1){
			// userId = userId.substring(0, userId.indexOf("@"));
			// chk = memberService.isImMemberCheck(userId);
			// if(chk)resultCode="IM";
			// }

			if (userId.indexOf("@nate.com") > -1)
				userId = userId.substring(0, userId.indexOf("@"));

			imIdpReceiverM = ImIDPManager.getInstance().findJoinServiceList(userId);
			if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
				String imSvcNo = imIdpReceiverM.getResponseBody().getIm_int_svc_no();
				String spList = imIdpReceiverM.getResponseBody().getSp_list();

				if (spList.indexOf(Constants.SSO_SST_CD_ WEB) == -1 && spList.indexOf(",") > -1) {// 리턴 리스트 중에 T
																										// Store가 없고
																										// 타사이트 정보가 있으면
																										// 이용동의 가입

					// 미동의 가입자 동일인확인 절차 : 아이디 패스워드 인증 IM 연동
					String imResult = jwork.sso.agent.SSOManager.authDisagreeMember(userId,
							CipherAES.getSHA256(user_passwd));
					log.info(imResult);
					String imValue[] = imResult.split("\\|");
					String imCode = imValue[0];

					// 이용동의 가입자 세션 정보
					int pwdErrorCount = 0;
					CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
					if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
						checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION");
					}

					if ("S001".equals(imCode)) { // IM 연동 성공시
						if (null != checkPwdInfo)
							SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION"); // 세션 초기화

						String imLoginStatus = jwork.cipher.client.JworkCrypto.decrypt(imValue[2].getBytes());
						log.info("imLoginStatus : " + imLoginStatus);
						if ("null".equals(imLoginStatus) || "10".equals(imLoginStatus)) {// 정상
							resultCode = "NA";
							jsonObject.put("imSvcNo", imSvcNo); // 전환시 이용동의가입자 체크후 이용동의 가입시 필요
						} else { // 로그인 제한상태
							resultCode = "NA_LU";
						}
					} else { // 비번 틀린경우나 연동 실패(미동의 사용자 5회 실패시 LOCK 설정)
						resultCode = "NAF";

						if (checkPwdInfo.getUserId() != null) {
							if (checkPwdInfo.getUserId().equals(userId)) {
								pwdErrorCount = checkPwdInfo.getErrorCount();
							}
						}
						if ("N".equals(doubleChk)) {
							pwdErrorCount = pwdErrorCount + 1;
							checkPwdInfo.setUserId(userId);
							checkPwdInfo.setErrorCount(pwdErrorCount);
							SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo);
							doubleChk = "Y";
						}

						if (pwdErrorCount == 6) {
							imIdpReceiverM = ImIDPManager.getInstance().setLoginStatus(userId, "20");
							if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
								log.info("미동의 가입자 loginStatus stop");
							}
						}
						if (pwdErrorCount > 5)
							resultCode = "NA_LU";
					}

				} else if (spList.indexOf(Constants.SSO_SST_CD_ WEB) > -1) { //   가입된 아이디인 경우(DB체크 대신 사용)
					resultCode = "IM";
					tId = "Y";
				} else {
					resultCode = "IDP";
					tId = "Y";
				}
			}

			if ("N".equals(tId)) { //   계정이 아닌 경우에만 처리
				imIdpReceiverM = ImIDPManager.getInstance().checkIdStatusIdpIm(userId);// 타사이트 가가입 체크
				if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
					Object im_user_status_cd = imIdpReceiverM.getResponseBody().getIm_user_status_cd();
					if (null != im_user_status_cd && !"".equals(im_user_status_cd)) {
						if ("11".equals(im_user_status_cd)) {
							// 계정 정보가 동일한 경우만 가가입 팝업
							String imResult = jwork.sso.agent.SSOManager.authDisagreeMember(userId,
									CipherAES.getSHA256(user_passwd));
							log.info(imResult);
							String imValue[] = imResult.split("\\|");
							String imCode = imValue[0];

							// 가가입자 로그인 세션정보
							int pwdErrorCount = 0;
							CheckPwdInfo checkPwdInfo = new CheckPwdInfo();
							if (SessionUtil.getAnySession(getRequest(), "CHECK_PWD_SESSION") != null) {
								checkPwdInfo = (CheckPwdInfo) SessionUtil.getAnySession(getRequest(),
										"CHECK_PWD_SESSION");
							}

							if ("S001".equals(imCode)) { // IM 연동 성공시
								if (null != checkPwdInfo)
									SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION"); // 세션 초기화

								String imLoginStatus = jwork.cipher.client.JworkCrypto.decrypt(imValue[2].getBytes());
								log.info("imLoginStatus : " + imLoginStatus);
								if ("null".equals(imLoginStatus) || "10".equals(imLoginStatus)) {// 정상
									resultCode = "OT";
								} else { // 로그인 제한상태
									resultCode = "OT_LU";
								}
							} else { // 비번 틀린경우나 연동 실패(가승인자 5회 실패시 LOCK 설정)
								resultCode = "OTF";

								if (checkPwdInfo.getUserId() != null) {
									if (checkPwdInfo.getUserId().equals(userId)) {
										pwdErrorCount = checkPwdInfo.getErrorCount();
									}
								}

								if ("N".equals(doubleChk)) {
									pwdErrorCount = pwdErrorCount + 1;
									checkPwdInfo.setUserId(userId);
									checkPwdInfo.setErrorCount(pwdErrorCount);
									SessionUtil.setAnySession(getRequest(), "CHECK_PWD_SESSION", checkPwdInfo);
									doubleChk = "Y";
								}

								if (pwdErrorCount == 6) {
									imIdpReceiverM = ImIDPManager.getInstance().setLoginStatus(userId, "20");
									if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader()
											.getResult())) {
										log.info("가승인 가입자 loginStatus stop");
									}
								}
								if (pwdErrorCount > 5)
									resultCode = "OT_LU";
							}
						}
					}
				}
			}

			jsonObject.put("resultCode", resultCode);
			log.info("########################################## resultCode ");
			log.info("resultCode : " + resultCode);
			writer = response.getWriter();
			writer.write(jsonObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
		return SUCCESS;
	}

	/*
	 * 통합아이디 로그인 상태 설정(가능/제한)
	 */
	public String setImMemberLoginStatusAjax() {
		log.info("setImMemberLoginStatusAjax start()");
		PrintWriter writer = null;
		String resultCode = "N";
		try {

			JSONObject jsonObject = new JSONObject();
			HttpServletResponse response = getResponse();

			String user_id = getRequest().getParameter("user_id") == null ? "" : getRequest().getParameter("user_id");
			String chkMember = getRequest().getParameter("chkMember") == null ? "" : getRequest().getParameter(
					"chkMember");

			if ("IM".equals(chkMember)) {// 통합아이디 회원인 경우 IDP 로그인 정상 처리

				imIdpReceiverM = ImIDPManager.getInstance().setLoginStatus(user_id, "10"); // 로그인 가능 상태로 처리
				if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) {
					log.info("user loginStatus update code10");
					resultCode = "Y";
				}
			} else if ("IDP".equals(chkMember)) {// 기존IDP 회원인 경우 DB 정상 처리
				member = memberService.selectMember(user_id, null);
				Member updateStat = new Member();
				updateStat.setMbrNo(member.getMbrNo());
				updateStat.setMbrStatCd("US000503");
				consumerService.updateConsumer(updateStat);
				log.info("user mbrstatcd update code503");
				resultCode = "Y";
			}
			SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION"); // 로그인 실패 세션도 초기화
			jsonObject.put("resultCode", resultCode);

			writer = response.getWriter();
			writer.write(jsonObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
		return SUCCESS;
	}

	/*
	 * 통합아이디   회원 전환가입 팝업
	 */
	public String popupTstoreToOneId() {
		log.info("popupTstoreToOneId ");
		try {
			loginId = getRequest().getParameter("idpId") == null ? "" : getRequest().getParameter("idpId");
			password = getRequest().getParameter("idpPwd") == null ? "" : getRequest().getParameter("idpPwd");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return SUCCESS;
	}

	/*
	 * 통합아이디 타채널 회원 전환가입 팝업
	 */
	public String popupOtherToOneId() {
		log.info("popupOtherToOneId");
		try {
			loginId = getRequest().getParameter("idpId") == null ? "" : getRequest().getParameter("idpId");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return SUCCESS;
	}

	/*
	 * 통합아이디 이용동의가입 팝업
	 */
	public String popupOneIdAgree() {
		log.info("popupOneIdAgree");
		try {
			user_id = getRequest().getParameter("user_id") == null ? "" : getRequest().getParameter("user_id");
			imSvcNo = getRequest().getParameter("imSvcNo") == null ? "" : getRequest().getParameter("imSvcNo");
		} catch (Exception e) {
			e.printStackTrace();
		}
		return SUCCESS;
	}

	/*
	 * 통합아이디   가가입 팝업
	 */
	public String popupWaitTstoreImMember() {
		log.info("popupWaitTstoreImMember");
		try {
			user_id = getRequest().getParameter("user_id") == null ? "" : getRequest().getParameter("user_id");

			emailList = consumerService.getEmailList();
			if (user_id != null) {
				member = memberService.selectMember(user_id, null); // 타채널 팝업에 사용
				setEmail(member.getEmailAddr());
				log.info("======>>>>>" + member.getEmailAddr());
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return SUCCESS;
	}

	/*
	 * 통합아이디 타사이트 가가입 팝업
	 */
	public String popupWaitOtherImMember() {
		log.info("popupWaitOtherImMember");
		try {
			user_id = getRequest().getParameter("user_id") == null ? "" : getRequest().getParameter("user_id");
			sp_url = "http://oneid.skplanet.co.kr";
		} catch (Exception e) {
			e.printStackTrace();
		}
		return SUCCESS;
	}

	public String popupNateIdNoti() {
		log.info("popupNateIdNoti ");
		try {
			sp_url = Constants.NATE_REGIST_URL + Constants.SITE_REDIRECT_URL;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return SUCCESS;
	}

	public String popupWaitOtherLock() {
		sp_url = "http://oneid.skplanet.co.kr";
		return SUCCESS;
	}

	public String popupNotAgreeLock() {
		sp_url = "http://oneid.skplanet.co.kr";
		return SUCCESS;
	}

	/*
	 * 통합아이디 전환 가입시 사용가능 아이디 여부 체크
	 */
	public String popupOtherImMemberCheckAjx() {
		log.info("popupOtherImMemberCheckAjx");
		PrintWriter writer = null;
		String resultCode = "";
		try {
			JSONObject jsonObject = new JSONObject();
			HttpServletRequest request = getRequest();
			HttpServletResponse response = getResponse();
			response.setHeader("Content-Type", "text/html; charset=UTF-8");

			user_id = request.getParameter("user_id") == null ? "" : request.getParameter("user_id");

			imIdpReceiverM = ImIDPManager.getInstance().dupUserIdCheck(user_id); // 가입한 사이트 체크
			StringBuffer sb = new StringBuffer();
			boolean available = true;
			if (ImIDPManager.IDP_RES_CODE_OK.equals(imIdpReceiverM.getResponseHeader().getResult())) { // 성공은 사용가능여부가
																									   // 아님. dup_sst
																									   // 유뮤에 따라 처리
				sb.append("");
				StringTokenizer st = null;
				StringTokenizer st1 = null;
				String spList = imIdpReceiverM.getResponseBody().getDup_sst();
				if (null != spList && !"".equals(spList)) {
					int i = 0;
					if (null != spList) {
						st = new StringTokenizer(spList, "\\|");
						while (st.hasMoreTokens()) {
							String temp = st.nextToken().trim();
							st1 = new StringTokenizer(temp, ",");
							if (st1.hasMoreTokens()) {
								String site = st1.nextToken().trim();
								String userId = st1.nextToken();
								String resultCd = st1.nextToken(); // Y인 경우 타사이트에서 사용 못하도록 막은 케이스임
								if ("Y".equals(resultCd))
									available = false; // 하나라도 Y가 있으면 사용 불가 (전환 불가 신규 아이디로 전환처리)

								if ("null".equals(site)) { // null 인경우는 중복체크 결과 사용가능한 경우 임
									// 중복된 타사이트 없음 사용가능
									sb.append("OK");
								} else {

									if (Constants.SSO_SST_CD_11ST_WEB.equals(site)) {
										site = Constants.SSO_SST_11ST;
										if (sb.indexOf(site) < 0) {
											if (i > 0)
												sb.append(", ");
											sb.append(site);
										}
									} else if (Constants.SSO_SST_CD_CYWORLD_WEB.equals(site)) {
										site = Constants.SSO_SST_CYWORLD;
										if (sb.indexOf(site) < 0) {
											if (i > 0)
												sb.append(", ");
											sb.append(site);
										}
									} else if (Constants.SSO_SST_CD_MELON_WEB.equals(site)) {
										site = Constants.SSO_SST_MELON;
										if (sb.indexOf(site) < 0) {
											if (i > 0)
												sb.append(", ");
											sb.append(site);
										}
									} else if (Constants.SSO_SST_CD_NATE_WEB.equals(site)) {
										site = Constants.SSO_SST_NATE;
										if (sb.indexOf(site) < 0) {
											if (i > 0)
												sb.append(", ");
											sb.append(site);
										}
									} else if (Constants.SSO_SST_CD_TCLOUD_WEB.equals(site)) {
										site = Constants.SSO_SST_TCLOUD;
										if (sb.indexOf(site) < 0) {
											if (i > 0)
												sb.append(", ");
											sb.append(site);
										}
									} else if (Constants.SSO_SST_CD_TMAP_WEB.equals(site)) {
										site = Constants.SSO_SST_TMAP;
										if (sb.indexOf(site) < 0) {
											if (i > 0)
												sb.append(", ");
											sb.append(site);
										}
									} else if (Constants.SSO_SST_CD_IM_DEV_CENTER.equals(site)) {
										site = Constants.sSO_SST_DEVCENTER;
										if (sb.indexOf(site) < 0) {
											if (i > 0)
												sb.append(", ");
											sb.append(site);
										}

									} else if (Constants.SSO_SST_CD_CONTEXT_PORTAL.equals(site)) {
										site = Constants.SSO_SST_C_PORTAL;
										if (sb.indexOf(site) < 0) {
											if (i > 0)
												sb.append(", ");
											sb.append(site);
										}

									} else if (Constants.SSO_SST_CD_NOP.equals(site)) {
										site = Constants.SSO_SST_NOP;
										if (sb.indexOf(site) < 0) {
											if (i > 0)
												sb.append(", ");
											sb.append(site);
										}

									} else if (Constants.SSO_SST_CD_ WEB.equals(site)) {
										// site = Constants.SSO_SST_TSTORE;
										// if(sb.indexOf(site) < 0){
										// if( i > 0 )sb.append(", ");
										// sb.append(site);
										// }
										//  인 경우 기존사용자 아이디가 통합 pool에 등록이 되어 있어
										// 중복아이디 체크시 이때만  는 제외하고 체크해서 본인인증 받지 않도록 한다.
									}
								}

							}
							i++;
						}
					}
					if ("OK".equals(sb.toString())) {
						log.info("아이디 사용 가능");
					} else {
						log.info("(아이디 사용 불가) 가입한 처리 된 사이트 : " + sb.toString());
					}

					resultCode = sb.toString();
					if ("".equals(resultCode))
						resultCode = "OK"; //  만 포함된 경우
				}
				SessionUtil.setAnySession(request, "changeDupIdCheck", user_id); // 전환가입 중복 체크 재확인시

			} else {
				resultCode = "FAIL";
			}

			if (available == false) {// 바로 전환가입(신규아이디 입력) 화면으로 이동
				resultCode = "NEWID";
			}

			jsonObject.put("resultCode", resultCode);

			writer = response.getWriter();
			writer.write(jsonObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
		return SUCCESS;
	}

	/*
	 * 통합아이디 전환 가입시아이디 이미사용중 NOTI
	 */
	public String popupImIdAlreadyUse() {

		user_id = getRequest().getParameter("user_id") == null ? "" : getRequest().getParameter("user_id");
		join_site = getRequest().getParameter("join_site") == null ? "" : getRequest().getParameter("join_site");
		change_type = getRequest().getParameter("change_type") == null ? "" : getRequest().getParameter("change_type");
		return SUCCESS;
	}

	public String encryptAjax() {
		log.debug("encryptAjax start()");
		PrintWriter writer = null;
		String resultCode = "";

		try {
			JSONObject jsonObject = new JSONObject();
			HttpServletRequest request = getRequest();
			HttpServletResponse response = getResponse();

			resultCode = getRequest().getParameter("tppw") == null ? "" : CipherAES.encrypt(getRequest().getParameter(
					"tppw"));

			jsonObject.put("resultCode", resultCode);

			writer = response.getWriter();
			writer.write(jsonObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
		return SUCCESS;
	}

	/**
	 * 모바일 전용회원으로 등록된 휴대폰 번호가 있는지 확인.
	 * 
	 * @return
	 */
	public String popupCheckMdnAuth() {
		String mdn = prePhoneNumber + phone_01 + phone_02;
		String mbrCatCd = "";
		// checkMdnAuth = "MDN_NOT_JOIN_MEMBER";

		Idp Check  Chk = new Idp Check();

		boolean isSkt = false;
		if ("Y".equals( Chk.isSktUser(mdn)))
			isSkt = true;

		/*
		 * 모바일 전용회원 코드 확인.
		 */
		mbrCatCd = memberService.checkMdnAuth(mdn);
		if (mbrCatCd != null) {
			if (CodeConstWeb.MEM_TYPE_MOBILE.equals(mbrCatCd)) {
				if (isSkt) {
					checkMdnAuth = "MDN_JOIN_MEMBER";
				} else {
					// 1.4
					checkMdnAuth = "NSKT_FAIL_ID_TURN";
				}
				log.info("<checkMdnAuth> MDN[" + mdn + "] is Mobile Member.");
			} else if (CodeConstWeb.MEM_TYPE_NORMAL.equals(mbrCatCd)
					|| CodeConstWeb.MEM_TYPE_NORMAL_DEV_NOPAY.equals(mbrCatCd)
					|| CodeConstWeb.MEM_TYPE_NORMAL_DEV_PAY.equals(mbrCatCd)) { // 사용자POC 웹회원
				checkMdnAuth = "WEB_JOIN_MEMBER";
				log.info("<checkMdnAuth> MDN[" + mdn + "] is USER_POC WEB Member.");
			} else if (CodeConstWeb.MEM_TYPE_DEV_NOPAY.equals(mbrCatCd)
					|| CodeConstWeb.MEM_TYPE_DEV_PAY.equals(mbrCatCd)) { // 개발자POC 웹회원( 현재는 개발자POC 메세지가 따로 없으므로 사용자POC와
																		 // 동일한 메세지창 보여준다.)
				checkMdnAuth = "WEB_JOIN_MEMBER";
				log.info("<checkMdnAuth> MDN[" + mdn + "] is DEV_POC WEB Member.");
			}
		} else {
			if (isSkt) {
				// 1.3 기존 인증번호 발송 처리 전 팝업 선택(ID/MDN가입) 페이지로
				checkMdnAuth = "MDN_NOT_JOIN_MEMBER";
			} else {
				// 1.2
				checkMdnAuth = "NSKT_FAIL_ID_REGIST";
			}
		}

		return SUCCESS;
	}

	/**
	 * 모바일 전용회원 회원가입 유도.
	 * 
	 * @return
	 */
	public String pupRegistMdn() {
		String mdn = prePhoneNumber + phone_01 + phone_02;
		log.info("<pupRegistMdn> mdn :: " + mdn);
		result = "FAIL";

		try {
			IDPReceiverM idpReceiverM = IDPManager.getInstance().sendMobileAuthCode(mdn, "SKT");
			if ("1000".equals(idpReceiverM.getResponseHeader().getResult())) {
				mobile_sign = idpReceiverM.getResponseBody().getMobile_sign();
				sign_data = idpReceiverM.getResponseBody().getSign_data();
				svc_mng_num = idpReceiverM.getResponseBody().getSvc_mng_num();
				model_id = idpReceiverM.getResponseBody().getModel_id();

				if ("".equals(svc_mng_num) || "".equals(model_id) || svc_mng_num == null || model_id == null) {
					result = "NOT_SKT";
				} else {
					result = "SUCCESS";
				}
			}
			log.debug("result :: " + result);
			// // 인증번호 생성
			// Random rand = new Random(System.currentTimeMillis()); // seed값을 배정하여 생성
			// int authNum = Math.abs(rand.nextInt(999999)+1);
			// log.info("<pupRegistMdn> MDN[" + mdn + "] Auth Number[" + authNum + "]");
			//
			// // 인증번호 전송 (개발기에서는 skip)
			// HttpServletRequest req = getRequest();
			// String serverIp = "";
			// if(req.getLocalAddr() != null) serverIp = req.getLocalAddr();
			// else if(req.getLocalName() != null) serverIp = req.getLocalName();
			// else serverIp = InetAddress.getLocalHost().getHostAddress();
			// if (!"211.234.235.65".equals(serverIp) && !"127.0.0.1".equals(serverIp) && !"localhost".equals(serverIp))
			// {
			// SendSmsUtil smsSend = new SendSmsUtil();
			// Message message = new Message(mdn, CodeConstWeb.TELECOM_SKT);
			// message.setBody("TStore 모바일 회원가입 인증번호는 [" + authNum + "] 입니다.");
			// MessageResult mr = smsSend.sendSms(message);
			// if(mr.isSuccess()){
			// log.info("<pupRegistMdn> Send SMS Success. MDN[" + mdn + "]");
			// result = "인증번호를 전송했습니다."; // 인증번호 성공
			// } else {
			// log.info("<pupRegistMdn> Send SMS Fail. MDN[" + mdn + "]");
			// }
			// } else {
			// result = "인증번호를 전송했습니다."; // 개발기에서는 SMS 전송 무조건 성공했다고 보고 진행
			// }
			//
			// // 인증번호 세션에 저장
			// SessionUtil.setAnySession(getRequest(), "AUTH_NUM_FOR_JOIN_WAP", authNum);
			// log.debug("AUTH_NUM_FOR_JOIN_WAP : " + SessionUtil.getAnySession(getRequest(), "AUTH_NUM_FOR_JOIN_WAP"));
		} catch (Exception e) {
			e.printStackTrace();
			log.error("<pupRegistMdn> ERROR. couse:" + e);
		}

		return SUCCESS;
	}

	/**
	 * 모바일 전용회원 회원가입 유무 판단.
	 * 
	 * @return
	 */
	public String pupCheckMdn() {
		try {
			String mdn = prePhoneNumber + phone_01 + phone_02;
			log.debug("mdn :: " + mdn + ", phone_auth_code :: " + phone_auth_code);
			log.debug("mobile_sign :: " + mobile_sign + ", sign_data :: " + sign_data);

			IDPReceiverM idpReceiverM = IDPManager.getInstance().mobileAuth(mdn, phone_auth_code, mobile_sign,
					sign_data);
			result = idpReceiverM.getResponseHeader().getResult();

			if ("1000".equals(result)) {
				// 회원가입 여부 판단
				IDPReceiverM idpReceiverM2 = IDPManager.getInstance().aleadyJoinCheck4Mdn(mdn);
				result = idpReceiverM2.getResponseBody().getJoin_type();

				int dupCnt = memberHpService.dupHpNum(mdn);
				log.info("DB Duplicate Member cnt : " + dupCnt);
				if (dupCnt > 0)
					result = "svc";
			} else {
				// 인증번호 틀림.
				log.info("<pupCheckMdn> Not Match AuthCode!");
				result = "NOT_MATCH";
			}

			// // 인증번호 확인
			// int authNumSS = (Integer) SessionUtil.getAnySession(getRequest(), "AUTH_NUM_FOR_JOIN_WAP");
			// log.debug("AUTH_NUM_FOR_JOIN_WAP :: " + authNumSS);
			// if (phone_auth_code.equals(authNumSS+"")) {
			// // 회원가입 여부 판단
			// IDPReceiverM idpReceiverM = IDPManager.getInstance().aleadyJoinCheck4Mdn(mdn);
			// result = idpReceiverM.getResponseBody().getJoin_type();
			// } else {
			// log.info("<pupCheckMdn> Not Match AuthCode!");
			// result = "NOT_MATCH";
			// }

		} catch (Exception e) {
			e.printStackTrace();
			log.error("<pupCheckMdn> ERROR. couse:" + e);
		}
		return SUCCESS;
	}

	/**
	 * 모바일 전용회원 회원가입
	 * 
	 * @return
	 */
	public String pupRegistMdnResult() {
		String resultPage = ERROR;
		try {
			String mdn = prePhoneNumber + phone_01 + phone_02;
			log.debug("mdn :: " + mdn);

			// 회원가입
			IDPReceiverM idpReceiverM = IDPManager.getInstance().join4Wap(mdn);
			result = idpReceiverM.getResponseHeader().getResult();

			if (IDPManager.IDP_RES_CODE_OK.equals(idpReceiverM.getResponseHeader().getResult())) {
				// 모바일 전용회원 회원가입
				consumerService.registMobileMember(idpReceiverM, useStatsYn);
				resultPage = SUCCESS;
				user_mdn = idpReceiverM.getResponseBody().getUser_mdn();
				svc_mng_num = idpReceiverM.getResponseBody().getSvc_mng_num();
				model_id = idpReceiverM.getResponseBody().getModel_id();

				/*
				 * 가입완료 시점에 자동으로 로그인 처리. 20100128 soohee (김웅 M)
				 */
				Member member = memberService.selectMemberByMbrNo(idpReceiverM.getResponseBody().getUser_key());
				memberService.insertLoginInfo(member.getMbrNo(), getRequest());
				// 세션 생성
				SessionUtil.setMemberSession(getRequest(), member);
				representPhone = topService.getRepresentPhone(member.getMbrNo());
				if (representPhone != null) {
					if (multiService.getPhoneCheck(representPhone.getPhoneModelCd())) {
						representPhone.setMultiPhoneYn("Y");
					} else {
						representPhone.setMultiPhoneYn("N");
					}
					SessionUtil.setAnySession(getRequest(), "REP_HP_SESSION", representPhone);
				} else {
					SessionUtil.removeAnySession(getRequest(), "REP_HP_SESSION");
				}
				if (representPhone != null) {
					// if(representPhone.getPhoneModelCd().indexOf("미지원") == 0){ 대체. 20100222 soohee
					if (!CommonUtil.isSupportPhone(representPhone.getPhoneModelCd())) {
						SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
					} else {
						SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "MYPHONE");
					}
				} else {
					SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
				}
			} else {
				log.warn("<pupRegistMdnResult> Join Mobile Member fail. result[" + result + "] result_text["
						+ idpReceiverM.getResponseHeader().getResult_text() + "]");
			}
		} catch (Exception e) {
			e.printStackTrace();
			log.error("<pupRegistMdnResult> REGIST MOBILE MEMBER ERROR. couse:" + e);
		}
		return resultPage;
	}

	public String pupWebAlreadyJoin() {
		return SUCCESS;
	}

	public String popupMdnNotJoin() {
		return SUCCESS;
	}

	/**
	 * TODO MDN 로그인
	 * <P/>
	 * MDN 로그인
	 * 
	 * @return
	 */
	public String getMdnLogin() {
		String mdn = prePhoneNumber + phone_01 + phone_02;

		Enumeration enums = null;
		enums = getRequest().getParameterNames();
		String requestName = "";
		log.info("========== IDP MDN LOGIN REQUEST AUTH NUMBER Reqest Variable Names START ==============================");
		while (enums.hasMoreElements()) {
			requestName = (String) enums.nextElement();
			log.info("names :" + requestName + ", value : " + getRequest().getParameter(requestName));
		}
		log.info("========== IDP MDN LOGIN REQUEST AUTH NUMBER Reqest Variable Names END==============================");
		if (result.equals("1000")) {
			return "success";
		} else {
			return "GET_FAIL";
		}
	}

	/**
	 * TODO MDN 로그인 결과
	 * <P/>
	 * MDN 로그인 결과
	 * 
	 * @return
	 */
	public String getMdnAuthResult() {

		String pageResult = "";

		Enumeration enums = null;
		enums = getRequest().getParameterNames();
		String requestName = "";
		log.info("========== IDP MDN LOGIN Reqest Variable Names START ==============================");
		while (enums.hasMoreElements()) {
			requestName = (String) enums.nextElement();
			log.info("names :" + requestName + ", value : " + getRequest().getParameter(requestName));
		}
		log.info("========== IDP MDN LOGIN Reqest Variable Names END==============================");

		if (result != null) {
			mobileLoginResult = result;
		}

		// 인증 성공일 경우 Login_info DB에 insert 한다.
		String mdn = "";
		if (user_mdn != null) {
			mdn = user_mdn.replace("-", "");
		}
		// 결과가 성공일 경우
		if (result.equals("1000")) {
			// member = memberService.selectMember(null, mdn);
			member = memberService.selectMemberByMbrNo(user_key);
			if (member != null) {
				member.setUser_auth_key(user_auth_key);
				member.setUser_key(user_key);
				memberService.insertLoginInfo(member.getMbrNo(), getRequest());
				// 세션을 생성한다.
				SessionUtil.setMemberSession(getRequest(), member);
				representPhone = topService.getRepresentPhone(member.getMbrNo());
				if (representPhone != null) {
					if (multiService.getPhoneCheck(representPhone.getPhoneModelCd())) {
						representPhone.setMultiPhoneYn("Y");
					} else {
						representPhone.setMultiPhoneYn("N");
					}
					SessionUtil.setAnySession(getRequest(), "REP_HP_SESSION", representPhone);
				}

				if (representPhone != null) {
					// if(representPhone.getPhoneModelCd().indexOf("미지원") == 0){ 대체. 20100222 soohee
					if (!CommonUtil.isSupportPhone(representPhone.getPhoneModelCd())) {
						SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
					} else {
						SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "MYPHONE");
					}
				} else {
					SessionUtil.setAnySession(getRequest(), "DO_PROVISIONING", "ALL");
				}
				SessionUtil.removeAnySession(getRequest(), "CHECK_PWD_SESSION");
				pageResult = "success";
			} else {
				pageResult = "error1";
			}
		} else if (result.equals("2204")) {
			pageResult = "error1";
		} else if (result.equals("2900") || result.equals("2216")) {
			pageResult = "error2";
		} else if (result.equals("2202")) {
			pageResult = "auth_number_fail";
		} else {
			pageResult = "error1";
		}

		return pageResult;
	}

	/**
	 * 통합서버에서 호출하는 SSO 로그아웃
	 * <P/>
	 * 로그아웃
	 * 
	 * @return
	 */
	public void getLogout() {
		Enumeration enums = null;
		enums = getRequest().getParameterNames();
		String requestName = "";
		log.info("========== IDP LOGOUT Reqest Variable Names START ==============================");
		while (enums.hasMoreElements()) {
			requestName = (String) enums.nextElement();
			log.info("names :" + requestName + ", value : " + getRequest().getParameter(requestName));
		}
		log.info("========== IDP LOGOUT Reqest Variable Names END==============================");

		try {
			if (null != SessionUtil.getMemberSession(getRequest())) {
				ringBellService.logOut();
				member = (Member) SessionUtil.getMemberSession(getRequest());
				SessionUtil.removeMemberSession(getRequest());
				SessionUtil.removeAnySession(getRequest(), "REP_HP_SESSION");
				SessionUtil.removeAnySession(getRequest(), "NOT_LOGIN_REP_HP_SESSION");
				SessionUtil.removeAnySession(getRequest(), "DO_PROVISIONING");
				SessionUtil.removeAnySession(getRequest(), "adultAuth"); // 세션 유지되는 동안 19금 상품 성인인증 1회 체크
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/*
	 * 기존아이디 로그아웃
	 */
	public String getIdpLogout() {
		Enumeration enums = null;
		enums = getRequest().getParameterNames();
		String requestName = "";
		log.info("========== IDP LOGOUT Reqest Variable Names START ==============================");
		while (enums.hasMoreElements()) {
			requestName = (String) enums.nextElement();
			log.info("names :" + requestName + ", value : " + getRequest().getParameter(requestName));
		}
		log.info("========== IDP LOGOUT Reqest Variable Names END==============================");

		try {
			ringBellService.logOut();
			member = (Member) SessionUtil.getMemberSession(getRequest());
			SessionUtil.removeMemberSession(getRequest());
			SessionUtil.removeAnySession(getRequest(), "REP_HP_SESSION");
			SessionUtil.removeAnySession(getRequest(), "NOT_LOGIN_REP_HP_SESSION");
			SessionUtil.removeAnySession(getRequest(), "DO_PROVISIONING");
			SessionUtil.removeAnySession(getRequest(), "adultAuth"); // 세션 유지되는 동안 19금 상품 성인인증 1회 체크
		} catch (Exception e) {
			e.printStackTrace();
		}
		return SUCCESS;
	}

	/*
	 * 통합아이디 로그아웃
	 */
	public String getImLogout() {
		Enumeration enums = null;
		enums = getRequest().getParameterNames();
		String requestName = "";
		log.info("========== IM IDP LOGOUT Reqest Variable Names START ==============================");
		while (enums.hasMoreElements()) {
			requestName = (String) enums.nextElement();
			log.info("names :" + requestName + ", value : " + getRequest().getParameter(requestName));
		}
		log.info("========== IM IDP LOGOUT Reqest Variable Names END==============================");

		ringBellService.logOut();

		member = (Member) SessionUtil.getMemberSession(getRequest());
		SessionUtil.removeMemberSession(getRequest());
		SessionUtil.removeAnySession(getRequest(), "REP_HP_SESSION");
		SessionUtil.removeAnySession(getRequest(), "NOT_LOGIN_REP_HP_SESSION");
		SessionUtil.removeAnySession(getRequest(), "DO_PROVISIONING");
		SessionUtil.removeAnySession(getRequest(), "adultAuth"); // 세션 유지되는 동안 19금 상품 성인인증 1회 체크
		StatisticsLogUtil.writeLog(getRequest());
		return SUCCESS;
	}

	public String getMdnAuthResultConfirm() {
		telecomList = CacheCommCode.getCommCode(CommCodeGroupDefinitions.GRP_CD_US_TELECOM);
		return result;
	}

	public String chkPasswordAjax() {
		log.debug("chkPasswordAjax start()");
		PrintWriter writer = null;
		String resultCode = "";

		try {

			JSONObject jsonObject = new JSONObject();
			HttpServletRequest request = getRequest();
			HttpServletResponse response = getResponse();

			String userId = request.getParameter("user_id") == null ? "" : request.getParameter("user_id");
			String userPwd = request.getParameter("user_passwd") == null ? "" : request.getParameter("user_passwd");

			member = (Member) SessionUtil.getMemberSession(getRequest());

			if (member.getMbrId().equals(userId)) {// 20120830 변조 방지 처리
				String result = "";
				String imResult = "";
				boolean chk = memberService.isImMemberCheck(userId);
				if (chk) { // 통합IDP 회원
					imIdpReceiverM = ImIDPManager.getInstance().checkIdPwdAuth(userId, userPwd);
					imResult = imIdpReceiverM.getResponseHeader().getResult();

				} else { // 기존 IDP 회원
					idpReceiverM = IDPManager.getInstance().userAuthForId(userId, userPwd);
					result = idpReceiverM.getResponseHeader().getResult();
				}

				int chMeb = -1;
				if (result != null && !"".equals(result)) {
					chMeb = Integer.parseInt(result);
				}

				if (chMeb == 1000 || imResult.equals(ImIDPConstants.IDP_RES_CODE_OK)) {
					resultCode = "AUTH_OK";
				} else if (chMeb == 2201 || imResult.equals(ImIDPConstants.IDP_RES_CODE_WRONG_PASSWD)) {
					resultCode = "WRONG_PWD";
				}
			}

			jsonObject.put("resultCode", resultCode);

			writer = response.getWriter();
			writer.write(jsonObject.toString());
		} catch (Exception e) {
			e.printStackTrace();
			log.error("비밀번호 확인 중 에러가 발생하였습니다. " + e);
			// throw e;
		} finally {
			if (writer != null) {
				writer.close();
			}
		}
		return SUCCESS;
	}

	public String popupWaitMember() {
		// 이메일 주소 조회
		emailList = consumerService.getEmailList();
		if (user_id != null) {
			member = memberService.selectMember(user_id, null); // 타채널 팝업에 사용
			setEmail(member.getEmailAddr());
			log.info("======>>>>>" + member.getEmailAddr());
		}
		return SUCCESS;
	}

	public String popupPunishMember() {
		return SUCCESS;
	}

	/*
	 * SEND MAIL ID FIND RETURN = FAIL OR SENDMAIL
	 */
	public String sendPasswordMail(String SENDER, String RECEIVER, String header, String contents) {

		Connection con = null;
		Calendar cal = Calendar.getInstance();
		Timestamp ts = new Timestamp(cal.getTimeInMillis());

		try {
			Class.forName("oracle.jdbc.driver.OracleDriver").newInstance();
			con = DriverManager.getConnection("jdbc:oracle:thin:@" + Constants.USER_EMAIL_DB_URL + ":"
					+ Constants.USER_EMAIL_DB_PORT + ":" + Constants.USER_EMAIL_DB_NAME, Constants.USER_EMAIL_DB_ID,
					Constants.USER_EMAIL_DB_PASS);

			if (con != null) {
				con.setAutoCommit(false);

				Vector vt = new Vector();
				// vt.addElement(new String[] {contents});
				String[] param = header.split(",");
				SendMail sm = new SendMail(con);

				if (sm.setRecipient(0, null, param[3], RECEIVER, param, vt) == SendMail.SUCCESS) {
					if (sm.reserveMail(0, "T store", SENDER, null, "[T store] 임시 비밀번호가 발급 되었습니다.",
							SendMail.CONTENT_TEMPLATEDB, 4, "100", "", ts) == SendMail.SUCCESS) {
						try {
							con.commit();
						} catch (Exception ex) {
						}
						RESULT = "SENDEMAIL";
					} else {
						try {
							con.rollback();
						} catch (Exception ex) {
						}
					}
				} else {
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		} finally {
			try {
				if (con != null) {
					con.close();
				}
			} catch (Exception e) {
			}
		}
		return RESULT;
	}

	public String pupIdTurn() {
		String mdn = prePhoneNumber + phone_01 + phone_02;
		log.info("<pupIdTurn> mdn :: " + mdn);

		try {
			MemberHp memberHp = new MemberHp();
			memberHp.setHpNo(mdn);
			memberHp.setMbrNo("");
			List<MemberHp> list = memberHpService.getValidMobileMemberHp(memberHp);
			if (null != list) {
				String mbrNo = list.get(0).getMbrNo();

				List<MemberHp> list2 = memberHpService.selectHpByMbrNo(mbrNo);
				model_id = list2.get(0).getPhoneModelCd();
			}
			user_mdn = mdn;

			log.debug("model_id :: " + model_id);
		} catch (Exception e) {
			e.printStackTrace();
			log.error("<pubIdTurn> ERROR. couse:" + e);
		}

		return SUCCESS;
	}

	public String pupIdRegist() {
		String mdn = prePhoneNumber + phone_01 + phone_02;
		log.info("<pupIdRegist> mdn :: " + mdn);

		return SUCCESS;
	}

	public String pupSelectJoinType() {
		String mdn = prePhoneNumber + phone_01 + phone_02;
		log.info("<pupSelectJoinType> mdn :: " + mdn);

		return SUCCESS;
	}

	public String viewIntroChangeWeb() {
		return SUCCESS;
	}

	public String getMobileStore() {
		return SUCCESS;
	}

	/**
	 * 입력한 아이디가 타 서비스 가입 아이디 인 경우, T store 미 가입 팝업.
	 * 
	 * @return
	 */
	public String popupAnother() {
		return SUCCESS;
	}

	public String getLoginId() {
		return loginId;
	}

	public void setLoginId(String loginId) {
		this.loginId = loginId;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPhone_01() {
		return phone_01;
	}

	public void setPhone_01(String phone_01) {
		this.phone_01 = phone_01;
	}

	public String getPhone_02() {
		return phone_02;
	}

	public void setPhone_02(String phone_02) {
		this.phone_02 = phone_02;
	}

	public int getLoginResult() {
		return loginResult;
	}

	public void setLoginResult(int loginResult) {
		this.loginResult = loginResult;
	}

	public String getUser_code() {
		return user_code;
	}

	public void setUser_code(String user_code) {
		this.user_code = user_code;
	}

	public String getMobile_sign() {
		return mobile_sign;
	}

	public void setMobile_sign(String mobile_sign) {
		this.mobile_sign = mobile_sign;
	}

	public String getCmd() {
		return cmd;
	}

	public void setCmd(String cmd) {
		this.cmd = cmd;
	}

	public String getResult_text() {
		return result_text;
	}

	public void setResult_text(String result_text) {
		this.result_text = result_text;
	}

	public String getResp_url() {
		return resp_url;
	}

	public void setResp_url(String resp_url) {
		this.resp_url = resp_url;
	}

	public String getResp_type() {
		return resp_type;
	}

	public void setResp_type(String resp_type) {
		this.resp_type = resp_type;
	}

	public String getUser_id() {
		return user_id;
	}

	public void setUser_id(String user_id) {
		this.user_id = user_id;
	}

	public String getSp_auth_key() {
		return sp_auth_key;
	}

	public void setSp_auth_key(String sp_auth_key) {
		this.sp_auth_key = sp_auth_key;
	}

	public String getResp_flow() {
		return resp_flow;
	}

	public void setResp_flow(String resp_flow) {
		this.resp_flow = resp_flow;
	}

	public String getSp_id() {
		return sp_id;
	}

	public void setSp_id(String sp_id) {
		this.sp_id = sp_id;
	}

	public String getUser_mdn() {
		return user_mdn;
	}

	public void setUser_mdn(String user_mdn) {
		this.user_mdn = user_mdn;
	}

	public String getSign_data() {
		return sign_data;
	}

	public void setSign_data(String sign_data) {
		this.sign_data = sign_data;
	}

	public String getUser_mdn1() {
		return user_mdn1;
	}

	public void setUser_mdn1(String user_mdn1) {
		this.user_mdn1 = user_mdn1;
	}

	public String getUser_mdn2() {
		return user_mdn2;
	}

	public void setUser_mdn2(String user_mdn2) {
		this.user_mdn2 = user_mdn2;
	}

	public String getUser_mdn3() {
		return user_mdn3;
	}

	public void setUser_mdn3(String user_mdn3) {
		this.user_mdn3 = user_mdn3;
	}

	public String getPhone_auth_code() {
		return phone_auth_code;
	}

	public void setPhone_auth_code(String phone_auth_code) {
		this.phone_auth_code = phone_auth_code;
	}

	public String getSvc_mng_num() {
		return svc_mng_num;
	}

	public void setSvc_mng_num(String svc_mng_num) {
		this.svc_mng_num = svc_mng_num;
	}

	public String getMobileLoginResult() {
		return mobileLoginResult;
	}

	public void setMobileLoginResult(String mobileLoginResult) {
		this.mobileLoginResult = mobileLoginResult;
	}

	public String getUser_auth_key() {
		return user_auth_key;
	}

	public void setUser_auth_key(String user_auth_key) {
		this.user_auth_key = user_auth_key;
	}

	public String getUser_key() {
		return user_key;
	}

	public void setUser_key(String user_key) {
		this.user_key = user_key;
	}

	public RepresentPhone getRepresentPhone() {
		return representPhone;
	}

	public void setRepresentPhone(RepresentPhone representPhone) {
		this.representPhone = representPhone;
	}

	public String getPrePhoneNumber() {
		return prePhoneNumber;
	}

	public void setPrePhoneNumber(String prePhoneNumber) {
		this.prePhoneNumber = prePhoneNumber;
	}

	public String getModel_id() {
		return model_id;
	}

	public void setModel_id(String model_id) {
		this.model_id = model_id;
	}

	public String getLoginResultMsg() {
		return loginResultMsg;
	}

	public void setLoginResultMsg(String loginResultMsg) {
		this.loginResultMsg = loginResultMsg;
	}

	public String getRedirectActionURL() {
		return redirectActionURL;
	}

	public void setRedirectActionURL(String redirectActionURL) {
		this.redirectActionURL = redirectActionURL;
	}

	public String getRedirectActionParam() {
		return redirectActionParam;
	}

	public void setRedirectActionParam(String redirectActionParam) {
		this.redirectActionParam = redirectActionParam;
	}

	public MemberPunish getMemberPunish() {
		return memberPunish;
	}

	public void setMemberPunish(MemberPunish memberPunish) {
		this.memberPunish = memberPunish;
	}

	public String getCheckMdnAuth() {
		return checkMdnAuth;
	}

	public void setCheckMdnAuth(String checkMdnAuth) {
		this.checkMdnAuth = checkMdnAuth;
	}

	public String getLoginRedirectURL() {
		return loginRedirectURL;
	}

	public void setLoginRedirectURL(String loginRedirectURL) {
		this.loginRedirectURL = loginRedirectURL;
	}

	public String getGnbLoginRedirectURL() {
		return gnbLoginRedirectURL;
	}

	public void setGnbLoginRedirectURL(String gnbLoginRedirectURL) {
		this.gnbLoginRedirectURL = gnbLoginRedirectURL;
	}

	public String getV4SprtYn() {
		return v4SprtYn;
	}

	public String getHpNo() {
		return hpNo;
	}

	public void setHpNo(String hpNo) {
		this.hpNo = hpNo;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public List<Member> getEmailList() {
		return emailList;
	}

	public void setEmailList(List<Member> emailList) {
		this.emailList = emailList;
	}

	public String getUser_mdn_type() {
		return user_mdn_type;
	}

	public void setUser_mdn_type(String user_mdn_type) {
		this.user_mdn_type = user_mdn_type;
	}

	public String getIm_int_svc_no() {
		return im_int_svc_no;
	}

	public void setIm_int_svc_no(String im_int_svc_no) {
		this.im_int_svc_no = im_int_svc_no;
	}

	public String getJoin_sst_list() {
		return join_sst_list;
	}

	public void setJoin_sst_list(String join_sst_list) {
		this.join_sst_list = join_sst_list;
	}

	public String getJoin_site() {
		return join_site;
	}

	public void setJoin_site(String join_site) {
		this.join_site = join_site;
	}

	public String getImSvcNo() {
		return imSvcNo;
	}

	public void setImSvcNo(String imSvcNo) {
		this.imSvcNo = imSvcNo;
	}

	public String getImgSign() {
		return imgSign;
	}

	public void setImgSign(String imgSign) {
		this.imgSign = imgSign;
	}

	public String getSignData() {
		return signData;
	}

	public void setSignData(String signData) {
		this.signData = signData;
	}

	public String getImgUrl() {
		return imgUrl;
	}

	public void setImgUrl(String imgUrl) {
		this.imgUrl = imgUrl;
	}

	public String getResultText() {
		return resultText;
	}

	public void setResultText(String resultText) {
		this.resultText = resultText;
	}

	public String getChange_type() {
		return change_type;
	}

	public void setChange_type(String change_type) {
		this.change_type = change_type;
	}

	public String getLoginFailURL() {
		return loginFailURL;
	}

	public void setLoginFailURL(String loginFailURL) {
		this.loginFailURL = loginFailURL;
	}

	public String getSp_url() {
		return sp_url;
	}

	public void setSp_url(String sp_url) {
		this.sp_url = sp_url;
	}

	public String getStActionPositionNm() {
		return stActionPositionNm;
	}

	public void setStActionPositionNm(String stActionPositionNm) {
		this.stActionPositionNm = stActionPositionNm;
	}

	public String getStPrePageNm() {
		return stPrePageNm;
	}

	public void setStPrePageNm(String stPrePageNm) {
		this.stPrePageNm = stPrePageNm;
	}

	public String getStrCurrPageNm() {
		return strCurrPageNm;
	}

	public void setStrCurrPageNm(String strCurrPageNm) {
		this.strCurrPageNm = strCurrPageNm;
	}

}
