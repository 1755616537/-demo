package ZhiFuFen

import (
	"4/API/WeiXin"
	"time"
)

//支付分获取证书
func ZhiFuFenHuoQuZhengShu()string  {
	method:="GET"
	openid:="oIbBd6BLlrkNuQJsN6jWwh1Z3PdA"
	appid:="wx32238000bf89db68"
	service_id:="00004000000000740485051164945313"
	//url:="/v3/payscore/permissions/openid/oIbBd6BLlrkNuQJsN6jWwh1Z3PdA?appid=wx32238000bf89db68&service_id=00004000000000740485051164945313"
	url:="/v3/payscore/user-service-state?service_id="+service_id+"&appid="+appid+"&openid="+openid
	data := make(map[string]interface{})
	data["service_id"] =service_id
	data["appid"] = appid
	data["openid"] = openid

	packageString:= WeiXin.Get(method,url,data,"4D14847ECF54E76D07B6AF4882BCA497DD3EBD7A","1555281461","D:\\ZhangGuoBiao\\万物互联网\\万物互联网/apiclient_key.pem");
	return packageString
}
//创建支付分订单API
func ChuangJianZhiFuFenDingDan()string  {
	//商户服务订单号
	out_order_no:="1234323JKHDFE1243252"
	//公众账号ID
	appid:="wxaf0fb50363b5e46e"
	//服务ID
	service_id:="00004000000000740485051164945313"
	//服务信息
	service_introduction:="无人售货柜"
	//服务开始时间
	start_time:=time.Now().Format("20060102150405")
	//服务开始时间备注
	start_time_remark:="开始购物日期"
	//服务开始地点
	start_location:="广西南宁1号"
	//预计服务结束位置
	end_location:="广西南宁1号"
	//风险金名称
	risk_fund_name:="ESTIMATE_ORDER_COST"
	//风险金额
	risk_fund_amount:=200
	//风险说明
	description:="购物的预估费用"
	//商户回调地址
	notify_url:="http://pay.gz-ego.com/creditpayex/sign/wepay/n/1555281461"
	//用户标识
	openid:=""
	//是否需要用户确认
	need_user_confirm:=true

	method:="POST"
	url:="/v3/payscore/serviceorder"

	data := make(map[string]interface{})
	data["out_order_no"]=out_order_no
	data["appid"]=appid
	data["service_id"]=service_id
	data["service_introduction"]=service_introduction
	//服务时间段
	time_range:= make(map[string]interface{})
	time_range["start_time"]=start_time
	time_range["start_time_remark"]=start_time_remark
	data["time_range"]=time_range
	//服务位置
	location:= make(map[string]interface{})
	location["start_location"]=start_location
	location["end_location"]=end_location
	data["location"]=location
	//订单风险金
	risk_fund:= make(map[string]interface{})
	risk_fund["name"]=risk_fund_name
	risk_fund["amount"]=risk_fund_amount
	risk_fund["description"]=description
	data["risk_fund"]=risk_fund
	data["notify_url"]=notify_url
	data["openid"]=openid
	data["need_user_confirm"]=need_user_confirm

	packageString:= WeiXin.Get(method,url,data,"4D14847ECF54E76D07B6AF4882BCA497DD3EBD7A","1555281461","D:\\ZhangGuoBiao\\万物互联网\\万物互联网/apiclient_key.pem");
	return packageString
}