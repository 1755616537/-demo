package ZhiFuFen

import "4/API/WeiXin"

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
