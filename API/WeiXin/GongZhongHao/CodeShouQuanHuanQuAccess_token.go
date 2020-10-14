package GongZhongHao

import (
	"4/API"
	"errors"
	"fmt"
)

var appid string = "wx32238000bf89db68"
var appsecret string = "ce096d218c3c8c2956c8809bbe88f916"

//公众号授权成功-Code授权换取Access_token
func CodeShouQuanHuanQuAccess_token(code string)(map[string]interface{},error) {
	url := fmt.Sprint(
		"https://api.weixin.qq.com/sns/oauth2/access_token?appid=",
		appid,
		"&secret=",
		appsecret,
		"&code=",
		code,
		"&grant_type=authorization_code",
	)
	//HTTP请求
	resData, err :=API.Json_MapString(API.HTTPGet("GET", url, map[string]interface{}{}))
	if nil!=err {
		return nil,errors.New("请求http错误,解析数据错误")
	}
	//错误信息验证
	if nil!=resData["errcode"] {
		if nil==resData["errmsg"]{
			return nil,errors.New("请求http错误,未定义错误信息")
		}
		return nil,errors.New(fmt.Sprint(resData["errmsg"]))
	}
	//数据结构是否完整
	if nil==resData["access_token"] {
		return nil,errors.New("access_token获取不到")
	}
	if nil==resData["openid"]{
		return nil,errors.New("openid获取不到")
	}

	return resData,nil;
}
