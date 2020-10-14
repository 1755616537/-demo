package GongZhongHao

import (
	"4/API"
	"errors"
	"fmt"
)

//获取用户信息
func GetYongHuXinXi(access_token string,openid string)(map[string]interface{},error)  {
	url := fmt.Sprint(
		"https://api.weixin.qq.com/sns/userinfo?access_token=",
		access_token,
		"&openid=",
		openid,
		"&lang=zh_CN",
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

	return resData,nil;
}
