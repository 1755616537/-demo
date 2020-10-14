package GongZhongHao

import (
	"4/API/WeiXin"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"strconv"
	"time"
)

//JSAPI支付下单
func GetXiaDan()string  {
	method:="POST"
	url:="/v3/pay/transactions/jsapi"
	data := make(map[string]interface{})
	data["appid"] = "wx32238000bf89db68"
	data["mchid"] = "1602157237"
	data["description"] = "广西-机柜1-苹果 "
	data["out_trade_no"] = "1217752501201407033233368020"
	data["notify_url"] = "https://m-store.com.cn/lingshou/wx/callback/pay_notify"
	amount := make(map[string]interface{})
	amount["total"]=1
	amount["currency"]="CNY"
	data["amount"]=amount
	payer:= make(map[string]interface{})
	payer["openid"]="oIbBd6DlJZ1uURUq1w3BwEAuk-xo"
	data["payer"]=payer

	packageString:= WeiXin.Get(method,url,data,"5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233","1602157237","C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem");
	fmt.Println("JSAPI下单",packageString)

	packageJson := make(map[string]interface{})
	err := json.Unmarshal([]byte(packageString), &packageJson)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	package2:=fmt.Sprintln(packageJson["prepay_id"])
	//package2:="wx25123031790770b381e781da1301dc0000"
	return package2
}

//JSAPI支付
func GetZhiFu(package2 string)  {
	appId:="wx32238000bf89db68"
	nonce_str := "1YjQ56C6lwFcWO17s9LFYxzbYX0M38b1" //32位随机字符串
	timestamp := strconv.FormatInt(time.Now().Unix(), 10) //时间戳
	fmt.Println("JSAPI支付时间戳",timestamp)
	signature, _ := WeiXin.SignJSAPI(appId,timestamp,nonce_str, "prepay_id="+package2,"C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	fmt.Println("JSAPI支付签名",signature)
}

//JSAPI支付回调-取得回复后调用此方法进行签名验证
func CheckSign(sign map[string]string,serial_no string,keypath string) (bool, error) {
	time := sign["timestamp"]//HTTP头Wechatpay-Timestam时间戳
	nonce := sign["nonce"]//HTTP头Wechatpay-Nonce随机字符串
	signature := sign["signature"]//HTTP头Wechatpay-Signature应答签名
	body := sign["body"]//应答主体
	wxSerial := sign["wxSerial"]//HTTP头Wechatpay-Serial证书序列号

	//验签之前需要先验证平台证书序列号是否正确一致
	if serial_no != wxSerial {
		return false, errors.New("证书号错误或已过期")
	}

	checkStr := time + "\n" + nonce + "\n" + body + "\n"

	//读证书文件
	//var keypath = "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/cert.pem"
	key, err := ioutil.ReadFile(keypath)
	//从证书中提取公钥
	blocks, _ := pem.Decode(key)
	if blocks == nil || blocks.Type != "PUBLIC KEY" {
		return false, errors.New("无法解码公钥")
	}
	//解密base64
	oldSign, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	//解析公钥
	publicKey, err := x509.ParsePKIXPublicKey(blocks.Bytes)
	if err != nil {
		return false, err
	}
	//生成散列值
	hashed := sha256.Sum256([]byte(checkStr))
	//验签
	err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], oldSign)
	if err != nil {
		return false, err
	}
	return true, err
}
