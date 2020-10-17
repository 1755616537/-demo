package GongZhongHao

import (
	"4/API/WeiXin"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gogf/gf/encoding/gjson"
	"net/http"
	"strconv"
	"time"
)

//JSAPI支付下单
func GetXiaDan() (string, error) {
	method := "POST"
	url := "/v3/pay/transactions/jsapi"
	data := make(map[string]interface{})
	//公众号ID
	data["appid"] = "wx32238000bf89db68"
	//直连商户号
	data["mchid"] = "1602157237"
	//商品描述
	data["description"] = "广西-机柜1-苹果 "
	//商户订单号
	data["out_trade_no"] = "1217752501201407033233368021"
	//通知地址
	data["notify_url"] = "https://m-store.com.cn/lingshou/wx/callback/pay_notify"
	//订单金额
	amount := make(map[string]interface{})
	//总金额
	amount["total"] = 1
	//货币类型
	amount["currency"] = "CNY"
	data["amount"] = amount
	//支付者
	payer := make(map[string]interface{})
	//用户标识
	payer["openid"] = "oIbBd6DlJZ1uURUq1w3BwEAuk-xo"
	data["payer"] = payer

	//Administrator
	_, _, packageString,_ := WeiXin.Get(method, url, data, "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233", "1602157237", "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	fmt.Println("JSAPI下单", packageString)

	packageJson := make(map[string]interface{})
	err := json.Unmarshal([]byte(packageString), &packageJson)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	package2 := fmt.Sprintln(packageJson["prepay_id"])
	//package2:="wx25123031790770b381e781da1301dc0000"
	return package2, nil
}

//JSAPI支付
func GetZhiFu(package2 string) {
	appId := "wx32238000bf89db68"
	nonce_str := "1YjQ56C6lwFcWO17s9LFYxzbYX0M38b1"       //32位随机字符串
	timestamp := strconv.FormatInt(time.Now().Unix(), 10) //时间戳
	fmt.Println("JSAPI支付时间戳", timestamp)
	signature, _ := WeiXin.SignJSAPI(appId, timestamp, nonce_str, "prepay_id="+package2, "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	fmt.Println("JSAPI支付签名", signature)
}

//获取平台证书
func GetPingTaiZhengShu() (string,http.Header, error) {
	//packageString := WeiXin.Get("GET", "/v3/certificates", nil, "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233", "1602157237", "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	resHeader, resStatusCode, resbody,err := WeiXin.Get("GET", "/v3/certificates", nil, "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233", "1602157237", "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	if err != nil {
		return "", nil, err
	}
	if resStatusCode != 200 {
		return "",nil, errors.New(fmt.Sprint("请求StatusCode异常", resStatusCode))
	}
	fmt.Println("获取平台证书", "Header", resHeader)
	//转换格式
	jsonRetBody, err := gjson.DecodeToJson(resbody)
	if err != nil {
		return "", nil, errors.New(fmt.Sprint("获取平台证书","解析jsonRetBody失败"))
	}
	if jsonRetBody.Get("code") != nil {
		return "",nil, errors.New(fmt.Sprint(jsonRetBody.GetString("code"), jsonRetBody.GetString("message")))
	}
	//验证头部信息是否完整
	WechatpayNonce := resHeader.Get("Wechatpay-Nonce")
	WechatpaySerial := resHeader.Get("Wechatpay-Serial")
	WechatpaySignature := resHeader.Get("Wechatpay-Signature")
	WechatpayTimestamp := resHeader.Get("Wechatpay-Timestamp")
	if WechatpayNonce == "" || WechatpaySerial == "" || WechatpaySignature == "" || WechatpayTimestamp == "" {
		return "",nil, errors.New("请求的平台证书头部信息不完整")
	}
	fmt.Println("获取平台证书", "HTTP请求结果", resbody)
	return resbody,resHeader, nil
}

//获取指定平台证书
//需要传递（获取平台证书返回的数据的jsonresbody类型数据）
func GetZhiDingPingTaiZhengShu(serial_no string, PingTaiZhengShuList *gjson.Json,resHeader http.Header) (string, string, error) {
	for i := 0; i < len(PingTaiZhengShuList.GetArray("data")); i++ {
		dataSerial_no := PingTaiZhengShuList.GetString(fmt.Sprint("data.", i, ".serial_no"))
		dataAlgorithm := PingTaiZhengShuList.GetString(fmt.Sprint("data.", i, ".encrypt_certificate.algorithm"))
		dataNonce := PingTaiZhengShuList.GetString(fmt.Sprint("data.", i, ".encrypt_certificate.nonce"))
		dataAssociated_data := PingTaiZhengShuList.GetString(fmt.Sprint("data.", i, ".encrypt_certificate.associated_data"))
		dataCiphertext := PingTaiZhengShuList.GetString(fmt.Sprint("data.", i, ".encrypt_certificate.ciphertext"))
		if dataSerial_no == "" || dataAlgorithm == "" || dataNonce == "" || dataAssociated_data == "" || dataCiphertext == "" {
			fmt.Println("平台证书", i, "缺少参数")
			continue
		}
		if serial_no == dataSerial_no {
			data, err := WeiXin.JieMiBaoWen("", dataAlgorithm, dataCiphertext, dataNonce, dataAssociated_data,resHeader)
			if err != nil {
				return "", "", err
			}
			return data, PingTaiZhengShuList.GetString(fmt.Sprint("data.", i)), nil
		}
	}
	return "", "", errors.New(fmt.Sprint("获取指定平台证书", "找不到对应证书", serial_no))
}

//验签入口
func YanQianRuKou(PingTaiZhengShuList *gjson.Json,resHeader http.Header,sign map[string]string) (bool,error) {
	//获取指定平台证书
	PingTaiZhengShuData, dataPingTaiZhengShu, err := GetZhiDingPingTaiZhengShu(sign["wxSerial"], PingTaiZhengShuList,resHeader)
	if err != nil {
		return false,err
	}
	jsonDataPingTaiZhengShu := gjson.New(dataPingTaiZhengShu)
	//请求类型
	sign["method"] = "POST"
	res, err := YanQian(
		sign,
		jsonDataPingTaiZhengShu.GetString("serial_no"),
		jsonDataPingTaiZhengShu.GetString("encrypt_certificate.ciphertext"),
		jsonDataPingTaiZhengShu.GetString("encrypt_certificate.nonce"),
		jsonDataPingTaiZhengShu.GetString("encrypt_certificate.associated_data"),
		PingTaiZhengShuData,
	)
	return res,err
}

//验签
func YanQian(sign map[string]string, serial_no string, PUBLICKEY string, ZHnonce string, ZHassociated_data string, PingTaiZhengShuData string) (bool, error) {
	//请求类型
	if sign["method"] != "POST" {
		return false, errors.New("错误请求类型")
	}

	time := sign["timestamp"]      //HTTP头Wechatpay-Timestam时间戳
	nonce := sign["nonce"]         //HTTP头Wechatpay-Nonce随机字符串
	signature := sign["signature"] //HTTP头Wechatpay-Signature应答签名
	body := sign["body"]           //应答主体
	wxSerial := sign["wxSerial"]   //HTTP头Wechatpay-Serial证书序列号

	//验签之前需要先验证平台证书序列号是否正确一致
	if serial_no != wxSerial {
		fmt.Println("证书号", serial_no, wxSerial)
		return false, errors.New("证书号错误或已过期")
	}

	checkStr := time + "\n" + nonce + "\n" + body + "\n"
	_ = WeiXin.SetBaoCunWenBenDaoWenJian(checkStr, "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\平台证书/明文.txt")

	//解密signature base64
	signatureB64, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	_ = WeiXin.SetBaoCunWenBenDaoWenJian(string(signatureB64), "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\平台证书/签名.txt")

	fmt.Println("平台证书", PingTaiZhengShuData)
	_ = WeiXin.SetBaoCunWenBenDaoWenJian(PingTaiZhengShuData, "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\平台证书/证书.pem")
	GongYao, err := WeiXin.GetZhengShuQuGongYao(PingTaiZhengShuData)
	if err != nil {
		return false, err
	}

	//生成散列值
	hashed := sha256.Sum256([]byte(checkStr))
	//验签
	err = rsa.VerifyPKCS1v15(GongYao.(*rsa.PublicKey), crypto.SHA256, hashed[:], signatureB64)
	if err != nil {
		return false, err
	}
	return true, nil
}
