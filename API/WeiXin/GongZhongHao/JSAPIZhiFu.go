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
	_, _, packageString := WeiXin.Get(method, url, data, "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233", "1602157237", "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
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
func GetPingTaiZhengShu() (map[string]interface{},http.Header, error) {
	//packageString := WeiXin.Get("GET", "/v3/certificates", nil, "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233", "1602157237", "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	resHeader, resStatusCode, resbody := WeiXin.Get("GET", "/v3/certificates", nil, "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233", "1602157237", "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	fmt.Println("获取平台证书", "Header", resHeader)
	//转换格式
	jsonRetBody, err := gjson.DecodeToJson(resbody)
	if err != nil {
		return nil, nil, errors.New(fmt.Sprint("获取平台证书","解析jsonRetBody失败"))
	}
	//验证头部信息是否完整
	WechatpayNonce := resHeader.Get("Wechatpay-Nonce")
	WechatpaySerial := resHeader.Get("Wechatpay-Serial")
	WechatpaySignature := resHeader.Get("Wechatpay-Signature")
	WechatpayTimestamp := resHeader.Get("Wechatpay-Timestamp")
	if WechatpayNonce == "" || WechatpaySerial == "" || WechatpaySignature == "" || WechatpayTimestamp == "" {
		return nil,nil, errors.New("请求的平台证书头部信息不完整")
	}

	if jsonRetBody.Get("code") != nil {
		return nil,nil, errors.New(fmt.Sprint(jsonRetBody.GetString("code"), jsonRetBody.GetString("message")))
	}
	if resStatusCode != 200 {
		return nil,nil, errors.New(fmt.Sprint("请求StatusCode异常", resStatusCode))
	}
	fmt.Println("获取平台证书", "HTTP请求结果", resbody)
	packageJson := make(map[string]interface{})
	err = json.Unmarshal([]byte(resbody), &packageJson)
	if err != nil {
		return nil,nil, err
	}
	return packageJson,resHeader, nil
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

func CheckSign2(PingTaiZhengShuList *gjson.Json,resHeader http.Header) (bool,error) {
	sign := map[string]string{}
	////HTTP头Wechatpay-Timestam时间戳
	//sign["timestamp"] = "1601034297"
	////HTTP头Wechatpay-Nonce随机字符串
	//sign["nonce"] = "qlLWeXWfPQeUwVqfhiW7VR37ilLa7gKI"
	////HTTP头Wechatpay-Signature应答签名
	//sign["signature"] = "gociYGOSPQWRhT9yo65D0PFzs/gG+9E81j42MgIcfwEgLymM0FrqrdnlMJsBYgPGP3HmxS1TW6DEgU8LiHek8pZi8e6cLwM7/4k0CF1FbHACGsN7NjGpgUQUM1g/DFP34aWTRDvjuJ8NZkK2jEg3XqvuvZh/KrdVMcR6ocEK7Dh+mgUogX27cHmepYM3UGHtwgVFHNUJHVC3GiycnQwluwUE+/E2NhmquugeeYCTIFQBKt/3tAS9sRPTwNp4dbQZpFldX6Ak1jlXP4Ro5MeCONWEdhIG02P4ZtJdim8bQR78FdfgwPLesjmxPdGVk8+4GP9jCeDGPcWIjjhWDhrAhg=="
	////应答主体
	//sign["body"] = "{\"id\":\"23a4f032-c4bf-588c-bfac-652fadff7f58854c\",\"create_time\":\"2020-09-25T17:28:29+08:00\",\"resource_type\":\"encrypt-resource\",\"event_type\":\"TRANSACTION.SUCCESS\",\"summary\":\"支付成功\",\"resource\":{\"original_type\":\"transaction\",\"algorithm\":\"AEAD_AES_256_GCM\",\"ciphertext\":\"GXJI0QFp75xaqviXd1sCvxR9g9PlVyrBHypJD7KZdFN0n1oIGN7Q8EKb1jRQDFaFlHRoOeZjYXffcjjxsru5ZPXqTYFLbEE3O477Wq6lxEQg12J6T+4sz9a3QRqRchphFoVO6a49zSfN06g4iBRJ12IMBX+dKEfJIYGJwaptMe9EOwnbYqOl2IG8btCLIXLNSTJY8jhwDYCotuy+8dQii/0oscAam3b9z2EX6nkjdArsLesT0z/qO5ru+3wfih6XfowLvwIvX924NiTFgnUPzDR8I/usFlQSO63XAViN2Vuc2jOC8+IhIf4T9Da96hOprWT4bcYLHf2RVk5n/EDR32CNbSykAxr45kcELBBv96EWALUzz38BYOgPdfuykoMuB063vXkF4c2bimPjgRGivGhYqz721dFYbB9h4wEnPFZLhAe8No6eEN1KZKAmIMTCUU0GpSrk1i5uC1oXLelZibSdtABer+vu2DAYY0EPk7XaelzqE99bIgvBkJis8oNSuZsMwUiaQ/cZoTlpvGpN15tJestDRbXyVcbaVBEzjxPFGq6v9sZe618iv7JS+eI=\",\"associated_data\":\"transaction\",\"nonce\":\"EyzzrcitYxPr\"}}"
	////HTTP头Wechatpay-Serial证书序列号
	//sign["wxSerial"] = "3BE8D7D58A068970391BEBD6D77640D5DE7CE668"

	//sign["timestamp"] = "1601087098"
	//sign["nonce"] = "q5fo6XB87nREzxUgeByUau7TI0YU6dBM"
	//sign["body"] = "{\"summary\":\"支付成功\",\"event_type\":\"TRANSACTION.SUCCESS\",\"create_time\":\"2020-09-26T10:24:57+08:00\",\"resource\":{\"original_type\":\"transaction\",\"algorithm\":\"AEAD_AES_256_GCM\",\"ciphertext\":\"pECbQysXC0OMRFazhm666AR/jZCnLqdhL8wH66PkIikIMgwU/Xoel+VTvuy0F6BBjU/tt1mQV2DRXtmkbA/P6JAsFIX/Kz5iCXeQphOyeCqh4xaoSao/JD39sbox+bkHXjQo4mfyAkvBNt4tRUOYtC+I8jrw8y3hxXRCdQNKBA7zqwiPXrGsqGaEespfjcaZVcKAmLd1mZWwWhQ2qEen04Xv3vsIhV5au4CbVssZPEyVMNjGxxJVK8FmWboEA21voim+PmWleCWlk6r8Qm/gTHJLe3K4lmm4rkxzczQsaFBCeRU8LO9mJsxKQT+/JdLuOKL1szVg+4etURh81FnkLW/8mbYPeY+Vbas/waYetKgUnKfshbKrZigZX/fcionxBMOSyzxgrvcLiIPrZemMBoGr2cwfgQksz1JWQ5TXN3moHLLPiTDflNeT42/qFtlNHTDZFelRmg5V8YepmCY9ibXKayMPZBGBnUim0r/Iwyyq5uTJCICHN0OH4Jti+EqlGh8MSPTkWSDtyunb0kZDHlVkxQxc+lAxxoTwWX/eUiBa+RyIFPPYPTa8Om7TTwrkdZI5\",\"associated_data\":\"transaction\",\"nonce\":\"yeZNRIHY08b9\"},\"resource_type\":\"encrypt-resource\",\"id\":\"2f28eab6-0a00-5bbf-a5b4-68d5a221b1fc\"}"
	//sign["signature"] = "Vtqzoo//yaSUsODWWcAnNaIGCs3qEWPTvAzztF/kik+JGx10r+LAvsA6z+YtGFVbUHve/CivGvcq9xwy069gYUol52IpsnaIIAgEdxZxLOdEjb/WscaUJMfOnXnuqPqts+LibfmztAdDFtX1lVt6ytnv0ntiwAXnY2RQkAHhMMO9cghFvnQfe53dXwtMOCD/qGHdMxWevekvYXoDiid2+sk0Wuf6HrNulVbIDr6BCjx68JkCQgqXwXFgdn9ZyZePif6oK317rZAYI36UikSpRqgy+VbldHhvzqZuvHOfzGFoav/EjiD1qd34Cm5r5yODVKoXAV1RtPoMfYNWYoYiTg=="
	//sign["wxSerial"] = "3BE8D7D58A068970391BEBD6D77640D5DE7CE668"

	sign["timestamp"] = resHeader.Get("Wechatpay-Timestamp")
	sign["nonce"] = resHeader.Get("Wechatpay-Nonce")
	sign["body"] = PingTaiZhengShuList.MustToJsonString()
	sign["signature"] = resHeader.Get("Wechatpay-Signature")
	sign["wxSerial"] = resHeader.Get("Wechatpay-Serial")+"a"

	//获取指定平台证书
	PingTaiZhengShuData, dataPingTaiZhengShu, err := GetZhiDingPingTaiZhengShu(sign["wxSerial"], PingTaiZhengShuList,resHeader)
	if err != nil {
		return false,err
	}
	jsonDataPingTaiZhengShu := gjson.New(dataPingTaiZhengShu)
	//请求类型
	sign["method"] = "POST"
	res, err := CheckSign(
		sign,
		jsonDataPingTaiZhengShu.GetString("serial_no"),
		jsonDataPingTaiZhengShu.GetString("encrypt_certificate.ciphertext"),
		jsonDataPingTaiZhengShu.GetString("encrypt_certificate.nonce"),
		jsonDataPingTaiZhengShu.GetString("encrypt_certificate.associated_data"),
		PingTaiZhengShuData,
	)
	if err != nil {
		fmt.Println(err.Error())
	}

	return res,nil
}

//验签
func CheckSign(sign map[string]string, serial_no string, PUBLICKEY string, ZHnonce string, ZHassociated_data string, PingTaiZhengShuData string) (bool, error) {
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
	_ = WeiXin.SetBaoCunWenBenDaoWenJian(checkStr, "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\平台证书/明文.pem")

	//解密signature base64
	signatureB64, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return false, err
	}
	_ = WeiXin.SetBaoCunWenBenDaoWenJian(string(signatureB64), "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\平台证书/签名.pem")

	fmt.Println("平台证书", PingTaiZhengShuData)
	_ = WeiXin.SetBaoCunWenBenDaoWenJian(PingTaiZhengShuData, "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\平台证书/证书.pem")
	GongYao, err := WeiXin.GetZhengShuQuGongYao(PingTaiZhengShuData)
	fmt.Println("平台证书公钥", GongYao)
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
