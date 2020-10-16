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
	"strconv"
	"time"
)

//JSAPI支付下单
func GetXiaDan() string {
	method := "POST"
	url := "/v3/pay/transactions/jsapi"
	data := make(map[string]interface{})
	data["appid"] = "wx32238000bf89db68"
	data["mchid"] = "1602157237"
	data["description"] = "广西-机柜1-苹果 "
	data["out_trade_no"] = "1217752501201407033233368020"
	data["notify_url"] = "https://m-store.com.cn/lingshou/wx/callback/pay_notify"
	amount := make(map[string]interface{})
	amount["total"] = 1
	amount["currency"] = "CNY"
	data["amount"] = amount
	payer := make(map[string]interface{})
	payer["openid"] = "oIbBd6DlJZ1uURUq1w3BwEAuk-xo"
	data["payer"] = payer

	packageString := WeiXin.Get(method, url, data, "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233", "1602157237", "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	fmt.Println("JSAPI下单", packageString)

	packageJson := make(map[string]interface{})
	err := json.Unmarshal([]byte(packageString), &packageJson)
	if err != nil {
		fmt.Println(err)
		return ""
	}
	package2 := fmt.Sprintln(packageJson["prepay_id"])
	//package2:="wx25123031790770b381e781da1301dc0000"
	return package2
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
func GetPingTaiZhengShu()map[string]interface{}  {
	packageString := WeiXin.Get("GET", "/v3/certificates", nil, "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233", "1602157237", "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	fmt.Println("packageString",packageString)
	packageJson := make(map[string]interface{})
	err := json.Unmarshal([]byte(packageString), &packageJson)
	if err != nil {
		fmt.Println(err)
		return nil
	}
	return packageJson
}

func CheckSign2(PUBLICKEY,serial_no,nonce,associated_data string) {
	sign := map[string]string{}
	//HTTP头Wechatpay-Timestam时间戳
	sign["timestamp"] = "1601034297"
	//HTTP头Wechatpay-Nonce随机字符串
	sign["nonce"] = "qlLWeXWfPQeUwVqfhiW7VR37ilLa7gKI"
	//HTTP头Wechatpay-Signature应答签名
	sign["signature"] = "gociYGOSPQWRhT9yo65D0PFzs/gG+9E81j42MgIcfwEgLymM0FrqrdnlMJsBYgPGP3HmxS1TW6DEgU8LiHek8pZi8e6cLwM7/4k0CF1FbHACGsN7NjGpgUQUM1g/DFP34aWTRDvjuJ8NZkK2jEg3XqvuvZh/KrdVMcR6ocEK7Dh+mgUogX27cHmepYM3UGHtwgVFHNUJHVC3GiycnQwluwUE+/E2NhmquugeeYCTIFQBKt/3tAS9sRPTwNp4dbQZpFldX6Ak1jlXP4Ro5MeCONWEdhIG02P4ZtJdim8bQR78FdfgwPLesjmxPdGVk8+4GP9jCeDGPcWIjjhWDhrAhg=="
	//应答主体
	sign["body"] = "{\"id\":\"23a4f032-c4bf-588c-bfac-652fadff7f58854c\",\"create_time\":\"2020-09-25T17:28:29+08:00\",\"resource_type\":\"encrypt-resource\",\"event_type\":\"TRANSACTION.SUCCESS\",\"summary\":\"支付成功\",\"resource\":{\"original_type\":\"transaction\",\"algorithm\":\"AEAD_AES_256_GCM\",\"ciphertext\":\"GXJI0QFp75xaqviXd1sCvxR9g9PlVyrBHypJD7KZdFN0n1oIGN7Q8EKb1jRQDFaFlHRoOeZjYXffcjjxsru5ZPXqTYFLbEE3O477Wq6lxEQg12J6T+4sz9a3QRqRchphFoVO6a49zSfN06g4iBRJ12IMBX+dKEfJIYGJwaptMe9EOwnbYqOl2IG8btCLIXLNSTJY8jhwDYCotuy+8dQii/0oscAam3b9z2EX6nkjdArsLesT0z/qO5ru+3wfih6XfowLvwIvX924NiTFgnUPzDR8I/usFlQSO63XAViN2Vuc2jOC8+IhIf4T9Da96hOprWT4bcYLHf2RVk5n/EDR32CNbSykAxr45kcELBBv96EWALUzz38BYOgPdfuykoMuB063vXkF4c2bimPjgRGivGhYqz721dFYbB9h4wEnPFZLhAe8No6eEN1KZKAmIMTCUU0GpSrk1i5uC1oXLelZibSdtABer+vu2DAYY0EPk7XaelzqE99bIgvBkJis8oNSuZsMwUiaQ/cZoTlpvGpN15tJestDRbXyVcbaVBEzjxPFGq6v9sZe618iv7JS+eI=\",\"associated_data\":\"transaction\",\"nonce\":\"EyzzrcitYxPr\"}}"
	//HTTP头Wechatpay-Serial证书序列号
	sign["wxSerial"] = "3BE8D7D58A068970391BEBD6D77640D5DE7CE668"

	//sign["timestamp"] = "1601087098"
	//sign["nonce"] = "q5fo6XB87nREzxUgeByUau7TI0YU6dBM"
	//sign["body"] = "{\"summary\":\"支付成功\",\"event_type\":\"TRANSACTION.SUCCESS\",\"create_time\":\"2020-09-26T10:24:57+08:00\",\"resource\":{\"original_type\":\"transaction\",\"algorithm\":\"AEAD_AES_256_GCM\",\"ciphertext\":\"pECbQysXC0OMRFazhm666AR/jZCnLqdhL8wH66PkIikIMgwU/Xoel+VTvuy0F6BBjU/tt1mQV2DRXtmkbA/P6JAsFIX/Kz5iCXeQphOyeCqh4xaoSao/JD39sbox+bkHXjQo4mfyAkvBNt4tRUOYtC+I8jrw8y3hxXRCdQNKBA7zqwiPXrGsqGaEespfjcaZVcKAmLd1mZWwWhQ2qEen04Xv3vsIhV5au4CbVssZPEyVMNjGxxJVK8FmWboEA21voim+PmWleCWlk6r8Qm/gTHJLe3K4lmm4rkxzczQsaFBCeRU8LO9mJsxKQT+/JdLuOKL1szVg+4etURh81FnkLW/8mbYPeY+Vbas/waYetKgUnKfshbKrZigZX/fcionxBMOSyzxgrvcLiIPrZemMBoGr2cwfgQksz1JWQ5TXN3moHLLPiTDflNeT42/qFtlNHTDZFelRmg5V8YepmCY9ibXKayMPZBGBnUim0r/Iwyyq5uTJCICHN0OH4Jti+EqlGh8MSPTkWSDtyunb0kZDHlVkxQxc+lAxxoTwWX/eUiBa+RyIFPPYPTa8Om7TTwrkdZI5\",\"associated_data\":\"transaction\",\"nonce\":\"yeZNRIHY08b9\"},\"resource_type\":\"encrypt-resource\",\"id\":\"2f28eab6-0a00-5bbf-a5b4-68d5a221b1fc\"}"
	//sign["signature"] = "Vtqzoo//yaSUsODWWcAnNaIGCs3qEWPTvAzztF/kik+JGx10r+LAvsA6z+YtGFVbUHve/CivGvcq9xwy069gYUol52IpsnaIIAgEdxZxLOdEjb/WscaUJMfOnXnuqPqts+LibfmztAdDFtX1lVt6ytnv0ntiwAXnY2RQkAHhMMO9cghFvnQfe53dXwtMOCD/qGHdMxWevekvYXoDiid2+sk0Wuf6HrNulVbIDr6BCjx68JkCQgqXwXFgdn9ZyZePif6oK317rZAYI36UikSpRqgy+VbldHhvzqZuvHOfzGFoav/EjiD1qd34Cm5r5yODVKoXAV1RtPoMfYNWYoYiTg=="
	//sign["wxSerial"] = "3BE8D7D58A068970391BEBD6D77640D5DE7CE668"

	//请求类型
	sign["method"] = "POST"
	et, err := CheckSign(
		sign,
		serial_no,
		PUBLICKEY,
		nonce,
		associated_data,
	)

	fmt.Println(et, err.Error())
}

//JSAPI支付回调-取得回复后调用此方法进行签名验证
func CheckSign(sign map[string]string, serial_no string, PUBLICKEY string,ZHnonce string,ZHassociated_data string) (bool, error) {

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
		return false, errors.New("证书号错误或已过期")
	}

	checkStr := time + "\n" + nonce + "\n" + body + "\n"

	//读证书文件
	//key, err := ioutil.ReadFile(keypath)
	//PUBLICKEY="-----BEGIN PUBLIC KEY-----\n"+PUBLICKEY+"\n-----END PUBLIC KEY----"
	fmt.Println(PUBLICKEY)
	//解密base64
	//key, err := base64.StdEncoding.DecodeString(PUBLICKEY)
	//if err != nil {
	//	return false, err
	//}
	plaintext, _ :=WeiXin.RsaDecrypt(PUBLICKEY,ZHnonce,ZHassociated_data)
	//fmt.Println("key2",plaintext)
	//从证书中提取公钥
	blocks, _ := pem.Decode([]byte(plaintext))
	if blocks == nil  {
		return false, errors.New("无法证书")
	}
	if blocks.Type!="CERTIFICATE"{
		return false, errors.New("不是证书")
	}
	cert, err := x509.ParseCertificate(blocks.Bytes)
	if err != nil {
		return false, err
	}
	publicKeyDer, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	//fmt.Println("publicKeyDer",string(publicKeyDer))
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	//解析公钥
	blocks, _ = pem.Decode([]byte(publicKeyPem))
	if blocks == nil  {
		return false, errors.New("无法公钥")
	}
	publicKey, err := x509.ParsePKIXPublicKey(blocks.Bytes)
	//fmt.Println("publicKey", publicKey)
	if err != nil {
		return false, err
	}
	//生成散列值
	hashed := sha256.Sum256([]byte(checkStr))
	//fmt.Println("hashed", hashed)
	//解密signature base64
	oldSign, err := base64.StdEncoding.DecodeString(signature)
	//fmt.Println("oldSign", oldSign)
	if err != nil {
		return false, err
	}
	//验签
	err = rsa.VerifyPKCS1v15(publicKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], oldSign)
	if err != nil {
		return false, err
	}
	return true, err
}
