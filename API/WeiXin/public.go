package WeiXin

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"
)


const (
	//商户号
	ShangHuHao string="1602157237"
	//API密钥
	APIMiYue string = "UJATIMB38cHO5X4ABekT4FZT0V7O0Put"
	//APIV3密钥
	APIV3MiYue string = "UJATIMB38cHO5X4ABekT4FZT0V7O0Pv3"
	//APIV3密钥长度
	APIV3MiYueLen int =32
	//商户证书序列号
	ShanɡHuZhengShuXuLieHao string = "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233"
)

func Get(method string,url string,data map[string]interface{},serial_no string,mchid string,keypath string)(http.Header,int,string,error)  {
	var bytesData []byte
	var Authorization string
	if  data!= nil {
		bytesData, _ = json.Marshal(data)
		fmt.Println("HTTP请求JSON字符串",string(bytesData))
		Authorization, _ = GetAuth(method, url, string(bytesData),serial_no,mchid,keypath)
	}else {
		Authorization, _ = GetAuth(method, url, "",serial_no,mchid,keypath)
	}
	//请求头
	headers := map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "application/json",
		"User-Agent":       "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1",
		"Authorization":    Authorization,
		"Wechatpay-Serial": serial_no,
	}
	fmt.Println("Authorization",Authorization)

	var bytesData2 io.Reader
	client := &http.Client{}
	if data==nil{
		bytesData2=nil
	}else {
		bytesData2=bytes.NewReader(bytesData)
	}

	req,err := http.NewRequest(method,"https://api.mch.weixin.qq.com"+url,bytesData2)
	if err != nil {
		return nil, 0, "", err
	}
	for i, i2 := range headers {
		req.Header.Add(i,i2)
	}
	resp,err := client.Do(req)
	if err != nil {
		return nil, 0, "", err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, "", err
	}
	return resp.Header,resp.StatusCode,string(body),nil
}
func GetUrl(method string,url string,data map[string]interface{},serial_no string,mchid string,keypath string)string  {
	bytesData, _ := json.Marshal(data)
	fmt.Println(string(bytesData))
	//string(bytesData)
	Authorization, _ := GetAuth(method, url, string(bytesData),serial_no,mchid,keypath)
	//请求头
	headers := map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "application/json",
		"User-Agent":       "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1",
		"Authorization":    Authorization,
		"Wechatpay-Serial": serial_no,
	}
	fmt.Println("Authorization",Authorization)

	client := &http.Client{}
	bytesData2:=bytes.NewReader(bytesData)
	req,_ := http.NewRequest(method,url,bytesData2)
	for i, i2 := range headers {
		req.Header.Add(i,i2)
	}
	resp,_ := client.Do(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body);
}
func GetAuth(method, url, body string,serial_no string,mchid string,keypath string) (res string, err error) {
	Authorization := "WECHATPAY2-SHA256-RSA2048" //固定字符串
	//mchid := "1602157237" //服务商商户号

	nonce_str := "1YjQ56C6lwFcWO17s9LFYxzbYX0M38b1"                         //32位随机字符串
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)                   //时间戳
	signature, err := Sign(method, url, timestamp, body, nonce_str,keypath) //生成签名

	//serial_no := "5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233" //取自配置 商户证书序列号
	Authorization = fmt.Sprintf(`%s mchid="%s",nonce_str="%s",signature="%s",timestamp="%s",serial_no="%s"`,
		Authorization, mchid, nonce_str, signature, timestamp, serial_no)

	return Authorization, err

}
func Sign(method, url, timestamp, body, nonce_str string,keypath string) (res string, err error) {
	//组装被加密的字符串
	randomStr := nonce_str
	targetStr := method + "\n" + url + "\n" + timestamp + "\n" + randomStr + "\n" + body + "\n"
	//加密
	sign, err := SHA256WithRsaBase64(targetStr,keypath)

	return sign, err
}
//JSAPI签名
func SignJSAPI(appId string,timestamp string,nonce_str string,package2 string,keypath string) (res string, err error) {
	//组装被加密的字符串
	randomStr := nonce_str
	targetStr := appId + "\n" + timestamp + "\n" + randomStr + "\n" + package2 + "\n"
	//加密
	sign, err := SHA256WithRsaBase64(targetStr,keypath)

	return sign, err
}
func SHA256WithRsaBase64(origData string,keypath string) (sign string, err error) {

	//var keypath = "C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem"
	key, err := ioutil.ReadFile(keypath)

	blocks, _ := pem.Decode(key)
	if blocks == nil || blocks.Type != "PRIVATE KEY" {
		fmt.Println("无法解码私钥")
		return

	}
	privateKey, err := x509.ParsePKCS8PrivateKey(blocks.Bytes)

	h := sha256.New()
	h.Write([]byte(origData))
	digest := h.Sum(nil)
	s, _ := rsa.SignPKCS1v15(nil, privateKey.(*rsa.PrivateKey), crypto.SHA256, digest)
	sign = base64.StdEncoding.EncodeToString(s)

	return sign, err
}
//AES-256-GCM解密
func RsaDecrypt(ciphertext, nonce2, associatedData2 string) (plaintext string, err error) {
	key := []byte("UJATIMB38cHO5X4ABekT4FZT0V7O0Pv3") //key是APIv3密钥，长度32位，由管理员在商户平台上自行设置的
	additionalData := []byte(associatedData2)
	nonce := []byte(nonce2)

	block, err := aes.NewCipher(key)
	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	cipherdata, _ := base64.StdEncoding.DecodeString(ciphertext)
	plaindata, err := aesgcm.Open(nil, nonce, cipherdata, additionalData)
	//fmt.Println("plaintext: ", string(plaindata))

	return string(plaindata), err
}
//AES - ECB解密
func AesDecrypt(ciphertext string) string {
	key := []byte("UJATIMB38cHO5X4ABekT4FZT0V7O0Pv3") // 加密的密钥
	encrypted, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		fmt.Println(err)
		return ""
	}

	genKey := make([]byte, 16)
	copy(genKey, key)
	for i := 16; i < len(key); {
		for j := 0; j < 16 && i < len(key); j, i = j+1, i+1 {
			genKey[j] ^= key[i]
		}
	}

	cipher, _ := aes.NewCipher(genKey)
	decrypted := make([]byte, len(encrypted))

	for bs, be := 0, cipher.BlockSize(); bs < len(encrypted); bs, be = bs+cipher.BlockSize(), be+cipher.BlockSize() {
		cipher.Decrypt(decrypted[bs:be], encrypted[bs:be])
	}

	trim := 0
	if len(decrypted) > 0 {
		trim = len(decrypted) - int(decrypted[len(decrypted)-1])
	}

	decrypted = decrypted[:trim]

	log.Println("解密结果：", string(decrypted))
	return string(decrypted)
}
//验证
func RsaVerySignWithSha256(data, signData, keyBytes []byte) bool {
	block, _ := pem.Decode(keyBytes)
	if block == nil {
		panic(errors.New("public key error"))
	}
	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		panic(err)
	}

	hashed := sha256.Sum256(data)
	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, hashed[:], signData)
	if err != nil {
		panic(err)
	}
	return true
}

// 公钥加密
func RsaEncrypt2(origData,publicKey []byte) ([]byte, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return rsa.EncryptPKCS1v15(rand.Reader, pub, origData)
}
// 私钥解密
func RsaDecrypt2(ciphertext,privateKey []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error!")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}
//获取商户公钥
func GetShangHuGongYao()(string,error)  {
	key, err := ioutil.ReadFile("C:\\Users\\17556\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/cert.pem")
	return string(key),err
}
//获取商户私钥
func GetShangHuSiYao()(string,error)  {
	key, err := ioutil.ReadFile("C:\\Users\\17556\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/apiclient_key.pem")
	return string(key),err
}
//解密报文
//original_type 加密前的对象类型
//algorithm 加密算法
//ciphertext Base64编码后的密文
//nonce 加密使用的随机串初始化向量）
//associated_data 附加数据包（可能为空）
func JieMiBaoWen(original_type,algorithm,ciphertext,nonce,associated_data string,resHeader http.Header)(string,error)  {
	//验证参数是否完整
	if original_type=="" {
		//return "",errors.New("original_type 加密前的对象类型 为空")
	}
	if algorithm=="" {
		return "",errors.New("algorithm 加密算法 为空")
	}
	if ciphertext=="" {
		return "",errors.New("ciphertext Base64编码后的密文 为空")
	}
	if nonce=="" {
		return "",errors.New("nonce 加密使用的随机串初始化向量） 为空")
	}

	//解密
	switch algorithm {
	case "AEAD_AES_256_GCM":
		data, err := AEAD_AES_256_GCMJieMi(ciphertext, nonce, associated_data)
		if err != nil {
			return "", err
		}
		return data, nil
	default:
		return "", errors.New(fmt.Sprint("使用了未定义的加密算法",algorithm))
	}
}
//AEAD_AES_256_GCM解密
func AEAD_AES_256_GCMJieMi(ciphertext,nonce,associated_data string)(string,error)  {
	APIV3MiYue, err :=GetAPIV3MiYue()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher([]byte(APIV3MiYue))
	if err != nil {
		return "", err
	}
	aesgcm, err := cipher.NewGCMWithNonceSize(block, len(nonce))
	if err != nil {
		return "", err
	}
	cipherdata, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}
	plaindata, err := aesgcm.Open(nil, []byte(nonce), cipherdata, []byte(associated_data))
	if err != nil {
		return "", err
	}
	return string(plaindata), nil
}
//获取APIV3密钥
func GetAPIV3MiYue()(string,error)  {
	if len(APIV3MiYue)!=APIV3MiYueLen {
		return "",errors.New("APIV3密钥长度不足32位")
	}
	return APIV3MiYue,nil
}
//证书取公钥
func GetZhengShuQuGongYao(ZhengShu string)(interface{},error)  {
	block, _ := pem.Decode([]byte(ZhengShu))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	fmt.Println("证书cert.Subject.Names",cert.Subject.Names)
	publicKeyDer, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	publicKeyBlock := pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyDer,
	}
	publicKeyPem := string(pem.EncodeToMemory(&publicKeyBlock))
	//解析公钥
	blocks, _ := pem.Decode([]byte(publicKeyPem))
	if blocks == nil {
		return nil, errors.New("无法公钥")
	}
	publicKey, err := x509.ParsePKIXPublicKey(blocks.Bytes)
	if err != nil {
		return nil, err
	}
	switch publicKey.(type) {
	case *rsa.PublicKey:
		fmt.Println("publicKeyPem is of type RSA")
	case *dsa.PublicKey:
		fmt.Println("publicKeyPem is of type DSA")
	case *ecdsa.PublicKey:
		fmt.Println("publicKeyPem is of type ECDSA")
	case ed25519.PublicKey:
		fmt.Println("publicKeyPem is of type Ed25519")
	default:
	}
	return publicKey, nil
}
//保存文本到文件
func SetBaoCunWenBenDaoWenJian(data,fileNamem string)error  {
	dstFile,err := os.Create(fileNamem)
	if err!=nil{
		return err
	}
	defer dstFile.Close()
	_, err = dstFile.WriteString(data)
	if err != nil {
		return  err
	}
	return err
}
//读入文件
func GetDouRuWenJian(fileNamem string)(string,error)  {
	fp, err := os.OpenFile(fileNamem, os.O_CREATE|os.O_APPEND, 6) // 读写方式打开
	if err != nil {
		return "", err
	}
	// defer延迟调用
	defer fp.Close()  //关闭文件，释放资源。

	var data []byte
	_, err= fp.Read(data)
	if err != nil {
		return "", err
	}
	return string(data), nil
}