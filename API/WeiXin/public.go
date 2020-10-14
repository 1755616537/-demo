package WeiXin

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"time"
)

func Get(method string,url string,data map[string]interface{},serial_no string,mchid string,keypath string)string  {
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
	req,_ := http.NewRequest(method,"https://api.mch.weixin.qq.com"+url,bytesData2)
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
