package main

import (
	"4/API/WeiXin/GongZhongHao"
	"fmt"
	_ "fmt"
	"github.com/gogf/gf/encoding/gjson"
	"io/ioutil"
)

func main() {
	//ciphertext:="GXJI0QFp75xaqviXd1sCvxR9g9PlVyrBHypJD7KZdFN0n1oIGN7Q8EKb1jRQDFaFlHRoOeZjYXffcjjxsru5ZPXqTYFLbEE3O477Wq6lxEQg12J6T+4sz9a3QRqRchphFoVO6a49zSfN06g4iBRJ12IMBX+dKEfJIYGJwaptMe9EOwnbYqOl2IG8btCLIXLNSTJY8jhwDYCotuy+8dQii/0oscAam3b9z2EX6nkjdArsLesT0z/qO5ru+3wfih6XfowLvwIvX924NiTFgnUPzDR8I/usFlQSO63XAViN2Vuc2jOC8+IhIf4T9Da96hOprWT4bcYLHf2RVk5n/EDR32CNbSykAxr45kcELBBv96EWALUzz38BYOgPdfuykoMuB063vXkF4c2bimPjgRGivGhYqz721dFYbB9h4wEnPFZLhAe8No6eEN1KZKAmIMTCUU0GpSrk1i5uC1oXLelZibSdtABer+vu2DAYY0EPk7XaelzqE99bIgvBkJis8oNSuZsMwUiaQ/cZoTlpvGpN15tJestDRbXyVcbaVBEzjxPFGq6v9sZe618iv7JS+eI="
	//nonce:="EyzzrcitYxPr"
	//associatedData:="transaction"
	//ret, _ := RsaDecrypt(ciphertext, nonce, associatedData)
	//fmt.Println(ret)

	//fmt.Println(GongZhongHao.GetXiaDan())
	//fmt.Println(GongZhongHao.CodeShouQuanHuanQuAccess_token("1"))

	//sign:=map[string]string{}
	////HTTP头Wechatpay-Timestam时间戳
	//sign["timestamp"]="1601034297"
	////HTTP头Wechatpay-Nonce随机字符串
	//sign["nonce"]="qlLWeXWfPQeUwVqfhiW7VR37ilLa7gKI"
	////HTTP头Wechatpay-Signature应答签名
	//sign["signature"]="gociYGOSPQWRhT9yo65D0PFzs/gG+9E81j42MgIcfwEgLymM0FrqrdnlMJsBYgPGP3HmxS1TW6DEgU8LiHek8pZi8e6cLwM7/4k0CF1FbHACGsN7NjGpgUQUM1g/DFP34aWTRDvjuJ8NZkK2jEg3XqvuvZh/KrdVMcR6ocEK7Dh+mgUogX27cHmepYM3UGHtwgVFHNUJHVC3GiycnQwluwUE+/E2NhmquugeeYCTIFQBKt/3tAS9sRPTwNp4dbQZpFldX6Ak1jlXP4Ro5MeCONWEdhIG02P4ZtJdim8bQR78FdfgwPLesjmxPdGVk8+4GP9jCeDGPcWIjjhWDhrAhg=="
	////应答主体
	//sign["body"]="{\"id\":\"23a4f032-c4bf-588c-bfac-652fadff7f58854c\",\"create_time\":\"2020-09-25T17:28:29+08:00\",\"resource_type\":\"encrypt-resource\",\"event_type\":\"TRANSACTION.SUCCESS\",\"summary\":\"支付成功\",\"resource\":{\"original_type\":\"transaction\",\"algorithm\":\"AEAD_AES_256_GCM\",\"ciphertext\":\"GXJI0QFp75xaqviXd1sCvxR9g9PlVyrBHypJD7KZdFN0n1oIGN7Q8EKb1jRQDFaFlHRoOeZjYXffcjjxsru5ZPXqTYFLbEE3O477Wq6lxEQg12J6T+4sz9a3QRqRchphFoVO6a49zSfN06g4iBRJ12IMBX+dKEfJIYGJwaptMe9EOwnbYqOl2IG8btCLIXLNSTJY8jhwDYCotuy+8dQii/0oscAam3b9z2EX6nkjdArsLesT0z/qO5ru+3wfih6XfowLvwIvX924NiTFgnUPzDR8I/usFlQSO63XAViN2Vuc2jOC8+IhIf4T9Da96hOprWT4bcYLHf2RVk5n/EDR32CNbSykAxr45kcELBBv96EWALUzz38BYOgPdfuykoMuB063vXkF4c2bimPjgRGivGhYqz721dFYbB9h4wEnPFZLhAe8No6eEN1KZKAmIMTCUU0GpSrk1i5uC1oXLelZibSdtABer+vu2DAYY0EPk7XaelzqE99bIgvBkJis8oNSuZsMwUiaQ/cZoTlpvGpN15tJestDRbXyVcbaVBEzjxPFGq6v9sZe618iv7JS+eI=\",\"associated_data\":\"transaction\",\"nonce\":\"EyzzrcitYxPr\"}}"
	////HTTP头Wechatpay-Serial证书序列号
	//sign["wxSerial"]="5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233"
	//et, err := CheckSign(sign,"5D0FBDA24CE5BFA1AAA00B375F11A794FD18F233","C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\1602157237_20200924_cert/cert.pem")
	//fmt.Println(et,err.Error())

	//fmt.Println(ZhiFuFenHuoQuZhengShu())

	//微信支付分创建订单
	//fmt.Println(ZhiFuFen.ChuangJianZhiFuFenDingDan())

	//JSAPI下单
	//package2, err :=GongZhongHao.GetXiaDan()
	//if err!=nil {
	//	fmt.Println(err.Error())
	//	return
	//}
	//GongZhongHao.GetZhiFu(package2)
	//return

	//获取平台证书
	resBody, resHeader, err :=GongZhongHao.GetPingTaiZhengShu()
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	sign:=map[string]string{}
	//sign["timestamp"] = resHeader.Get("Wechatpay-Timestamp")
	//sign["nonce"] = resHeader.Get("Wechatpay-Nonce")
	//sign["body"] = resBody
	//sign["signature"] = resHeader.Get("Wechatpay-Signature")
	//sign["wxSerial"] = resHeader.Get("Wechatpay-Serial")

	sign["timestamp"] = "1602920087"
	sign["nonce"] = "OHCxYkIb57PvHL0s9TbXbnOkrQxjDqYD"
	sign["body"], err = GetCeShi()
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	sign["signature"] = "VbxdX/fMx1pe2jugkcSkInrRiuw3FtpnOzkXAXBi5Tf9AjqkOizrfIGdD8Ze5aFXuhoGrR/rLAUIQGcwV+PbZuYfvVFFP52HoGT2yVTUNgtSXj+nokQgo9B8iZr1EEBG3XN6yBUdpEwzYI17UqzhJgKLZO8QLWYsjcK9POPnxupeR+RnlLoew8UGabjc51CqiuEJRLDKB/v6PhUFjkmL1HosPoLadGaTDh6UNRJKL+p1QRGoLzvHi2coY7QI20i1HHbpeLT1Iuc0oCTHBZiaRVgOKnHzmVmg+qahnWsrS3GpuPtHKqmkmRuMxgyugHHn4D4YOYFudaT4CHPQYsDAhQ=="
	sign["wxSerial"] = "3BE8D7D58A068970391BEBD6D77640D5DE7CE668"
	jsonResBody, err := gjson.DecodeToJson(resBody)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//验签
	ret, err := GongZhongHao.YanQianRuKou(jsonResBody, resHeader,sign)
	fmt.Println("验签结果",ret,err)

}
//获取测试Body数据
func GetCeShi()(string,error)  {
	body, err := ioutil.ReadFile("C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\测试数据/body.txt")
	//body, err := WeiXin.GetDouRuWenJian("C:\\Users\\Administrator\\OneDrive\\文本资料\\宇翔\\微信支付\\证书\\测试数据/body.txt")
	if err != nil {
		fmt.Println(err.Error())
		return "",err
	}
	return string(body), nil
}



