package API

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
)

//json[string]转换map[string]
func Json_MapString(data string)(map[string]interface{},error)  {
	var mapData map[string]interface{}
	err := json.Unmarshal([]byte(data), &mapData)
	if err != nil {
		return nil,err
	}
	return mapData,nil
}

//HTTP请求
func HTTPGet(method string,url string,data map[string]interface{}) string {
	bytesData, _ := json.Marshal(data)
	headers := map[string]string{
		"Content-Type":     "application/json",
		"Accept":           "application/json",
		"User-Agent":       "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/535.1 (KHTML, like Gecko) Chrome/14.0.835.163 Safari/535.1",
	}
	client := &http.Client{}
	bytesData2:=bytes.NewReader(bytesData)
	req,_ := http.NewRequest(method,url,bytesData2)
	for i, i2 := range headers {
		req.Header.Add(i,i2)
	}
	resp,_ := client.Do(req)
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	return string(body)
}
