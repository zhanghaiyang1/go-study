package main

func main(){
	/*
	appid:tta08ed6333fbfa94301
	appSecret:4e01bc8d93a94d70c48342e544a0429d9c94d8f0
	*/
/* 获取openid
{
    "err_no": 0,
    "err_tips": "success",
    "data": {
        "session_key": "jsW5Ko6bDi+UeE8df6DIfw==",
        "openid": "_0009LwRIl3LEIeGjQz2G2_8i2D74fYIVVi-",
        "anonymous_openid": "",
        "unionid": "d65b3c2d-406f-5b98-9dec-33012dfa0e6f",
        "dopenid": ""
    }
}
*/

/* 生成client_token 7200
curl --location 'https://open.douyin.com/oauth/client_token/' \
--header 'Content-Type: application/json' \
--data '{
    "grant_type": "client_credential",
    "client_key": "tta08ed6333fbfa94301",
    "client_secret": "4e01bc8d93a94d70c48342e544a0429d9c94d8f0"
}' 


clt.850c41b53496fb6c07f00167182b0462N6yaoitZf3ugzuirTNdmIQPwAtxs
*/

/*查询用户券列表
curl --location --request POST 'https://open.douyin.com/api/trade/v2/fulfillment/query_user_certificates' \
--header 'Content-Type: application/json' \
--header 'access-token: clt.62ee7aabe08262c645b0d3622e473b4cLmbAhKWo8jabKyJZZi1ZCmiPe34g' \
--data-raw '{"open_id":"_0009LwRIl3LEIeGjQz2G2_8i2D74fYIVVi-","account_id":"7296781329369139211","page":1,"page_size":10}'

{"data":{"orders":[{"can_use":true,"certificates":[{"sku_info":{"spu_id":"1796091790116912","third_sku_id":"","groupon_type":1,"market_price":5000,"sold_start_time":1712884578,"title":"【青岛】踏青季中国石油45代50元汽油直抵券","account_id":"7296781329369139211","out_id":"","sku_id":"1796091790116912"},"start_time":1713146529,"amount":{"coupon_pay_amount":4500,"merchant_ticket_amount":0,"original_amount":4500,"pay_amount":4500,"payment_discount_amount":0,"platform_ticket_amount":0},"certificate_id":"7357908262957744147","expire_time":1744300799},{"start_time":1713146529,"amount":{"payment_discount_amount":1,"platform_ticket_amount":0,"coupon_pay_amount":4500,"merchant_ticket_amount":0,"original_amount":4500,"pay_amount":4499},"certificate_id":"7357908262957727763","expire_time":1744300799,"sku_info":{"market_price":5000,"out_id":"","sku_id":"1796091790116912","sold_start_time":1712884578,"spu_id":"1796091790116912","third_sku_id":"","account_id":"7296781329369139211","groupon_type":1,"title":"【青岛】踏青季中国石油45代50元汽油直抵券"}}],"order_id":"1039880231041949228"}],"total":2,"error_code":0,"description":""},"extra":{"error_code":0,"description":"","sub_error_code":0,"sub_description":"success","logid":"20240415100243B9FBB8D8B73D40861277","now":1713146563}}
*/

/* 券状态查询

curl --location --request POST 'https://open.douyin.com/api/apps/trade/v2/toolkit/query_certificate_info' \
--header 'Content-Type: application/json' \
--header 'access-token: clt.62ee7aabe08262c645b0d3622e473b4cLmbAhKWo8jabKyJZZi1ZCmiPe34g' \
--data-raw '{"certificate_id_list": ["7357908262957727763", "7357908262957744147"]}'

{"data":{"certificate_info_list":[{"certificate_id":"7357908262957727763","order_id":"1039880231041949228","status":1},{"order_id":"1039880231041949228","status":1,"certificate_id":"7357908262957744147"}]},"err_msg":"","err_no":0,"log_id":"20240415104906314ADCAB81C2C163094D"}

券状态
 0  : 初始化
 1  :  待履约
 2  :  履约中
 3  :  已履约
 4  : 履约完结（已推结算）
 50 :  售后中
 5  : 履约关闭
*/
}

