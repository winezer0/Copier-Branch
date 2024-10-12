# Copier

Copier is a Burp Suite extension (compatible with both Community and Professional editions) which allows users to easily copy requests and responses while making automated modifications using custom rules.

This allows requests and responses to be easily copied into reports without editing to remove large cookie values, extraneous headers, or sensitive data. To watch Copier in action, please watch this YouTube video: https://youtu.be/m4y6IeZVAjg

## Examples

Download and import the CopyProfiles.json file in the examples directory to see some recommended default copy profiles & rules!


## 修改功能

1、允许正则替换内容框为空

2、修改 Case Sensitive 勾选框为 StoreLocate 勾选框为, 用于确定是否仅提取Location部分的数据 而不是全文复制 

3、修改 Enable 勾选框为 Base64 Encode , 用于确定是否对 报文内容 进行 Base64 编码

注意：任意请求|响应规则中调用 Base64编码后, 最终输出结果是Json格式，否则就是文本格式

注意：对于存在多条规则的情况下，所有规则都参与替换，且仅调用最后一条规则用于位置提取.
