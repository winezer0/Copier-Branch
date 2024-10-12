# Copier

Copier Burp扩展（兼容社区和专业版），允许用户轻松地复制请求和响应，同时使用自定义规则进行自动修改。

这允许将请求和响应轻松地复制到报告中，而无需编辑以删除大的cookie值、无关的标头或敏感数据。

Copier 原项目地址 请访问 https://github.com/Tib3rius/Copier

## 修改功能

1、允许正则替换内容框为空

2、取消 Case Sensitive 勾选框 和 Enable 勾选框。

3、增加 StoreLocate 勾选框, 用于确定是否仅提取 Location 指定部分的数据而不是全文复制
```
目前已实现
switch (requestRule.getLocation()) {
    Request | Response 保留 请求体 | 响应体
    Request line | Response line 保留 请求行 | 响应行
    Request Body | Response Body 保留 请求体 | 响应体
    Request Headers | Response Headers 保留 请求头 | 响应头 【带首行】
    其他选项 未精确实现, 保留 请求行+请求体 | 响应行+响应体
```


3、增加 EnabledBase64 勾选框, 用于确定是否对报文内容进行Base64编码

4、增加 jsonFormat 勾选框 , 用于确定是否输出Json格式的结果

注意：对于存在多条规则的情况下，所有规则都参与替换，但是且仅调用最后一条规则用于位置提取.
