# Copier

Copier Burp扩展（兼容社区和专业版），允许用户轻松地复制请求和响应，同时使用自定义规则进行自动修改。

这允许将请求和响应轻松地复制到报告中，而无需编辑以删除大的cookie值、无关的标头或敏感数据。

Copier 原项目地址 请访问 https://github.com/Tib3rius/Copier


## 修改功能

1、允许正则替换内容框为空

2、取消 Case Sensitive 勾选框。

3、增加 LocateRule 勾选框, 表明是提取规则, 用于确定是否仅提取 Location 指定部分的数据而不是全文复制

```
目前已实现
switch (requestRule.getLocation()) {
    Request | Response 保留 请求体 | 响应体
    Request line | Response line 保留 请求行 | 响应行
    Request Body | Response Body 保留 请求体 | 响应体
    Request Headers | Response Headers 保留 请求头 | 响应头 【带首行】
    其他选项 未精确实现, 保留 请求行+请求体 | 响应行+响应体
```


4、增加 EnabledBase64 勾选框, 用于确定是否对报文内容进行Base64编码

5、增加 jsonFormat 勾选框 , 用于确定是否输出Json格式的结果

6、支持写入到文件或剪贴板

7、支持多种方式保存【剪贴板、单文件、多文件】

注意：对于存在多条规则的情况下，所有规则都参与替换，但对于非Json模式下的提取，且仅调用最后一条规则用于位置提取，对于Json模式下支持选择多个位置。

注意：该插件使用的是高版本 montoya-api Jdk 较高版本语法 需要使用新版burp (2024+)

注意：删除规则的确认按钮在右侧!!!


### TODO

1、修复中文保存后的乱码问题