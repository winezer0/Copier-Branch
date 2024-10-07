# Copier

Copier is a Burp Suite extension (compatible with both Community and Professional editions) which allows users to easily copy requests and responses while making automated modifications using custom rules.

This allows requests and responses to be easily copied into reports without editing to remove large cookie values, extraneous headers, or sensitive data. To watch Copier in action, please watch this YouTube video: https://youtu.be/m4y6IeZVAjg

## Examples

Download and import the CopyProfiles.json file in the examples directory to see some recommended default copy profiles & rules!

# TODO

1、允许正则替换内容框为空  OK
2、修改 Location 的 意思为 所需要复制的部位，而不是修改的地方【修改Case Sensitive框实现, 用于选择是否只保留指定位置的数据】 
3、修改 Case Sensitive 勾选框为 StoreLocate , 用于确定是否仅提取指定部分的数据 而不是全文复制 OK
4、修改 Enable 勾选框为Base64 Encode , 用于确定是否对项目内容进行编码  
