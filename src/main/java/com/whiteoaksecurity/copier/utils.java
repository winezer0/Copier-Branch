package com.whiteoaksecurity.copier;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;

import static com.whiteoaksecurity.copier.CopyProfile.NONE_CONTENT;

public class utils {

    public static ArrayList<Rule> listAddList(ArrayList<Rule> requestLocateRules, ArrayList<Rule> responseLocateRules) {
        ArrayList<Rule> locateRules = new ArrayList<>();
        locateRules.addAll(requestLocateRules);
        locateRules.addAll(responseLocateRules);
        return locateRules;
    }

    //从所有规则中找到 开启非提取功能的规则
    public static ArrayList<Rule> getReplaceRules(ArrayList<Rule> rules) {
        ArrayList<Rule> replaceRules = new ArrayList<>();
        for(Rule rule : rules){
            if (!rule.isStoreLocate()){
                replaceRules.add(rule);
            }
        }
        return replaceRules;
    }

    //从所有规则中找到 开启了提取功能的规则
    public static ArrayList<Rule> getLocateRules(ArrayList<Rule> rules) {
        ArrayList<Rule> locateRules = new ArrayList<>();
        for(Rule rule : rules){
            if (rule.isStoreLocate()){
                locateRules.add(rule);
            }
        }
        return locateRules;
    }

    //	检查是否使用Json格式导出
    public static boolean checkUseJsonFormat(ArrayList<Rule> locateRules) {
        for (Rule rule : locateRules) {
            if (rule.isJsonFormat())
                return true;
        }
        return false;
    }

    //从所有提取规则中获取最后一条规则
    public static Rule getLocateRule(ArrayList<Rule> locateRules) {
        Rule locateRule = null;
        if (locateRules.size() > 0){
            locateRule = locateRules.get(locateRules.size() - 1);
            if (locateRules.size() > 1){
                System.out.println(locateRule.toString());
            }
        }
        return locateRule;
    }

    /**
     * 根据当前的规则值和字符串内容 判断是否需要进行base64编码
     * @param string 需要编码的字符串
     * @param enabledBase64 是否需要编码
     * @return
     */
    public static String base64EncodeStrWithCheck(String string,  boolean enabledBase64) {
        if (!string.isEmpty() && !NONE_CONTENT.equals(string) && enabledBase64){
            string = base64EncodeStr(string);
        }
        return string;
    }

    /**
     * 进行base64编码字符串
     * @return
     */
    public static String base64EncodeStr(String string) {
        // 将字符串转换为字节数组
        byte[] bytes = string.getBytes(StandardCharsets.UTF_8);
        // 使用 Base64 进行编码
        String encodedString = Base64.getEncoder().encodeToString(bytes);
        return encodedString;
    }

    /**
     * 获取响应头
     */
     public static String getResponseHeaders(HttpResponse httpResponse) {
        String entireResponse = httpResponse.toByteArray().toString();

        String responseHeaders = "";
        if (httpResponse.bodyOffset()>0){
            responseHeaders = entireResponse.substring(0, httpResponse.bodyOffset()).trim();
        } else if (entireResponse.contains(CopyProfile.SPILT)){
            System.out.println(String.format("获取响应头发生错误: bodyOffset=[%s] 尝试切割方案获取请求头", httpResponse.bodyOffset()));
            responseHeaders = entireResponse.split(CopyProfile.SPILT,2)[0];
        } else {
            System.out.println("获取响应头发生错误: 当前不包含(换行*2)特征 返回空值");
        }
        return responseHeaders;
    }

    public static String getRequestHeaders(HttpRequest httpRequest) {
        String requestHeaders = "";

        String entireRequest = httpRequest.toByteArray().toString();

        if (httpRequest.bodyOffset() > 0){
            requestHeaders = entireRequest.substring(0, httpRequest.bodyOffset()).trim();
        } else if (entireRequest.contains(CopyProfile.SPILT)){
            System.out.println(String.format("获取请求头发生错误: bodyOffset=[%s] 尝试切割方案获取请求头", httpRequest.bodyOffset()));
            requestHeaders = entireRequest.split(CopyProfile.SPILT,2)[0];
        } else {
            System.out.println("获取请求头发生错误: 当前不包含(换行*2)特征 返回全文作为请求头");
        }
        return requestHeaders;
    }
}
