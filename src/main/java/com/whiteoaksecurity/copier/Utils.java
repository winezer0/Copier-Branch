package com.whiteoaksecurity.copier;

import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import static com.whiteoaksecurity.copier.CopyProfile.NONE_CONTENT;

public class Utils {

    public static ArrayList<Rule> listAddList(ArrayList<Rule> requestLocateRules, ArrayList<Rule> responseLocateRules) {
        ArrayList<Rule> locateRules = new ArrayList<>();
        locateRules.addAll(requestLocateRules);
        locateRules.addAll(responseLocateRules);
        return locateRules;
    }

    //从所有规则中找到 开启非提取功能的规则
    public static ArrayList<Rule> getEnabledReplaceRules(ArrayList<Rule> rules) {
        ArrayList<Rule> replaceRules = new ArrayList<>();
        for(Rule rule : rules){
            if (rule.isEnabledRule() && !rule.isLocateRule()){
                replaceRules.add(rule);
            }
        }
        return replaceRules;
    }

    //从所有规则中找到 开启了提取功能的规则
    public static ArrayList<Rule> getEnabledLocateRules(ArrayList<Rule> rules) {
        ArrayList<Rule> locateRules = new ArrayList<>();
        for(Rule rule : rules){
            if (rule.isEnabledRule() && rule.isLocateRule()){
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
    public static Rule getLastLocateRule(ArrayList<Rule> locateRules) {
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
        String entireRequest = httpRequest.toByteArray().toString();

        // 如果请求体偏移量大于0，或包含特定分隔符，则处理；否则返回空字符串。
        if (httpRequest.bodyOffset() <= 0 && !entireRequest.contains(CopyProfile.SPILT)) {
            System.out.println("获取请求头发生错误: 当前不包含(换行*2)特征 返回空字符串作为请求头");
            return "";
        }

        // 根据条件选择切割请求头的索引
        int bodyStartIndex = httpRequest.bodyOffset() > 0 ? httpRequest.bodyOffset() : entireRequest.indexOf(CopyProfile.SPILT);
        if (bodyStartIndex <= 0)  return "";

        // 提取请求头部
        String requestHeaders = entireRequest.substring(0, bodyStartIndex).trim();

        // 将请求头部转换为字符串数组并去除第一个元素（通常是请求行）
        String[] headersAsArray = requestHeaders.lines().toList().toArray(new String[0]);
        if (headersAsArray.length <= 1) return "";
        String onlyRequestHeaders = String.join("\r\n", Arrays.copyOfRange(headersAsArray, 1, headersAsArray.length));
        return onlyRequestHeaders;
    }

    /*
        修改替换规则为提取规则,提取对象为所有位置
     */
    public static ArrayList<Rule> fixReplaceRulesToLocateRules(ArrayList<Rule> replaceRules) {
        for (Rule rule: replaceRules){
            rule.setLocation(0); //Case 0 保存全文
        }
        return replaceRules;
    }

    /**
     * 追加写入到文件中
     */
    public static void writeToFileAppend(Path path, String content, Charset charset) throws IOException {
        //StandardOpenOption.CREATE 在文件不存在时创建文件
        //StandardOpenOption.APPEND 追加写入
        Files.write(path, content.getBytes(charset), StandardOpenOption.CREATE, StandardOpenOption.APPEND);
    }

    /**
     * 覆盖写入到文件中
     */
    public static void writeToFileCover(Path path, String content, Charset charset) throws IOException {
        //StandardOpenOption.TRUNCATE_EXISTING 覆盖写入
        Files.write(path, content.getBytes(charset), StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
    }


    /**
     * 获取 ByteArray 的字符串 自定义编码
     */
    public static String ByteArrayToString(ByteArray bodyBytes, Charset charset) {
        return new String(bodyBytes.getBytes(), charset);
    }
}
